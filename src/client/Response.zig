//! A response: its head, and its body, read through `reader`.
//!
//! The head is copied out of the connection's buffer into one borrowed from
//! the client's pool, with the head's fields beside it and the body
//! reader's buffer after them, so a response costs no allocation once the
//! client is warm. `deinit` gives everything back, and the connection to
//! the pool when the body was read to its end, reading what is left of it
//! first when that is little.
//!
//! A response must not move once `reader` has been called: the reader
//! points into it.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const wire = @import("uplink.wire");
const h1 = wire.h1;
const fields = wire.fields;
const coding = wire.coding;
const Method = wire.Method;
const Version = wire.Version;
const Connection = @import("../transport/Connection.zig");
const H2 = @import("../transport/H2.zig");
const Context = @import("../transport/Context.zig");
const Diagnostics = @import("../transport/Diagnostics.zig");
const Pool = @import("../pool/Pool.zig");
const Body = @import("../transport/Body.zig");
const Head = @import("../transport/Head.zig");
const Decoder = @import("../coding/Decoder.zig");
const Upgraded = @import("Upgraded.zig");
const Cache = @import("Cache.zig");

const Response = @This();

status: std.http.Status,
version: Version,
/// The reason phrase, as the server wrote it.
reason: []const u8,
headers: fields.Headers,
/// The URL the response came from: the request's, or where its redirects
/// led. Valid until `deinit`; the request's own text when no redirect was
/// followed.
url: []const u8 = "",

/// Private: what the response came over: a connection of its own, or a
/// stream of a shared HTTP/2 one.
ctx: *Context,
pool: *Pool,
conn: ?*Connection,
h2: ?*H2 = null,
stream: ?*H2.Stream = null,
/// Private: the head, its fields and the body reader's buffer.
head_buffer: []u8,
body_buffer: []u8,
/// Private: the final URL's bytes, when a redirect was followed.
url_buffer: []u8 = &.{},
/// Private: the trailer's fields, once parsed.
trailer_fields: ?fields.Headers = null,
keep_alive: bool,
/// Private: the response to a `CONNECT`.
tunnel: bool = false,
body: Body,
/// Private: the body's codings undone, when the client decodes them; its
/// state lives in the buffers it holds, so the response stays small to
/// pass around.
decoder: ?Decoder = null,
/// Private: the decoded body's reader, once started.
decoded: ?*Io.Reader = null,
started: bool = false,
/// Where the response came from, when the client has a cache: `none`
/// when it has none.
cache: CacheStatus = .none,
/// Private: the stored variant a response from the cache reads, held
/// until `deinit`.
stored: ?Stored = null,
/// Private: the store a response from the network is written to as it is
/// read, kept only when its body ends whole.
tee: ?Tee = null,

/// Where a response came from (RFC 9211's `Cache-Status`, in short).
pub const CacheStatus = enum {
    /// The client has no cache, or the request was not one it keeps.
    none,
    /// The network's, the cache having nothing usable.
    miss,
    /// The cache's, fresh.
    hit,
    /// The cache's, stale, as the request's `max-stale` or the response's
    /// `stale-if-error` allows.
    stale,
    /// The cache's, after the origin said it was still good (304).
    revalidated,
    /// Made by the cache: a 504 for `only-if-cached` with nothing stored
    /// (RFC 9111 §5.2.1.7).
    synthesized,
};

/// A stored variant being read.
const Stored = struct {
    cache: *Cache,
    entry: Cache.Entry,
    bytes: Io.Reader = undefined,
    file: Io.File.Reader = undefined,
};

/// A response from the network on its way into the store: the body's
/// bytes as they came (still content-coded), handed to the store as the
/// reader passes them on.
const Tee = struct {
    cache: *Cache,
    writing: Cache.Writing,
    source: *Io.Reader = undefined,
    io: Io = undefined,
    /// The store took no more, or failed: aborted at `deinit`.
    dropped: bool = false,
    interface: Io.Reader = .{ .vtable = &.{ .stream = teeStream }, .buffer = &.{}, .seek = 0, .end = 0 },
};

fn teeStream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
    const t: *Tee = @fieldParentPtr("interface", r);
    const dest = limit.slice(try w.writableSliceGreedy(1));
    const n = t.source.readSliceShort(dest) catch return error.ReadFailed;
    if (n == 0) return error.EndOfStream;
    if (!t.dropped) {
        const kept = t.cache.store.append(t.io, t.writing, dest[0..n]) catch false;
        if (!kept) t.dropped = true;
    }
    w.advance(n);
    return n;
}

/// Errors from reading the body, by name.
pub const ReadError = error{
    ConnectionFailed,
    TimedOut,
    TlsFailed,
    ClientCertificateRejected,
    Canceled,
    /// Chunk framing that does not parse.
    HttpProtocolError,
    /// A coded body that does not decode: not a stream of its coding, a
    /// checksum that is not the data's, a zstd window past the client's
    /// cap, or a stream cut short. `decodingFailure` says which.
    BadContentEncoding,
    /// The connection ended before the body did.
    BodyIncomplete,
};

/// Errors from `collect`.
pub const CollectError = error{
    ConnectionFailed,
    TimedOut,
    TlsFailed,
    ClientCertificateRejected,
    Canceled,
    HttpProtocolError,
    BadContentEncoding,
    BodyIncomplete,
    OutOfMemory,
    /// The body is longer than the limit given.
    StreamTooLong,
};

/// The body, decoded per `Content-Encoding` and any coding before
/// `chunked` when the client decompresses and every one is gzip, deflate
/// or zstd, their checksums verified; a body under any other coding is
/// handed over as it came, for the caller to decode. Reads keep the client's timeouts. `io`
/// is the one the reads run on until the response is released.
pub fn reader(r: *Response, io: Io) *Io.Reader {
    return r.open(io, null);
}

/// `reader`, buffered through `buffer` in place of the room the response's
/// head leaves, which is at least 1 KiB: for a caller that peeks or takes
/// more of the body at once, as a protocol of long framed lines does. A
/// body the client decodes is buffered in its decoder's window, 32 KiB or
/// more, and leaves `buffer` unused. It takes effect when called in place of the
/// first `reader`, and `buffer` must outlive the reads.
pub fn readerBuffered(r: *Response, io: Io, buffer: []u8) *Io.Reader {
    return r.open(io, buffer);
}

fn open(r: *Response, io: Io, buffer: ?[]u8) *Io.Reader {
    if (r.conn) |c| c.io = io;
    if (r.stream) |st| st.read_io = io;
    r.body.trailer_io = io;
    if (r.tee) |*t| t.io = io;
    if (!r.started) {
        r.started = true;
        r.body.in = if (r.conn) |c| c.reader() else if (r.stream) |st| st.reader(io) else if (r.stored) |*st| storedReader(st, io) else Io.Reader.ending;
        r.body.trailer_pool = &r.ctx.buffers;
        // A body on its way into the store reads through the tee, which
        // then holds the reader's buffer.
        const source: *Io.Reader = if (r.tee) |*t| tee: {
            t.source = &r.body.interface;
            t.interface.buffer = r.body.interface.buffer;
            r.body.interface.buffer = &.{};
            break :tee &t.interface;
        } else &r.body.interface;
        if (r.decoder) |*d| {
            r.decoded = d.start(source, &r.ctx.zstd);
        } else if (buffer) |b| {
            source.buffer = b;
        }
        if (r.decoder == null) return source;
    }
    return r.decoded orelse if (r.tee) |*t| &t.interface else &r.body.interface;
}

fn storedReader(st: *Stored, io: Io) *Io.Reader {
    switch (st.entry.body) {
        .bytes => |bytes| {
            st.bytes = .fixed(bytes);
            return &st.bytes;
        },
        .file => |f| {
            st.file = f.file.readerStreaming(io, &.{});
            return &st.file.interface;
        },
    }
}

/// Why a coded body did not decode, after a read failed with
/// `BadContentEncoding`.
pub fn decodingFailure(r: *const Response) ?Decoder.Error {
    const d = &(r.decoder orelse return null);
    return d.failure(&r.ctx.zstd);
}

/// After the body's end: the fields of a chunked body's trailer section,
/// or null when it had none or the body is not read to its end.
pub fn trailers(r: *Response) ?fields.Headers {
    if (r.trailer_fields) |t| return t;
    if (r.stream) |st| {
        if (!r.body.complete()) return null;
        r.trailer_fields = .init(st.trailers orelse return null);
        return r.trailer_fields;
    }
    const bytes = r.body.trailerBytes() orelse return null;
    // `bytes` starts the pool buffer, which is aligned past a Field's need.
    const end = std.mem.alignForward(usize, bytes.len, @alignOf(fields.Field));
    const field_ptr: [*]fields.Field = @ptrCast(@alignCast(r.body.trailer.ptr + end)); // safe: pool buffers are 64-aligned and `end` is aligned for a Field, with room for `trailer_fields` of them
    const parsed = h1.parseTrailer(bytes, field_ptr[0..Body.trailer_fields]) catch return null;
    r.trailer_fields = parsed;
    return parsed;
}

/// Errors from `upgrade`.
pub const UpgradeError = error{
    /// Not a 101, nor a 2xx to `CONNECT`, or the body was read.
    NotUpgraded,
};

/// After a `101 Switching Protocols`, or a 2xx to a `CONNECT` the caller
/// sent: the connection, for the caller to speak its new protocol on. The
/// response is spent: only `deinit` is owed, which then releases its
/// buffers alone.
pub fn upgrade(r: *Response, io: Io) UpgradeError!Upgraded {
    const conn = r.conn orelse return error.NotUpgraded;
    const code = @backingInt(r.status);
    if (code != 101 and !(r.tunnel and code / 100 == 2)) return error.NotUpgraded;
    if (r.started) return error.NotUpgraded;
    conn.io = io;
    conn.deadline = null;
    conn.diagnostics = null;
    r.conn = null;
    return .{ .ctx = r.ctx, .pool = r.pool, .conn = conn };
}

/// The whole body, at most `limit` bytes, in `gpa`.
pub fn collect(r: *Response, gpa: Allocator, io: Io, limit: Io.Limit) CollectError![]u8 {
    const rd = r.reader(io);
    return rd.allocRemaining(gpa, limit) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.StreamTooLong => error.StreamTooLong,
        error.ReadFailed => r.failure(),
    };
}

/// Why the last read of the body failed.
pub fn failure(r: *const Response) ReadError {
    return switch (r.body.state) {
        .incomplete => error.BodyIncomplete,
        .malformed => error.HttpProtocolError,
        .too_large => unreachable, // unreachable: the client caps no body
        .read_failed => if (r.conn) |c| c.readError() else if (r.stream) |st| streamError(st) else error.ConnectionFailed,
        // The body read fine: the decoder refused it.
        .reading, .done => error.BadContentEncoding,
    };
}

fn streamError(st: *const H2.Stream) ReadError {
    return switch (st.read_failure orelse return error.ConnectionFailed) {
        error.TimedOut => error.TimedOut,
        error.Canceled => error.Canceled,
        error.TlsFailed => error.TlsFailed,
        error.ClientCertificateRejected => error.ClientCertificateRejected,
        error.ConnectionFailed, error.Refused, error.OutOfMemory => error.ConnectionFailed,
    };
}

/// Release the response. Its connection is kept for the next exchange when
/// the body was read to its end, or what was left of it was no more than
/// the pool's `drain_limit` and came within the activity timeout, and
/// nothing said to close it.
pub fn deinit(r: *Response, io: Io) void {
    if (r.tee) |*t| {
        // Kept only when the body ended whole, every byte of it through the
        // tee, and the store took all of it; before a drain reads the rest
        // past it.
        if (r.body.state == .done and !t.dropped) {
            // glint-ignore: Z026 -- a store that fails costs the cache, never the response; the observer heard of a failed begin
            t.cache.store.commit(io, t.writing) catch {};
        } else t.cache.store.abort(io, t.writing);
        // The body's buffer back from the tee, for the drain below.
        if (r.started) {
            r.body.interface.buffer = t.interface.buffer;
            r.body.interface.seek = 0;
            r.body.interface.end = 0;
        }
    }
    if (r.conn) |c| {
        c.io = io;
        if (r.keep_alive and !r.body.complete() and c.reusable()) r.drain(io);
        const reusable = r.keep_alive and r.body.complete() and c.reusable() and c.reader().bufferedLen() == 0;
        release(io, r.ctx, r.pool, c, reusable);
    }
    if (r.stream) |st| {
        const h = r.h2.?;
        h.finish(io, st);
        releaseShared(io, r.ctx, r.pool, h);
    }
    if (r.decoder) |*d| d.deinit(io, r.ctx.gpa, &r.ctx.buffers, &r.ctx.zstd);
    if (r.stored) |*st| st.cache.store.release(io, &st.entry);
    if (r.body.trailer.len != 0) r.ctx.buffers.release(io, r.body.trailer);
    if (r.url_buffer.len != 0) r.ctx.buffers.release(io, r.url_buffer);
    r.ctx.buffers.release(io, r.head_buffer);
    r.* = undefined;
}

/// A response from a stored variant, its head `head` (the status line,
/// the fields, `Age` and the body's length, as HTTP/1.1 writes them), its
/// body the variant's, which it holds until `deinit`; with no variant, a
/// response the cache made, with no body. A head that does not parse
/// releases the variant and is `HttpProtocolError`.
pub fn fromStored(io: Io, ctx: *Context, pool: *Pool, cache: *Cache, entry: ?Cache.Entry, head: []const u8, status: CacheStatus, options: StoredOptions) (Allocator.Error || error{HttpProtocolError})!Response {
    errdefer if (entry) |e| cache.store.release(io, &e);
    var text: Io.Reader = .fixed(head);
    var progress = false;
    var gathered = Head.gather(io, &ctx.buffers, &text, options.limits, &progress) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.HttpProtocolError,
    };
    errdefer gathered.release(io, &ctx.buffers);
    const parsed = (h1.parseResponse(gathered.bytes(), gathered.fields(), options.limits) catch return error.HttpProtocolError) orelse
        return error.HttpProtocolError;
    const length = if (entry) |e| e.body.len() else 0;
    var response: Response = .{
        .status = parsed.head.status,
        .version = parsed.head.version,
        .reason = parsed.head.reason,
        .headers = parsed.head.headers,
        .ctx = ctx,
        .pool = pool,
        .conn = null,
        .head_buffer = gathered.buffer,
        .body_buffer = gathered.bodyBuffer(),
        .keep_alive = false,
        .body = .init(Io.Reader.ending, if (options.method.bodiless()) .none else .{ .length = length }, gathered.bodyBuffer()),
        .cache = status,
        .stored = if (entry) |e| .{ .cache = cache, .entry = e } else null,
    };
    if (options.decompress) try response.planDecoding(io);
    return response;
}

pub const StoredOptions = struct {
    method: Method,
    limits: h1.Limits,
    decompress: bool,
};

/// Write the body, as it is read, to `cache`'s store as `writing`: kept
/// at `deinit` when it ended whole. Before the first `reader`.
pub fn storeInto(r: *Response, cache: *Cache, writing: Cache.Writing) void {
    std.debug.assert(!r.started and r.tee == null and r.stored == null);
    r.tee = .{ .cache = cache, .writing = writing };
}

/// Release an interim response's head and nothing else: the connection
/// stays with the request that waits on it.
pub fn releaseHead(r: *Response, io: Io) void {
    std.debug.assert(r.decoder == null);
    r.ctx.buffers.release(io, r.head_buffer);
    r.* = undefined;
}

/// Read what is left of the body, as it came, when it is no more than the
/// pool's `drain_limit`, so the connection can be kept.
fn drain(r: *Response, io: Io) void {
    var left: usize = r.pool.options.drain_limit.raw();
    if (left == 0) return;
    if (!r.started) {
        r.started = true;
        r.body.in = r.conn.?.reader();
    }
    r.body.trailer_io = io;
    switch (r.body.framing) {
        // A known length past the limit is not worth reading.
        .length => if (r.body.remaining > left) return,
        .chunked => {},
        .none, .until_close => return,
    }
    while (left > 0) {
        const n = r.body.interface.discard(.limited(left)) catch return;
        if (n == 0) return;
        left -= n;
    }
}

/// Give a connection back after its exchange: kept when `reusable`, closed
/// otherwise; the connection the pool puts out to make room is closed too,
/// and one idle past its time.
pub fn release(io: Io, ctx: *Context, pool: *Pool, conn: *Connection, reusable: bool) void {
    _ = ctx.counters.in_use.fetchSub(1, .monotonic);
    if (!reusable) return pool.close(io, .{ .h1 = conn });
    conn.park(io);
    const kept = pool.keep(io, .{ .h1 = conn });
    for ([_]?Pool.Kind{ kept.evicted, kept.expired }) |out| if (out) |k| pool.close(io, k);
}

/// Give back an exchange's share of an HTTP/2 connection, its stream
/// finished.
pub fn releaseShared(io: Io, ctx: *Context, pool: *Pool, h: *H2) void {
    _ = ctx.counters.in_use.fetchSub(1, .monotonic);
    pool.unshare(io, h);
}

/// What `fromStream` needs besides the stream.
pub const StreamOptions = struct {
    method: Method,
    decompress: bool,
    /// The exchange's deadline, which the body's reads keep.
    deadline: ?Io.Timestamp,
};

/// The response whose head came on `st`, which it then holds; its body is
/// the stream's data.
pub fn fromStream(io: Io, ctx: *Context, pool: *Pool, h: *H2, st: *H2.Stream, options: StreamOptions) Allocator.Error!Response {
    const buffer = try ctx.buffers.acquire(io, .small);
    errdefer ctx.buffers.release(io, buffer);
    const status: std.http.Status = @fromBackingInt(st.status.?);
    const code = st.status.?;
    const bodiless = options.method.bodiless() or code == 204 or code == 304;
    st.read_deadline = options.deadline;
    var response: Response = .{
        .status = status,
        .version = .h2,
        .reason = "",
        .headers = .init(st.fields),
        .ctx = ctx,
        .pool = pool,
        .conn = null,
        .h2 = h,
        .stream = st,
        .head_buffer = buffer,
        .body_buffer = buffer,
        // The stream ends the exchange; the connection goes on regardless.
        .keep_alive = true,
        .body = .init(Io.Reader.ending, if (bodiless) .none else .until_close, buffer),
    };
    if (options.decompress) try response.planDecoding(io);
    return response;
}

/// Errors from `receive`.
pub const ReceiveError = error{
    ConnectionFailed,
    TimedOut,
    TlsFailed,
    ClientCertificateRejected,
    Canceled,
    HttpProtocolError,
    OutOfMemory,
};

/// What `receive` needs besides the connection.
pub const ReceiveOptions = struct {
    method: Method,
    limits: h1.Limits,
    decompress: bool,
    diagnostics: ?*Diagnostics,
    /// Set once a byte of the response has arrived.
    progress: *bool,
    /// Return a `100 Continue` rather than skipping it: the request waits
    /// for one before its body.
    want_continue: bool = false,
};

/// Read the response to the request just written on `conn`, which it then
/// holds. Interim 1xx heads other than 101 are skipped.
pub fn receive(io: Io, ctx: *Context, pool: *Pool, conn: *Connection, options: ReceiveOptions) ReceiveError!Response {
    if (options.diagnostics) |d| d.stage = .head;
    while (true) {
        var head = try receiveHead(io, ctx, conn, options);
        errdefer ctx.buffers.release(io, head.buffer);
        const code = @backingInt(head.head.status);
        if (code / 100 == 1 and code != 101 and !(code == 100 and options.want_continue)) {
            ctx.buffers.release(io, head.buffer);
            continue;
        }
        const framing = h1.responseFraming(options.method, &head.head) catch return error.HttpProtocolError;
        var response: Response = .{
            .status = head.head.status,
            .version = head.head.version,
            .reason = head.head.reason,
            .headers = head.head.headers,
            .ctx = ctx,
            .pool = pool,
            .conn = conn,
            .head_buffer = head.buffer,
            .body_buffer = head.body_buffer,
            .keep_alive = framing.keep_alive,
            .tunnel = options.method.eql(.CONNECT),
            .body = .init(Io.Reader.ending, framing.framing, head.body_buffer),
        };
        if (options.decompress) try response.planDecoding(io);
        if (options.diagnostics) |d| d.stage = .body;
        return response;
    }
}

/// Decode a body whose codings are all gzip, deflate or zstd; a body
/// under any other, or under codings uplink cannot read, is handed over as
/// it came, `Content-Encoding` and all.
fn planDecoding(r: *Response, io: Io) Allocator.Error!void {
    if (r.body.state == .done) return;
    const codings = coding.Codings.of(&r.headers) catch return;
    if (codings.len == 0 or !Decoder.decodes(codings.slice())) return;
    r.decoder = try .init(io, r.ctx.gpa, &r.ctx.buffers, &r.ctx.zstd, codings.slice());
}

/// A response head, parsed in its pooled buffer.
const Received = struct {
    buffer: []u8,
    head: h1.ResponseHead,
    body_buffer: []u8,
};

/// Read one head from `conn` into a pooled buffer and parse it there.
fn receiveHead(io: Io, ctx: *Context, conn: *Connection, options: ReceiveOptions) ReceiveError!Received {
    var head = Head.gather(io, &ctx.buffers, conn.reader(), options.limits, options.progress) catch |err| return switch (err) {
        error.HeadTooLarge, error.StartLineTooLong, error.NoStartLine => error.HttpProtocolError,
        error.EndOfStream => if (conn.failed() == .none) error.ConnectionFailed else conn.readError(),
        error.ReadFailed => conn.readError(),
        error.OutOfMemory => error.OutOfMemory,
    };
    errdefer head.release(io, &ctx.buffers);
    const parsed = (h1.parseResponse(head.bytes(), head.fields(), options.limits) catch return error.HttpProtocolError) orelse
        return error.HttpProtocolError;
    std.debug.assert(parsed.len == head.len);
    return .{ .buffer = head.buffer, .head = parsed.head, .body_buffer = head.bodyBuffer() };
}
