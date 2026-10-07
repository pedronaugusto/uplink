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
const h1 = @import("../wire/h1.zig");
const fields = @import("../wire/fields.zig");
const coding = @import("../wire/coding.zig");
const Method = @import("../wire/Method.zig");
const Version = @import("../wire/version.zig").Version;
const Connection = @import("../transport/Connection.zig");
const Context = @import("../transport/Context.zig");
const Diagnostics = @import("../transport/Diagnostics.zig");
const BufferPool = @import("../transport/BufferPool.zig");
const Pool = @import("../pool/Pool.zig");
const Body = @import("Body.zig");
const Upgraded = @import("Upgraded.zig");

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

/// Private: what the response came over.
ctx: *Context,
pool: *Pool,
conn: ?*Connection,
/// Private: the head, its fields and the body reader's buffer.
head_buffer: []u8,
body_buffer: []u8,
/// Private: the decompression window, when the body is decoded.
window: []u8 = &.{},
/// Private: the final URL's bytes, when a redirect was followed.
url_buffer: []u8 = &.{},
/// Private: the trailer's fields, once parsed.
trailer_fields: ?fields.Headers = null,
keep_alive: bool,
/// Private: the response to a `CONNECT`.
tunnel: bool = false,
body: Body,
decoder: Decoder = .none,
started: bool = false,

const Decoder = union(enum) {
    none,
    flate: struct {
        container: std.compress.flate.Container,
        state: std.compress.flate.Decompress,
    },
    zstd: std.compress.zstd.Decompress,
};

/// Errors from reading the body, by name.
pub const ReadError = error{
    ConnectionFailed,
    TimedOut,
    TlsFailed,
    ClientCertificateRejected,
    Canceled,
    /// Chunk framing or compressed data that does not decode.
    HttpProtocolError,
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
    BodyIncomplete,
    OutOfMemory,
    /// The body is longer than the limit given.
    StreamTooLong,
};

/// The body, decoded per `Content-Encoding` when the client decompresses
/// and the coding is gzip or deflate; any other coding is handed over as it
/// came, for the caller to decode. Reads keep the client's timeouts. `io`
/// is the one the reads run on until the response is released.
pub fn reader(r: *Response, io: Io) *Io.Reader {
    if (r.conn) |c| c.io = io;
    r.body.trailer_io = io;
    if (!r.started) {
        r.started = true;
        r.body.in = if (r.conn) |c| c.reader() else Io.Reader.ending;
        r.body.trailer_pool = &r.ctx.buffers;
        switch (r.decoder) {
            .none => {},
            .flate => |*f| f.state = .init(&r.body.interface, f.container, r.window),
            .zstd => |*z| z.* = .init(&r.body.interface, r.window, .{ .window_len = @intCast(r.window.len - std.compress.zstd.block_size_max) }),
        }
    }
    return switch (r.decoder) {
        .none => &r.body.interface,
        .flate => |*f| &f.state.reader,
        .zstd => |*z| &z.reader,
    };
}

/// After the body's end: the fields of a chunked body's trailer section,
/// or null when it had none or the body is not read to its end.
pub fn trailers(r: *Response) ?fields.Headers {
    if (r.trailer_fields) |t| return t;
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
        .read_failed => if (r.conn) |c| c.readError() else error.ConnectionFailed,
        // The body read fine: the decoder refused it.
        .reading, .done => error.HttpProtocolError,
    };
}

/// Release the response. Its connection is kept for the next exchange when
/// the body was read to its end, or what was left of it was no more than
/// the pool's `drain_limit` and came within the activity timeout, and
/// nothing said to close it.
pub fn deinit(r: *Response, io: Io) void {
    if (r.conn) |c| {
        c.io = io;
        if (r.keep_alive and !r.body.complete() and c.reusable()) r.drain(io);
        const reusable = r.keep_alive and r.body.complete() and c.reusable() and c.reader().bufferedLen() == 0;
        release(io, r.ctx, r.pool, c, reusable);
    }
    switch (r.decoder) {
        .zstd => r.ctx.releaseZstdWindow(r.window),
        .flate => r.ctx.buffers.release(io, r.window),
        .none => {},
    }
    if (r.body.trailer.len != 0) r.ctx.buffers.release(io, r.body.trailer);
    if (r.url_buffer.len != 0) r.ctx.buffers.release(io, r.url_buffer);
    r.ctx.buffers.release(io, r.head_buffer);
    r.* = undefined;
}

/// Release an interim response's head and nothing else: the connection
/// stays with the request that waits on it.
pub fn releaseHead(r: *Response, io: Io) void {
    std.debug.assert(r.decoder == .none);
    r.ctx.buffers.release(io, r.head_buffer);
    r.* = undefined;
}

/// Read what is left of the body, as it came, when it is no more than the
/// pool's `drain_limit`, so the connection can be kept.
fn drain(r: *Response, io: Io) void {
    var left: usize = r.pool.options.drain_limit;
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
    if (!reusable) return closeConnection(io, pool, conn);
    conn.park(io);
    const kept = pool.keep(io, .{ .h1 = conn });
    for ([_]?Pool.Kind{ kept.evicted, kept.expired }) |out| if (out) |k| switch (k) {
        .h1 => |old| closeConnection(io, pool, old),
    };
}

/// Close a connection and give its room on its route to whoever waits.
pub fn closeConnection(io: Io, pool: *Pool, conn: *Connection) void {
    const route = conn.route;
    conn.close(io);
    pool.closed(io, route);
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

/// Decode a body under one gzip, deflate or zstd coding; any other, or
/// more than one, is handed over as it came, `Content-Encoding` and all.
fn planDecoding(r: *Response, io: Io) Allocator.Error!void {
    if (r.body.state == .done) return;
    const codings = coding.Codings.of(&r.headers) catch return;
    if (codings.len != 1) return;
    const container: std.compress.flate.Container = switch (codings.items[0]) {
        .gzip => .gzip,
        .deflate => .zlib,
        .zstd => {
            r.window = try r.ctx.acquireZstdWindow();
            r.decoder = .{ .zstd = undefined };
            return;
        },
        .identity, .br => return,
    };
    r.window = try r.ctx.buffers.acquire(io, .large);
    r.decoder = .{ .flate = .{ .container = container, .state = undefined } };
}

const Head = struct {
    buffer: []u8,
    head: h1.ResponseHead,
    body_buffer: []u8,
};

/// The smallest body reader buffer a head buffer leaves.
const min_body_buffer = 1024;

fn fieldsBytes(limits: h1.Limits) usize {
    return @as(usize, limits.max_fields) * @sizeOf(fields.Field);
}

/// Read one head from `conn` into a pooled buffer.
fn receiveHead(io: Io, ctx: *Context, conn: *Connection, options: ReceiveOptions) ReceiveError!Head {
    const r = conn.reader();
    var scan: usize = 0;
    while (true) {
        const buffered = r.buffered();
        if (buffered.len != 0) options.progress.* = true;
        const window = buffered[0..@min(buffered.len, options.limits.max_head)];
        if (h1.findHeadEnd(window, scan)) |end| {
            const head = try place(io, ctx, buffered[0..end], options.limits);
            r.toss(end);
            return head;
        }
        if (buffered.len >= options.limits.max_head) return error.HttpProtocolError;
        if (buffered.len == r.buffer.len) return receiveLong(io, ctx, conn, options);
        scan = buffered.len -| 3;
        r.fillMore() catch |err| return switch (err) {
            error.EndOfStream => if (conn.failure == .none) error.ConnectionFailed else conn.readError(),
            error.ReadFailed => conn.readError(),
        };
    }
}

/// A head longer than the connection's buffer: gathered piece by piece into
/// a large pooled buffer, taking from the connection only the head's bytes.
fn receiveLong(io: Io, ctx: *Context, conn: *Connection, options: ReceiveOptions) ReceiveError!Head {
    const r = conn.reader();
    const buffer = try ctx.buffers.acquire(io, .large);
    errdefer ctx.buffers.release(io, buffer);
    const cap = @min(options.limits.max_head, buffer.len - fieldsBytes(options.limits) - min_body_buffer - @alignOf(fields.Field));
    var len: usize = 0;
    while (true) {
        const chunk = r.buffered();
        const take = @min(chunk.len, cap - len);
        @memcpy(buffer[len..][0..take], chunk[0..take]);
        if (h1.findHeadEnd(buffer[0 .. len + take], len -| 3)) |end| {
            r.toss(end - len);
            return parseIn(buffer, end, options.limits);
        }
        r.toss(take);
        len += take;
        if (len == cap) return error.HttpProtocolError;
        r.fillMore() catch |err| return switch (err) {
            error.EndOfStream => error.HttpProtocolError,
            error.ReadFailed => conn.readError(),
        };
    }
}

/// Copy `bytes`, a whole head, into a pooled buffer that fits it, its
/// fields and a body reader buffer, and parse it there.
fn place(io: Io, ctx: *Context, bytes: []const u8, limits: h1.Limits) ReceiveError!Head {
    const need = std.mem.alignForward(usize, bytes.len, @alignOf(fields.Field)) + fieldsBytes(limits) + min_body_buffer;
    const class = BufferPool.Class.fitting(@max(need, BufferPool.Class.record.len())) orelse return error.HttpProtocolError;
    const buffer = try ctx.buffers.acquire(io, class);
    errdefer ctx.buffers.release(io, buffer);
    @memcpy(buffer[0..bytes.len], bytes);
    return parseIn(buffer, bytes.len, limits);
}

fn parseIn(buffer: []u8, end: usize, limits: h1.Limits) ReceiveError!Head {
    const fields_at = std.mem.alignForward(usize, end, @alignOf(fields.Field));
    const field_ptr: [*]fields.Field = @ptrCast(@alignCast(buffer.ptr + fields_at)); // safe: pool buffers are 64-aligned and `fields_at` is aligned for a Field
    const field_slice = field_ptr[0..limits.max_fields];
    const parsed = (h1.parseResponse(buffer[0..end], field_slice, limits) catch return error.HttpProtocolError) orelse
        return error.HttpProtocolError;
    std.debug.assert(parsed.len == end);
    return .{ .buffer = buffer, .head = parsed.head, .body_buffer = buffer[fields_at + fieldsBytes(limits) ..] };
}
