//! One connection a server serves: its socket and TLS session, the
//! deadline each wait is kept to, and the loop that reads its requests in
//! order, pipelined ones included, and answers each.
//!
//! Every read and write goes through one place, which keeps the deadline
//! of the wait at hand: the TLS handshake, the time between requests, the
//! whole of a request's head, or, while a request is answered, the
//! activity timeout of each operation. A plain connection keeps a 4 KiB
//! read buffer between requests and nothing else; its write buffer is
//! borrowed while it answers.

const std = @import("std");
const builtin = @import("builtin");
const aegis = @import("aegis");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const cloak = @import("cloak");
const wire = @import("uplink.wire");
const h1 = wire.h1;
const coding = wire.coding;
const tls = @import("../tls.zig");
const span = @import("../span.zig");
const BufferPool = @import("../transport/BufferPool.zig");
const Body = @import("../transport/Body.zig");
const Head = @import("../transport/Head.zig");
const Timed = @import("../transport/Timed.zig");
const Decoder = @import("../coding/Decoder.zig");
const Server = @import("Server.zig");
const Request = @import("Request.zig");
const Response = @import("Response.zig");

const Connection = @This();

/// Private: the server.
server: *Server,
/// Private: the `Io` the connection's task runs on, for the adapters.
io: Io,
/// Private: the socket.
stream: Io.net.Stream,
/// Private: on the server's list of live connections.
node: std.DoublyLinkedList.Node = .{},
/// Private: waiting for a request; read and written under the server's
/// lock, which `shutdown` holds when it ends idle connections.
idle: bool = false,
/// Private: the socket's operations, each ended at its deadline.
timed: Timed,
input: SocketReader,
output: SocketWriter,
/// Private: TLS, when the server speaks it.
session: cloak.tls.Session = undefined,
secure: bool = false,
session_buffers: [2][]u8 = .{ &.{}, &.{} },
/// Private: which wait the next operation is part of.
phase: Phase = .head,
/// Private: the end of the handshake, the idle wait or the head, on the
/// awake clock.
until: ?Io.Timestamp = null,
/// Private: why the last operation failed.
failure: Failure = .none,
/// Private: the handler took the connection over.
hijacked: bool = false,

const Phase = enum { handshake, idle, head, answer };

/// Why an operation failed.
pub const Failure = enum { none, timed_out, canceled, broken };

/// A connection over `stream`, not yet started.
pub fn init(server: *Server, io: Io, stream: Io.net.Stream) Connection {
    return .{
        .server = server,
        .io = io,
        .stream = stream,
        .timed = .init(stream.socket.handle),
        .input = .init(&.{}),
        .output = .init(&.{}),
    };
}

/// Serve the connection to its end, then close it.
pub fn run(c: *Connection) void {
    defer c.close();
    const s = c.server;
    const io = c.io;
    const in_class: BufferPool.Class = if (s.options.tls != null) .record else .small;
    c.input.interface.buffer = s.buffers.acquire(io, in_class) catch return;
    if (s.options.tls) |options| c.handshake(options) catch return;
    var first = true;
    while (true) {
        if (!c.awaitRequest(first)) return;
        first = false;
        if (!c.serveOne()) return;
    }
}

fn close(c: *Connection) void {
    const io = c.io;
    const pool = &c.server.buffers;
    if (c.secure) {
        if (c.failure == .none and !c.timed.fired()) {
            // glint-ignore: Z026 -- the close_notify is a courtesy; the socket closes whether or not the peer heard it
            c.session.finish() catch {};
            // glint-ignore: Z026 -- as above
            c.output.interface.flush() catch {};
        }
        c.session.deinit();
        for (c.session_buffers) |b| pool.release(io, b);
        c.secure = false;
    }
    c.timed.deinit(io, c.server.keeper());
    c.stream.close(io);
    for ([_][]u8{ c.input.interface.buffer, c.output.interface.buffer }) |b| if (b.len != 0) pool.release(io, b);
}

fn handshake(c: *Connection, options: tls.ServerOptions) error{Failed}!void {
    const s = c.server;
    const io = c.io;
    const pool = &s.buffers;
    c.output.interface.buffer = pool.acquire(io, .record) catch return error.Failed;
    const read_buffer = pool.acquire(io, .record) catch return error.Failed;
    const write_buffer = pool.acquire(io, .record) catch {
        pool.release(io, read_buffer);
        return error.Failed;
    };
    c.phase = .handshake;
    c.until = if (s.options.timeouts.handshake) |t| Io.Clock.awake.now(io).addDuration(span.toIo(t)) else null;
    var report: cloak.tls.Session.Diagnostics = .{};
    c.session.accept(s.gpa, io, &c.input.interface, &c.output.interface, .{
        .credentials = options.credentials,
        .alpn = tls.server_protocols,
        .client_auth = options.client_certificate,
        .client_trust = if (options.client_trust) |t| .{ .snapshot = t } else .none,
        .key_log = if (options.key_log) |w| tls.keyLog(w) else null,
        // HTTP says where a message ends: a bare end of the transport is
        // the end of the connection, not an attack on a body.
        .eof = .allow,
        .diagnostics = &report,
    }, read_buffer, write_buffer) catch |err| {
        pool.release(io, read_buffer);
        pool.release(io, write_buffer);
        if (s.options.observer) |o| o.emit(.{ .handshake_failed = .{ .error_name = @errorName(err) } });
        if (c.failure == .timed_out) c.noteTimeout(.handshake);
        return error.Failed;
    };
    c.session_buffers = .{ read_buffer, write_buffer };
    c.secure = true;
}

/// Wait for the next request's first byte, or take one already buffered
/// (pipelined). False when the connection ends: the client closed it, the
/// idle wait ran out, or the server is stopping.
fn awaitRequest(c: *Connection, first: bool) bool {
    const s = c.server;
    const io = c.io;
    const t = s.options.timeouts;
    const r = c.reader();
    if (first or r.bufferedLen() != 0) {
        if (!first and s.isStopping()) return false;
        c.startHead(io);
        return true;
    }
    c.park();
    if (!s.setIdle(io, c, true)) return false;
    c.phase = .idle;
    c.until = if (t.idle) |d| Io.Clock.awake.now(io).addDuration(span.toIo(d)) else null;
    const more = r.fillMore();
    const stopping = !s.setIdle(io, c, false);
    more catch |err| {
        if (err == error.ReadFailed and c.failure == .timed_out) c.noteTimeout(.idle);
        return false;
    };
    if (stopping) return false;
    c.startHead(io);
    return true;
}

fn startHead(c: *Connection, io: Io) void {
    c.phase = .head;
    c.until = if (c.server.options.timeouts.head) |d| Io.Clock.awake.now(io).addDuration(span.toIo(d)) else null;
}

/// Between requests a plain connection gives its write buffer back.
fn park(c: *Connection) void {
    if (c.secure) return;
    const w = &c.output.interface;
    if (w.buffer.len != 0 and w.end == 0) {
        c.server.buffers.release(c.io, w.buffer);
        w.buffer = &.{};
    }
}

/// Read one request and answer it. False when the connection is not to
/// carry another.
fn serveOne(c: *Connection) bool {
    const s = c.server;
    const io = c.io;
    const options = &s.options;
    var progress = false;
    var head = Head.gather(io, &s.buffers, c.reader(), options.limits, &progress) catch |err| return switch (err) {
        error.HeadTooLarge => c.refuse(.request_header_fields_too_large, "head too large"),
        error.EndOfStream => false,
        error.ReadFailed => {
            if (c.failure == .timed_out) c.noteTimeout(.head);
            return false;
        },
        error.OutOfMemory => c.refuse(.service_unavailable, "out of memory"),
    };
    defer head.release(io, &s.buffers);
    const arrived = Io.Clock.awake.now(io);
    c.phase = .answer;
    c.until = null;
    if (c.output.interface.buffer.len == 0) c.output.interface.buffer = s.buffers.acquire(io, .record) catch return false;

    const maybe = h1.parseRequest(head.bytes(), head.fields(), options.limits) catch |err| return switch (err) {
        error.UnsupportedVersion => c.refuse(.http_version_not_supported, "version"),
        error.TooManyFields => c.refuse(.request_header_fields_too_large, "too many fields"),
        error.HeadTooLarge => c.refuse(.request_header_fields_too_large, "head too large"),
        else => c.refuse(.bad_request, @errorName(err)),
    };
    const parsed = maybe orelse return c.refuse(.bad_request, "no head");
    const rh = &parsed.head;
    if (rh.version != .http1_0 and rh.version != .http1_1) return c.refuse(.http_version_not_supported, "version");
    const target = Request.Target.parse(rh.method, rh.target) catch return c.refuse(.bad_request, "target");
    // RFC 9112 §3.2: an HTTP/1.1 request has exactly one Host.
    const host_field = rh.headers.getKnown(.host);
    if (rh.version == .http1_1 and (host_field == null or countFields(&rh.headers, "host") != 1)) return c.refuse(.bad_request, "host");
    if (host_field) |h| if (!validHost(h)) return c.refuse(.bad_request, "host");
    const framing = h1.requestFraming(rh) catch return c.refuse(.bad_request, "framing");
    var expects_continue = false;
    if (rh.headers.getKnown(.expect)) |e| {
        if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, e, " \t"), "100-continue")) return c.refuse(.expectation_failed, "expectation");
        expects_continue = rh.version == .http1_1 and framing != .none;
    }
    if (options.max_body) |max| switch (framing) {
        .length => |n| if (aegis.units.Bytes(u64).fromRaw(n).compare(max) == .gt) return c.refuse(.payload_too_large, "body too large"),
        else => {},
    };

    var request: Request = .{
        .method = rh.method,
        .target = rh.target,
        .path = target.path,
        .query = target.query,
        .version = rh.version,
        .headers = rh.headers,
        .host = target.authority orelse host_field orelse "",
        .remote = if (c.stream.socket.address == .ip4 or c.stream.socket.address == .ip6) c.stream.socket.address else null,
        .secure = c.secure,
        .conn = c,
        .body = .init(c.reader(), framing, head.bodyBuffer()),
        .expects_continue = expects_continue,
    };
    defer request.release(io);
    request.body.trailer_pool = &s.buffers;
    request.body.trailer_io = io;
    if (options.max_body) |max| request.body.cap(max.raw());
    defer if (request.body.trailer.len != 0) s.buffers.release(io, request.body.trailer);
    if (options.decompress and framing != .none) {
        if (coding.Codings.of(&rh.headers)) |codings| {
            if (codings.len != 0 and Decoder.decodes(codings.slice()))
                request.decoder = Decoder.init(io, s.gpa, &s.buffers, &s.zstd, codings.slice()) catch return c.refuse(.service_unavailable, "out of memory");
        } else |_| {}
    }
    defer if (request.decoder) |*d| d.deinit(io, s.gpa, &s.buffers, &s.zstd);

    var response: Response = .init(c, rh.method.eql(.HEAD), rh.version == .http1_0);
    defer response.release(io);
    const keep_alive = h1.keepAlive(rh.version, &rh.headers);
    if (!keep_alive) response.closeAfter();
    _ = s.counters.requests.fetchAdd(1, .monotonic);

    s.handler.handle(io, &request, &response) catch |err| {
        if (options.observer) |o| o.emit(.{ .failed = .{ .method = rh.method.name, .path = target.path, .error_name = @errorName(err), .head_sent = response.headSent() } });
        if (response.headSent()) {
            // What went out stays out, cut where the handler stopped: the
            // client sees a truncation, never a short success.
            // glint-ignore: Z026 -- the connection closes next whether or not the partial body reached the client
            c.flush() catch {};
            return false;
        }
        response.reset(io);
        response.status = .internal_server_error;
        response.closeAfter();
        // glint-ignore: Z026 -- the connection closes either way; a 500 that cannot be written changes nothing
        response.send(io, "") catch {};
        return false;
    };
    if (c.hijacked) return false;
    // A handler that did not end its response has it ended now.
    response.end(io) catch return false;
    if (options.observer) |o| o.emit(.{ .answered = .{ .method = rh.method.name, .path = target.path, .status = @backingInt(response.status), .took = span.of(arrived.durationTo(Io.Clock.awake.now(io))) } });
    if (!response.keepsConnection() or c.failure != .none or c.timed.fired()) return false;
    return c.finishBody(&request);
}

/// The request's body, read to its end so the connection can carry the
/// next: what is left of it, when that is within `drain_limit`. A client
/// still waiting for `100 Continue` will not send it at all, so its
/// connection is closed instead.
fn finishBody(c: *Connection, request: *Request) bool {
    if (request.body.complete()) return true;
    if (request.expects_continue and !request.continued) return false;
    var left: usize = c.server.options.drain_limit.raw();
    switch (request.body.framing) {
        .length => if (request.body.remaining > left) return false,
        .chunked => {},
        .none, .until_close => return false,
    }
    while (left > 0) {
        const n = request.body.interface.discard(.limited(left)) catch |err| return err == error.EndOfStream and request.body.complete();
        if (n == 0) break;
        left -= n;
    }
    return request.body.complete();
}

fn countFields(headers: *const wire.fields.Headers, name: []const u8) usize {
    var n: usize = 0;
    var it = headers.iterator();
    while (it.next()) |f| {
        if (std.ascii.eqlIgnoreCase(f.name, name)) n += 1;
    }
    return n;
}

/// A `Host` value a server may take (RFC 9110 §7.2): a host and optional
/// port, with nothing a path or a list would put there.
fn validHost(value: []const u8) bool {
    for (value) |ch| switch (ch) {
        '/', '?', '#', '@', ' ', '\t', ',' => return false,
        else => {},
    };
    return true;
}

/// Answer a request the server refuses before any handler sees it, and
/// end the connection: its head was not trusted, so nothing after it is.
fn refuse(c: *Connection, status: std.http.Status, reason: []const u8) bool {
    const s = c.server;
    if (s.options.observer) |o| o.emit(.{ .refused = .{ .status = @backingInt(status), .reason = reason } });
    if (c.output.interface.buffer.len == 0) c.output.interface.buffer = s.buffers.acquire(c.io, .small) catch return false;
    c.phase = .answer;
    const w = c.writer();
    h1.writeStatusLine(w, status) catch return false;
    w.writeAll("Content-Length: 0\r\nConnection: close\r\n\r\n") catch return false;
    // glint-ignore: Z026 -- the connection closes next whether or not the refusal reached the client
    c.flush() catch {};
    return false;
}

/// Send `100 Continue` to a client waiting for it before its body.
pub fn sendContinue(c: *Connection) void {
    const w = c.writer();
    // A client that cannot hear it sends the body after its own wait, or
    // the read that follows fails and says why.
    w.writeAll("HTTP/1.1 100 Continue\r\n\r\n") catch return;
    c.flush() catch return;
}

fn noteTimeout(c: *Connection, phase: Server.Timeout) void {
    if (c.server.options.observer) |o| o.emit(.{ .timed_out = .{ .phase = phase } });
}

/// The reader of the top layer.
pub fn reader(c: *Connection) *Io.Reader {
    return if (c.secure) c.session.reader() else &c.input.interface;
}

/// The writer of the top layer.
pub fn writer(c: *Connection) *Io.Writer {
    return if (c.secure) c.session.writer() else &c.output.interface;
}

/// Push everything written through every layer to the socket.
pub fn flush(c: *Connection) Io.Writer.Error!void {
    if (c.secure) try c.session.writer().flush();
    try c.output.interface.flush();
}

/// Why a read failed, by name.
pub fn readError(c: *const Connection) Request.ReadError {
    return switch (c.failure) {
        .timed_out => error.TimedOut,
        .canceled => error.Canceled,
        .none, .broken => error.ConnectionFailed,
    };
}

/// The deadline of an operation starting now.
fn deadline(c: *Connection) ?Io.Timestamp {
    return switch (c.phase) {
        .handshake, .idle, .head => c.until,
        .answer => if (c.server.options.timeouts.activity) |a| Io.Clock.awake.now(c.io).addDuration(span.toIo(a)) else null,
    };
}

/// One socket operation within the deadline of the wait at hand.
fn perform(c: *Connection, op: Io.Operation) error{Failed}!Io.Operation.Result {
    return c.timed.perform(c.io, c.server.keeper(), op, c.deadline()) catch |err| {
        c.note(switch (err) {
            error.TimedOut => .timed_out,
            error.Canceled => .canceled,
        });
        return error.Failed;
    };
}

fn note(c: *Connection, failure: Failure) void {
    if (c.failure == .none) c.failure = failure;
}

const SocketReader = struct {
    interface: Io.Reader,

    fn init(buffer: []u8) SocketReader {
        return .{ .interface = .{ .vtable = &.{ .stream = streamImpl, .readVec = readVec }, .buffer = buffer, .seek = 0, .end = 0 } };
    }

    fn connection(r: *Io.Reader) *Connection {
        const sr: *SocketReader = @alignCast(@fieldParentPtr("interface", r)); // safe: this vtable is installed only on a SocketReader's interface
        return @alignCast(@fieldParentPtr("input", sr)); // safe: a SocketReader lives only in a Connection's `input`
    }

    fn streamImpl(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const dest = limit.slice(try w.writableSliceGreedy(1));
        var data: [1][]u8 = .{dest};
        const n = try readVec(r, &data);
        w.advance(n);
        return n;
    }

    fn readVec(r: *Io.Reader, data: [][]u8) Io.Reader.Error!usize {
        const c = connection(r);
        var iovecs: [8][]u8 = undefined;
        const dest_n, const data_size = try r.writableVector(&iovecs, data);
        const result = c.perform(.{ .net_read = .{ .socket_handle = c.stream.socket.handle, .data = iovecs[0..dest_n] } }) catch return error.ReadFailed;
        const n = (result.net_read catch {
            c.note(.broken);
            return error.ReadFailed;
        }).data_len;
        if (n == 0) return error.EndOfStream;
        if (n > data_size) {
            r.end += n - data_size;
            return data_size;
        }
        return n;
    }
};

const SocketWriter = struct {
    interface: Io.Writer,

    fn init(buffer: []u8) SocketWriter {
        return .{ .interface = .{ .vtable = &.{ .drain = drain }, .buffer = buffer } };
    }

    fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const sw: *SocketWriter = @alignCast(@fieldParentPtr("interface", w)); // safe: this vtable is installed only on a SocketWriter's interface
        const c: *Connection = @alignCast(@fieldParentPtr("output", sw)); // safe: a SocketWriter lives only in a Connection's `output`
        const result = c.perform(.{ .net_write = .{
            .socket_handle = c.stream.socket.handle,
            .header = w.buffered(),
            .data = data,
            .splat = splat,
        } }) catch return error.WriteFailed;
        const n = result.net_write catch {
            c.note(.broken);
            return error.WriteFailed;
        };
        return w.consume(n);
    }
};
