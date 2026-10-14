//! One connection a server serves, from its first request to its end: the
//! requests read in order, pipelined ones included, each checked as a
//! server must, answered by the handler, and the connection kept for the
//! next or closed.

const std = @import("std");
const aegis = @import("aegis");
const Io = std.Io;
const wire = @import("uplink.wire");
const h1 = wire.h1;
const coding = wire.coding;
const span = @import("../span.zig");
const BufferPool = @import("../transport/BufferPool.zig");
const Head = @import("../transport/Head.zig");
const Decoder = @import("../coding/Decoder.zig");
const Context = @import("Context.zig");
const Socket = @import("Socket.zig");
const Request = @import("Request.zig");
const Response = @import("Response.zig");
const Handler = @import("Handler.zig");
const h2_serve = @import("h2.zig");

const Connection = @This();

socket: Socket,
handler: Handler,

/// Serve `stream` to its end on the caller's task, then close it.
pub fn serve(context: *Context, handler: Handler, io: Io, stream: Io.net.Stream) void {
    var c: Connection = .{ .socket = .init(context, io, stream), .handler = handler };
    context.enter(io, &c.socket.entry);
    defer context.leave(io, &c.socket.entry);
    defer c.socket.close();
    const in_class: BufferPool.Class = if (context.options.tls != null) .record else .small;
    c.socket.input.interface.buffer = context.buffers.acquire(io, in_class) catch return;
    if (context.options.tls) |options| c.socket.handshake(options) catch return;
    if (std.mem.eql(u8, c.socket.alpn(), "h2")) return h2_serve.serve(context, handler, &c.socket);
    if (!c.socket.secure) switch (context.options.h2c) {
        .off => {},
        .only => return h2_serve.serve(context, handler, &c.socket),
        .alongside_http1 => if (c.priorKnowledge()) return h2_serve.serve(context, handler, &c.socket),
    };
    var first = true;
    while (true) {
        if (!c.awaitRequest(first)) return;
        first = false;
        if (!c.serveOne()) return;
    }
}

/// Whether the connection starts with HTTP/2's preface: the client knows
/// the server speaks it.
fn priorKnowledge(c: *Connection) bool {
    c.socket.startHead(c.socket.io);
    const r = c.socket.reader();
    const want = wire.h2.preface;
    while (r.bufferedLen() < want.len) {
        const have = r.buffered();
        if (!std.mem.startsWith(u8, want, have)) return false;
        r.fillMore() catch return false;
    }
    return std.mem.startsWith(u8, r.buffered(), want);
}

/// Wait for the next request's first byte, or take one already buffered
/// (pipelined). False when the connection ends: the client closed it, the
/// idle wait ran out, or the server is stopping.
fn awaitRequest(c: *Connection, first: bool) bool {
    const s = c.socket.context;
    const io = c.socket.io;
    const r = c.socket.reader();
    if (first or r.bufferedLen() != 0) {
        if (!first and s.isStopping()) return false;
        c.socket.startHead(io);
        return true;
    }
    c.socket.park();
    if (!s.setIdle(io, &c.socket.entry, true)) return false;
    c.socket.startIdle(io);
    // An idle connection past its time is closed cleanly where the `Io`
    // can wait without a deadline that aborts the socket: a FIN, not a
    // reset that could take the last response's bytes with it.
    if (s.options.timeouts.idle) |idle| switch (c.socket.awaitReadable(io, span.toIo(idle)) catch .ready) {
        .ready, .unbounded => {},
        .timed_out => {
            _ = s.setIdle(io, &c.socket.entry, false);
            c.socket.noteTimeout(.idle);
            return false;
        },
    };
    // What the wait read is the request's start; else the read waits for it.
    const more = if (r.bufferedLen() != 0) {} else r.fillMore();
    const stopping = !s.setIdle(io, &c.socket.entry, false);
    more catch |err| {
        if (err == error.ReadFailed and c.socket.failed() == .timed_out) c.socket.noteTimeout(.idle);
        return false;
    };
    if (stopping) return false;
    c.socket.startHead(io);
    return true;
}

/// Read one request and answer it. False when the connection is not to
/// carry another.
fn serveOne(c: *Connection) bool {
    const s = c.socket.context;
    const io = c.socket.io;
    const options = &s.options;
    var progress = false;
    var head = Head.gather(io, &s.buffers, c.socket.reader(), options.limits, &progress) catch |err| return switch (err) {
        error.HeadTooLarge => c.refuse(.request_header_fields_too_large, "head too large"),
        error.StartLineTooLong => c.refuse(.uri_too_long, "target too long"),
        error.NoStartLine => c.refuse(.bad_request, "no request line"),
        error.EndOfStream => false,
        error.ReadFailed => {
            if (c.socket.failed() == .timed_out) c.socket.noteTimeout(.head);
            return false;
        },
        error.OutOfMemory => c.refuse(.service_unavailable, "out of memory"),
    };
    defer head.release(io, &s.buffers);
    const arrived = Io.Clock.awake.now(io);
    c.socket.startAnswer();
    if (c.socket.output.interface.buffer.len == 0) c.socket.output.interface.buffer = s.buffers.acquire(io, .record) catch return false;

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
        .remote = if (c.socket.stream.socket.address == .ip4 or c.socket.stream.socket.address == .ip6) c.socket.stream.socket.address else null,
        .secure = c.socket.secure,
        .socket = &c.socket,
        .body = .initStrict(c.socket.reader(), framing, head.bodyBuffer()),
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

    var response: Response = .init(&c.socket, rh.method.eql(.HEAD), rh.version == .http1_0, rh.headers.getKnown(.@"accept-encoding"));
    defer response.release(io);
    const keep_alive = h1.keepAlive(rh.version, &rh.headers);
    if (!keep_alive) response.closeAfter();
    _ = s.counters.requests.fetchAdd(1, .monotonic);

    c.handler.handle(io, &request, &response) catch |err| {
        if (options.observer) |o| o.emit(.{ .failed = .{ .method = rh.method.name, .path = target.path, .error_name = @errorName(err), .head_sent = response.headSent() } });
        if (response.headSent()) {
            // What went out stays out, cut where the handler stopped: the
            // client sees a truncation, never a short success.
            // glint-ignore: Z026 -- the connection closes next whether or not the partial body reached the client
            c.socket.flush() catch {};
            return false;
        }
        response.reset(io);
        response.status = request.bodyFault() orelse .internal_server_error;
        response.closeAfter();
        // glint-ignore: Z026 -- the connection closes either way; a 500 that cannot be written changes nothing
        response.send(io, "") catch {};
        return false;
    };
    if (c.socket.hijacked) return false;
    // A handler that did not end its response has it ended now.
    response.end(io) catch return false;
    if (options.observer) |o| o.emit(.{ .answered = .{ .method = rh.method.name, .path = target.path, .status = @backingInt(response.status), .took = span.of(arrived.durationTo(Io.Clock.awake.now(io))) } });
    if (!response.keepsConnection() or c.socket.failed() != .none or c.socket.timed.fired()) return false;
    return c.finishBody(&request);
}

/// The request's body, read to its end so the connection can carry the
/// next: what is left of it, when that is within `drain_limit`. A client
/// still waiting for `100 Continue` will not send it at all, so its
/// connection is closed instead.
fn finishBody(c: *Connection, request: *Request) bool {
    if (request.body.complete()) return true;
    if (request.expects_continue and !request.continued) return false;
    var left: usize = c.socket.context.options.drain_limit.raw();
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

/// How many fields named `name` the head has.
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
/// Whether `value` is a `Host` as an http or https URI's authority has
/// it: a host, never empty (RFC 9110 §4.2.1), an IP literal or a name of
/// the characters a URI's host takes, and a port of digits. A comma, which
/// a second host could hide behind, is refused too.
fn validHost(value: []const u8) bool {
    var host = value;
    var port: ?[]const u8 = null;
    if (value.len != 0 and value[0] == '[') {
        const close = std.mem.findScalar(u8, value, ']') orelse return false;
        host = value[1..close];
        if (host.len == 0) return false;
        for (host) |ch| if (!(std.ascii.isHex(ch) or ch == ':' or ch == '.')) return false;
        const rest = value[close + 1 ..];
        if (rest.len != 0) {
            if (rest[0] != ':') return false;
            port = rest[1..];
        }
    } else {
        if (std.mem.findScalar(u8, value, ':')) |colon| {
            host = value[0..colon];
            port = value[colon + 1 ..];
        }
        if (host.len == 0) return false;
        for (host) |ch| if (!(std.ascii.isAlphanumeric(ch) or std.mem.findScalar(u8, "-._~%!$&'()*+;=", ch) != null)) return false;
    }
    if (port) |p| for (p) |ch| if (!std.ascii.isDigit(ch)) return false;
    return true;
}

/// Answer a request the server refuses before any handler sees it, and
/// end the connection: its head was not trusted, so nothing after it is.
fn refuse(c: *Connection, status: std.http.Status, reason: []const u8) bool {
    const s = c.socket.context;
    if (s.options.observer) |o| o.emit(.{ .refused = .{ .status = @backingInt(status), .reason = reason } });
    if (c.socket.output.interface.buffer.len == 0) c.socket.output.interface.buffer = s.buffers.acquire(c.socket.io, .small) catch return false;
    c.socket.startAnswer();
    const w = c.socket.writer();
    h1.writeStatusLine(w, status) catch return false;
    w.writeAll("Content-Length: 0\r\nConnection: close\r\n\r\n") catch return false;
    // glint-ignore: Z026 -- the connection closes next whether or not the refusal reached the client
    c.socket.flush() catch {};
    return false;
}
