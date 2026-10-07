//! An HTTP/1.1 client: requests over kept connections, through a proxy when
//! one is set, with TLS, timeouts and decompression.
//!
//! A client may be used by several tasks at once. It must not move once it
//! has made a connection: connections point at its shared state.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const h1 = @import("../wire/h1.zig");
const fields = @import("../wire/fields.zig");
const url_mod = @import("../wire/url.zig");
const tls = @import("../tls.zig");
const Connection = @import("../transport/Connection.zig");
const Context = @import("../transport/Context.zig");
const Diagnostics = @import("../transport/Diagnostics.zig");
const Proxy = @import("../transport/Proxy.zig");
const Timer = @import("../transport/Timer.zig");
const Pool = @import("../pool/Pool.zig");
const Request = @import("Request.zig");
const Response = @import("Response.zig");
const Outgoing = @import("Outgoing.zig");

const Client = @This();

/// Private: what the connections share.
context: Context,
/// Private: the idle connections.
pool: Pool,
options: Options,

/// How a client connects and what it asks for.
pub const Options = struct {
    /// Every connection goes through this proxy. `Proxy.fromEnvironment`
    /// reads one the way curl or Go would.
    proxy: ?Proxy = null,
    tls: tls.ClientOptions = .{},
    timeouts: Context.Timeouts = .{},
    pool: Pool.Options = .{},
    /// Turn Nagle's algorithm off on every socket.
    nodelay: bool = true,
    /// Send `Accept-Encoding: gzip, deflate` unless a request names its
    /// own, and decode gzip and deflate bodies.
    decompress: bool = true,
    /// Sent as `User-Agent` unless a request names its own.
    user_agent: ?[]const u8 = null,
    /// The largest response head, and the most fields in one.
    limits: h1.Limits = .{},
};

/// A client with `options`. Nothing is allocated until the first request.
pub fn init(gpa: Allocator, options: Options) Client {
    var limits = options.limits;
    limits.max_head = @min(limits.max_head, 64 << 10);
    limits.max_fields = @min(limits.max_fields, 256);
    var o = options;
    o.limits = limits;
    return .{
        .context = .{
            .gpa = gpa,
            .buffers = .init(gpa, @as(u32, options.pool.max_idle) * 2 + 4),
            .timer = if (options.timeouts.shortestPerOperation()) |shortest| Timer.init(shortest) else null,
            .proxy = options.proxy,
            .tls = options.tls,
            .timeouts = options.timeouts,
            .nodelay = options.nodelay,
        },
        .pool = .init(gpa, options.pool),
        .options = o,
    };
}

/// Close every kept connection, TLS close_notify sent as a courtesy within
/// the activity timeout, and release everything. Exchanges still holding
/// connections must have been released first.
pub fn deinit(c: *Client, io: Io) void {
    while (c.pool.drain(io)) |k| switch (k) {
        .h1 => |conn| conn.close(io),
    };
    c.pool.deinit();
    c.context.deinit(io);
    c.* = undefined;
}

/// Why an exchange failed.
pub const SendError = error{
    /// Not an `http` or `https` URL, or one with a byte a request line
    /// cannot carry.
    InvalidUrl,
    UnsupportedScheme,
    /// A field name or value that cannot be sent, or a field uplink writes
    /// itself.
    InvalidHeader,
    NameNotResolved,
    ConnectionFailed,
    TimedOut,
    /// The TLS handshake failed: `Diagnostics.tls_error` says why.
    TlsFailed,
    ClientCertificateRejected,
    ClientCertificateSchemeUnsupported,
    CertificateBundleUnreadable,
    ProxyRefused,
    ProxyAuthenticationRequired,
    ProxyAuthMethodUnsupported,
    ProxyAddressUnsupported,
    ProxyHostUnreachable,
    /// A proxy's answer that is neither SOCKS nor HTTP.
    ProxyProtocolError,
    /// A response that is not HTTP/1.x.
    HttpProtocolError,
    /// A body reader that ended before its declared length.
    BodyIncomplete,
    /// A body kind the call does not take: `.streamed` to `send`, bytes or
    /// a reader to `begin`.
    InvalidBody,
    /// The request body's reader failed.
    BodyReadFailed,
    /// A host name with no task to look it up beside the caller's, on a
    /// target with no lookup of its own.
    ConcurrencyUnavailable,
    OutOfMemory,
    Canceled,
};

/// One exchange: connect or reuse, write the request, read the response's
/// head. A kept connection the server closed meanwhile is replaced and the
/// request sent again, when no byte of a response came back and either the
/// request had no body or its method is idempotent. A 407 from an HTTP
/// proxy, for a request it is handed whole, is answered and the request
/// sent once more.
pub fn send(c: *Client, io: Io, request: Request) SendError!Response {
    if (request.diagnostics) |d| d.reset();
    const url = try c.prepare(request);
    if (request.body == .streamed) return error.InvalidBody;
    var response = try c.exchange(io, request, url);
    if (response.status != .proxy_auth_required or !c.absoluteForm(url)) return response;
    if (request.diagnostics) |d| d.proxy_status = 407;
    const again = c.proxyChallenged(io, &response, request.diagnostics) catch |err| {
        response.deinit(io);
        return err;
    };
    if (!again or request.body == .reader) return response;
    // ziglint-ignore: Z026 a body left unread costs only the connection: deinit keeps it only when the body is complete
    _ = response.reader(io).discardRemaining() catch {};
    response.deinit(io);
    return c.exchange(io, request, url);
}

/// Start an exchange whose body the caller writes: the request's body must
/// be `.streamed`, or `.none` for chunks. The head goes out with the body.
pub fn begin(c: *Client, io: Io, request: Request) SendError!Outgoing {
    if (request.diagnostics) |d| d.reset();
    const url = try c.prepare(request);
    const length: ?u64 = switch (request.body) {
        .streamed => |s| s.length,
        .none => null,
        .bytes, .reader => return error.InvalidBody,
    };
    const route = routeOf(url);
    const lease = try c.acquire(io, route, request.diagnostics);
    errdefer Response.release(io, &c.context, &c.pool, lease.conn, false);
    const buffer = try c.context.buffers.acquire(io, .record);
    errdefer c.context.buffers.release(io, buffer);
    c.writeHead(io, lease.conn, request, url, if (length) |n| .{ .length = n } else .chunked) catch
        return lease.conn.writeError();
    return .init(&c.context, &c.pool, lease.conn, buffer, request.method, length, c.options.limits, c.options.decompress, request.diagnostics);
}

/// What a client has done, read without a lock.
pub const Stats = struct {
    connections_opened: u64,
    /// Exchanges that went over a kept connection.
    reused: u64,
    idle: u32,
    in_use: u32,
    /// Timeouts asked for that could not be kept: no task to keep them, and
    /// an `Io` that cannot bound the operation itself.
    timeouts_unenforced: u64,
};

pub fn stats(c: *const Client) Stats {
    const k = &c.context.counters;
    return .{
        .connections_opened = k.opened.load(.monotonic),
        .reused = k.reused.load(.monotonic),
        .idle = c.pool.count(),
        .in_use = k.in_use.load(.monotonic),
        .timeouts_unenforced = k.timeouts_unenforced.load(.monotonic),
    };
}

/// Check everything about a request that does not need the network.
fn prepare(c: *const Client, request: Request) SendError!url_mod.Url {
    const url = url_mod.parse(request.url) catch |err| return switch (err) {
        error.InvalidUrl => error.InvalidUrl,
        error.UnsupportedScheme => error.UnsupportedScheme,
    };
    if (!fields.isToken(request.method.name)) return error.InvalidHeader;
    for (request.headers) |h| {
        h1.checkHeader(h) catch return error.InvalidHeader;
        for ([_][]const u8{ "host", "content-length", "transfer-encoding" }) |own| {
            if (std.ascii.eqlIgnoreCase(h.name, own)) return error.InvalidHeader;
        }
    }
    if (c.options.user_agent) |ua| if (!fields.isFieldValue(ua)) return error.InvalidHeader;
    return url;
}

fn routeOf(url: url_mod.Url) Context.Route {
    return .{ .secure = url.secure, .host = url.host, .port = url.port };
}

/// Whether requests to `url` go to an HTTP proxy whole, as absolute URLs.
fn absoluteForm(c: *const Client, url: url_mod.Url) bool {
    const p = c.options.proxy orelse return false;
    return !url.secure and !p.kind.socks();
}

const Lease = struct { conn: *Connection, reused: bool };

/// A kept connection to `route` that still looks alive, or a new one.
fn acquire(c: *Client, io: Io, route: Context.Route, diagnostics: ?*Diagnostics) SendError!Lease {
    while (c.pool.take(io, route)) |k| {
        const conn = k.h1;
        conn.unpark(io, diagnostics) catch {
            conn.close(io);
            return error.OutOfMemory;
        };
        const alive = conn.alive(io) catch {
            conn.close(io);
            return error.Canceled;
        };
        if (!alive) {
            conn.close(io);
            continue;
        }
        _ = c.context.counters.reused.fetchAdd(1, .monotonic);
        _ = c.context.counters.in_use.fetchAdd(1, .monotonic);
        return .{ .conn = conn, .reused = true };
    }
    const conn = Connection.open(&c.context, io, route, diagnostics) catch |err| return switch (err) {
        error.InvalidHostName => error.InvalidUrl,
        else => |e| e,
    };
    _ = c.context.counters.in_use.fetchAdd(1, .monotonic);
    return .{ .conn = conn, .reused = false };
}

/// Send the request and read its response's head, once more on a fresh
/// connection when a kept one turns out stale.
fn exchange(c: *Client, io: Io, request: Request, url: url_mod.Url) SendError!Response {
    const route = routeOf(url);
    var retried = false;
    while (true) {
        const lease = try c.acquire(io, route, request.diagnostics);
        var progress = false;
        const response = c.attempt(io, lease.conn, request, url, &progress) catch |err| {
            Response.release(io, &c.context, &c.pool, lease.conn, false);
            const replayable = switch (request.body) {
                .none => true,
                .bytes => request.method.idempotent(),
                .reader, .streamed => false,
            };
            if (err == error.ConnectionFailed and lease.reused and !retried and !progress and replayable) {
                retried = true;
                continue;
            }
            return err;
        };
        return response;
    }
}

fn attempt(c: *Client, io: Io, conn: *Connection, request: Request, url: url_mod.Url, progress: *bool) SendError!Response {
    if (request.diagnostics) |d| d.stage = .write;
    const framing: h1.Framing = switch (request.body) {
        .none => if (request.method.eql(.POST) or request.method.eql(.PUT) or request.method.eql(.PATCH)) .{ .length = 0 } else .none,
        .bytes => |b| .{ .length = b.len },
        .reader => |r| if (r.length) |n| .{ .length = n } else .chunked,
        .streamed => unreachable, // unreachable: `send` refuses a streamed body
    };
    c.writeHead(io, conn, request, url, framing) catch return conn.writeError();
    switch (request.body) {
        .none, .streamed => {},
        .bytes => |b| conn.writer().writeAll(b) catch return conn.writeError(),
        .reader => |r| try c.writeReader(io, conn, r.reader, r.length),
    }
    conn.flush() catch return conn.writeError();
    return Response.receive(io, &c.context, &c.pool, conn, .{
        .method = request.method,
        .limits = c.options.limits,
        .decompress = c.options.decompress,
        .diagnostics = request.diagnostics,
        .progress = progress,
    });
}

/// A body from a reader: exactly `length` bytes, or in chunks to its end.
fn writeReader(c: *Client, io: Io, conn: *Connection, source: *Io.Reader, length: ?u64) SendError!void {
    const w = conn.writer();
    if (length) |n| {
        source.streamExact64(w, n) catch |err| return switch (err) {
            error.ReadFailed => error.BodyReadFailed,
            error.EndOfStream => error.BodyIncomplete,
            error.WriteFailed => conn.writeError(),
        };
        return;
    }
    const buffer = try c.context.buffers.acquire(io, .record);
    defer c.context.buffers.release(io, buffer);
    var chunked: h1.ChunkedWriter = .init(w, buffer);
    _ = source.streamRemaining(&chunked.interface) catch |err| return switch (err) {
        error.ReadFailed => error.BodyReadFailed,
        error.WriteFailed => conn.writeError(),
    };
    chunked.end() catch return conn.writeError();
}

/// Write the request line and fields, checked by `prepare`, into the
/// connection's writer.
fn writeHead(c: *Client, io: Io, conn: *Connection, request: Request, url: url_mod.Url, framing: h1.Framing) Io.Writer.Error!void {
    const w = conn.writer();
    try w.writeAll(request.method.name);
    try w.writeByte(' ');
    if (conn.absolute_form) {
        try w.writeAll("http://");
        try url.writeAuthority(w, false);
    }
    try url.writeTarget(w);
    try w.writeAll(" HTTP/1.1\r\nHost: ");
    try url.writeAuthority(w, false);
    try w.writeAll("\r\n");
    if (conn.absolute_form) {
        // Answered for with the path as the Digest target, as curl answers.
        const path = if (url.target.len != 0 and url.target[0] == '/') url.target else "/";
        _ = try c.context.proxy_auth.writeField(io, w, c.options.proxy.?.credential, request.method.name, path);
    }
    if (c.options.user_agent) |ua| if (!named(request.headers, "user-agent")) try h1.writeField(w, .{ .name = "User-Agent", .value = ua });
    if (c.options.decompress and !named(request.headers, "accept-encoding")) try w.writeAll("Accept-Encoding: gzip, deflate\r\n");
    for (request.headers) |h| try h1.writeField(w, h);
    switch (framing) {
        .none, .until_close => {},
        .length => |n| try w.print("Content-Length: {d}\r\n", .{n}),
        .chunked => try w.writeAll("Transfer-Encoding: chunked\r\n"),
    }
    try w.writeAll("\r\n");
}

fn named(headers: []const std.http.Header, name: []const u8) bool {
    for (headers) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return true;
    return false;
}

/// Take a 407's challenges for the next request.
fn proxyChallenged(c: *Client, io: Io, response: *Response, diagnostics: ?*Diagnostics) SendError!bool {
    var offered_buf: [256]u8 = undefined;
    var offered: Io.Writer = .fixed(&offered_buf);
    return c.context.proxy_auth.challenged(c.context.gpa, io, c.options.proxy.?.credential, &response.headers, &offered) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.ProxyAuthMethodUnsupported => {
            if (diagnostics) |d| d.proxy_offered.set(offered.buffered(), offered.end == offered_buf.len);
            return error.ProxyAuthMethodUnsupported;
        },
    };
}
