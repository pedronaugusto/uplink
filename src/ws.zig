//! WebSocket (RFC 6455) on uplink's client and server: the opening
//! handshake both ways, with subprotocols and permessage-deflate (RFC 7692)
//! negotiated, and a `Conn` over the stream the upgrade leaves.
//!
//! `accept` answers a server's request; `connect` opens one through a
//! `Client`, so a WebSocket goes through its proxies, TLS, cookies and
//! credentials as any request does. Neither `Client` nor `Server` knows
//! WebSocket exists: they hand over an upgraded stream, and this layer
//! does the rest.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const wire = @import("uplink.wire");
const ws = wire.ws;
const fields = wire.fields;
const Timed = @import("net/Timed.zig");
const Client = @import("client/Client.zig");
const Upgraded = @import("client/Upgraded.zig");
const ServerRequest = @import("server/Request.zig");
const ServerResponse = @import("server/Response.zig");

/// A WebSocket connection.
pub const Conn = @import("ws/Conn.zig");

/// Which compression an end offers or accepts.
pub const Compression = struct {
    /// Compress what this end sends with a fresh history per message, so
    /// no compressor is kept between messages: what a server asks by
    /// default, since a kept one costs its memory per connection.
    no_context_takeover: bool = false,
    /// The history this end's compressor keeps, 2^bits, 9-15.
    window_bits: u4 = 15,
};

/// How a server accepts.
pub const AcceptOptions = struct {
    conn: Conn.Options = .{},
    /// The subprotocols the server speaks, its preference first.
    protocols: []const []const u8 = &.{},
    /// permessage-deflate, when the client offers it; null declines it.
    compression: ?Compression = .{ .no_context_takeover = true },
};

/// A WebSocket a server accepted: the connection, and the stream under it,
/// which the server closes when the handler returns. It must not move.
pub const Accepted = struct {
    conn: Conn,
    stream: ServerResponse.Hijacked,
    /// The subprotocol agreed, if any.
    protocol: ?[]const u8,

    pub fn deinit(a: *Accepted) void {
        a.conn.deinit();
    }
};

/// Why a request was not accepted. The response went out with the reason:
/// 400, or 426 with the version the server speaks.
pub const AcceptError = error{
    /// Not a WebSocket handshake: its method, version, `Upgrade`,
    /// `Connection` or key.
    NotWebSocket,
    /// A version other than 13.
    UnsupportedVersion,
    /// Writing the answer failed.
    WriteFailed,
    /// The task answering was canceled, or the connection's.
    Canceled,
    OutOfMemory,
};

/// Answer `request` as a WebSocket handshake and take the connection over,
/// into `out`, which must stay where it is while the connection is used.
/// Over HTTP/2 the handshake is an extended `CONNECT` (RFC 8441), and the
/// stream is taken over.
pub fn accept(out: *Accepted, gpa: Allocator, io: Io, request: *ServerRequest, response: *ServerResponse, options: AcceptOptions) AcceptError!void {
    const h = &request.headers;
    const over_h2 = request.version == .h2;
    const handshake = if (over_h2)
        request.method.eql(.CONNECT) and std.mem.eql(u8, request.protocol orelse "", "websocket")
    else
        request.method.eql(.GET) and request.version == .http1_1 and
            h.hasToken("upgrade", "websocket") and h.hasToken("connection", "upgrade");
    const key = h.get("sec-websocket-key") orelse "";
    if (!handshake or (!over_h2 and !ws.validKey(key))) return refuse(io, response, .bad_request, error.NotWebSocket);
    const version = std.mem.trim(u8, h.get("sec-websocket-version") orelse "", " \t");
    if (!std.mem.eql(u8, version, "13")) {
        response.header("Sec-WebSocket-Version", "13") catch return error.WriteFailed;
        return refuse(io, response, .upgrade_required, error.UnsupportedVersion);
    }
    var protocol: ?[]const u8 = null;
    if (options.protocols.len != 0) for (options.protocols) |p| {
        if (h.hasToken("sec-websocket-protocol", p)) {
            protocol = p;
            break;
        }
    };
    const agreed = if (options.compression) |c| agreeDeflate(h, c) else null;
    response.status = if (over_h2) .ok else .switching_protocols;
    headers: {
        if (!over_h2) {
            const accept_key = ws.acceptKey(key);
            response.header("Upgrade", "websocket") catch break :headers;
            response.header("Connection", "Upgrade") catch break :headers;
            response.header("Sec-WebSocket-Accept", &accept_key) catch break :headers;
        }
        if (protocol) |p| response.header("Sec-WebSocket-Protocol", p) catch break :headers;
        if (agreed) |d| {
            var buf: [256]u8 = undefined;
            var w: Io.Writer = .fixed(&buf);
            d.write(&w) catch unreachable; // unreachable: the parameters are under 256 bytes
            response.header("Sec-WebSocket-Extensions", w.buffered()) catch break :headers;
        }
    }
    const stream = response.hijack(io) catch |err| return answerFailed(err);
    out.* = .{ .stream = stream, .protocol = protocol, .conn = undefined };
    out.conn = .init(gpa, .server, .{
        .reader = stream.reader,
        .writer = stream.writer,
        .context = out,
        .flushFn = flushAccepted,
        .readableFn = readableAccepted,
        .canceledFn = canceledAccepted,
    }, options.conn, agreed);
}

fn flushAccepted(context: ?*anyopaque, _: Io) Io.Writer.Error!void {
    const a: *Accepted = @ptrCast(@alignCast(context.?)); // safe: `accept` passes its Accepted
    return a.stream.flush();
}

fn readableAccepted(context: ?*anyopaque, io: Io, timeout: Io.Duration) Io.Cancelable!Timed.Readiness {
    const a: *Accepted = @ptrCast(@alignCast(context.?)); // safe: `accept` passes its Accepted
    return a.stream.awaitReadable(io, timeout);
}

fn canceledAccepted(context: ?*anyopaque) bool {
    const a: *Accepted = @ptrCast(@alignCast(context.?)); // safe: `accept` passes its Accepted
    return a.stream.canceled();
}

fn refuse(io: Io, response: *ServerResponse, status: std.http.Status, err: AcceptError) AcceptError {
    response.status = status;
    response.closeAfter();
    response.send(io, "") catch |e| return answerFailed(e);
    return err;
}

/// The handshake's answer failed to go.
fn answerFailed(err: ServerResponse.Error) AcceptError {
    return switch (err) {
        error.Canceled => error.Canceled,
        error.OutOfMemory => error.OutOfMemory,
        else => error.WriteFailed,
    };
}

/// The permessage-deflate parameters to answer the client's offers with:
/// the first offer this end can take, or null.
fn agreeDeflate(h: *const fields.Headers, c: Compression) ?ws.Deflate {
    var lines = h.values("sec-websocket-extensions");
    while (lines.next()) |element| {
        const semi = std.mem.findScalar(u8, element, ';') orelse element.len;
        if (!std.ascii.eqlIgnoreCase(std.mem.trim(u8, element[0..semi], " \t"), "permessage-deflate")) continue;
        const offer = ws.Deflate.parse(element[semi..]) catch continue;
        var answer: ws.Deflate = .{
            .server_no_context_takeover = offer.server_no_context_takeover or c.no_context_takeover,
            .client_no_context_takeover = offer.client_no_context_takeover,
            .server_max_window_bits = if (offer.server_max_window_bits) |bits| @min(bits, c.window_bits) else if (c.window_bits < 15) c.window_bits else null,
        };
        // A window the client caps below 9 is one warp's encoder cannot
        // keep to; the offer is declined, as RFC 7692 lets a server.
        if (answer.server_max_window_bits) |bits| if (bits < 9) continue;
        if (offer.client_max_window_bits) |bits| answer.client_max_window_bits = bits;
        return answer;
    }
    return null;
}

/// How a client opens a connection.
pub const ConnectOptions = struct {
    conn: Conn.Options = .{},
    /// The subprotocols offered, the client's preference first.
    protocols: []const []const u8 = &.{},
    /// permessage-deflate offered; null offers none.
    compression: ?Compression = .{},
    /// More fields for the handshake request.
    headers: []const std.http.Header = &.{},
};

/// A WebSocket a client opened: the connection and the stream under it.
/// It must not move.
pub const Opened = struct {
    conn: Conn,
    stream: Upgraded,
    /// The subprotocol the server chose, if any.
    protocol: ?[]const u8,
    /// Private: the protocol's name, kept from the response's head.
    protocol_buffer: [64]u8 = undefined,

    /// Free the connection and close the stream.
    pub fn deinit(o: *Opened, io: Io) void {
        o.conn.deinit();
        o.stream.close(io);
    }
};

/// Why a connection was not opened.
pub const ConnectError = Client.SendError || error{
    /// A URL whose scheme is not `ws` or `wss`.
    InvalidWebSocketUrl,
    /// The server answered with something other than 101.
    HandshakeRefused,
    /// A 101 that is not a WebSocket's: a wrong `Sec-WebSocket-Accept`,
    /// an `Upgrade` or `Connection` missing, a subprotocol or extension
    /// never offered.
    InvalidHandshake,
};

/// Open a WebSocket to `url` (`ws://` or `wss://`) through `client`,
/// into `out`, which must stay where it is while the connection is used.
pub fn connect(out: *Opened, client: *Client, gpa: Allocator, io: Io, url: []const u8, options: ConnectOptions) ConnectError!void {
    var url_buffer: [8192]u8 = undefined;
    const http_url = httpUrl(url, &url_buffer) orelse return error.InvalidWebSocketUrl;
    var random: [16]u8 = undefined;
    io.random(&random);
    const key = ws.keyOf(random);
    var headers: [12]std.http.Header = undefined;
    var n: usize = 0;
    headers[n] = .{ .name = "Connection", .value = "Upgrade" };
    n += 1;
    headers[n] = .{ .name = "Upgrade", .value = "websocket" };
    n += 1;
    headers[n] = .{ .name = "Sec-WebSocket-Version", .value = "13" };
    n += 1;
    headers[n] = .{ .name = "Sec-WebSocket-Key", .value = &key };
    n += 1;
    var protocols_buffer: [512]u8 = undefined;
    if (options.protocols.len != 0) {
        var w: Io.Writer = .fixed(&protocols_buffer);
        for (options.protocols, 0..) |p, i| {
            if (i != 0) w.writeAll(", ") catch return error.InvalidHeader;
            w.writeAll(p) catch return error.InvalidHeader;
        }
        headers[n] = .{ .name = "Sec-WebSocket-Protocol", .value = w.buffered() };
        n += 1;
    }
    var offer_buffer: [128]u8 = undefined;
    if (options.compression) |c| {
        var w: Io.Writer = .fixed(&offer_buffer);
        const offer: ws.Deflate = .{
            .client_no_context_takeover = c.no_context_takeover,
            .client_bits_offered = c.window_bits == 15,
            .client_max_window_bits = if (c.window_bits < 15) c.window_bits else null,
        };
        offer.write(&w) catch unreachable; // unreachable: an offer is under 128 bytes
        headers[n] = .{ .name = "Sec-WebSocket-Extensions", .value = w.buffered() };
        n += 1;
    }
    var all: [44]std.http.Header = undefined;
    @memcpy(all[0..n], headers[0..n]);
    const extra = @min(options.headers.len, all.len - n);
    @memcpy(all[n..][0..extra], options.headers[0..extra]);
    var response = try client.send(io, .{ .url = http_url, .headers = all[0 .. n + extra] });
    defer response.deinit(io);
    if (response.status != .switching_protocols) return error.HandshakeRefused;
    const rh = &response.headers;
    if (!rh.hasToken("upgrade", "websocket") or !rh.hasToken("connection", "upgrade")) return error.InvalidHandshake;
    const expected = ws.acceptKey(&key);
    if (!std.mem.eql(u8, std.mem.trim(u8, rh.get("sec-websocket-accept") orelse "", " \t"), &expected)) return error.InvalidHandshake;
    out.protocol = null;
    if (rh.get("sec-websocket-protocol")) |chosen| {
        const p = std.mem.trim(u8, chosen, " \t");
        const offered = for (options.protocols) |o| {
            if (std.mem.eql(u8, o, p)) break true;
        } else false;
        if (!offered or p.len > out.protocol_buffer.len) return error.InvalidHandshake;
        @memcpy(out.protocol_buffer[0..p.len], p);
        out.protocol = out.protocol_buffer[0..p.len];
    }
    var agreed: ?ws.Deflate = null;
    if (rh.get("sec-websocket-extensions")) |ext| {
        const semi = std.mem.findScalar(u8, ext, ';') orelse ext.len;
        const name = std.mem.trim(u8, ext[0..semi], " \t");
        if (options.compression == null or !std.ascii.eqlIgnoreCase(name, "permessage-deflate")) return error.InvalidHandshake;
        const answer = ws.Deflate.parse(ext[semi..]) catch return error.InvalidHandshake;
        if (answer.client_bits_offered) return error.InvalidHandshake;
        const c = options.compression.?;
        if (answer.client_max_window_bits) |bits| if (bits > c.window_bits) return error.InvalidHandshake;
        var d = answer;
        // This end compresses with what it offered, or what the server
        // asked for, whichever is fewer bits; with a fresh history when
        // either said so.
        d.client_no_context_takeover = answer.client_no_context_takeover or c.no_context_takeover;
        if (d.client_max_window_bits == null and c.window_bits < 15) d.client_max_window_bits = c.window_bits;
        agreed = d;
    }
    out.stream = response.upgrade(io) catch return error.InvalidHandshake;
    out.stream.unbind();
    out.conn = .init(gpa, .client, .{
        .reader = out.stream.reader(io),
        .writer = out.stream.writer(io),
        .context = out,
        .flushFn = flushOpened,
        .readableFn = readableOpened,
        .canceledFn = canceledOpened,
    }, options.conn, agreed);
}

fn flushOpened(context: ?*anyopaque, io: Io) Io.Writer.Error!void {
    const o: *Opened = @ptrCast(@alignCast(context.?)); // safe: `connect` passes its Opened
    o.stream.flush(io) catch return error.WriteFailed;
}

fn readableOpened(context: ?*anyopaque, io: Io, timeout: Io.Duration) Io.Cancelable!Timed.Readiness {
    const o: *Opened = @ptrCast(@alignCast(context.?)); // safe: `connect` passes its Opened
    return o.stream.awaitReadable(io, timeout);
}

fn canceledOpened(context: ?*anyopaque) bool {
    const o: *Opened = @ptrCast(@alignCast(context.?)); // safe: `connect` passes its Opened
    return o.stream.readFailure() == error.Canceled;
}

/// `url` with `ws` made `http` and `wss` made `https`, in `buffer`.
fn httpUrl(url: []const u8, buffer: []u8) ?[]const u8 {
    const scheme_end = std.mem.find(u8, url, "://") orelse return null;
    const scheme = url[0..scheme_end];
    const replacement: []const u8 = if (std.ascii.eqlIgnoreCase(scheme, "ws")) "http" else if (std.ascii.eqlIgnoreCase(scheme, "wss")) "https" else return null;
    return std.mem.print(buffer, "{s}{s}", .{ replacement, url[scheme_end..] }) catch null;
}

test {
    _ = Conn;
}
