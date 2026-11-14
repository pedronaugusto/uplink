//! The conformance suite: one round trip per feature over the system's
//! sockets, run on every `Io` the tests run on (`Io.Threaded`, and reactor's
//! runtime on each kernel backend the target has). The client and server
//! suites run on shakedown's simulated network (`test_io.simulated`), in
//! virtual time and once; this is where each feature they cover still meets
//! a real kernel's sockets on each backend. What only the system shows stays
//! in its own suite beside: socket options, the system's peek, named pipes,
//! sendfile, and interop with openssl, curl and the others.

const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const test_io = @import("testing/io.zig");
const Pki = @import("testing/Pki.zig");
const TestProxy = @import("testing/Proxy.zig");
const TestServer = @import("testing/Server.zig");
const Client = @import("client/Client.zig");
const Server = @import("server/Server.zig");
const Request = @import("server/Request.zig");
const Response = @import("server/Response.zig");
const Files = @import("server.zig").Files;
const Proxy = @import("transport/Proxy.zig");
const ws = @import("ws.zig");
const ReverseProxy = @import("ReverseProxy.zig");
const Http2 = @import("client/Shared.zig").Http2;
const Version = @import("uplink.wire").Version;

/// uplink's server on 127.0.0.1, on a port of the system's choosing.
const Running = struct {
    server: Server,
    listener: Io.net.Server,
    task: Io.Future(Server.ServeError!void),
    port: u16,

    fn start(r: *Running, options: Server.Options, handler: *Server.Handler) !void {
        const io = test_io.io();
        r.listener = try (try Io.net.IpAddress.parse("127.0.0.1", 0)).listen(io, .{ .reuse_address = true });
        errdefer r.listener.deinit(io);
        r.port = r.listener.socket.address.getPort();
        r.server = .init(testing.allocator, options, handler);
        r.task = io.concurrent(Server.serve, .{ &r.server, io, &r.listener }) catch return error.SkipZigTest;
    }

    fn stop(r: *Running) void {
        const io = test_io.io();
        r.server.shutdown(io);
        // serve ends with the shutdown; its result is not what the test checks
        r.task.await(io) catch {};
        r.server.deinit(io);
        r.listener.deinit(io);
    }

    fn url(r: *const Running, buffer: []u8, scheme: []const u8, path: []const u8) []const u8 {
        return std.mem.print(buffer, "{s}://127.0.0.1:{d}{s}", .{ scheme, r.port, path }) catch unreachable; // unreachable: callers pass room for a URL
    }
};

fn echo(io: Io, request: *Request, response: *Response) anyerror!void {
    const body = try request.collect(testing.allocator, io, .limited(1 << 20));
    defer testing.allocator.free(body);
    try response.send(io, body);
}

/// The body of a POST of `sent` to `url`, as the response says and `version`.
fn post(client: *Client, io: Io, url: []const u8, sent: []const u8, version: Version) !void {
    var response = try client.send(io, .{ .method = .POST, .url = url, .body = .{ .bytes = sent } });
    defer response.deinit(io);
    try testing.expectEqual(std.http.Status.ok, response.status);
    try testing.expectEqual(version, response.version);
    const body = try response.collect(testing.allocator, io, .limited(1 << 20));
    defer testing.allocator.free(body);
    try testing.expectEqualStrings(sent, body);
}

test "HTTP/1.1: two requests on one kept connection, a body each way" {
    const io = test_io.io();
    var running: Running = undefined;
    try running.start(.{}, .of(echo));
    defer running.stop();
    var client: Client = .init(testing.allocator, .{});
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    const url = running.url(&buf, "http", "/");
    try post(&client, io, url, "one", .http1_1);
    try post(&client, io, url, "two", .http1_1);
    try testing.expectEqual(@as(u64, 1), client.stats().connections_opened);
}

test "HTTP/1.1 over a Unix socket" {
    const gpa = testing.allocator;
    const io = test_io.io();
    if (!Io.net.has_unix_sockets) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const dir = dir_buf[0..try tmp.dir.realPath(io, &dir_buf)];
    var path_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const path = try std.mem.print(&path_buf, "{s}/c.sock", .{dir});
    if (path.len >= 104) return error.SkipZigTest;
    const server = TestServer.startUnix(gpa, io, path, TestServer.fixed("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")) catch return error.SkipZigTest;
    defer server.stop();
    var client: Client = .init(gpa, .{ .dial = .{ .unix_socket = path } });
    defer client.deinit(io);
    var response = try client.send(io, .{ .url = "http://unix.local/" });
    defer response.deinit(io);
    const body = try response.collect(gpa, io, .limited(1 << 10));
    defer gpa.free(body);
    try testing.expectEqualStrings("ok", body);
}

test "HTTP/2 by prior knowledge and by an h2c upgrade: two requests on one connection" {
    const io = test_io.io();
    var running: Running = undefined;
    try running.start(.{ .h2c = .alongside_http1 }, .of(echo));
    defer running.stop();
    var buf: [64]u8 = undefined;
    const url = running.url(&buf, "http", "/");
    for ([_]Client.Options{ .{ .http2 = .prior_knowledge }, .{ .http2 = .upgrade } }) |options| {
        var client: Client = .init(testing.allocator, options);
        defer client.deinit(io);
        // An upgrade answers its first request in HTTP/2 once switched.
        var first = try client.send(io, .{ .url = url });
        defer first.deinit(io);
        testing.allocator.free(try first.collect(testing.allocator, io, .limited(1 << 10)));
        try post(&client, io, url, "on the same connection", .h2);
        try testing.expectEqual(@as(u64, 1), client.stats().connections_opened);
    }
}

fn certificateSeen(io: Io, request: *Request, response: *Response) anyerror!void {
    try response.send(io, if (request.peer_certificate != null) "a client certificate" else "none");
}

test "TLS from cloak on both ends: HTTP/1.1 and HTTP/2 agreed by ALPN, a client certificate proved" {
    const io = test_io.io();
    var pki: Pki = undefined;
    try pki.init();
    defer pki.deinit();
    var running: Running = undefined;
    try running.start(.{ .tls = .{ .credentials = &pki.credentials, .client_certificate = .required, .client_trust = pki.client_trust } }, .of(certificateSeen));
    defer running.stop();
    var buf: [64]u8 = undefined;
    const url = running.url(&buf, "https", "/");
    for ([_]Http2{ .off, .negotiate }, [_]Version{ .http1_1, .h2 }) |http2, version| {
        var client: Client = .init(testing.allocator, .{ .http2 = http2, .tls = .{ .trust = pki.trust, .client_auth = pki.client_auth } });
        defer client.deinit(io);
        var response = try client.send(io, .{ .url = url });
        defer response.deinit(io);
        try testing.expectEqual(version, response.version);
        const body = try response.collect(testing.allocator, io, .limited(1 << 10));
        defer testing.allocator.free(body);
        try testing.expectEqualStrings("a client certificate", body);
    }
}

fn wsEcho(io: Io, request: *Request, response: *Response) anyerror!void {
    var accepted: ws.Accepted = undefined;
    ws.accept(&accepted, testing.allocator, io, request, response, .{}) catch return;
    defer accepted.deinit();
    while (true) {
        const message = accepted.conn.readMessage(io, testing.allocator, .limited(1 << 20)) catch return;
        const kind, const bytes = message orelse return;
        defer testing.allocator.free(bytes);
        try accepted.conn.send(io, kind, bytes);
    }
}

test "WebSocket by an HTTP/1.1 Upgrade and by an HTTP/2 extended CONNECT: a message echoed" {
    const gpa = testing.allocator;
    const io = test_io.io();
    var running: Running = undefined;
    try running.start(.{ .h2c = .alongside_http1 }, .of(wsEcho));
    defer running.stop();
    var buf: [64]u8 = undefined;
    const url = running.url(&buf, "ws", "/");
    for ([_]Http2{ .off, .prior_knowledge }) |http2| {
        var client: Client = .init(gpa, .{ .http2 = http2 });
        defer client.deinit(io);
        var opened: ws.Opened = undefined;
        try ws.connect(&opened, &client, gpa, io, url, .{});
        defer opened.deinit(io);
        try testing.expect((opened.stream.carrier == .stream) == (http2 != .off));
        try opened.conn.send(io, .text, "hello");
        _, const back = (try opened.conn.readMessage(io, gpa, .limited(1 << 10))).?;
        defer gpa.free(back);
        try testing.expectEqualStrings("hello", back);
    }
}

fn greet(io: Io, _: *Request, response: *Response) anyerror!void {
    try response.send(io, "through the tunnel");
}

test "a tunnel through an HTTP proxy (CONNECT) and through SOCKS5h carries TLS" {
    const gpa = testing.allocator;
    const io = test_io.io();
    var pki: Pki = undefined;
    try pki.init();
    defer pki.deinit();
    var running: Running = undefined;
    try running.start(.{ .tls = .{ .credentials = &pki.credentials } }, .of(greet));
    defer running.stop();
    for ([_]TestProxy.Kind{ .http, .socks }) |kind| {
        const proxy = try TestProxy.start(gpa, io, .{ .kind = kind });
        defer proxy.stop();
        var arena: std.heap.ArenaAllocator = .init(gpa);
        defer arena.deinit();
        var proxy_url: [64]u8 = undefined;
        var client: Client = .init(gpa, .{
            .tls = .{ .trust = pki.trust },
            .proxy = .{ .fixed = try Proxy.parse(arena.allocator(), try std.mem.print(&proxy_url, "{s}://127.0.0.1:{d}", .{ if (kind == .http) "http" else "socks5h", proxy.port }), .lowercase) },
        });
        defer client.deinit(io);
        var target: [64]u8 = undefined;
        var response = try client.send(io, .{ .url = try std.mem.print(&target, "https://server.test:{d}/", .{running.port}) });
        defer response.deinit(io);
        const body = try response.collect(gpa, io, .limited(1 << 10));
        defer gpa.free(body);
        try testing.expectEqualStrings("through the tunnel", body);
        const log = try proxy.lines(gpa);
        defer gpa.free(log);
        try testing.expect(std.mem.find(u8, log, "server.test:") != null);
    }
}

const page_text = @import("shakedown").corpus.repeat("a line of text, coded on the way and decoded on arrival\n", 64);

fn page(io: Io, _: *Request, response: *Response) anyerror!void {
    try response.header("Content-Type", "text/plain");
    try response.send(io, page_text);
}

test "bodies coded gzip, zstd and Brotli are decoded" {
    const io = test_io.io();
    for ([_]Server.Compression{ .{ .codings = &.{.gzip} }, .{ .codings = &.{.zstd} }, .{ .codings = &.{.br} } }) |compression| {
        var running: Running = undefined;
        try running.start(.{ .compression = compression }, .of(page));
        defer running.stop();
        var client: Client = .init(testing.allocator, .{});
        defer client.deinit(io);
        var buf: [64]u8 = undefined;
        var response = try client.send(io, .{ .url = running.url(&buf, "http", "/") });
        defer response.deinit(io);
        try testing.expectEqualStrings(@tagName(compression.codings[0]), response.headers.get("content-encoding").?);
        const body = try response.collect(testing.allocator, io, .limited(1 << 16));
        defer testing.allocator.free(body);
        try testing.expectEqualStrings(page_text, body);
    }
}

test "a file is served from the system's disk, whole and by range" {
    const gpa = testing.allocator;
    const io = test_io.io();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(io, .{ .sub_path = "a.txt", .data = page_text });
    var files: Files = .init(tmp.dir, .{});
    var running: Running = undefined;
    try running.start(.{}, files.handler());
    defer running.stop();
    var client: Client = .init(gpa, .{});
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    const url = running.url(&buf, "http", "/a.txt");
    {
        var response = try client.send(io, .{ .url = url });
        defer response.deinit(io);
        const body = try response.collect(gpa, io, .limited(1 << 16));
        defer gpa.free(body);
        try testing.expectEqualStrings(page_text, body);
    }
    var response = try client.send(io, .{ .url = url, .headers = &.{.{ .name = "Range", .value = "bytes=2-5" }} });
    defer response.deinit(io);
    try testing.expectEqual(std.http.Status.partial_content, response.status);
    const body = try response.collect(gpa, io, .limited(1 << 10));
    defer gpa.free(body);
    try testing.expectEqualStrings(page_text[2..6], body);
}

test "a request through an HTTP proxy in absolute form" {
    const gpa = testing.allocator;
    const io = test_io.io();
    var running: Running = undefined;
    try running.start(.{}, .of(greet));
    defer running.stop();
    const proxy = try TestProxy.start(gpa, io, .{});
    defer proxy.stop();
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    var proxy_url: [64]u8 = undefined;
    var client: Client = .init(gpa, .{ .proxy = .{ .fixed = try Proxy.parse(arena.allocator(), try std.mem.print(&proxy_url, "http://127.0.0.1:{d}", .{proxy.port}), .lowercase) } });
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    var response = try client.send(io, .{ .url = running.url(&buf, "http", "/") });
    defer response.deinit(io);
    const body = try response.collect(gpa, io, .limited(1 << 10));
    defer gpa.free(body);
    try testing.expectEqualStrings("through the tunnel", body);
    const log = try proxy.lines(gpa);
    defer gpa.free(log);
    try testing.expect(std.mem.startsWith(u8, log, "GET http://127.0.0.1:"));
}

test "an activity timeout ends a request its server leaves unanswered, as TimedOut" {
    const io = test_io.io();
    const server = try TestServer.start(testing.allocator, io, TestServer.fixedAnswer(.{ .silent = true }));
    defer server.stop();
    var client: Client = .init(testing.allocator, .{ .timeouts = .{ .activity = .literal("100ms") } });
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    try testing.expectError(error.TimedOut, client.send(io, .{ .url = server.url(&buf, "/") }));
}

fn sendOnce(client: *Client, io: Io, url: []const u8) Client.SendError!void {
    var response = try client.send(io, .{ .url = url });
    response.deinit(io);
}

test "a request canceled while it waits on its server ends Canceled" {
    const io = test_io.io();
    const server = try TestServer.start(testing.allocator, io, TestServer.fixedAnswer(.{ .silent = true }));
    defer server.stop();
    var client: Client = .init(testing.allocator, .{});
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    var sending = io.concurrent(sendOnce, .{ &client, io, server.url(&buf, "/") }) catch return error.SkipZigTest;
    // The request is out, and its response waited for.
    while (server.requests.load(.acquire) == 0 and server.accepted.load(.acquire) == 0) try io.sleep(.fromMilliseconds(5), .awake);
    try io.sleep(.fromMilliseconds(20), .awake);
    try testing.expectError(error.Canceled, sending.cancel(io));
}

/// A handler that waits, as one computing would, for its client to leave.
const Leaving = struct {
    var started: std.atomic.Value(bool) = .init(false);
    var left: std.atomic.Value(bool) = .init(false);

    fn handle(io: Io, request: *Request, response: *Response) anyerror!void {
        started.store(true, .release);
        const gone = try request.gone(io, .{ .duration = .{ .raw = .fromSeconds(20), .clock = .awake } });
        left.store(gone, .release);
        if (!gone) try response.send(io, "stayed");
    }

    fn until(flag: *std.atomic.Value(bool)) !void {
        const io = test_io.io();
        var waited: u32 = 0;
        while (!flag.load(.acquire) and waited < 1000) : (waited += 1) try io.sleep(.fromMilliseconds(10), .awake);
        try testing.expect(flag.load(.acquire));
    }
};

test "a handler learns its client left while it computes" {
    const io = test_io.io();
    Leaving.started.store(false, .release);
    Leaving.left.store(false, .release);
    var running: Running = undefined;
    try running.start(.{}, .of(Leaving.handle));
    defer running.stop();
    var client: Client = .init(testing.allocator, .{});
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    var sending = io.concurrent(sendOnce, .{ &client, io, running.url(&buf, "http", "/") }) catch return error.SkipZigTest;
    try Leaving.until(&Leaving.started);
    // the canceled send ends as it does; the handler's side is what is checked
    sending.cancel(io) catch {};
    try Leaving.until(&Leaving.left);
}

fn upstreamOf(io: Io, request: *Request, response: *Response) anyerror!void {
    if (std.mem.eql(u8, request.path, "/ws")) return wsEcho(io, request, response);
    return echo(io, request, response);
}

test "a reverse proxy passes a request on, and an upgrade's bytes both ways" {
    const gpa = testing.allocator;
    const io = test_io.io();
    var upstream: Running = undefined;
    try upstream.start(.{}, .of(upstreamOf));
    defer upstream.stop();
    var outbound: Client = .init(gpa, .{});
    defer outbound.deinit(io);
    var upstream_url: [64]u8 = undefined;
    var proxy: ReverseProxy = try .init(gpa, &outbound, .{ .upstream = upstream.url(&upstream_url, "http", "") });
    var front: Running = undefined;
    try front.start(.{}, &proxy.handler);
    defer front.stop();
    var client: Client = .init(gpa, .{});
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    try post(&client, io, front.url(&buf, "http", "/echo"), "passed on", .http1_1);
    var opened: ws.Opened = undefined;
    try ws.connect(&opened, &client, gpa, io, front.url(&buf, "ws", "/ws"), .{});
    defer opened.deinit(io);
    try opened.conn.send(io, .text, "both ways");
    _, const back = (try opened.conn.readMessage(io, gpa, .limited(1 << 10))).?;
    defer gpa.free(back);
    try testing.expectEqualStrings("both ways", back);
}
