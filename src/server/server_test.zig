//! The server over loopback: against uplink's own client, and against raw
//! bytes where the bytes are the point (pipelining, smuggling, limits).

const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const test_io = @import("../testing/io.zig");
const Client = @import("../client/Client.zig");
const Server = @import("Server.zig");
const Request = @import("Request.zig");
const Response = @import("Response.zig");
const repeat = @import("shakedown").corpus.repeat;

/// A server listening on 127.0.0.1, serving on a task of its own.
const Running = struct {
    server: Server,
    listener: Io.net.Server,
    task: Io.Future(Server.ServeError!void),
    port: u16,

    fn start(gpa: std.mem.Allocator, options: Server.Options, handler: Server.Handler) !*Running {
        const io = test_io.io();
        const r = try gpa.create(Running);
        errdefer gpa.destroy(r);
        r.listener = try (try Io.net.IpAddress.parse("127.0.0.1", 0)).listen(io, .{ .reuse_address = true });
        errdefer r.listener.deinit(io);
        r.port = r.listener.socket.address.getPort();
        r.server = .init(gpa, options, handler);
        r.task = io.concurrent(Server.serve, .{ &r.server, io, &r.listener }) catch return error.SkipZigTest;
        return r;
    }

    fn stop(r: *Running) void {
        r.halt();
        r.free();
    }

    /// Shut the server down and wait for `serve` to return.
    fn halt(r: *Running) void {
        const io = test_io.io();
        r.server.shutdown(io);
        // glint-ignore: Z026 -- serve ends with the shutdown; its result is not what the test checks
        r.task.await(io) catch {};
    }

    fn free(r: *Running) void {
        const io = test_io.io();
        r.server.deinit(io);
        r.listener.deinit(io);
        testing.allocator.destroy(r);
    }

    fn url(r: *const Running, buffer: []u8, path: []const u8) []const u8 {
        return std.mem.print(buffer, "http://127.0.0.1:{d}{s}", .{ r.port, path }) catch unreachable; // unreachable: callers pass room for a URL
    }

    /// Send `bytes` on a fresh connection and read until the server
    /// closes it, or `limit` bytes.
    fn raw(r: *const Running, gpa: std.mem.Allocator, bytes: []const u8) ![]u8 {
        const io = test_io.io();
        const address = try Io.net.IpAddress.parse("127.0.0.1", r.port);
        const stream = try address.connect(io, .{ .mode = .stream });
        defer stream.close(io);
        var wbuf: [1024]u8 = undefined;
        var w = stream.writer(io, &wbuf);
        try w.interface.writeAll(bytes);
        try w.interface.flush();
        var rbuf: [4096]u8 = undefined;
        var rd = stream.reader(io, &rbuf);
        return rd.interface.allocRemaining(gpa, .limited(1 << 20)) catch |err| switch (err) {
            error.ReadFailed => gpa.dupe(u8, ""),
            else => |e| e,
        };
    }
};

fn hello(_: Io, request: *Request, response: *Response) anyerror!void {
    try response.header("Content-Type", "text/plain");
    if (std.mem.eql(u8, request.path, "/stream")) {
        const w = try response.writer(test_io.io());
        for (0..1000) |i| try w.print("line {d}\n", .{i});
        return response.end(test_io.io());
    }
    try response.send(test_io.io(), "hello");
}

test "a client's requests are answered over one kept connection" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const running = try Running.start(gpa, .{}, .of(hello));
    defer running.stop();
    var client: Client = .init(gpa, .{});
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    for (0..10) |_| {
        var response = try client.send(io, .{ .url = running.url(&buf, "/") });
        defer response.deinit(io);
        try testing.expectEqual(std.http.Status.ok, response.status);
        try testing.expectEqualStrings("text/plain", response.headers.get("content-type").?);
        try testing.expect(response.headers.get("date") != null);
        const body = try response.collect(gpa, io, .limited(1 << 20));
        defer gpa.free(body);
        try testing.expectEqualStrings("hello", body);
    }
    try testing.expectEqual(@as(u64, 1), client.stats().connections_opened);
    try testing.expectEqual(@as(u64, 10), running.server.stats().requests);
}

test "a body longer than the buffer is chunked, and one that fits goes with its length" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const running = try Running.start(gpa, .{}, .of(hello));
    defer running.stop();
    var client: Client = .init(gpa, .{});
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    var response = try client.send(io, .{ .url = running.url(&buf, "/stream") });
    defer response.deinit(io);
    try testing.expectEqualStrings("chunked", response.headers.get("transfer-encoding").?);
    const body = try response.collect(gpa, io, .limited(1 << 20));
    defer gpa.free(body);
    try testing.expect(std.mem.startsWith(u8, body, "line 0\nline 1\n"));
    try testing.expect(std.mem.endsWith(u8, body, "line 999\n"));
    const plain = try running.raw(gpa, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    defer gpa.free(plain);
    try testing.expect(std.mem.find(u8, plain, "Content-Length: 5\r\n") != null);
    try testing.expect(std.mem.find(u8, plain, "Connection: close\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, plain, "\r\n\r\nhello"));
}

fn echo(io: Io, request: *Request, response: *Response) anyerror!void {
    const body = try request.collect(testing.allocator, io, .limited(1 << 20));
    defer testing.allocator.free(body);
    try response.send(io, body);
}

test "pipelined requests are answered in order, each body read as framed" {
    const gpa = testing.allocator;
    const running = try Running.start(gpa, .{}, .of(echo));
    defer running.stop();
    const got = try running.raw(gpa, "POST /a HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\none" ++
        "POST /b HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3\r\ntwo\r\n0\r\n\r\n" ++
        "POST /c HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nConnection: close\r\n\r\nthree");
    defer gpa.free(got);
    const first = std.mem.find(u8, got, "\r\n\r\none").?;
    const second = std.mem.find(u8, got, "\r\n\r\ntwo").?;
    const third = std.mem.find(u8, got, "\r\n\r\nthree").?;
    try testing.expect(first < second and second < third);
    try testing.expectEqual(@as(usize, 3), std.mem.count(u8, got, "HTTP/1.1 200 OK\r\n"));
}

test "a client that expects 100 Continue gets it, and its body is echoed" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const running = try Running.start(gpa, .{}, .of(echo));
    defer running.stop();
    var client: Client = .init(gpa, .{ .expect_continue_timeout = .literal("10s") });
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    var response = try client.send(io, .{ .method = .POST, .url = running.url(&buf, "/"), .body = .{ .bytes = "payload" }, .expect_continue = true });
    defer response.deinit(io);
    const body = try response.collect(gpa, io, .limited(1 << 20));
    defer gpa.free(body);
    try testing.expectEqualStrings("payload", body);
}

test "smuggling patterns, bad heads and limits are refused, each closing its connection" {
    const gpa = testing.allocator;
    const running = try Running.start(gpa, .{ .max_body = .literal("1KiB"), .limits = .{ .max_head = .literal("1KiB") } }, .of(echo));
    defer running.stop();
    const cases = [_]struct { []const u8, []const u8 }{
        .{ "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", "HTTP/1.1 400 " },
        .{ "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked, gzip\r\n\r\n", "HTTP/1.1 400 " },
        .{ "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabc", "HTTP/1.1 400 " },
        .{ "GET / HTTP/1.1\nHost: x\n\n", "HTTP/1.1 400 " },
        .{ "GET / HTTP/1.1\r\nHost: x\r\nX: a\r\n b\r\n\r\n", "HTTP/1.1 400 " },
        .{ "GET / HTTP/1.1\r\n\r\n", "HTTP/1.1 400 " },
        .{ "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", "HTTP/1.1 400 " },
        .{ "GET / HTTP/2.0\r\nHost: x\r\n\r\n", "HTTP/1.1 505 " },
        .{ "GET / HTTP/1.1\r\nHost: x\r\nPad: " ++ repeat("p", 1100) ++ "\r\n\r\n", "HTTP/1.1 431 " },
        .{ "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2000\r\n\r\n", "HTTP/1.1 413 " },
        .{ "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1\r\nExpect: 200-ok\r\n\r\nx", "HTTP/1.1 417 " },
        .{ "GET * HTTP/1.1\r\nHost: x\r\n\r\n", "HTTP/1.1 400 " },
    };
    for (cases) |case| {
        const got = try running.raw(gpa, case[0]);
        defer gpa.free(got);
        testing.expect(std.mem.startsWith(u8, got, case[1])) catch |err| {
            std.debug.print("sent {any}, got {any}\n", .{ case[0], got });
            return err;
        };
        try testing.expect(std.mem.find(u8, got, "Connection: close\r\n") != null);
    }
}

test "a HEAD is answered with the head a GET would have, and no body" {
    const gpa = testing.allocator;
    const running = try Running.start(gpa, .{}, .of(hello));
    defer running.stop();
    const got = try running.raw(gpa, "HEAD / HTTP/1.1\r\nHost: x\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    defer gpa.free(got);
    try testing.expectEqual(@as(usize, 2), std.mem.count(u8, got, "Content-Length: 5\r\n"));
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, got, "hello"));
    try testing.expect(std.mem.endsWith(u8, got, "hello"));
}

fn failing(io: Io, request: *Request, response: *Response) anyerror!void {
    if (std.mem.eql(u8, request.path, "/late")) {
        const w = try response.writer(io);
        try w.splatByteAll('x', 10_000);
        return error.Broken;
    }
    try response.header("X-Lost", "yes");
    return error.Broken;
}

test "a handler that fails before its head gets a 500, and after it a cut connection" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const running = try Running.start(gpa, .{}, .of(failing));
    defer running.stop();
    const early = try running.raw(gpa, "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    defer gpa.free(early);
    try testing.expect(std.mem.startsWith(u8, early, "HTTP/1.1 500 "));
    try testing.expect(std.mem.find(u8, early, "X-Lost") == null);
    var client: Client = .init(gpa, .{ .retries = .none });
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    var response = try client.send(io, .{ .url = running.url(&buf, "/late") });
    defer response.deinit(io);
    try testing.expectError(error.BodyIncomplete, response.collect(gpa, io, .limited(1 << 20)));
}

test "a gzip request body is decoded, its checksum verified" {
    const gpa = testing.allocator;
    const warp = @import("warp");
    const running = try Running.start(gpa, .{}, .of(echo));
    defer running.stop();
    var compressor: warp.Compressor = try .init(gpa, .{ .level = 6 });
    defer compressor.deinit();
    const frame: warp.Compressor.Frame = .{ .container = .gzip };
    var coded: [256]u8 = undefined;
    const n = try compressor.compress("a gzip request body", &coded, frame);
    var request: std.ArrayList(u8) = .empty;
    defer request.deinit(gpa);
    try request.print(gpa, "POST / HTTP/1.1\r\nHost: x\r\nContent-Encoding: gzip\r\nContent-Length: {d}\r\nConnection: close\r\n\r\n", .{n});
    try request.appendSlice(gpa, coded[0..n]);
    const got = try running.raw(gpa, request.items);
    defer gpa.free(got);
    try testing.expect(std.mem.endsWith(u8, got, "\r\n\r\na gzip request body"));
}

test "shutdown ends idle connections at once and lets an answer under way finish" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const running = try Running.start(gpa, .{}, .of(hello));
    var client: Client = .init(gpa, .{});
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    var response = try client.send(io, .{ .url = running.url(&buf, "/") });
    const body = try response.collect(gpa, io, .limited(1 << 20));
    gpa.free(body);
    response.deinit(io);
    // The client keeps its connection; the server ends it at shutdown.
    running.halt();
    defer running.free();
    try testing.expectEqual(@as(u32, 0), running.server.stats().open);
}

fn item(io: Io, request: *Request, response: *Response) anyerror!void {
    var buf: [128]u8 = undefined;
    const text = try std.mem.print(&buf, "item {s} of {s}", .{ request.param("id").?, request.param("list").? });
    try response.send(io, text);
}

test "a router serves its patterns, redirects, and answers 405 and 404" {
    const gpa = testing.allocator;
    const Router = @import("Router.zig");
    var router: Router = .init(gpa);
    defer router.deinit();
    try router.add("GET /lists/{list}/items/{id}", .of(item));
    try router.add("/files/", .of(hello));
    const running = try Running.start(gpa, .{}, router.handler());
    defer running.stop();
    const cases = [_]struct { []const u8, []const u8 }{
        .{ "GET /lists/a%20b/items/7 HTTP/1.1\r\nHost: x\r\n\r\n", "item 7 of a b" },
        .{ "HEAD /lists/a/items/7 HTTP/1.1\r\nHost: x\r\n\r\n", "Content-Length: 11\r\n" },
        .{ "DELETE /lists/a/items/7 HTTP/1.1\r\nHost: x\r\n\r\n", "HTTP/1.1 405 Method Not Allowed\r\n" },
        .{ "DELETE /lists/a/items/7 HTTP/1.1\r\nHost: x\r\n\r\n", "Allow: GET, HEAD\r\n" },
        .{ "GET /files HTTP/1.1\r\nHost: x\r\n\r\n", "Location: /files/\r\n" },
        .{ "GET /a/../files/x?q=1 HTTP/1.1\r\nHost: x\r\n\r\n", "Location: /files/x?q=1\r\n" },
        .{ "POST /files/../files HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n", "HTTP/1.1 308 Permanent Redirect\r\n" },
        .{ "GET /nothing HTTP/1.1\r\nHost: x\r\n\r\n", "HTTP/1.1 404 Not Found\r\n" },
        .{ "GET /files/%zz HTTP/1.1\r\nHost: x\r\n\r\n", "HTTP/1.1 400 Bad Request\r\n" },
    };
    for (cases) |case| {
        var request: std.ArrayList(u8) = .empty;
        defer request.deinit(gpa);
        try request.appendSlice(gpa, case[0][0 .. case[0].len - 2]);
        try request.appendSlice(gpa, "Connection: close\r\n\r\n");
        const got = try running.raw(gpa, request.items);
        defer gpa.free(got);
        testing.expect(std.mem.find(u8, got, case[1]) != null) catch |err| {
            std.debug.print("sent {s}\ngot {s}\n", .{ case[0], got });
            return err;
        };
    }
}

fn page(io: Io, request: *Request, response: *Response) anyerror!void {
    try response.header("Content-Type", if (std.mem.eql(u8, request.path, "/png")) "image/png" else "text/html; charset=utf-8");
    const lines: usize = if (std.mem.eql(u8, request.path, "/small")) 1 else if (std.mem.eql(u8, request.path, "/big")) 5000 else 60;
    const w = try response.writer(io);
    for (0..lines) |i| try w.print("<p>paragraph {d} of a page that compresses well</p>\n", .{i % 7});
    try response.end(io);
}

test "responses go compressed when the client accepts a coding, and as they are when not" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const running = try Running.start(gpa, .{ .compression = .{} }, .of(page));
    defer running.stop();
    var client: Client = .init(gpa, .{});
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    const Case = struct { path: []const u8, coding: ?[]const u8, chunked: bool };
    for ([_]Case{
        .{ .path = "/", .coding = "zstd", .chunked = false },
        .{ .path = "/big", .coding = "zstd", .chunked = true },
        .{ .path = "/small", .coding = null, .chunked = false },
        .{ .path = "/png", .coding = null, .chunked = false },
    }) |case| {
        var response = try client.send(io, .{ .url = running.url(&buf, case.path) });
        defer response.deinit(io);
        try testing.expectEqual(case.chunked, response.headers.get("transfer-encoding") != null);
        if (case.coding) |want| {
            try testing.expectEqualStrings(want, response.headers.get("content-encoding").?);
            try testing.expectEqualStrings("Accept-Encoding", response.headers.get("vary").?);
        } else try testing.expectEqual(null, response.headers.get("content-encoding"));
        const body = try response.collect(gpa, io, .limited(1 << 20));
        defer gpa.free(body);
        try testing.expect(std.mem.startsWith(u8, body, "<p>paragraph 0 of a page"));
    }
    // A client that asks for gzip only gets it.
    const got = try running.raw(gpa, "GET / HTTP/1.1\r\nHost: x\r\nAccept-Encoding: gzip;q=0.5, zstd;q=0\r\nConnection: close\r\n\r\n");
    defer gpa.free(got);
    try testing.expect(std.mem.find(u8, got, "Content-Encoding: gzip\r\n") != null);
    const plain = try running.raw(gpa, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    defer gpa.free(plain);
    try testing.expect(std.mem.find(u8, plain, "Content-Encoding") == null);
}

const cloak = @import("cloak");
const openssl = @import("../testing/openssl.zig");

fn whoami(io: Io, request: *Request, response: *Response) anyerror!void {
    try response.send(io, if (request.secure) "secure" else "plain");
}

test "TLS is terminated with cloak, a client certificate asked for and checked" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const pki = try openssl.Pki.make(gpa, io);
    defer pki.destroy();
    const cert = try pki.read(io, "server-ec.pem");
    defer gpa.free(cert);
    const key_pem = try pki.read(io, "server-ec.key");
    defer gpa.free(key_pem);
    const key = try cloak.PrivateKey.parse(gpa, key_pem, .{});
    defer key.deinit();
    var identity = try cloak.Identity.initPem(gpa, cert, key, .{});
    defer identity.deinit();
    const ca = try pki.read(io, "ca.pem");
    defer gpa.free(ca);
    var authorities: cloak.Trust = .init(gpa);
    defer authorities.deinit();
    try authorities.addPem(ca, .{});
    var clients = try authorities.freeze();
    defer clients.deinit();
    var servers_builder: cloak.Trust = .init(gpa);
    defer servers_builder.deinit();
    try servers_builder.addPem(cert, .{});
    var servers = try servers_builder.freeze();
    defer servers.deinit();
    const credentials = [_]cloak.tls.Credential{.{ .identity = identity }};
    const running = try Running.start(gpa, .{ .tls = .{ .credentials = &credentials, .client_certificate = .required, .client_trust = clients } }, .of(whoami));
    defer running.stop();

    const client_cert = try pki.read(io, "p256.pem");
    defer gpa.free(client_cert);
    const client_key_pem = try pki.read(io, "p256.key");
    defer gpa.free(client_key_pem);
    const client_key = try cloak.PrivateKey.parse(gpa, client_key_pem, .{});
    defer client_key.deinit();
    var auth = try cloak.ClientAuth.initPem(gpa, client_cert, client_key, .{});
    defer auth.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.mem.print(&url_buf, "https://127.0.0.1:{d}/", .{running.port});
    {
        var client: Client = .init(gpa, .{ .tls = .{ .trust = servers, .client_auth = auth } });
        defer client.deinit(io);
        for (0..2) |_| {
            var response = try client.send(io, .{ .url = url });
            defer response.deinit(io);
            const body = try response.collect(gpa, io, .limited(1 << 20));
            defer gpa.free(body);
            try testing.expectEqualStrings("secure", body);
        }
        try testing.expectEqual(@as(u64, 1), client.stats().connections_opened);
    }
    {
        // No certificate: refused.
        var client: Client = .init(gpa, .{ .tls = .{ .trust = servers }, .retries = .none });
        defer client.deinit(io);
        try testing.expectError(error.ClientCertificateRejected, client.send(io, .{ .url = url }));
    }
}

/// Connect to `running` over a fresh socket.
fn dialRaw(running: *const Running) !Io.net.Stream {
    const address = try Io.net.IpAddress.parse("127.0.0.1", running.port);
    return address.connect(test_io.io(), .{ .mode = .stream });
}

/// Read from `stream` until it ends, and how long that took.
fn readToEnd(stream: Io.net.Stream, gpa: std.mem.Allocator) !struct { []u8, Io.Duration } {
    const io = test_io.io();
    const started = Io.Clock.awake.now(io);
    var rbuf: [4096]u8 = undefined;
    var rd = stream.reader(io, &rbuf);
    const got = rd.interface.allocRemaining(gpa, .limited(1 << 20)) catch |err| switch (err) {
        error.ReadFailed => try gpa.dupe(u8, ""),
        else => |e| return e,
    };
    return .{ got, started.durationTo(Io.Clock.awake.now(io)) };
}

test "a head sent a byte at a time is cut off at the head timeout, whatever its pace" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const running = try Running.start(gpa, .{ .timeouts = .{ .head = .literal("200ms") } }, .of(hello));
    defer running.stop();
    const stream = try dialRaw(running);
    defer stream.close(io);
    const Trickle = struct {
        fn run(s: Io.net.Stream) Io.Cancelable!void {
            const tio = test_io.io();
            var wbuf: [64]u8 = undefined;
            var w = s.writer(tio, &wbuf);
            w.interface.writeAll("GET / HTTP/1.1\r\n") catch return;
            while (true) {
                w.interface.writeAll("X: a\r\n") catch return;
                w.interface.flush() catch return;
                try tio.sleep(.fromMilliseconds(20), .awake);
            }
        }
    };
    var trickle = io.concurrent(Trickle.run, .{stream}) catch return error.SkipZigTest;
    // glint-ignore: Z026 -- the trickle ends canceled; its result is not what the test checks
    defer trickle.cancel(io) catch {};
    const got, const took = try readToEnd(stream, gpa);
    defer gpa.free(got);
    try testing.expectEqualStrings("", got);
    try testing.expect(took.nanoseconds < 3 * std.time.ns_per_s);
}

test "a kept connection idle past the idle timeout is closed" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const running = try Running.start(gpa, .{ .timeouts = .{ .idle = .literal("150ms") } }, .of(hello));
    defer running.stop();
    const stream = try dialRaw(running);
    defer stream.close(io);
    var wbuf: [256]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    try w.interface.writeAll("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    try w.interface.flush();
    const got, const took = try readToEnd(stream, gpa);
    defer gpa.free(got);
    try testing.expect(std.mem.endsWith(u8, got, "hello"));
    try testing.expect(took.nanoseconds >= 100 * std.time.ns_per_ms);
    try testing.expect(took.nanoseconds < 3 * std.time.ns_per_s);
}

fn slow(io: Io, _: *Request, response: *Response) anyerror!void {
    try io.sleep(.fromMilliseconds(200), .awake);
    try response.send(io, "late but whole");
}

test "shutdown lets an answer under way finish, telling its client the connection closes" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const running = try Running.start(gpa, .{}, .of(slow));
    const stream = try dialRaw(running);
    defer stream.close(io);
    var wbuf: [256]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    try w.interface.writeAll("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    try w.interface.flush();
    // Once the handler runs, shut down.
    while (running.server.stats().requests == 0) try io.sleep(.fromMilliseconds(1), .awake);
    const Stop = struct {
        fn run(r: *Running) Io.Cancelable!void {
            r.halt();
        }
    };
    var stopping = io.concurrent(Stop.run, .{running}) catch return error.SkipZigTest;
    const got, _ = try readToEnd(stream, gpa);
    defer gpa.free(got);
    // glint-ignore: Z026 -- the shutdown's task returns nothing the test checks
    stopping.await(io) catch {};
    running.free();
    try testing.expect(std.mem.find(u8, got, "Connection: close\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, got, "late but whole"));
}

const server_ns = @import("../server.zig");

fn file(io: Io, _: *Request, response: *Response, captures: server_ns.Captures("GET /files/{name}/{rest...}")) anyerror!void {
    var buf: [128]u8 = undefined;
    try response.send(io, try std.mem.print(&buf, "{s}|{s}", .{ captures.name, captures.rest }));
}

test "comptime routes serve with typed captures, their escapes undone" {
    const gpa = testing.allocator;
    const routes = server_ns.Routes(.{.{ "GET /files/{name}/{rest...}", file }});
    const running = try Running.start(gpa, .{}, routes.handler());
    defer running.stop();
    const got = try running.raw(gpa, "GET /files/a%20b/c/d%2Fe HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    defer gpa.free(got);
    try testing.expect(std.mem.endsWith(u8, got, "a b|c/d/e"));
    const missing = try running.raw(gpa, "POST /files/a/b HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    defer gpa.free(missing);
    try testing.expect(std.mem.startsWith(u8, missing, "HTTP/1.1 405 "));
}

test "files are served with their validators, conditions and ranges" {
    const gpa = testing.allocator;
    const io = test_io.io();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var text: [1000]u8 = undefined;
    for (&text, 0..) |*c, i| c.* = 'a' + @as(u8, @intCast(i % 26));
    try tmp.dir.writeFile(io, .{ .sub_path = "a.txt", .data = &text });
    try tmp.dir.createDirPath(io, "sub");
    try tmp.dir.writeFile(io, .{ .sub_path = "sub/index.html", .data = "<h1>index</h1>" });
    var files: server_ns.Files = .init(tmp.dir, .{});
    const running = try Running.start(gpa, .{}, files.handler());
    defer running.stop();

    const whole = try running.raw(gpa, "GET /a.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    defer gpa.free(whole);
    try testing.expect(std.mem.find(u8, whole, "Content-Type: text/plain; charset=utf-8\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, whole, &text));
    const etag_at = std.mem.find(u8, whole, "ETag: ").? + "ETag: ".len;
    const etag = whole[etag_at .. etag_at + std.mem.findScalar(u8, whole[etag_at..], '\r').?];

    var request_buf: [512]u8 = undefined;
    const conditional = try running.raw(gpa, try std.mem.print(&request_buf, "GET /a.txt HTTP/1.1\r\nHost: x\r\nIf-None-Match: {s}\r\nConnection: close\r\n\r\n", .{etag}));
    defer gpa.free(conditional);
    try testing.expect(std.mem.startsWith(u8, conditional, "HTTP/1.1 304 "));
    try testing.expect(std.mem.endsWith(u8, conditional, "\r\n\r\n"));

    const failed = try running.raw(gpa, "GET /a.txt HTTP/1.1\r\nHost: x\r\nIf-Match: \"other\"\r\nConnection: close\r\n\r\n");
    defer gpa.free(failed);
    try testing.expect(std.mem.startsWith(u8, failed, "HTTP/1.1 412 "));

    const one = try running.raw(gpa, "GET /a.txt HTTP/1.1\r\nHost: x\r\nRange: bytes=0-9\r\nConnection: close\r\n\r\n");
    defer gpa.free(one);
    try testing.expect(std.mem.startsWith(u8, one, "HTTP/1.1 206 "));
    try testing.expect(std.mem.find(u8, one, "Content-Range: bytes 0-9/1000\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, one, "\r\n\r\nabcdefghij"));

    const two = try running.raw(gpa, "GET /a.txt HTTP/1.1\r\nHost: x\r\nRange: bytes=0-1, -2\r\nConnection: close\r\n\r\n");
    defer gpa.free(two);
    try testing.expect(std.mem.find(u8, two, "multipart/byteranges; boundary=") != null);
    try testing.expect(std.mem.find(u8, two, "Content-Range: bytes 998-999/1000\r\n\r\nkl\r\n") != null);

    const beyond = try running.raw(gpa, "GET /a.txt HTTP/1.1\r\nHost: x\r\nRange: bytes=5000-\r\nConnection: close\r\n\r\n");
    defer gpa.free(beyond);
    try testing.expect(std.mem.startsWith(u8, beyond, "HTTP/1.1 416 "));
    try testing.expect(std.mem.find(u8, beyond, "Content-Range: bytes */1000\r\n") != null);

    const dir = try running.raw(gpa, "GET /sub HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    defer gpa.free(dir);
    try testing.expect(std.mem.find(u8, dir, "Location: /sub/\r\n") != null);
    const index = try running.raw(gpa, "GET /sub/ HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    defer gpa.free(index);
    try testing.expect(std.mem.endsWith(u8, index, "<h1>index</h1>"));
    const named = try running.raw(gpa, "GET /sub/index.html HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    defer gpa.free(named);
    try testing.expect(std.mem.find(u8, named, "Location: /sub/\r\n") != null);
    const escape = try running.raw(gpa, "GET /sub/%2E%2E/a.txt HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    defer gpa.free(escape);
    try testing.expect(std.mem.startsWith(u8, escape, "HTTP/1.1 404 "));
    const posted = try running.raw(gpa, "POST /a.txt HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    defer gpa.free(posted);
    try testing.expect(std.mem.startsWith(u8, posted, "HTTP/1.1 405 "));
}

fn upgrading(io: Io, _: *Request, response: *Response) anyerror!void {
    response.status = .switching_protocols;
    try response.header("Connection", "Upgrade");
    try response.header("Upgrade", "echo");
    const taken = try response.hijack(io);
    // Echo one line back.
    const line = try taken.reader.takeDelimiterInclusive('\n');
    try taken.writer.writeAll(line);
    try taken.flush();
}

test "a handler takes the connection over after a 101, and speaks its own protocol" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const running = try Running.start(gpa, .{}, .of(upgrading));
    defer running.stop();
    var client: Client = .init(gpa, .{});
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    var response = try client.send(io, .{ .url = running.url(&buf, "/"), .headers = &.{ .{ .name = "Connection", .value = "Upgrade" }, .{ .name = "Upgrade", .value = "echo" } } });
    defer response.deinit(io);
    try testing.expectEqual(std.http.Status.switching_protocols, response.status);
    var upgraded = try response.upgrade(io);
    defer upgraded.close(io);
    try upgraded.writer(io).writeAll("ping\n");
    try upgraded.flush(io);
    const echoed = try upgraded.reader(io).takeDelimiterInclusive('\n');
    try testing.expectEqualStrings("ping\n", echoed);
}

fn trailing(io: Io, request: *Request, response: *Response) anyerror!void {
    const body = try request.collect(testing.allocator, io, .limited(1 << 20));
    defer testing.allocator.free(body);
    const t = request.trailers().?;
    const w = try response.writer(io);
    try w.writeAll(body);
    try w.splatByteAll('.', 5000);
    try response.trailer("X-Checksum", t.get("x-checksum").?);
    try response.end(io);
}

test "trailers are read from a chunked request and written after a chunked response" {
    const gpa = testing.allocator;
    const running = try Running.start(gpa, .{}, .of(trailing));
    defer running.stop();
    const got = try running.raw(gpa, "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n4\r\nbody\r\n0\r\nX-Checksum: 42\r\n\r\n");
    defer gpa.free(got);
    try testing.expect(std.mem.find(u8, got, "Transfer-Encoding: chunked\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, got, "0\r\nX-Checksum: 42\r\n\r\n"));
}

const Seen = struct {
    answered: std.atomic.Value(u32) = .init(0),
    refused: std.atomic.Value(u32) = .init(0),

    fn event(context: ?*anyopaque, e: Server.Observer.Event) void {
        const seen: *Seen = @ptrCast(@alignCast(context.?)); // safe: the test passes its Seen
        switch (e) {
            .answered => |a| if (a.status == 200) {
                _ = seen.answered.fetchAdd(1, .monotonic);
            },
            .refused => _ = seen.refused.fetchAdd(1, .monotonic),
            else => {},
        }
    }
};

test "the observer is told each answer and each refusal" {
    const gpa = testing.allocator;
    var seen: Seen = .{};
    const running = try Running.start(gpa, .{ .observer = .{ .context = &seen, .eventFn = Seen.event } }, .of(hello));
    defer running.stop();
    const ok = try running.raw(gpa, "GET / HTTP/1.1\r\nHost: x\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    defer gpa.free(ok);
    const bad = try running.raw(gpa, "GET / HTTP/1.1\r\n\r\n");
    defer gpa.free(bad);
    try testing.expectEqual(@as(u32, 2), seen.answered.load(.monotonic));
    try testing.expectEqual(@as(u32, 1), seen.refused.load(.monotonic));
}

test "past max_connections a connection waits for one to end" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const running = try Running.start(gpa, .{ .max_connections = 1 }, .of(hello));
    defer running.stop();
    const first = try dialRaw(running);
    var wbuf: [256]u8 = undefined;
    var w = first.writer(io, &wbuf);
    try w.interface.writeAll("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    try w.interface.flush();
    var rbuf: [512]u8 = undefined;
    var r = first.reader(io, &rbuf);
    _ = try r.interface.peekDelimiterInclusive('o');
    // The first is open and kept: a second is accepted by the system only.
    try testing.expectEqual(@as(u32, 1), running.server.stats().open);
    const Second = struct {
        fn run(rn: *Running, out: *[]u8) Io.Cancelable!void {
            out.* = rn.raw(testing.allocator, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n") catch &.{};
        }
    };
    var second_out: []u8 = &.{};
    var second = io.concurrent(Second.run, .{ running, &second_out }) catch return error.SkipZigTest;
    try io.sleep(.fromMilliseconds(100), .awake);
    try testing.expectEqual(@as(u64, 1), running.server.stats().accepted);
    first.close(io);
    // glint-ignore: Z026 -- the task returns nothing the test checks
    second.await(io) catch {};
    defer gpa.free(second_out);
    try testing.expect(std.mem.endsWith(u8, second_out, "hello"));
    try testing.expectEqual(@as(u64, 2), running.server.stats().accepted);
}

/// `curl` with `args` against the running server; its output, or null
/// without curl, which only a hosted runner must have.
fn curl(gpa: std.mem.Allocator, args: []const []const u8) !?[]u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(gpa);
    try argv.appendSlice(gpa, &.{ "curl", "-sS", "--max-time", "20" });
    try argv.appendSlice(gpa, args);
    const result = std.process.run(gpa, test_io.io(), .{ .argv = argv.items }) catch return null;
    defer gpa.free(result.stderr);
    if (result.term != .exited or result.term.exited != 0) {
        std.debug.print("curl failed: {s}\n", .{result.stderr});
        gpa.free(result.stdout);
        return error.CurlFailed;
    }
    return result.stdout;
}

test "curl speaks HTTP/2 to the server, by prior knowledge and over TLS" {
    const gpa = testing.allocator;
    const running = try Running.start(gpa, .{ .h2c = .alongside_http1 }, .of(echoVersion));
    defer running.stop();
    var url_buf: [64]u8 = undefined;
    const out = try curl(gpa, &.{ "--http2-prior-knowledge", "-d", "hello h2", running.url(&url_buf, "/x") }) orelse return error.SkipZigTest;
    defer gpa.free(out);
    try testing.expectEqualStrings("h2 POST /x hello h2", out);
    const many = try curl(gpa, &.{ "--http2-prior-knowledge", running.url(&url_buf, "/a"), running.url(&url_buf, "/b") }) orelse return error.SkipZigTest;
    defer gpa.free(many);
    try testing.expect(std.mem.find(u8, many, "h2 GET /") != null);
    const h1 = try curl(gpa, &.{running.url(&url_buf, "/plain")}) orelse return error.SkipZigTest;
    defer gpa.free(h1);
    try testing.expectEqualStrings("http1_1 GET /plain ", h1);
}

fn echoVersion(io: Io, request: *Request, response: *Response) anyerror!void {
    const body = try request.collect(testing.allocator, io, .limited(1 << 20));
    defer testing.allocator.free(body);
    var buf: [256]u8 = undefined;
    try response.send(io, try std.mem.print(&buf, "{t} {s} {s} {s}", .{ request.version, request.method.name, request.path, body }));
}
