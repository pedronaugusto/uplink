//! The reverse proxy between uplink's own client and servers, over
//! loopback: what goes upstream, what comes back, bytes as they came both
//! ways, and the statuses a failing upstream is answered with.

const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const test_io = @import("testing/io.zig");
const ReverseProxy = @import("ReverseProxy.zig");
const Client = @import("client/Client.zig");
const CookieJar = @import("client/CookieJar.zig");
const Server = @import("server/Server.zig");
const Request = @import("server/Request.zig");
const Response = @import("server/Response.zig");

const Running = struct {
    server: Server,
    listener: Io.net.Server,
    task: Io.Future(Server.ServeError!void),
    port: u16,

    fn start(gpa: std.mem.Allocator, options: Server.Options, handler: *const Server.Handler) !*Running {
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
        const io = test_io.io();
        r.server.shutdown(io);
        // glint-ignore: Z026 -- serve ends with the shutdown; its result is not what the test checks
        r.task.await(io) catch {};
        r.server.deinit(io);
        r.listener.deinit(io);
        testing.allocator.destroy(r);
    }

    fn url(r: *const Running, buffer: []u8, path: []const u8) []const u8 {
        return std.mem.print(buffer, "http://127.0.0.1:{d}{s}", .{ r.port, path }) catch unreachable; // unreachable: callers pass room for a URL
    }

    /// Send `bytes` and read until the server ends the connection.
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

/// An upstream, a proxy in front of it, and the client the proxy sends
/// through.
const Fixture = struct {
    upstream: *Running,
    front: *Running,
    client: Client,
    proxy: ReverseProxy,
    upstream_url: [64]u8,

    fn start(f: *Fixture, handler: *const Server.Handler, path: []const u8, options: ReverseProxy.Options) !void {
        const gpa = testing.allocator;
        f.upstream = try Running.start(gpa, .{}, handler);
        errdefer f.upstream.stop();
        f.client = .init(gpa, .{});
        errdefer f.client.deinit(test_io.io());
        var with = options;
        with.upstream = f.upstream.url(&f.upstream_url, path);
        f.proxy = try .init(gpa, &f.client, with);
        f.front = try Running.start(gpa, .{}, &f.proxy.handler);
    }

    fn stop(f: *Fixture) void {
        f.front.stop();
        f.client.deinit(test_io.io());
        f.upstream.stop();
    }
};

/// Answer with what came: the request line's method and target, every
/// field, a blank line, the body.
fn describe(io: Io, request: *Request, response: *Response) anyerror!void {
    const body = try request.collect(testing.allocator, io, .limited(1 << 20));
    defer testing.allocator.free(body);
    const w = try response.writer(io);
    try w.print("{s} {s}\n", .{ request.method.name, request.target });
    for (request.headers.fields) |f| try w.print("{s}: {s}\n", .{ f.name, f.value });
    try w.print("\n{s}", .{body});
    try response.end(io);
}

fn sent(gpa: std.mem.Allocator, client: *Client, io: Io, request: @import("client/Request.zig")) ![]u8 {
    var response = try client.send(io, request);
    defer response.deinit(io);
    return response.collect(gpa, io, .limited(1 << 20));
}

test "a request goes upstream under the upstream's path, its connection's fields left behind and Forwarded added" {
    const gpa = testing.allocator;
    const io = test_io.io();
    var f: Fixture = undefined;
    try f.start(.of(describe), "/base/?key=1", .{ .upstream = undefined });
    defer f.stop();
    var client: Client = .init(gpa, .{ .decompress = false });
    defer client.deinit(io);
    var buf: [96]u8 = undefined;
    const seen = try sent(gpa, &client, io, .{
        .method = .POST,
        .url = f.front.url(&buf, "/items/7?page=2"),
        .headers = &.{
            .{ .name = "Connection", .value = "X-Hop" },
            .{ .name = "X-Hop", .value = "dropped" },
            .{ .name = "Keep-Alive", .value = "timeout=5" },
            .{ .name = "TE", .value = "trailers, deflate" },
            .{ .name = "Proxy-Authorization", .value = "Basic Zm9vOmJhcg==" },
            .{ .name = "Forwarded", .value = "for=192.0.2.60;proto=https" },
            .{ .name = "X-Kept", .value = "kept" },
        },
        .body = .{ .bytes = "the body" },
    });
    defer gpa.free(seen);
    try testing.expect(std.mem.startsWith(u8, seen, "POST /base/items/7?key=1&page=2\n"));
    var host_buf: [32]u8 = undefined;
    const host = try std.mem.print(&host_buf, "Host: 127.0.0.1:{d}\n", .{f.upstream.port});
    try testing.expect(std.mem.find(u8, seen, host) != null);
    for ([_][]const u8{ "X-Hop", "Keep-Alive", "Proxy-Authorization", "deflate" }) |gone| {
        try testing.expect(std.mem.find(u8, seen, gone) == null);
    }
    try testing.expect(std.mem.find(u8, seen, "TE: trailers\n") != null);
    try testing.expect(std.mem.find(u8, seen, "X-Kept: kept\n") != null);
    try testing.expect(std.mem.find(u8, seen, "Accept-Encoding: identity\n") != null);
    try testing.expect(std.mem.find(u8, seen, "Content-Length: 8\n") != null);
    try testing.expect(std.mem.find(u8, seen, "Forwarded: for=192.0.2.60;proto=https\n") != null);
    var forwarded_buf: [96]u8 = undefined;
    const forwarded = try std.mem.print(&forwarded_buf, ";host=\"127.0.0.1:{d}\";proto=http\n", .{f.front.port});
    try testing.expect(std.mem.find(u8, seen, "Forwarded: for=\"127.0.0.1:") != null);
    try testing.expect(std.mem.find(u8, seen, forwarded) != null);
    try testing.expect(std.mem.endsWith(u8, seen, "\n\nthe body"));
}

/// A chunked body in two flushed pieces, with a trailer.
fn chunked(io: Io, _: *Request, response: *Response) anyerror!void {
    try response.header("Connection", "X-Upstream-Hop");
    try response.header("X-Upstream-Hop", "dropped");
    try response.header("Trailer", "X-Sum");
    const w = try response.writer(io);
    try w.writeAll("first,");
    try response.flush(io);
    try w.writeAll("second");
    try response.trailer("X-Sum", "11");
    try response.end(io);
}

test "a streamed answer comes back streamed, with its trailer and without its connection's fields" {
    const gpa = testing.allocator;
    var f: Fixture = undefined;
    try f.start(.of(chunked), "", .{ .upstream = undefined });
    defer f.stop();
    const got = try f.front.raw(gpa, "GET / HTTP/1.1\r\nHost: x\r\nTE: trailers\r\nConnection: close\r\n\r\n");
    defer gpa.free(got);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.find(u8, got, "Transfer-Encoding: chunked\r\n") != null);
    try testing.expect(std.mem.find(u8, got, "X-Upstream-Hop") == null);
    try testing.expect(std.mem.endsWith(u8, got, "\r\n0\r\nX-Sum: 11\r\n\r\n"));
    try testing.expect(std.mem.find(u8, got, "first,") != null);
    try testing.expect(std.mem.find(u8, got, "second") != null);
}

fn hello(io: Io, _: *Request, response: *Response) anyerror!void {
    try response.send(io, "hello");
}

test "a HEAD comes back with the length a GET would have" {
    const gpa = testing.allocator;
    var f: Fixture = undefined;
    try f.start(.of(hello), "", .{ .upstream = undefined });
    defer f.stop();
    const got = try f.front.raw(gpa, "HEAD / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    defer gpa.free(got);
    try testing.expect(std.mem.startsWith(u8, got, "HTTP/1.1 200 OK\r\n"));
    try testing.expect(std.mem.find(u8, got, "Content-Length: 5\r\n") != null);
    try testing.expect(std.mem.endsWith(u8, got, "\r\n\r\n"));
}

/// Answer with the body's bytes as they came, under the coding they came
/// in, and say what `Accept-Encoding` asked for.
fn coded(io: Io, request: *Request, response: *Response) anyerror!void {
    const body = try request.collect(testing.allocator, io, .limited(1 << 20));
    defer testing.allocator.free(body);
    try response.header("X-Asked", request.headers.get("accept-encoding") orelse "nothing");
    if (request.headers.get("content-encoding")) |c| try response.header("Content-Encoding", c);
    try response.send(io, body);
}

test "coded bodies pass as they came, both ways, whatever either end decodes" {
    const gpa = testing.allocator;
    const io = test_io.io();
    // The upstream and the proxy's own server both decode request bodies
    // by default; neither may touch these bytes.
    const gzip = "\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03\xcb\x48\xcd\xc9\xc9\x07\x00\x86\xa6\x10\x36\x05\x00\x00\x00";
    var f: Fixture = undefined;
    const upstream = try Running.start(gpa, .{ .decompress = false }, .of(coded));
    f.upstream = upstream;
    f.client = .init(gpa, .{});
    f.proxy = try .init(gpa, &f.client, .{ .upstream = upstream.url(&f.upstream_url, "") });
    f.front = try Running.start(gpa, .{}, &f.proxy.handler);
    defer f.stop();
    var client: Client = .init(gpa, .{});
    defer client.deinit(io);
    var url_buf: [64]u8 = undefined;
    var response = try client.send(io, .{
        .method = .PUT,
        .url = f.front.url(&url_buf, "/"),
        .headers = &.{ .{ .name = "Content-Encoding", .value = "gzip" }, .{ .name = "Accept-Encoding", .value = "gzip" } },
        .body = .{ .bytes = gzip },
    });
    defer response.deinit(io);
    try testing.expectEqualStrings("gzip", response.headers.get("x-asked").?);
    try testing.expectEqualStrings("gzip", response.headers.get("content-encoding").?);
    const back = try response.collect(gpa, io, .limited(1 << 10));
    defer gpa.free(back);
    try testing.expectEqualSlices(u8, gzip, back);
}

fn redirect(io: Io, _: *Request, response: *Response) anyerror!void {
    response.status = .found;
    try response.header("Location", "/elsewhere");
    try response.send(io, "");
}

test "a redirect comes back to the client, not followed" {
    const gpa = testing.allocator;
    const io = test_io.io();
    var f: Fixture = undefined;
    try f.start(.of(redirect), "", .{ .upstream = undefined });
    defer f.stop();
    var client: Client = .init(gpa, .{ .redirects = .none });
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    var response = try client.send(io, .{ .url = f.front.url(&buf, "/") });
    defer response.deinit(io);
    try testing.expectEqual(std.http.Status.found, response.status);
    try testing.expectEqualStrings("/elsewhere", response.headers.get("location").?);
}

fn slow(io: Io, _: *Request, response: *Response) anyerror!void {
    try io.sleep(.fromMilliseconds(500), .awake);
    try response.send(io, "late");
}

test "an upstream that cannot be reached is a 502, and one out of time a 504" {
    const gpa = testing.allocator;
    const io = test_io.io();
    var f: Fixture = undefined;
    try f.start(.of(slow), "", .{ .upstream = undefined, .timeout = .{ .duration = .{ .raw = .fromMilliseconds(50), .clock = .awake } } });
    defer f.stop();
    var client: Client = .init(gpa, .{});
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    var late = try client.send(io, .{ .url = f.front.url(&buf, "/") });
    defer late.deinit(io);
    try testing.expectEqual(std.http.Status.gateway_timeout, late.status);

    // A port nothing listens on: the one a closed listener had.
    var closed = try (try Io.net.IpAddress.parse("127.0.0.1", 0)).listen(io, .{ .reuse_address = true });
    const port = closed.socket.address.getPort();
    closed.deinit(io);
    var upstream_buf: [64]u8 = undefined;
    var refused: ReverseProxy = try .init(gpa, &f.client, .{ .upstream = try std.mem.print(&upstream_buf, "http://127.0.0.1:{d}", .{port}) });
    const front = try Running.start(gpa, .{}, &refused.handler);
    defer front.stop();
    var gone = try client.send(io, .{ .url = front.url(&buf, "/") });
    defer gone.deinit(io);
    try testing.expectEqual(std.http.Status.bad_gateway, gone.status);
}

test "a proxy refuses a client that would add to what it forwards" {
    const gpa = testing.allocator;
    const io = test_io.io();
    var jar: CookieJar = .init(gpa, .{});
    defer jar.deinit(io);
    var with_jar: Client = .init(gpa, .{ .cookies = &jar });
    defer with_jar.deinit(io);
    try testing.expectError(error.ClientKeepsCookies, ReverseProxy.init(gpa, &with_jar, .{ .upstream = "http://127.0.0.1/" }));
    var named: Client = .init(gpa, .{ .user_agent = "me" });
    defer named.deinit(io);
    try testing.expectError(error.ClientNamesItself, ReverseProxy.init(gpa, &named, .{ .upstream = "http://127.0.0.1/" }));
    var plain: Client = .init(gpa, .{});
    defer plain.deinit(io);
    try testing.expectError(error.InvalidUpstream, ReverseProxy.init(gpa, &plain, .{ .upstream = "ftp://127.0.0.1/" }));
}

/// Sends every request to `/v2` of the upstream, and names the proxy.
const Versioned = struct {
    rewrite: ReverseProxy.Rewrite = .{ .rewriteFn = rewriteFn },
    upstream_port: u16,

    fn rewriteFn(r: *const ReverseProxy.Rewrite, _: Io, request: *const Request, out: *ReverseProxy.Outbound) anyerror!void {
        const v: *const Versioned = @alignCast(@fieldParentPtr("rewrite", r));
        out.url = try out.arena.print("http://127.0.0.1:{d}/v2{s}", .{ v.upstream_port, request.path });
        try out.headers.append(out.arena, .{ .name = "X-Via", .value = "versioned" });
    }
};

test "a rewrite decides where a request goes and what it carries" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const upstream = try Running.start(gpa, .{}, .of(describe));
    defer upstream.stop();
    var versioned: Versioned = .{ .upstream_port = upstream.port };
    var through: Client = .init(gpa, .{});
    defer through.deinit(io);
    var proxy: ReverseProxy = try .init(gpa, &through, .{ .upstream = "http://unused.invalid/", .rewrite = &versioned.rewrite });
    const front = try Running.start(gpa, .{}, &proxy.handler);
    defer front.stop();
    var client: Client = .init(gpa, .{});
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    const seen = try sent(gpa, &client, io, .{ .url = front.url(&buf, "/thing") });
    defer gpa.free(seen);
    try testing.expect(std.mem.startsWith(u8, seen, "GET /v2/thing\n"));
    try testing.expect(std.mem.find(u8, seen, "X-Via: versioned\n") != null);
}

test "a proxy whose task is canceled while it reaches the upstream ends with no answer, not a 502" {
    const gpa = testing.allocator;
    const base = test_io.io();
    const shakedown = @import("shakedown");
    const upstream = try Running.start(gpa, .{}, .of(hello));
    defer upstream.stop();
    var through: Client = .init(gpa, .{});
    defer through.deinit(base);
    var upstream_url: [64]u8 = undefined;
    var proxy: ReverseProxy = try .init(gpa, &through, .{ .upstream = upstream.url(&upstream_url, "") });
    // The first connect the front's task makes is the proxy's, upstream.
    const plan = [_]shakedown.IoPlan.Entry{.{ .at = .{ .nth = .{ .call = .netConnectIp, .n = 1 } }, .fault = .cancel }};
    const fio = try shakedown.FaultIo.init(gpa, base, .{ .plan = &plan });
    defer fio.deinit();
    const r = try gpa.create(Running);
    defer gpa.destroy(r);
    r.listener = try (try Io.net.IpAddress.parse("127.0.0.1", 0)).listen(base, .{ .reuse_address = true });
    defer r.listener.deinit(base);
    r.port = r.listener.socket.address.getPort();
    r.server = .init(gpa, .{}, &proxy.handler);
    defer r.server.deinit(base);
    r.task = base.concurrent(Server.serve, .{ &r.server, fio.io(), &r.listener }) catch return error.SkipZigTest;
    defer {
        r.server.shutdown(base);
        // glint-ignore: Z026 -- serve ends with the shutdown; its result is not what the test checks
        r.task.await(base) catch {};
    }
    const canceled = try r.raw(gpa, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    defer gpa.free(canceled);
    try testing.expectEqualStrings("", canceled);
    // The next request goes through.
    const again = try r.raw(gpa, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n");
    defer gpa.free(again);
    try testing.expect(std.mem.endsWith(u8, again, "\r\n\r\nhello"));
}

/// Switch to `echo` when asked, and echo lines until the client leaves;
/// switch to `other` when asked for `wrong`.
fn upgrading(io: Io, request: *Request, response: *Response) anyerror!void {
    const asked = request.headers.get("upgrade") orelse return response.send(io, "not asked");
    response.status = .switching_protocols;
    try response.header("Connection", "Upgrade");
    try response.header("Upgrade", if (std.mem.eql(u8, asked, "wrong")) "other" else asked);
    const taken = try response.hijack(io);
    while (true) {
        const line = taken.reader.takeDelimiterInclusive('\n') catch return;
        try taken.writer.writeAll(line);
        try taken.flush();
    }
}

test "an upgrade passes through: the upstream's 101, then each side's bytes to the other" {
    const gpa = testing.allocator;
    const io = test_io.io();
    var f: Fixture = undefined;
    try f.start(.of(upgrading), "", .{ .upstream = undefined });
    defer f.stop();
    var client: Client = .init(gpa, .{});
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    var response = try client.send(io, .{ .url = f.front.url(&buf, "/"), .headers = &.{ .{ .name = "Connection", .value = "Upgrade" }, .{ .name = "Upgrade", .value = "echo" } } });
    defer response.deinit(io);
    try testing.expectEqual(std.http.Status.switching_protocols, response.status);
    try testing.expectEqualStrings("echo", response.headers.get("upgrade").?);
    var upgraded = try response.upgrade(io);
    defer upgraded.close(io);
    for ([_][]const u8{ "ping\n", "and again\n" }) |line| {
        try upgraded.writer(io).writeAll(line);
        try upgraded.flush(io);
        const echoed = try upgraded.reader(io).takeDelimiterInclusive('\n');
        try testing.expectEqualStrings(line, echoed);
    }

    // An upstream that switches to a protocol not asked for is a 502.
    var wrong = try client.send(io, .{ .url = f.front.url(&buf, "/"), .headers = &.{ .{ .name = "Connection", .value = "Upgrade" }, .{ .name = "Upgrade", .value = "wrong" } } });
    defer wrong.deinit(io);
    try testing.expectEqual(std.http.Status.bad_gateway, wrong.status);
}
