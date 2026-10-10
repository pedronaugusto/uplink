//! The client's policy against a server of the tests' own, over loopback:
//! redirects, retries, answers to challenges, cookies, per-route limits,
//! draining, deadlines and low speed, `Expect: 100-continue`, upgrades,
//! trailers, the observer and the prepare hook, proxies from the
//! environment, resolvers and Unix sockets.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const testing = std.testing;
const test_io = @import("../testing/io.zig");
const shakedown = @import("shakedown");
const Client = @import("Client.zig");
const CookieJar = @import("CookieJar.zig");
const Credentials = @import("Credentials.zig");
const Prepare = @import("Prepare.zig");
const Request = @import("Request.zig");
const policy = @import("policy.zig");
const Method = @import("../wire/Method.zig");
const Server = @import("../testing/Server.zig");
const TestProxy = @import("../testing/Proxy.zig");
const Diagnostics = @import("../transport/Diagnostics.zig");
const Observer = @import("../transport/Observer.zig");
const Proxy = @import("../transport/Proxy.zig");
const Resolver = @import("../net/Resolver.zig");
const sse = @import("../wire/sse.zig");
const url_mod = @import("../wire/url.zig");

/// A buffer an answer is printed into, one per server task.
threadlocal var answer_buf: [8 << 10]u8 = undefined;

fn print(comptime format: []const u8, args: anytype) []const u8 {
    return std.mem.print(&answer_buf, format, args) catch unreachable; // unreachable: the tests' answers fit
}

fn ok(body: []const u8) Server.Answer {
    return .{ .bytes = print("HTTP/1.1 200 OK\r\nContent-Length: {d}\r\n\r\n{s}", .{ body.len, body }) };
}

fn redirect(status: u16, location: []const u8) Server.Answer {
    return .{ .bytes = print("HTTP/1.1 {d} Moved\r\nLocation: {s}\r\nContent-Length: 0\r\n\r\n", .{ status, location }) };
}

/// The method, body and content type a request arrived with.
fn echoOf(request: Server.Request) Server.Answer {
    const method = request.head[0..std.mem.findScalar(u8, request.head, ' ').?];
    var line_buf: [256]u8 = undefined;
    const line = std.mem.print(&line_buf, "{s}|{s}|{s}|{s}|{s}", .{
        method,
        request.body,
        Server.headerValue(request.head, "content-type") orelse "-",
        Server.headerValue(request.head, "authorization") orelse "-",
        Server.headerValue(request.head, "cookie") orelse "-",
    }) catch unreachable; // unreachable: the tests' requests fit
    return ok(line);
}

fn get(client: *Client, io: Io, request: Request) ![]u8 {
    var response = try client.send(io, request);
    defer response.deinit(io);
    return response.collect(testing.allocator, io, .limited(1 << 20));
}

fn redirecting(_: ?*anyopaque, request: Server.Request) Server.Answer {
    const path = Server.pathOf(request.head);
    if (std.mem.eql(u8, path, "/a")) return redirect(302, "/b");
    if (std.mem.eql(u8, path, "/b")) return ok("landed");
    if (std.mem.eql(u8, path, "/moved")) return redirect(301, "/echo");
    if (std.mem.eql(u8, path, "/other")) return redirect(303, "/echo");
    if (std.mem.eql(u8, path, "/keep")) return redirect(307, "/echo");
    if (std.mem.eql(u8, path, "/loop")) return redirect(302, "/loop");
    if (std.mem.eql(u8, path, "/dir/sub/rel")) return redirect(302, "../up/./x?q=1");
    if (std.mem.eql(u8, path, "/nowhere")) return .{ .bytes = "HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\r\n" };
    if (std.mem.eql(u8, path, "/gopher")) return redirect(302, "gopher://h/");
    return echoOf(request);
}

test "redirects are followed as RFC 9110 has them, the method and body changed or kept" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const server = try Server.start(gpa, io, .{ .answer = redirecting });
    defer server.stop();
    var client: Client = .init(gpa, .{});
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    {
        var d: Diagnostics = .{};
        var response = try client.send(io, .{ .url = server.url(&buf, "/a"), .diagnostics = &d });
        defer response.deinit(io);
        const body = try response.collect(gpa, io, .unlimited);
        defer gpa.free(body);
        try testing.expectEqualStrings("landed", body);
        try testing.expect(std.mem.endsWith(u8, response.url, "/b"));
        try testing.expectEqual(@as(u8, 1), d.redirects);
    }
    const typed: []const std.http.Header = &.{.{ .name = "Content-Type", .value = "text/plain" }};
    for ([_]struct { []const u8, Method, []const u8 }{
        .{ "/moved", .POST, "GET||-|-|-" },
        .{ "/other", .PUT, "GET||-|-|-" },
        .{ "/keep", .POST, "POST|x|text/plain|-|-" },
    }) |case| {
        const body = try get(&client, io, .{ .method = case[1], .url = server.url(&buf, case[0]), .headers = typed, .body = .{ .bytes = "x" } });
        defer gpa.free(body);
        try testing.expectEqualStrings(case[2], body);
    }
    {
        var source: Io.Reader = .fixed("once");
        try testing.expectError(error.BodyNotReplayable, client.send(io, .{ .method = .POST, .url = server.url(&buf, "/keep"), .body = .{ .reader = .{ .reader = &source, .length = 4 } } }));
    }
    try testing.expectError(error.TooManyRedirects, client.send(io, .{ .url = server.url(&buf, "/loop") }));
    try testing.expectError(error.TooManyRedirects, client.send(io, .{ .url = server.url(&buf, "/loop"), .redirects = .{ .follow = .{ .max = 2 } } }));
    try testing.expectError(error.InvalidRedirect, client.send(io, .{ .url = server.url(&buf, "/gopher") }));
    {
        var response = try client.send(io, .{ .url = server.url(&buf, "/loop"), .redirects = .none });
        defer response.deinit(io);
        try testing.expectEqual(std.http.Status.found, response.status);
    }
    {
        var response = try client.send(io, .{ .url = server.url(&buf, "/nowhere") });
        defer response.deinit(io);
        try testing.expectEqual(std.http.Status.found, response.status);
    }
    {
        var response = try client.send(io, .{ .url = server.url(&buf, "/dir/sub/rel") });
        defer response.deinit(io);
        try testing.expect(std.mem.endsWith(u8, response.url, "/dir/up/x?q=1"));
    }
    try testing.expectEqual(@as(u32, 0), client.stats().in_use);
}

/// Redirects every request to the server whose port the context holds.
fn elsewhere(context: ?*anyopaque, request: Server.Request) Server.Answer {
    _ = request;
    const port: *const u16 = @ptrCast(@alignCast(context.?)); // safe: the test passes the other server's port
    var location_buf: [64]u8 = undefined;
    return redirect(302, std.mem.print(&location_buf, "http://127.0.0.1:{d}/echo", .{port.*}) catch unreachable); // unreachable: a URL of a port fits
}

test "a redirect to another origin drops the caller's credentials and cookies" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const target = try Server.start(gpa, io, .{ .answer = redirecting });
    defer target.stop();
    const first = try Server.start(gpa, io, .{ .context = &target.port, .answer = elsewhere });
    defer first.stop();
    var client: Client = .init(gpa, .{});
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    const body = try get(&client, io, .{
        .url = first.url(&buf, "/"),
        .headers = &.{ .{ .name = "Authorization", .value = "Basic c2VjcmV0" }, .{ .name = "Cookie", .value = "a=1" } },
    });
    defer gpa.free(body);
    try testing.expectEqualStrings("GET||-|-|-", body);
    try testing.expectError(error.TooManyRedirects, client.send(io, .{ .url = first.url(&buf, "/"), .redirects = .{ .follow = .{ .max = 0 } } }));
    var response = try client.send(io, .{ .url = first.url(&buf, "/"), .redirects = .{ .follow = .{ .same_origin_only = true } } });
    defer response.deinit(io);
    try testing.expectEqual(std.http.Status.found, response.status);
}

test "a redirect off the origin keeps the proxy's answer, and the jar's cookies for where it leads" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const target = try Server.start(gpa, io, .{ .answer = redirecting });
    defer target.stop();
    const first = try Server.start(gpa, io, .{ .context = &target.port, .answer = elsewhere });
    defer first.stop();
    const proxy = try TestProxy.start(gpa, io, .{ .credential = "u:p" });
    defer proxy.stop();
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    var jar: CookieJar = .init(gpa, .{});
    defer jar.deinit(io);
    var target_url: [64]u8 = undefined;
    try jar.store(io, try url_mod.parse(target.url(&target_url, "/")), "there=1");
    var proxy_url: [64]u8 = undefined;
    var client: Client = .init(gpa, .{
        .proxy = .{ .fixed = try Proxy.parse(arena.allocator(), try std.mem.print(&proxy_url, "http://u:p@127.0.0.1:{d}", .{proxy.port}), .lowercase) },
        .cookies = &jar,
    });
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    const body = try get(&client, io, .{ .url = first.url(&buf, "/"), .headers = &.{.{ .name = "Cookie", .value = "mine=1" }} });
    defer gpa.free(body);
    try testing.expectEqualStrings("GET||-|-|there=1", body);
    const log = try proxy.lines(gpa);
    defer gpa.free(log);
    // A challenge, the answer, and the redirected request answered at once.
    try testing.expectEqual(@as(usize, 3), std.mem.count(u8, log, "\n"));
    try testing.expect(std.mem.endsWith(u8, log, "/echo HTTP/1.1 [Basic ]\n"));
}

/// 503 to each connection's first request, then the request echoed.
fn unavailableFirst(context: ?*anyopaque, request: Server.Request) Server.Answer {
    const retry_after: *const []const u8 = @ptrCast(@alignCast(context.?)); // safe: the test passes its Retry-After
    if (request.index == 0) return .{ .bytes = print("HTTP/1.1 503 Busy\r\nRetry-After: {s}\r\nContent-Length: 0\r\n\r\n", .{retry_after.*}) };
    return echoOf(request);
}

test "statuses the retries cover are tried again after Retry-After or a backoff, within the deadline" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const fast: Client.Options = .{ .retries = .{ .statuses = policy.Retries.transient, .base = .fromMilliseconds(1), .cap = .fromMilliseconds(5) } };
    var buf: [64]u8 = undefined;
    for ([_][]const u8{ "0", "Thu, 01 Jan 1970 00:00:00 GMT" }) |after| {
        const server = try Server.start(gpa, io, .{ .context = @ptrCast(@constCast(&after)), .answer = unavailableFirst }); // safe: the handler only reads it
        defer server.stop();
        var client: Client = .init(gpa, fast);
        defer client.deinit(io);
        var d: Diagnostics = .{};
        const body = try get(&client, io, .{ .method = .POST, .url = server.url(&buf, "/"), .body = .{ .bytes = "b" }, .diagnostics = &d });
        defer gpa.free(body);
        try testing.expectEqualStrings("POST|b|-|-|-", body);
        try testing.expectEqual(@as(u8, 1), d.retries);
        try testing.expectEqual(@as(u32, 2), server.requests.load(.monotonic));
    }
    {
        // Not covered by default, and not past what the caller waits for.
        const long: []const u8 = "3600";
        const server = try Server.start(gpa, io, .{ .context = @ptrCast(@constCast(&long)), .answer = unavailableFirst }); // safe: the handler only reads it
        defer server.stop();
        var plain: Client = .init(gpa, .{});
        defer plain.deinit(io);
        var response = try plain.send(io, .{ .url = server.url(&buf, "/") });
        try testing.expectEqual(std.http.Status.service_unavailable, response.status);
        response.deinit(io);
        var client: Client = .init(gpa, fast);
        defer client.deinit(io);
        var again = try client.send(io, .{ .url = server.url(&buf, "/") });
        defer again.deinit(io);
        try testing.expectEqual(std.http.Status.service_unavailable, again.status);
        try testing.expectEqual(@as(u32, 2), server.requests.load(.monotonic));
    }
    {
        // A backoff that would end past the request's deadline is not waited.
        const five: []const u8 = "5";
        const server = try Server.start(gpa, io, .{ .context = @ptrCast(@constCast(&five)), .answer = unavailableFirst }); // safe: the handler only reads it
        defer server.stop();
        var client: Client = .init(gpa, fast);
        defer client.deinit(io);
        var response = try client.send(io, .{ .url = server.url(&buf, "/"), .timeout = .{ .duration = .{ .raw = .fromSeconds(2), .clock = .awake } } });
        defer response.deinit(io);
        try testing.expectEqual(std.http.Status.service_unavailable, response.status);
    }
}

/// The first request the server sees is met by a closed connection.
fn hangUpFirst(_: ?*anyopaque, request: Server.Request) Server.Answer {
    if (request.number == 0) return .{ .close = true };
    return echoOf(request);
}

test "a connection that fails before any answer is tried again when the request can go again" {
    const gpa = testing.allocator;
    const io = test_io.io();
    var buf: [64]u8 = undefined;
    const fast: Client.Options = .{ .retries = .{ .base = .fromMilliseconds(1) } };
    {
        const server = try Server.start(gpa, io, .{ .answer = hangUpFirst });
        defer server.stop();
        var client: Client = .init(gpa, fast);
        defer client.deinit(io);
        var d: Diagnostics = .{};
        const body = try get(&client, io, .{ .url = server.url(&buf, "/"), .diagnostics = &d });
        defer gpa.free(body);
        try testing.expectEqualStrings("GET||-|-|-", body);
        try testing.expectEqual(@as(u8, 1), d.retries);
    }
    {
        // A POST may have reached the server: never sent twice.
        const server = try Server.start(gpa, io, .{ .answer = hangUpFirst });
        defer server.stop();
        var client: Client = .init(gpa, fast);
        defer client.deinit(io);
        try testing.expectError(error.ConnectionFailed, client.send(io, .{ .method = .POST, .url = server.url(&buf, "/"), .body = .{ .bytes = "x" } }));
        try testing.expectEqual(@as(u32, 1), server.requests.load(.monotonic));
    }
}

/// A server that wants `Mufasa:Circle of Life`, by the scheme the context
/// names.
fn guarded(context: ?*anyopaque, request: Server.Request) Server.Answer {
    const scheme: *const []const u8 = @ptrCast(@alignCast(context.?)); // safe: the test passes its scheme
    const given = Server.headerValue(request.head, "authorization") orelse "";
    const good = if (std.mem.eql(u8, scheme.*, "Basic"))
        std.mem.eql(u8, given, "Basic TXVmYXNhOkNpcmNsZSBvZiBMaWZl")
    else if (std.mem.eql(u8, scheme.*, "Bearer"))
        std.mem.eql(u8, given, "Bearer t0k3n")
    else
        // Digest: the first answer is told its nonce went stale.
        std.mem.find(u8, given, "nonce=\"n2\"") != null and std.mem.startsWith(u8, given, "Digest username=\"Mufasa\"");
    if (good) return echoOf(request);
    if (std.mem.eql(u8, scheme.*, "Digest")) {
        const stale = std.mem.find(u8, given, "nonce=\"n1\"") != null;
        return .{ .bytes = print("HTTP/1.1 401 No\r\nWWW-Authenticate: Digest realm=\"r\", qop=\"auth\", nonce=\"{s}\"{s}\r\nContent-Length: 0\r\n\r\n", .{ if (stale) "n2" else "n1", if (stale) ", stale=true" else "" }) };
    }
    return .{ .bytes = print("HTTP/1.1 401 No\r\nWWW-Authenticate: {s} realm=\"r\"\r\nContent-Length: 0\r\n\r\n", .{scheme.*}) };
}

const Store = struct {
    secret: Credentials.Secret,
    filled: u32 = 0,
    taken: u32 = 0,
    refused: u32 = 0,

    fn credentials(s: *Store) Credentials {
        return .{ .context = s, .fillFn = fill, .doneFn = done };
    }

    fn fill(_: Io, context: ?*anyopaque, query: Credentials.Query) Credentials.FillError!?Credentials.Secret {
        const s: *Store = @ptrCast(@alignCast(context.?)); // safe: the tests pass a Store
        std.debug.assert(std.mem.eql(u8, query.realm.?, "r"));
        s.filled += 1;
        return s.secret;
    }

    fn done(_: Io, context: ?*anyopaque, _: Credentials.Query, _: Credentials.Secret, accepted: bool) void {
        const s: *Store = @ptrCast(@alignCast(context.?)); // safe: the tests pass a Store
        if (accepted) s.taken += 1 else s.refused += 1;
    }
};

test "a 401 is answered from the caller's credentials once, and the answer sent from then on" {
    const gpa = testing.allocator;
    const io = test_io.io();
    var buf: [64]u8 = undefined;
    for ([_]struct { []const u8, Credentials.Secret }{
        .{ "Basic", .{ .password = .{ .user = "Mufasa", .password = "Circle of Life" } } },
        .{ "Bearer", .{ .token = "t0k3n" } },
        .{ "Digest", .{ .password = .{ .user = "Mufasa", .password = "Circle of Life" } } },
    }) |case| {
        const server = try Server.start(gpa, io, .{ .context = @ptrCast(@constCast(&case[0])), .answer = guarded }); // safe: the handler only reads it
        defer server.stop();
        var store: Store = .{ .secret = case[1] };
        var client: Client = .init(gpa, .{ .credentials = store.credentials() });
        defer client.deinit(io);
        for (0..3) |_| {
            const body = try get(&client, io, .{ .method = .PUT, .url = server.url(&buf, "/repo"), .body = .{ .bytes = "x" } });
            defer gpa.free(body);
            try testing.expect(std.mem.startsWith(u8, body, "PUT|x|-|"));
        }
        try testing.expectEqual(@as(u32, 1), store.filled);
        try testing.expectEqual(@as(u32, 1), store.taken);
        // 401, then the answer (Digest: twice, for the stale nonce), then
        // the answer at once for each later request.
        const extra: u32 = if (std.mem.eql(u8, case[0], "Digest")) 1 else 0;
        try testing.expectEqual(@as(u32, 4 + extra), server.requests.load(.monotonic));
    }
}

test "a refused answer is reported and the 401 handed back, and a request's own credentials go unasked" {
    const gpa = testing.allocator;
    const io = test_io.io();
    var buf: [64]u8 = undefined;
    const scheme: []const u8 = "Basic";
    const server = try Server.start(gpa, io, .{ .context = @ptrCast(@constCast(&scheme)), .answer = guarded }); // safe: the handler only reads it
    defer server.stop();
    var store: Store = .{ .secret = .{ .password = .{ .user = "Mufasa", .password = "wrong" } } };
    var client: Client = .init(gpa, .{ .credentials = store.credentials() });
    defer client.deinit(io);
    var response = try client.send(io, .{ .url = server.url(&buf, "/") });
    try testing.expectEqual(std.http.Status.unauthorized, response.status);
    response.deinit(io);
    try testing.expectEqual(@as(u32, 1), store.refused);
    const body = try get(&client, io, .{ .url = server.url(&buf, "/"), .auth = .{ .basic = .{ .user = "Mufasa", .password = "Circle of Life" } } });
    defer gpa.free(body);
    try testing.expectEqualStrings("GET||-|Basic TXVmYXNhOkNpcmNsZSBvZiBMaWZl|-", body);
    try testing.expectEqual(@as(u32, 1), store.filled);
}

/// Sets a cookie at `/login` and redirects home; echoes elsewhere.
fn session(_: ?*anyopaque, request: Server.Request) Server.Answer {
    const path = Server.pathOf(request.head);
    if (std.mem.eql(u8, path, "/login")) return .{ .bytes = "HTTP/1.1 302 Found\r\nSet-Cookie: sid=42; Path=/; HttpOnly\r\nSet-Cookie: lang=en\r\nLocation: /home\r\nContent-Length: 0\r\n\r\n" };
    return echoOf(request);
}

test "cookies set on a redirect go with the redirected request and every later one" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const server = try Server.start(gpa, io, .{ .answer = session });
    defer server.stop();
    var jar: CookieJar = .init(gpa, .{});
    defer jar.deinit(io);
    var client: Client = .init(gpa, .{ .cookies = &jar });
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    const home = try get(&client, io, .{ .url = server.url(&buf, "/login") });
    defer gpa.free(home);
    try testing.expectEqualStrings("GET||-|-|sid=42; lang=en", home);
    const own = try get(&client, io, .{ .url = server.url(&buf, "/x"), .headers = &.{.{ .name = "Cookie", .value = "mine=1" }} });
    defer gpa.free(own);
    try testing.expectEqualStrings("GET||-|-|mine=1", own);
    try testing.expectEqual(@as(u32, 2), jar.count());
}

/// A body that takes a while, so connections are held.
fn slowOk(_: ?*anyopaque, _: Server.Request) Server.Answer {
    return .{ .bytes = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nslow", .piece = 2, .pause = .fromMilliseconds(20) };
}

test "a route at its limit makes requests wait their turn, or time out waiting" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const server = try Server.start(gpa, io, .{ .answer = slowOk });
    defer server.stop();
    var client: Client = .init(gpa, .{ .pool = .{ .max_per_route = 1 } });
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    const url = server.url(&buf, "/");
    const Task = struct {
        fn run(c: *Client, u: []const u8, out: *anyerror!void) void {
            out.* = each(c, u);
        }
        fn each(c: *Client, u: []const u8) !void {
            for (0..3) |_| {
                const body = try get(c, test_io.io(), .{ .url = u });
                defer testing.allocator.free(body);
                if (!std.mem.eql(u8, body, "slow")) return error.TestUnexpectedResult;
            }
        }
    };
    var group: Io.Group = .init;
    defer group.cancel(io);
    var results: [3]anyerror!void = undefined;
    for (&results) |*out| group.concurrent(io, Task.run, .{ &client, url, out }) catch return error.SkipZigTest;
    try group.await(io);
    for (results) |r| try r;
    try testing.expectEqual(@as(u64, 1), client.stats().connections_opened);
    // One held: the next waits until its deadline.
    var held = try client.send(io, .{ .url = url });
    defer held.deinit(io);
    var d: Diagnostics = .{};
    try testing.expectError(error.TimedOut, client.send(io, .{ .url = url, .timeout = .{ .duration = .{ .raw = .fromMilliseconds(50), .clock = .awake } }, .diagnostics = &d }));
    try testing.expectEqual(Diagnostics.Stage.wait, d.stage);
    try testing.expectEqual(Diagnostics.Timeout.deadline, d.timeout.?);
}

fn kib(_: ?*anyopaque, _: Server.Request) Server.Answer {
    const body: [1000]u8 = @splat('k');
    return .{ .bytes = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3e8\r\n" ++ body ++ "\r\n0\r\n\r\n" };
}

test "a body left unread is drained when it is small, so the connection is kept" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const server = try Server.start(gpa, io, .{ .answer = kib });
    defer server.stop();
    var buf: [64]u8 = undefined;
    for ([_]struct { u32, u64 }{ .{ 64 << 10, 1 }, .{ 10, 3 } }) |case| {
        var client: Client = .init(gpa, .{ .pool = .{ .drain_limit = .fromRaw(case[0]) } });
        defer client.deinit(io);
        for (0..3) |_| {
            var response = try client.send(io, .{ .url = server.url(&buf, "/") });
            response.deinit(io);
        }
        try testing.expectEqual(case[1], client.stats().connections_opened);
    }
}

test "a request's deadline bounds its head and its body's reads" {
    const gpa = testing.allocator;
    const io = test_io.io();
    var buf: [64]u8 = undefined;
    const ms100: Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(100), .clock = .awake } };
    {
        const server = try Server.start(gpa, io, Server.fixedAnswer(.{ .silent = true }));
        defer server.stop();
        var client: Client = .init(gpa, .{});
        defer client.deinit(io);
        var d: Diagnostics = .{};
        try testing.expectError(error.TimedOut, client.send(io, .{ .url = server.url(&buf, "/"), .timeout = ms100, .diagnostics = &d }));
        try testing.expectEqual(Diagnostics.Timeout.deadline, d.timeout.?);
        try testing.expectEqual(@as(u32, 0), client.stats().idle);
    }
    {
        const server = try Server.start(gpa, io, Server.fixedAnswer(.{ .bytes = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n0123456789", .piece = 41, .pause = .fromSeconds(5) }));
        defer server.stop();
        var client: Client = .init(gpa, .{});
        defer client.deinit(io);
        var d: Diagnostics = .{};
        var response = try client.send(io, .{ .url = server.url(&buf, "/"), .timeout = ms100, .diagnostics = &d });
        defer response.deinit(io);
        try testing.expectError(error.TimedOut, response.collect(gpa, io, .unlimited));
        try testing.expectEqual(Diagnostics.Timeout.deadline, d.timeout.?);
    }
}

test "a connection slower than the low-speed limit is given up on" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const trickle = "HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n" ++ "abcdefghijklmnopqrst";
    const server = try Server.start(gpa, io, Server.fixedAnswer(.{ .bytes = trickle, .piece = 1, .pause = .fromMilliseconds(30) }));
    defer server.stop();
    var client: Client = .init(gpa, .{ .timeouts = .{ .low_speed = .{ .bytes_per_second = 1000, .window = .fromMilliseconds(200) } } });
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    var d: Diagnostics = .{};
    const result = client.send(io, .{ .url = server.url(&buf, "/"), .diagnostics = &d });
    if (result) |r| {
        var response = r;
        defer response.deinit(io);
        try testing.expectError(error.TimedOut, response.collect(gpa, io, .unlimited));
    } else |err| try testing.expectEqual(error.TimedOut, err);
    try testing.expectEqual(Diagnostics.Timeout.low_speed, d.timeout.?);
}

test "Expect: 100-continue sends the body on the go-ahead, or never when refused" {
    const gpa = testing.allocator;
    const io = test_io.io();
    var buf: [64]u8 = undefined;
    for ([_]Server.Expect{ .go_ahead, .ignore, .refuse }) |expect| {
        // Windows' Io cannot wait a bounded time on a socket: the body goes
        // at once, into a connection the server may have closed.
        if (expect == .refuse and builtin.target.os.tag == .windows) continue;
        const server = try Server.start(gpa, io, .{ .answer = redirecting, .expect = expect });
        defer server.stop();
        var client: Client = .init(gpa, .{ .expect_continue_timeout = .fromMilliseconds(50) });
        defer client.deinit(io);
        var response = try client.send(io, .{ .method = .PUT, .url = server.url(&buf, "/echo"), .body = .{ .bytes = "payload" }, .expect_continue = true });
        defer response.deinit(io);
        const body = try response.collect(gpa, io, .unlimited);
        defer gpa.free(body);
        const seen = try server.received(gpa);
        defer gpa.free(seen);
        try testing.expect(std.mem.find(u8, seen, "Expect: 100-continue\r\n") != null);
        if (expect == .refuse) {
            try testing.expectEqual(std.http.Status.expectation_failed, response.status);
            try testing.expect(std.mem.find(u8, seen, "payload") == null);
        } else {
            try testing.expectEqualStrings("PUT|payload|-|-|-", body);
        }
    }
}

test "a written body waits for the go-ahead too, and goes nowhere when the server answers first" {
    const gpa = testing.allocator;
    const io = test_io.io();
    if (builtin.target.os.tag == .windows) return error.SkipZigTest;
    var buf: [64]u8 = undefined;
    for ([_]Server.Expect{ .go_ahead, .refuse }) |expect| {
        const server = try Server.start(gpa, io, .{ .answer = redirecting, .expect = expect });
        defer server.stop();
        var client: Client = .init(gpa, .{});
        defer client.deinit(io);
        var out = try client.begin(io, .{ .method = .PUT, .url = server.url(&buf, "/echo"), .body = .{ .streamed = .{ .length = 7 } }, .expect_continue = true });
        defer out.deinit(io);
        try out.writer().writeAll("payload");
        var response = try out.finish(io);
        defer response.deinit(io);
        const body = try response.collect(gpa, io, .unlimited);
        defer gpa.free(body);
        if (expect == .refuse) {
            try testing.expectEqual(std.http.Status.expectation_failed, response.status);
        } else try testing.expectEqualStrings("PUT|payload|-|-|-", body);
    }
}

fn switching(_: ?*anyopaque, _: Server.Request) Server.Answer {
    return .{ .bytes = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\n", .echo = true };
}

test "a 101 hands the connection over, and so does a CONNECT through a proxy" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const server = try Server.start(gpa, io, .{ .answer = switching });
    defer server.stop();
    var client: Client = .init(gpa, .{});
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    var response = try client.send(io, .{ .url = server.url(&buf, "/"), .headers = &.{ .{ .name = "Upgrade", .value = "echo" }, .{ .name = "Connection", .value = "Upgrade" } } });
    var upgraded = try response.upgrade(io);
    response.deinit(io);
    try upgraded.writer(io).writeAll("ping");
    try upgraded.flush(io);
    try testing.expectEqualStrings("ping", try upgraded.reader(io).takeArray(4));
    upgraded.close(io);
    try testing.expectEqual(@as(u32, 0), client.stats().in_use);

    const echo_server = try Server.start(gpa, io, .{ .answer = switching });
    defer echo_server.stop();
    const proxy = try TestProxy.start(gpa, io, .{});
    defer proxy.stop();
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    var proxy_url: [64]u8 = undefined;
    var through: Client = .init(gpa, .{ .proxy = .{ .fixed = try Proxy.parse(arena.allocator(), try std.mem.print(&proxy_url, "127.0.0.1:{d}", .{proxy.port}), .lowercase) } });
    defer through.deinit(io);
    var tunnel = try through.send(io, .{ .method = .CONNECT, .url = echo_server.url(&buf, "/") });
    try testing.expectEqual(std.http.Status.ok, tunnel.status);
    var raw = try tunnel.upgrade(io);
    tunnel.deinit(io);
    // The tunnel reaches the server itself: it answers HTTP, then echoes.
    try raw.writer(io).writeAll("GET / HTTP/1.1\r\nHost: x\r\n\r\n");
    try raw.flush(io);
    const head = try raw.reader(io).takeDelimiterInclusive('\n');
    try testing.expect(std.mem.startsWith(u8, head, "HTTP/1.1 101"));
    raw.close(io);
    const log = try proxy.lines(gpa);
    defer gpa.free(log);
    try testing.expect(std.mem.startsWith(u8, log, "CONNECT 127.0.0.1:"));
}

test "a chunked body's trailer fields are read once the body is" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const server = try Server.start(gpa, io, Server.fixed("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: Checksum\r\n\r\n2\r\nok\r\n0\r\nChecksum: abc\r\nX-Folded: a\r\n b\r\n\r\n"));
    defer server.stop();
    var client: Client = .init(gpa, .{});
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    for (0..2) |_| {
        var response = try client.send(io, .{ .url = server.url(&buf, "/") });
        defer response.deinit(io);
        try testing.expectEqual(null, response.trailers());
        const body = try response.collect(gpa, io, .unlimited);
        defer gpa.free(body);
        const t = response.trailers().?;
        try testing.expectEqualStrings("abc", t.get("checksum").?);
        try testing.expectEqualStrings("a   b", t.get("x-folded").?);
    }
    try testing.expectEqual(@as(u64, 1), client.stats().connections_opened);
}

const Recorder = struct {
    buf: [512]u8 = undefined,
    len: usize = 0,

    fn observer(r: *Recorder) Observer {
        return .{ .context = r, .eventFn = on };
    }

    fn on(context: ?*anyopaque, event: Observer.Event) void {
        const r: *Recorder = @ptrCast(@alignCast(context.?)); // safe: the test passes a Recorder
        const line = switch (event) {
            .head => |h| std.mem.print(r.buf[r.len..], "head{d} ", .{h.status}),
            else => std.mem.print(r.buf[r.len..], "{t} ", .{event}),
        } catch return;
        r.len += line.len;
    }
};

/// Adds the attempt's number as a field.
const Numbering = struct {
    texts: [8][4]u8 = undefined,

    fn hook(n: *Numbering) Prepare {
        return .{ .context = n, .prepareFn = prepare };
    }

    fn prepare(_: Io, context: ?*anyopaque, attempt: *Prepare.Attempt) Prepare.Error!void {
        const n: *Numbering = @ptrCast(@alignCast(context.?)); // safe: the test passes a Numbering
        const text = std.mem.print(&n.texts[attempt.number], "{d}", .{attempt.number}) catch unreachable; // unreachable: fewer than eight attempts
        attempt.add(.{ .name = "Content-Type", .value = text }) catch return error.PrepareFailed;
    }
};

test "the observer sees each step, and the prepare hook every attempt" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const server = try Server.start(gpa, io, .{ .answer = redirecting });
    defer server.stop();
    var recorder: Recorder = .{};
    var numbering: Numbering = .{};
    var client: Client = .init(gpa, .{ .observer = recorder.observer(), .prepare = numbering.hook() });
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    const body = try get(&client, io, .{ .url = server.url(&buf, "/keep"), .method = .POST, .body = .{ .bytes = "x" } });
    defer gpa.free(body);
    try testing.expectEqualStrings("POST|x|2|-|-", body);
    try testing.expectEqualStrings("connected sent head307 redirect reused sent head200 ", recorder.buf[0..recorder.len]);
}

test "a proxy is chosen from the environment per request, and no_proxy goes around it" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const server = try Server.start(gpa, io, .{ .answer = redirecting });
    defer server.stop();
    const proxy = try TestProxy.start(gpa, io, .{});
    defer proxy.stop();
    var env: std.process.Environ.Map = .init(gpa);
    defer env.deinit();
    var proxy_url: [64]u8 = undefined;
    try env.put("http_proxy", try std.mem.print(&proxy_url, "http://127.0.0.1:{d}", .{proxy.port}));
    try env.put("no_proxy", "bypass.test");
    const entries = [_]Resolver.Static.Entry{.{ .host = "bypass.test", .addresses = &.{.{ .ip4 = .loopback(0) }} }};
    const static: Resolver.Static = .{ .entries = &entries };
    var client: Client = .init(gpa, .{ .proxy = .{ .environment = .{ .env = &env, .rules = .lowercase } }, .resolver = static.resolver() });
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    const via = try get(&client, io, .{ .url = server.url(&buf, "/echo") });
    defer gpa.free(via);
    var direct_url: [64]u8 = undefined;
    const direct = try get(&client, io, .{ .url = try std.mem.print(&direct_url, "http://bypass.test:{d}/echo", .{server.port}) });
    defer gpa.free(direct);
    const log = try proxy.lines(gpa);
    defer gpa.free(log);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, log, "\n"));
    try testing.expect(std.mem.startsWith(u8, log, "GET http://127.0.0.1:"));
    try testing.expectEqual(@as(u64, 2), client.stats().connections_opened);
}

test "a Unix socket carries requests for any host, which the Host field still names" {
    const gpa = testing.allocator;
    const io = test_io.io();
    if (!Io.net.has_unix_sockets) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var dir_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const dir = dir_buf[0..try tmp.dir.realPath(io, &dir_buf)];
    var path_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const path = try std.mem.print(&path_buf, "{s}/d.sock", .{dir});
    if (path.len >= 104) return error.SkipZigTest;
    const server = Server.startUnix(gpa, io, path, .{ .answer = redirecting }) catch return error.SkipZigTest;
    defer server.stop();
    var client: Client = .init(gpa, .{ .dial = .{ .unix_socket = path } });
    defer client.deinit(io);
    for (0..2) |_| {
        const body = try get(&client, io, .{ .url = "http://docker.local/v1/echo" });
        defer gpa.free(body);
        try testing.expectEqualStrings("GET||-|-|-", body);
    }
    const seen = try server.received(gpa);
    defer gpa.free(seen);
    try testing.expect(std.mem.find(u8, seen, "Host: docker.local\r\n") != null);
    try testing.expectEqual(@as(u64, 1), client.stats().connections_opened);
}

test "Server-Sent Events are read from a body as it streams" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const stream = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n" ++
        "e\r\ndata: one\n\nid:\r\n" ++ "e\r\n 7\ndata: two\n\n\r\n" ++ "0\r\n\r\n";
    const server = try Server.start(gpa, io, Server.fixedAnswer(.{ .bytes = stream, .piece = 19, .pause = .fromMilliseconds(5) }));
    defer server.stop();
    var client: Client = .init(gpa, .{});
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    var response = try client.send(io, .{ .url = server.url(&buf, "/events") });
    defer response.deinit(io);
    var data: [64]u8 = undefined;
    var events: sse.Reader = .init(response.reader(io), &data);
    try testing.expectEqualStrings("one", (try events.next()).?.data);
    const two = (try events.next()).?;
    try testing.expectEqualStrings("two", two.data);
    try testing.expectEqualStrings("7", two.id);
    try testing.expectEqual(null, try events.next());
}

/// Wants `sid` sent and Basic answered; sets the cookie on the first
/// request.
fn sessionGuarded(_: ?*anyopaque, request: Server.Request) Server.Answer {
    if (Server.headerValue(request.head, "authorization") == null) return .{ .bytes = "HTTP/1.1 401 No\r\nWWW-Authenticate: Basic realm=\"r\"\r\nSet-Cookie: sid=1\r\nContent-Length: 0\r\n\r\n" };
    return .{ .bytes = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok" };
}

test "a warm client with cookies and a kept answer still allocates nothing per request" {
    const io = test_io.io();
    const server = try Server.start(testing.allocator, io, .{ .answer = sessionGuarded });
    defer server.stop();
    var counting: shakedown.alloc.Counting = .init(testing.allocator);
    var jar: CookieJar = .init(testing.allocator, .{});
    defer jar.deinit(io);
    var store: Store = .{ .secret = .{ .password = .{ .user = "a", .password = "b" } } };
    var client: Client = .init(counting.allocator(), .{ .cookies = &jar, .credentials = store.credentials(), .timeouts = .{ .activity = .fromSeconds(30) } });
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    const url = server.url(&buf, "/");
    var body: [8]u8 = undefined;
    for (0..53) |i| {
        if (i == 3) counting = .{ .child = counting.child, .live_bytes = counting.live_bytes };
        var response = try client.send(io, .{ .url = url });
        defer response.deinit(io);
        const n = try response.reader(io).readSliceShort(&body);
        try testing.expectEqualStrings("ok", body[0..n]);
    }
    try testing.expectEqual(@as(u64, 0), counting.allocations);
    try testing.expectEqual(@as(u64, 0), counting.frees);
    const seen = try server.received(testing.allocator);
    defer testing.allocator.free(seen);
    try testing.expect(std.mem.endsWith(u8, seen, "Authorization: Basic YTpi\r\nCookie: sid=1\r\n\r\n"));
}
