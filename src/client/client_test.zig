//! The client against a server of the tests' own, over loopback.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const testing = std.testing;
const Client = @import("Client.zig");
const Server = @import("../testing/Server.zig");
const Diagnostics = @import("../transport/Diagnostics.zig");
const shakedown = @import("shakedown");
const Proxy = @import("../transport/Proxy.zig");
const TestProxy = @import("../testing/Proxy.zig");

const ok_answer = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

fn get(client: *Client, io: Io, url: []const u8) ![]u8 {
    var response = try client.send(io, .{ .url = url });
    defer response.deinit(io);
    return response.collect(testing.allocator, io, .limited(1 << 20));
}

test "requests to one server go over one kept connection" {
    const io = testing.io;
    const server = try Server.start(testing.allocator, io, Server.fixed(ok_answer));
    defer server.stop();
    var client: Client = .init(testing.allocator, .{});
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    for (0..20) |_| {
        const body = try get(&client, io, server.url(&buf, "/"));
        defer testing.allocator.free(body);
        try testing.expectEqualStrings("ok", body);
    }
    const stats = client.stats();
    try testing.expectEqual(@as(u64, 1), stats.connections_opened);
    try testing.expectEqual(@as(u64, 19), stats.reused);
    try testing.expectEqual(@as(u32, 1), stats.idle);
    try testing.expectEqual(@as(u32, 0), stats.in_use);
    try testing.expectEqual(@as(u32, 1), server.accepted.load(.monotonic));
}

test "a request's head is written as curl writes it, with nothing unchecked" {
    const io = testing.io;
    const server = try Server.start(testing.allocator, io, Server.fixed(ok_answer));
    defer server.stop();
    var client: Client = .init(testing.allocator, .{ .user_agent = "uplink-test", .decompress = false });
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    var response = try client.send(io, .{
        .method = .POST,
        .url = server.url(&buf, "/repo.git/git-upload-pack?x=1#frag"),
        .headers = &.{.{ .name = "Git-Protocol", .value = "version=2" }},
        .body = .{ .bytes = "0000" },
    });
    response.deinit(io);
    const seen = try server.received(testing.allocator);
    defer testing.allocator.free(seen);
    var want_buf: [256]u8 = undefined;
    const want = try std.mem.print(&want_buf, "POST /repo.git/git-upload-pack?x=1 HTTP/1.1\r\nHost: 127.0.0.1:{d}\r\nUser-Agent: uplink-test\r\nGit-Protocol: version=2\r\nContent-Length: 4\r\n\r\n0000", .{server.port});
    try testing.expectEqualStrings(want, seen);
    for ([_][]const u8{ "X: a\r\nInjected: b", "a\x00b" }) |value| {
        try testing.expectError(error.InvalidHeader, client.send(io, .{ .url = server.url(&buf, "/"), .headers = &.{.{ .name = "X", .value = value }} }));
    }
    try testing.expectError(error.InvalidHeader, client.send(io, .{ .url = server.url(&buf, "/"), .headers = &.{.{ .name = "Host", .value = "evil" }} }));
    try testing.expectError(error.InvalidUrl, client.send(io, .{ .url = "http://127.0.0.1/a b" }));
    try testing.expectError(error.UnsupportedScheme, client.send(io, .{ .url = "ftp://127.0.0.1/" }));
    try testing.expectEqual(@as(u32, 1), server.requests.load(.monotonic));
}

/// The body of a response to `GET /` with `answer`, read whole.
fn bodyOf(comptime answer: []const u8, options: Client.Options) ![]u8 {
    const io = testing.io;
    // An answer framed by the connection's end ends the connection.
    const close = comptime std.mem.startsWith(u8, answer, "HTTP/1.0");
    const server = try Server.start(testing.allocator, io, Server.fixedAnswer(.{ .bytes = answer, .close = close }));
    defer server.stop();
    var client: Client = .init(testing.allocator, options);
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    return get(&client, io, server.url(&buf, "/"));
}

test "bodies are read as their framing says: length, chunks, the connection's end" {
    const cases = [_]struct { []const u8, []const u8 }{
        .{ "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5;x=y\r\npedia\r\n0\r\nT: v\r\n\r\n", "Wikipedia" },
        .{ "HTTP/1.0 200 OK\r\n\r\nto the end", "to the end" },
        .{ "HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n", "" },
        .{ "HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nreal", "real" },
        .{ "HTTP/1.1 200 OK\nContent-Length: 3\nX-Fold: a\n b\n\nlfs", "lfs" },
    };
    inline for (cases) |case| {
        const body = try bodyOf(case[0], .{});
        defer testing.allocator.free(body);
        try testing.expectEqualStrings(case[1], body);
    }
}

fn compressed(gpa: std.mem.Allocator, container: std.compress.flate.Container, text: []const u8) ![]u8 {
    var out: Io.Writer.Allocating = try .initCapacity(gpa, 256);
    defer out.deinit();
    const window = try gpa.alloc(u8, std.compress.flate.max_window_len);
    defer gpa.free(window);
    const compress = try gpa.create(std.compress.flate.Compress);
    defer gpa.destroy(compress);
    compress.* = try .init(&out.writer, window, container, .level_6);
    try compress.writer.writeAll(text);
    try compress.finish();
    return out.toOwnedSlice();
}

test "gzip and deflate bodies are decoded, and other codings handed over as they came" {
    const gpa = testing.allocator;
    const io = testing.io;
    const text = "a body worth compressing: repeated repeated repeated repeated";
    for ([_]struct { std.compress.flate.Container, []const u8 }{ .{ .gzip, "gzip" }, .{ .zlib, "deflate" } }) |case| {
        const coded = try compressed(gpa, case[0], text);
        defer gpa.free(coded);
        const answer = try gpa.print("HTTP/1.1 200 OK\r\nContent-Encoding: {s}\r\nContent-Length: {d}\r\n\r\n{s}", .{ case[1], coded.len, coded });
        defer gpa.free(answer);
        const Ctx = struct {
            fn answerFn(context: ?*anyopaque, _: Server.Request) Server.Answer {
                const bytes: *const []const u8 = @ptrCast(@alignCast(context.?)); // safe: the test passes a pointer to its answer
                return .{ .bytes = bytes.* };
            }
        };
        const server = try Server.start(gpa, io, .{ .context = @ptrCast(@constCast(&answer)), .answer = Ctx.answerFn });
        defer server.stop();
        var buf: [64]u8 = undefined;
        var client: Client = .init(gpa, .{});
        defer client.deinit(io);
        for (0..2) |_| {
            const body = try get(&client, io, server.url(&buf, "/"));
            defer gpa.free(body);
            try testing.expectEqualStrings(text, body);
        }
        try testing.expectEqual(@as(u64, 1), client.stats().connections_opened);
        const seen = try server.received(gpa);
        defer gpa.free(seen);
        try testing.expect(std.mem.find(u8, seen, "Accept-Encoding: gzip, deflate\r\n") != null);
        var raw: Client = .init(gpa, .{ .decompress = false });
        defer raw.deinit(io);
        const undecoded = try get(&raw, io, server.url(&buf, "/"));
        defer gpa.free(undecoded);
        try testing.expectEqualSlices(u8, coded, undecoded);
    }
    const zstd = try bodyOf("HTTP/1.1 200 OK\r\nContent-Encoding: zstd\r\nContent-Length: 4\r\n\r\n\x28\xb5\x2f\xfd", .{});
    defer gpa.free(zstd);
    try testing.expectEqualSlices(u8, "\x28\xb5\x2f\xfd", zstd);
}

test "a head longer than the connection's buffer is read, and one past the limit refused" {
    const gpa = testing.allocator;
    const pad: [40 << 10]u8 = @splat('b');
    const long = "HTTP/1.1 200 OK\r\nX-Pad: " ++ pad ++ "\r\nContent-Length: 2\r\n\r\nok";
    const body = try bodyOf(long, .{});
    defer gpa.free(body);
    try testing.expectEqualStrings("ok", body);
    const big: [70 << 10]u8 = @splat('b');
    const too_long = "HTTP/1.1 200 OK\r\nX-Pad: " ++ big ++ "\r\nContent-Length: 2\r\n\r\nok";
    try testing.expectError(error.HttpProtocolError, bodyOf(too_long, .{}));
    try testing.expectError(error.HttpProtocolError, bodyOf("HTTP/1.1 2000 OK\r\nContent-Length: 0\r\n\r\n", .{}));
    try testing.expectError(error.HttpProtocolError, bodyOf("HTTP/1.1 200 OK\r\nContent-Length: 1_0\r\n\r\n", .{}));
}

/// Echo each request's body back, with its length.
fn echo(_: ?*anyopaque, request: Server.Request) Server.Answer {
    const S = struct {
        threadlocal var buf: [64 << 10]u8 = undefined;
    };
    const chunked = Server.headerValue(request.head, "transfer-encoding") != null;
    const answer = std.mem.print(&S.buf, "HTTP/1.1 200 OK\r\nContent-Length: {d}\r\nX-Chunked: {}\r\n\r\n{s}", .{ request.body.len, chunked, request.body }) catch unreachable; // unreachable: the tests' bodies fit
    return .{ .bytes = answer };
}

test "a body from a reader goes with its length, or in chunks, and a short one is refused" {
    const io = testing.io;
    const server = try Server.start(testing.allocator, io, .{ .answer = echo });
    defer server.stop();
    var client: Client = .init(testing.allocator, .{});
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    const url = server.url(&buf, "/upload");
    {
        var source: Io.Reader = .fixed("exactly this");
        var response = try client.send(io, .{ .method = .PUT, .url = url, .body = .{ .reader = .{ .reader = &source, .length = 12 } } });
        defer response.deinit(io);
        const body = try response.collect(testing.allocator, io, .unlimited);
        defer testing.allocator.free(body);
        try testing.expectEqualStrings("exactly this", body);
        try testing.expectEqualStrings("false", response.headers.get("x-chunked").?);
    }
    {
        var source: Io.Reader = .fixed("streamed to its end");
        var response = try client.send(io, .{ .method = .POST, .url = url, .body = .{ .reader = .{ .reader = &source } } });
        defer response.deinit(io);
        const body = try response.collect(testing.allocator, io, .unlimited);
        defer testing.allocator.free(body);
        try testing.expect(std.mem.endsWith(u8, body, "streamed to its end\r\n0\r\n\r\n"));
        try testing.expectEqualStrings("true", response.headers.get("x-chunked").?);
    }
    var short: Io.Reader = .fixed("short");
    try testing.expectError(error.BodyIncomplete, client.send(io, .{ .method = .PUT, .url = url, .body = .{ .reader = .{ .reader = &short, .length = 10 } } }));
    try testing.expectError(error.InvalidBody, client.send(io, .{ .url = url, .body = .{ .streamed = .{} } }));
    try testing.expectEqual(@as(u32, 0), client.stats().in_use);
}

test "a body the caller writes goes exactly at its length, or in chunks" {
    const io = testing.io;
    const server = try Server.start(testing.allocator, io, .{ .answer = echo });
    defer server.stop();
    var client: Client = .init(testing.allocator, .{});
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    const url = server.url(&buf, "/upload");
    {
        var out = try client.begin(io, .{ .method = .POST, .url = url, .body = .{ .streamed = .{ .length = 11 } } });
        defer out.deinit(io);
        try out.writer().writeAll("hello ");
        try out.writer().writeAll("world");
        var response = try out.finish(io);
        defer response.deinit(io);
        const body = try response.collect(testing.allocator, io, .unlimited);
        defer testing.allocator.free(body);
        try testing.expectEqualStrings("hello world", body);
    }
    {
        var out = try client.begin(io, .{ .method = .POST, .url = url });
        defer out.deinit(io);
        for (0..100) |_| try out.writer().writeAll("0123456789");
        var response = try out.finish(io);
        defer response.deinit(io);
        try testing.expectEqualStrings("true", response.headers.get("x-chunked").?);
        try testing.expectError(error.ExchangeOver, out.finish(io));
    }
    {
        var out = try client.begin(io, .{ .method = .POST, .url = url, .body = .{ .streamed = .{ .length = 3 } } });
        defer out.deinit(io);
        // Past the length: the write fails, and `finish` says why.
        try testing.expectError(error.WriteFailed, writeAndFlush(out.writer(), "four"));
        try testing.expectError(error.BodyTooLong, out.finish(io));
    }
    {
        var out = try client.begin(io, .{ .method = .POST, .url = url, .body = .{ .streamed = .{ .length = 3 } } });
        defer out.deinit(io);
        try out.writer().writeAll("tw");
        try testing.expectError(error.BodyIncomplete, out.finish(io));
    }
    try testing.expectEqual(@as(u32, 0), client.stats().in_use);
}

fn writeAndFlush(w: *Io.Writer, bytes: []const u8) Io.Writer.Error!void {
    try w.writeAll(bytes);
    try w.flush();
}

/// Answer the first request on a connection and close it; on the second,
/// read the request and close without a word.
fn closing(_: ?*anyopaque, request: Server.Request) Server.Answer {
    if (request.index == 0) return .{ .bytes = ok_answer, .close = std.mem.startsWith(u8, request.head, "GET /close") };
    return .{ .close = true };
}

test "a kept connection the server closed is noticed before it is used, or replaced when it fails" {
    const io = testing.io;
    const server = try Server.start(testing.allocator, io, .{ .answer = closing });
    defer server.stop();
    var buf: [64]u8 = undefined;
    {
        // Closed while idle: the check before reuse sees its end.
        var client: Client = .init(testing.allocator, .{});
        defer client.deinit(io);
        for (0..3) |_| {
            const body = try get(&client, io, server.url(&buf, "/close"));
            testing.allocator.free(body);
            try io.sleep(.fromMilliseconds(20), .awake);
        }
        try testing.expectEqual(@as(u64, 3), client.stats().connections_opened);
        try testing.expectEqual(@as(u64, 0), client.stats().reused);
    }
    {
        // Closed after the request arrived, with no answer: a GET goes
        // again on a new connection; a POST with a body does not.
        var client: Client = .init(testing.allocator, .{});
        defer client.deinit(io);
        const first = try get(&client, io, server.url(&buf, "/keep"));
        testing.allocator.free(first);
        const again = try get(&client, io, server.url(&buf, "/keep"));
        testing.allocator.free(again);
        try testing.expectEqual(@as(u64, 2), client.stats().connections_opened);
        try testing.expectError(error.ConnectionFailed, client.send(io, .{ .method = .POST, .url = server.url(&buf, "/keep"), .body = .{ .bytes = "x" } }));
        try testing.expectEqual(@as(u32, 0), client.stats().in_use);
    }
}

test "an answer that stops coming is given up on at the activity timeout, and its connection not kept" {
    const io = testing.io;
    const server = try Server.start(testing.allocator, io, Server.fixedAnswer(.{ .silent = true }));
    defer server.stop();
    var client: Client = .init(testing.allocator, .{ .timeouts = .{ .activity = .fromMilliseconds(100) } });
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    var diagnostics: Diagnostics = .{};
    try testing.expectError(error.TimedOut, client.send(io, .{ .url = server.url(&buf, "/"), .diagnostics = &diagnostics }));
    try testing.expectEqual(Diagnostics.Timeout.activity, diagnostics.timeout.?);
    try testing.expectEqual(Diagnostics.Stage.head, diagnostics.stage);
    const stats = client.stats();
    try testing.expectEqual(@as(u32, 0), stats.idle);
    try testing.expectEqual(@as(u32, 0), stats.in_use);
    try testing.expectEqual(@as(u64, 0), stats.timeouts_unenforced);
}

/// An `Io` with no task to spare.
const Serial = shakedown.Layer(u8, .{
    .concurrent = struct {
        fn concurrent(_: ?*anyopaque, _: usize, _: std.mem.Alignment, _: []const u8, _: std.mem.Alignment, _: *const fn (*const anyopaque, *anyopaque) void) Io.ConcurrentError!*Io.AnyFuture {
            return error.ConcurrencyUnavailable;
        }
    }.concurrent,
    .groupConcurrent = struct {
        fn groupConcurrent(_: ?*anyopaque, _: *Io.Group, _: []const u8, _: std.mem.Alignment, _: *const fn (*const anyopaque) void) Io.ConcurrentError!void {
            return error.ConcurrencyUnavailable;
        }
    }.groupConcurrent,
});

test "with no task to spare, reads are bounded by the Io where it can, and counted where it cannot" {
    const server = try Server.start(testing.allocator, testing.io, Server.fixedAnswer(.{ .silent = true }));
    defer server.stop();
    var serial: Serial = .init(testing.io, 0);
    const io = serial.io();
    var client: Client = .init(testing.allocator, .{ .timeouts = .{ .activity = .fromMilliseconds(100) } });
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    if (builtin.target.os.tag == .windows) {
        // Zig 0.17's Threaded refuses a timed socket read on Windows: the
        // request would wait for ever, so it is not sent; the refusal is
        // proved by the transport's own test.
        return error.SkipZigTest;
    }
    try testing.expectError(error.TimedOut, client.send(io, .{ .url = server.url(&buf, "/") }));
    try testing.expectEqual(@as(u64, 0), client.stats().timeouts_unenforced);
}

test "tasks sending at once through one client share the connections it keeps" {
    const io = testing.io;
    const server = try Server.start(testing.allocator, io, Server.fixed(ok_answer));
    defer server.stop();
    var client: Client = .init(testing.allocator, .{ .pool = .{ .max_idle_per_route = 4 }, .timeouts = .{ .connect = .fromSeconds(10), .activity = .fromSeconds(10) } });
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    const url = server.url(&buf, "/");
    const Task = struct {
        fn run(c: *Client, u: []const u8, out: *anyerror!void) void {
            out.* = each(c, u);
        }
        fn each(c: *Client, u: []const u8) !void {
            for (0..5) |_| {
                const body = try get(c, testing.io, u);
                defer testing.allocator.free(body);
                if (!std.mem.eql(u8, body, "ok")) return error.TestUnexpectedResult;
            }
        }
    };
    var group: Io.Group = .init;
    defer group.cancel(io);
    var results: [4]anyerror!void = undefined;
    for (&results) |*out| group.concurrent(io, Task.run, .{ &client, url, out }) catch return error.SkipZigTest;
    try group.await(io);
    for (results) |r| try r;
    try testing.expect(client.stats().connections_opened <= 4);
    try testing.expect(client.stats().idle <= 4);
}

test "a request on a warm client allocates nothing" {
    const io = testing.io;
    const server = try Server.start(testing.allocator, io, Server.fixed(ok_answer));
    defer server.stop();
    var counting: shakedown.alloc.Counting = .init(testing.allocator);
    var client: Client = .init(counting.allocator(), .{ .timeouts = .{ .activity = .fromSeconds(30) } });
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
}

/// Counts the socket operations an `Io` is asked for.
const Counted = struct {
    reads: std.atomic.Value(u32) = .init(0),
    writes: std.atomic.Value(u32) = .init(0),
    polls: std.atomic.Value(u32) = .init(0),

    const L = shakedown.Layer(Counted, .{ .operate = operate, .batchAwaitConcurrent = batchAwaitConcurrent });

    fn operate(userdata: ?*anyopaque, op: Io.Operation) Io.Cancelable!Io.Operation.Result {
        const l = L.of(userdata);
        switch (op) {
            .net_read => _ = l.state.reads.fetchAdd(1, .monotonic),
            .net_write => _ = l.state.writes.fetchAdd(1, .monotonic),
            else => {},
        }
        return l.base.vtable.operate(l.base.userdata, op);
    }

    fn batchAwaitConcurrent(userdata: ?*anyopaque, b: *Io.Batch, timeout: Io.Timeout) Io.Batch.AwaitConcurrentError!void {
        const l = L.of(userdata);
        _ = l.state.polls.fetchAdd(1, .monotonic);
        return l.base.vtable.batchAwaitConcurrent(l.base.userdata, b, timeout);
    }
};

test "a small exchange on a kept connection is one write, one read and one readiness check" {
    const server = try Server.start(testing.allocator, testing.io, Server.fixed(ok_answer));
    defer server.stop();
    var counted: Counted.L = .init(testing.io, .{});
    const io = counted.io();
    var client: Client = .init(testing.allocator, .{});
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    const url = server.url(&buf, "/");
    for (0..11) |i| {
        if (i == 1) counted.state = .{};
        var response = try client.send(io, .{ .method = .POST, .url = url, .body = .{ .bytes = "a body sent with its head" } });
        defer response.deinit(io);
        var body: [8]u8 = undefined;
        _ = try response.reader(io).readSliceShort(&body);
    }
    try testing.expectEqual(@as(u32, 10), counted.state.writes.load(.monotonic));
    try testing.expectEqual(@as(u32, 10), counted.state.reads.load(.monotonic));
    try testing.expectEqual(@as(u32, 10), counted.state.polls.load(.monotonic));
}

test "a request through an HTTP proxy is sent whole, and the proxy's Digest challenge answered" {
    const gpa = testing.allocator;
    const io = testing.io;
    const server = try Server.start(gpa, io, Server.fixed(ok_answer));
    defer server.stop();
    const proxy = try TestProxy.start(gpa, io, .{ .credential = "user:secret", .scheme = .digest });
    defer proxy.stop();
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    var proxy_url: [64]u8 = undefined;
    var client: Client = .init(gpa, .{ .proxy = try Proxy.parse(arena.allocator(), try std.mem.print(&proxy_url, "http://user:secret@127.0.0.1:{d}", .{proxy.port}), .curl) });
    defer client.deinit(io);
    var buf: [64]u8 = undefined;
    const body = try get(&client, io, server.url(&buf, "/repo.git/info/refs"));
    defer gpa.free(body);
    try testing.expectEqualStrings("ok", body);
    const log = try proxy.lines(gpa);
    defer gpa.free(log);
    var want_buf: [256]u8 = undefined;
    const want = try std.mem.print(&want_buf, "GET http://127.0.0.1:{d}/repo.git/info/refs HTTP/1.1 [none]\nGET http://127.0.0.1:{d}/repo.git/info/refs HTTP/1.1 [Digest]\n", .{ server.port, server.port });
    try testing.expectEqualStrings(want, log);
}

test "a proxy is refused by name: schemes not spoken, a refusal, credentials refused" {
    const gpa = testing.allocator;
    const io = testing.io;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    var url_buf: [96]u8 = undefined;
    {
        const proxy = try TestProxy.start(gpa, io, .{ .credential = "a:b", .challenge = "Negotiate, NTLM" });
        defer proxy.stop();
        var client: Client = .init(gpa, .{ .proxy = try Proxy.parse(arena.allocator(), try std.mem.print(&url_buf, "http://a:b@127.0.0.1:{d}", .{proxy.port}), .curl) });
        defer client.deinit(io);
        var diagnostics: Diagnostics = .{};
        try testing.expectError(error.ProxyAuthMethodUnsupported, client.send(io, .{ .url = "https://git.test/", .diagnostics = &diagnostics }));
        try testing.expectEqualStrings("Negotiate, NTLM", diagnostics.proxy_offered.slice());
        try testing.expectEqual(@as(?u16, 407), diagnostics.proxy_status);
        diagnostics = .{};
        try testing.expectError(error.ProxyAuthMethodUnsupported, client.send(io, .{ .url = "http://git.test/", .diagnostics = &diagnostics }));
        try testing.expectEqualStrings("Negotiate, NTLM", diagnostics.proxy_offered.slice());
        try testing.expectEqual(@as(u32, 0), client.stats().in_use);
    }
    {
        const proxy = try TestProxy.start(gpa, io, .{ .refuse = 403 });
        defer proxy.stop();
        var client: Client = .init(gpa, .{ .proxy = try Proxy.parse(arena.allocator(), try std.mem.print(&url_buf, "127.0.0.1:{d}", .{proxy.port}), .curl) });
        defer client.deinit(io);
        var diagnostics: Diagnostics = .{};
        try testing.expectError(error.ProxyRefused, client.send(io, .{ .url = "https://git.test/", .diagnostics = &diagnostics }));
        try testing.expectEqual(@as(?u16, 403), diagnostics.proxy_status);
        try testing.expectEqual(Diagnostics.Stage.tunnel, diagnostics.stage);
    }
    {
        const proxy = try TestProxy.start(gpa, io, .{ .kind = .socks, .credential = "user:right" });
        defer proxy.stop();
        var client: Client = .init(gpa, .{ .proxy = try Proxy.parse(arena.allocator(), try std.mem.print(&url_buf, "socks5h://user:wrong@127.0.0.1:{d}", .{proxy.port}), .curl) });
        defer client.deinit(io);
        try testing.expectError(error.ProxyAuthenticationRequired, client.send(io, .{ .url = "http://git.test/" }));
    }
}

test "SOCKS 4, 4a, 5 and 5h reach the server, looking the name up where each says" {
    const gpa = testing.allocator;
    const io = testing.io;
    const server = try Server.start(gpa, io, Server.fixed(ok_answer));
    defer server.stop();
    const proxy = try TestProxy.start(gpa, io, .{ .kind = .socks });
    defer proxy.stop();
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    for ([_][]const u8{ "socks4", "socks4a", "socks5", "socks5h" }) |scheme| {
        var url_buf: [96]u8 = undefined;
        var client: Client = .init(gpa, .{ .proxy = try Proxy.parse(arena.allocator(), try std.mem.print(&url_buf, "{s}://127.0.0.1:{d}", .{ scheme, proxy.port }), .curl) });
        defer client.deinit(io);
        var target_buf: [64]u8 = undefined;
        const body = get(&client, io, try std.mem.print(&target_buf, "http://localhost:{d}/", .{server.port})) catch |err| {
            if (err == error.ConcurrencyUnavailable) return error.SkipZigTest;
            return err;
        };
        defer gpa.free(body);
        try testing.expectEqualStrings("ok", body);
    }
    const log = try proxy.lines(gpa);
    defer gpa.free(log);
    // SOCKS4 sends an IPv4 address; 4a and 5h send the name; 5 sends
    // whichever address of the name's comes first in curl's preference.
    var lines = std.mem.splitScalar(u8, log, '\n');
    try testing.expect(std.mem.startsWith(u8, lines.next().?, "SOCKS 4 127.0.0.1:"));
    try testing.expect(std.mem.startsWith(u8, lines.next().?, "SOCKS 4 localhost:"));
    const five = lines.next().?;
    try testing.expect(std.mem.startsWith(u8, five, "SOCKS 5 127.0.0.1:") or std.mem.startsWith(u8, five, "SOCKS 5 [::1]:"));
    try testing.expect(std.mem.startsWith(u8, lines.next().?, "SOCKS 5 localhost:"));
}
