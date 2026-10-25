//! The client's HTTP cache (RFC 9111) against a server of the tests' own:
//! what is served from store, what goes to the network, and what is kept.

const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const test_io = @import("../testing/io.zig");
const Client = @import("Client.zig");
const Cache = @import("Cache.zig");
const Response = @import("Response.zig");
const Server = @import("../testing/Server.zig");

/// A cache in memory and a client over it.
const Fixture = struct {
    memory: Cache.Memory,
    cache: Cache,
    client: Client,

    fn init(f: *Fixture) void {
        f.memory = .init(testing.allocator, .literal("1MiB"));
        f.cache = .init(f.memory.store(), .{});
        f.client = .init(testing.allocator, .{ .cache = &f.cache, .decompress = false });
    }

    fn deinit(f: *Fixture, io: Io) void {
        f.client.deinit(io);
        f.memory.deinit(io);
    }
};

const Got = struct {
    status: u16,
    cache: Response.CacheStatus,
    body: []u8,
    age: ?[]const u8 = null,
};

/// A whole exchange: the body read to its end.
fn get(f: *Fixture, io: Io, url: []const u8, headers: []const std.http.Header) !Got {
    var response = try f.client.send(io, .{ .url = url, .headers = headers });
    defer response.deinit(io);
    const body = try response.collect(testing.allocator, io, .limited(1 << 20));
    return .{ .status = @backingInt(response.status), .cache = response.cache, .body = body };
}

fn expectGot(got: Got, status: u16, cache: Response.CacheStatus, body: []const u8) !void {
    defer testing.allocator.free(got.body);
    try testing.expectEqual(status, got.status);
    try testing.expectEqual(cache, got.cache);
    try testing.expectEqualStrings(body, got.body);
}

test "a fresh response is served from the store, with its Age, and the server asked once" {
    const io = test_io.io();
    const server = try Server.start(testing.allocator, io, Server.fixed("HTTP/1.1 200 OK\r\nCache-Control: max-age=60\r\nContent-Length: 3\r\n\r\none"));
    defer server.stop();
    var f: Fixture = undefined;
    f.init();
    defer f.deinit(io);
    var buf: [64]u8 = undefined;
    const url = server.url(&buf, "/a");
    try expectGot(try get(&f, io, url, &.{}), 200, .miss, "one");
    var response = try f.client.send(io, .{ .url = url });
    defer response.deinit(io);
    try testing.expectEqual(Response.CacheStatus.hit, response.cache);
    try testing.expect(response.headers.get("age") != null);
    try testing.expectEqualStrings("3", response.headers.get("content-length").?);
    const body = try response.collect(testing.allocator, io, .limited(64));
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("one", body);
    try testing.expectEqual(@as(u32, 1), server.requests.load(.monotonic));
}

/// A body far past what a response's reader holds, so one read in part
/// has not all arrived.
const large: [64 << 10]u8 = @splat('x');

test "a body read in part is never stored, and no-store is never stored" {
    const io = test_io.io();
    const server = try Server.start(testing.allocator, io, Server.fixed("HTTP/1.1 200 OK\r\nCache-Control: max-age=60\r\nContent-Length: 65536\r\n\r\n" ++ large));
    defer server.stop();
    var f: Fixture = undefined;
    f.init();
    defer f.deinit(io);
    var buf: [64]u8 = undefined;
    const url = server.url(&buf, "/partial");
    {
        var response = try f.client.send(io, .{ .url = url });
        defer response.deinit(io);
        var two: [2]u8 = undefined;
        try response.reader(io).readSliceAll(&two);
    }
    try expectGot(try get(&f, io, url, &.{}), 200, .miss, &large);
    try testing.expectEqual(@as(u32, 2), server.requests.load(.monotonic));
    // Read whole, it is.
    try expectGot(try get(&f, io, url, &.{}), 200, .hit, &large);

    const never = try Server.start(testing.allocator, io, Server.fixed("HTTP/1.1 200 OK\r\nCache-Control: no-store, max-age=60\r\nContent-Length: 2\r\n\r\nno"));
    defer never.stop();
    var nbuf: [64]u8 = undefined;
    const nurl = never.url(&nbuf, "/");
    try expectGot(try get(&f, io, nurl, &.{}), 200, .miss, "no");
    try expectGot(try get(&f, io, nurl, &.{}), 200, .miss, "no");
    try testing.expectEqual(@as(u32, 2), never.requests.load(.monotonic));
}

/// An origin with an entity tag: a 200 stale at once, then 304s to a
/// request that names its tag, each with a new field and a lifetime.
const Validating = struct {
    fn answer(_: ?*anyopaque, request: Server.Request) Server.Answer {
        if (Server.headerValue(request.head, "if-none-match")) |tag| if (std.mem.eql(u8, tag, "\"v1\""))
            return .{ .bytes = "HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\nCache-Control: max-age=60\r\nX-Checked: yes\r\n\r\n" };
        return .{ .bytes = "HTTP/1.1 200 OK\r\nETag: \"v1\"\r\nCache-Control: max-age=0\r\nContent-Length: 3\r\n\r\none" };
    }
};

test "a stale response with a validator is revalidated: a 304 serves the stored body with the 304's fields, then fresh" {
    const io = test_io.io();
    const server = try Server.start(testing.allocator, io, .{ .answer = Validating.answer });
    defer server.stop();
    var f: Fixture = undefined;
    f.init();
    defer f.deinit(io);
    var buf: [64]u8 = undefined;
    const url = server.url(&buf, "/v");
    try expectGot(try get(&f, io, url, &.{}), 200, .miss, "one");
    {
        var response = try f.client.send(io, .{ .url = url });
        defer response.deinit(io);
        try testing.expectEqual(Response.CacheStatus.revalidated, response.cache);
        try testing.expectEqual(@as(u16, 200), @backingInt(response.status));
        try testing.expectEqualStrings("yes", response.headers.get("x-checked").?);
        const body = try response.collect(testing.allocator, io, .limited(64));
        defer testing.allocator.free(body);
        try testing.expectEqualStrings("one", body);
    }
    const seen = try server.received(testing.allocator);
    defer testing.allocator.free(seen);
    try testing.expect(std.mem.find(u8, seen, "If-None-Match: \"v1\"\r\n") != null);
    // The 304's max-age is the variant's now.
    try expectGot(try get(&f, io, url, &.{}), 200, .hit, "one");
    try testing.expectEqual(@as(u32, 2), server.requests.load(.monotonic));
}

/// An origin whose answer varies by language.
const Varying = struct {
    fn answer(_: ?*anyopaque, request: Server.Request) Server.Answer {
        const lang = Server.headerValue(request.head, "accept-language") orelse "none";
        if (std.mem.eql(u8, lang, "fr")) return .{ .bytes = "HTTP/1.1 200 OK\r\nVary: Accept-Language\r\nCache-Control: max-age=60\r\nContent-Length: 7\r\n\r\nbonjour" };
        return .{ .bytes = "HTTP/1.1 200 OK\r\nVary: Accept-Language\r\nCache-Control: max-age=60\r\nContent-Length: 5\r\n\r\nhello" };
    }
};

test "Vary keeps a variant per value of the fields it names" {
    const io = test_io.io();
    const server = try Server.start(testing.allocator, io, .{ .answer = Varying.answer });
    defer server.stop();
    var f: Fixture = undefined;
    f.init();
    defer f.deinit(io);
    var buf: [64]u8 = undefined;
    const url = server.url(&buf, "/lang");
    const en: []const std.http.Header = &.{.{ .name = "Accept-Language", .value = "en" }};
    const fr: []const std.http.Header = &.{.{ .name = "Accept-Language", .value = "fr" }};
    try expectGot(try get(&f, io, url, en), 200, .miss, "hello");
    try expectGot(try get(&f, io, url, fr), 200, .miss, "bonjour");
    try expectGot(try get(&f, io, url, en), 200, .hit, "hello");
    try expectGot(try get(&f, io, url, fr), 200, .hit, "bonjour");
    try expectGot(try get(&f, io, url, &.{}), 200, .miss, "hello");
    try testing.expectEqual(@as(u32, 3), server.requests.load(.monotonic));
}

test "an unsafe method's success removes what is stored for its URL" {
    const io = test_io.io();
    const server = try Server.start(testing.allocator, io, Server.fixed("HTTP/1.1 200 OK\r\nCache-Control: max-age=60\r\nContent-Length: 2\r\n\r\nok"));
    defer server.stop();
    var f: Fixture = undefined;
    f.init();
    defer f.deinit(io);
    var buf: [64]u8 = undefined;
    const url = server.url(&buf, "/item");
    try expectGot(try get(&f, io, url, &.{}), 200, .miss, "ok");
    try expectGot(try get(&f, io, url, &.{}), 200, .hit, "ok");
    {
        var response = try f.client.send(io, .{ .method = .POST, .url = url, .body = .{ .bytes = "x" } });
        response.deinit(io);
    }
    try expectGot(try get(&f, io, url, &.{}), 200, .miss, "ok");
    try testing.expectEqual(@as(u32, 3), server.requests.load(.monotonic));
}

test "only-if-cached with nothing stored is a 504 the cache makes, and the server is never asked" {
    const io = test_io.io();
    const server = try Server.start(testing.allocator, io, Server.fixed("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"));
    defer server.stop();
    var f: Fixture = undefined;
    f.init();
    defer f.deinit(io);
    var buf: [64]u8 = undefined;
    try expectGot(try get(&f, io, server.url(&buf, "/none"), &.{.{ .name = "Cache-Control", .value = "only-if-cached" }}), 504, .synthesized, "");
    try testing.expectEqual(@as(u32, 0), server.requests.load(.monotonic));
}

/// An origin that answers once, then fails.
const Failing = struct {
    fn answer(_: ?*anyopaque, request: Server.Request) Server.Answer {
        if (request.number == 0) return .{ .bytes = "HTTP/1.1 200 OK\r\nETag: \"a\"\r\nCache-Control: max-age=0, stale-if-error=600\r\nContent-Length: 4\r\n\r\nkept" };
        return .{ .bytes = "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n" };
    }
};

test "a 5xx to a revalidation serves the stale response where stale-if-error allows" {
    const io = test_io.io();
    const server = try Server.start(testing.allocator, io, .{ .answer = Failing.answer });
    defer server.stop();
    var f: Fixture = undefined;
    f.init();
    defer f.deinit(io);
    f.client.shared.options.retries.max_attempts = 1;
    var buf: [64]u8 = undefined;
    const url = server.url(&buf, "/flaky");
    try expectGot(try get(&f, io, url, &.{}), 200, .miss, "kept");
    try expectGot(try get(&f, io, url, &.{}), 200, .stale, "kept");
}

test "a store keeps no more than its bound, the least recently used evicted" {
    const io = test_io.io();
    var memory: Cache.Memory = .init(testing.allocator, .fromRaw(@sizeOf(usize) * 64 + 600));
    defer memory.deinit(io);
    const store = memory.store();
    const body: [200]u8 = @splat('x');
    for ([_][]const u8{ "a", "b", "c" }) |key| {
        const w = (try store.begin(io, key, .{ .requested = .fromRaw(0), .received = .fromRaw(0), .vary = "" }, "HTTP/1.1 200 OK\r\n")).?;
        try testing.expect(try store.append(io, w, &body));
        try store.commit(io, w);
    }
    var out: [Cache.max_variants]Cache.Entry = undefined;
    try testing.expectEqual(@as(usize, 0), try store.lookup(io, "a", &out));
    const n = try store.lookup(io, "c", &out);
    try testing.expectEqual(@as(usize, 1), n);
    // A variant held while it is removed stays readable until released.
    try store.remove(io, "c");
    try testing.expectEqual(@as(usize, 200), out[0].body.bytes.len);
    store.release(io, &out[0]);
}
