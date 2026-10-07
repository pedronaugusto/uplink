//! The client against a server of the tests' own, over loopback.

const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const Client = @import("Client.zig");
const Server = @import("../testing/Server.zig");

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
