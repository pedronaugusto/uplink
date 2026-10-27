//! HTTP over a Windows named pipe between uplink's own client and server:
//! the server on a pipe listener, the client by `Dial.named_pipe`, the
//! connection kept between requests as a socket's is. Off Windows the
//! client says the system has none.

const builtin = @import("builtin");
const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const reactor = @import("reactor");
const test_io = @import("testing/io.zig");
const Client = @import("client/Client.zig");
const Server = @import("server/Server.zig");
const Request = @import("server/Request.zig");
const Response = @import("server/Response.zig");

test "off Windows a named pipe is refused by name, nothing sent" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const io = test_io.io();
    var client: Client = .init(testing.allocator, .{ .dial = .{ .named_pipe = "\\\\.\\pipe\\uplink-test" } });
    defer client.deinit(io);
    try testing.expectError(error.NamedPipeUnsupported, client.send(io, .{ .url = "http://daemon/v1.45/version" }));
}

/// Answer with the path asked for, and whether the peer had an address.
fn named(io: Io, request: *Request, response: *Response) anyerror!void {
    try response.header("X-Remote", if (request.remote == null) "none" else "ip");
    try response.send(io, request.path);
}

test "a client and a server speak HTTP over a named pipe, the connection kept" {
    if (builtin.os.tag != .windows) return error.SkipZigTest;
    const gpa = testing.allocator;
    const io = test_io.io();
    var random: [8]u8 = undefined;
    io.random(&random);
    var name_buffer: [64]u8 = undefined;
    const name = try std.mem.print(&name_buffer, "\\\\.\\pipe\\uplink-test-{x}", .{&random});
    var listener = try reactor.net.listenPipe(name, .{ .security = .{ .sddl = "D:P(A;;GA;;;OW)(A;;GA;;;SY)" } });
    defer listener.deinit(io);
    var server: Server = .init(gpa, .{}, .of(named));
    defer server.deinit(io);
    var serving = io.concurrent(Server.servePipe, .{ &server, io, &listener }) catch return error.SkipZigTest;
    defer {
        server.shutdown(io);
        // glint-ignore: Z026 -- serve ends with the shutdown; its result is not what the test checks
        serving.await(io) catch {};
    }
    var client: Client = .init(gpa, .{ .dial = .{ .named_pipe = name } });
    defer client.deinit(io);
    for ([_][]const u8{ "/v1.45/version", "/v1.45/info" }) |path| {
        var url_buffer: [64]u8 = undefined;
        var response = try client.send(io, .{ .url = try std.mem.print(&url_buffer, "http://docker{s}", .{path}) });
        defer response.deinit(io);
        try testing.expectEqual(std.http.Status.ok, response.status);
        try testing.expectEqualStrings("none", response.headers.get("x-remote").?);
        const body = try response.collect(gpa, io, .limited(1 << 10));
        defer gpa.free(body);
        try testing.expectEqualStrings(path, body);
    }
    try testing.expectEqual(@as(u64, 1), client.stats().connections_opened);
}
