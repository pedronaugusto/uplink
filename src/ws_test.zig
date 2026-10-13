//! WebSocket between uplink's own client and server, over loopback: the
//! handshake, messages of every kind and size whole and in pieces, control
//! frames, compression both ways, and the protocol's refusals.

const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const test_io = @import("testing/io.zig");
const ws = @import("ws.zig");
const wire = @import("uplink.wire");
const Client = @import("client/Client.zig");
const Server = @import("server/Server.zig");
const Request = @import("server/Request.zig");
const Response = @import("server/Response.zig");

const Running = struct {
    server: Server,
    listener: Io.net.Server,
    task: Io.Future(Server.ServeError!void),
    port: u16,

    fn start(gpa: std.mem.Allocator, handler: Server.Handler) !*Running {
        const io = test_io.io();
        const r = try gpa.create(Running);
        errdefer gpa.destroy(r);
        r.listener = try (try Io.net.IpAddress.parse("127.0.0.1", 0)).listen(io, .{ .reuse_address = true });
        errdefer r.listener.deinit(io);
        r.port = r.listener.socket.address.getPort();
        r.server = .init(gpa, .{}, handler);
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
        return std.mem.print(buffer, "ws://127.0.0.1:{d}{s}", .{ r.port, path }) catch unreachable; // unreachable: callers pass room for a URL
    }
};

/// Echo every message back, as it came.
fn echo(io: Io, request: *Request, response: *Response) anyerror!void {
    const options: ws.AcceptOptions = .{ .protocols = &.{ "chat", "echo" } };
    var accepted: ws.Accepted = undefined;
    ws.accept(&accepted, testing.allocator, io, request, response, options) catch return;
    defer accepted.deinit();
    while (true) {
        const message = accepted.conn.readMessage(io, testing.allocator, .limited(1 << 24)) catch return;
        const kind, const bytes = message orelse return;
        defer testing.allocator.free(bytes);
        try accepted.conn.send(io, kind, bytes);
    }
}

fn open(running: *Running, client: *Client, opened: *ws.Opened, options: ws.ConnectOptions) !void {
    var buf: [64]u8 = undefined;
    try ws.connect(opened, client, testing.allocator, test_io.io(), running.url(&buf, "/"), options);
}

test "messages of every kind and size come back whole, compressed or not" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const running = try Running.start(gpa, .of(echo));
    defer running.stop();
    var client: Client = .init(gpa, .{});
    defer client.deinit(io);
    for ([_]?ws.Compression{ null, .{}, .{ .no_context_takeover = true, .window_bits = 10 } }) |compression| {
        var opened: ws.Opened = undefined;
        try open(running, &client, &opened, .{ .protocols = &.{ "echo", "chat" }, .compression = compression });
        defer opened.deinit(io);
        try testing.expectEqualStrings("chat", opened.protocol.?);
        try testing.expectEqual(compression != null, opened.conn.deflate != null);
        const big = try gpa.alloc(u8, 300_000);
        defer gpa.free(big);
        for (big, 0..) |*b, i| b.* = @truncate(i % 251);
        for ([_]struct { ws.Conn.Kind, []const u8 }{ .{ .text, "hello, κόσμε" }, .{ .binary, big }, .{ .text, "" }, .{ .binary, big[0..126] }, .{ .binary, big[0..65536] } }) |case| {
            try opened.conn.send(io, case[0], case[1]);
            const kind, const back = (try opened.conn.readMessage(io, gpa, .limited(1 << 24))).?;
            defer gpa.free(back);
            try testing.expectEqual(case[0], kind);
            try testing.expectEqualSlices(u8, case[1], back);
        }
        // In pieces, a ping between them.
        var piece_buf: [64]u8 = undefined;
        var mw = opened.conn.writer(io, .text, &piece_buf);
        for (0..50) |i| try mw.interface.print("piece {d}; ", .{i});
        try opened.conn.ping(io, "between");
        try mw.end();
        const kind, const back = (try opened.conn.readMessage(io, gpa, .limited(1 << 24))).?;
        defer gpa.free(back);
        try testing.expectEqual(ws.Conn.Kind.text, kind);
        try testing.expect(std.mem.startsWith(u8, back, "piece 0; piece 1; "));
        try testing.expect(std.mem.endsWith(u8, back, "piece 49; "));
        opened.conn.close(io, wire.ws.Close.normal, "done");
        try testing.expectEqual(wire.ws.Close.normal, opened.conn.peer_close.?.code);
    }
}

/// Send raw frames from the client side of a WebSocket; what the server
/// sends back, until it closes.
fn rawExchange(running: *Running, gpa: std.mem.Allocator, frames: []const u8) ![]u8 {
    const io = test_io.io();
    const address = try Io.net.IpAddress.parse("127.0.0.1", running.port);
    const stream = try address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var wbuf: [4096]u8 = undefined;
    var w = stream.writer(io, &wbuf);
    try w.interface.writeAll("GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n");
    try w.interface.writeAll(frames);
    try w.interface.flush();
    var rbuf: [4096]u8 = undefined;
    var r = stream.reader(io, &rbuf);
    const all = r.interface.allocRemaining(gpa, .limited(1 << 20)) catch |err| switch (err) {
        error.ReadFailed => return gpa.dupe(u8, ""),
        else => |e| return e,
    };
    defer gpa.free(all);
    const head_end = std.mem.find(u8, all, "\r\n\r\n").? + 4;
    try testing.expect(std.mem.find(u8, all[0..head_end], "Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n") != null);
    return gpa.dupe(u8, all[head_end..]);
}

/// A client's frame: masked with a zero key, which leaves the payload as
/// it is.
fn clientFrame(buf: []u8, first: u8, payload: []const u8) []const u8 {
    std.debug.assert(payload.len < 126);
    buf[0] = first;
    buf[1] = 0x80 | @as(u8, @intCast(payload.len));
    @memset(buf[2..6], 0);
    @memcpy(buf[6..][0..payload.len], payload);
    return buf[0 .. 6 + payload.len];
}

/// The close code of the close frame at the end of what a server sent.
fn closeCode(bytes: []const u8) ?u16 {
    var at: usize = 0;
    var code: ?u16 = null;
    while (at + 2 <= bytes.len) {
        const h, const size = (wire.ws.parseHeader(bytes[at..]) catch return null) orelse return code;
        const payload = bytes[at + size ..][0..@intCast(h.len)];
        if (h.opcode == .close and payload.len >= 2) code = std.mem.readInt(u16, payload[0..2], .big);
        at += size + payload.len;
    }
    return code;
}

test "frames RFC 6455 forbids are refused with the close code it names" {
    const gpa = testing.allocator;
    const running = try Running.start(gpa, .of(echo));
    defer running.stop();
    var buf: [256]u8 = undefined;
    const Case = struct { []const u8, u16 };
    var cases: [6]Case = undefined;
    var storage: [6][256]u8 = undefined;
    cases[0] = .{ clientFrame(&storage[0], 0x81, "ok \xc3\x28"), wire.ws.Close.invalid_payload };
    cases[1] = .{ clientFrame(&storage[1], 0x80, "lone continuation"), wire.ws.Close.protocol_error };
    cases[2] = .{ clientFrame(&storage[2], 0x83, "reserved opcode"), wire.ws.Close.protocol_error };
    cases[3] = .{ clientFrame(&storage[3], 0xc1, "rsv1 with no extension"), wire.ws.Close.protocol_error };
    cases[4] = .{ clientFrame(&storage[4], 0x09, "fragmented ping"), wire.ws.Close.protocol_error };
    // Unmasked from a client.
    @memcpy(buf[0..4], &[_]u8{ 0x81, 0x02, 'h', 'i' });
    cases[5] = .{ buf[0..4], wire.ws.Close.protocol_error };
    for (cases) |case| {
        const got = try rawExchange(running, gpa, case[0]);
        defer gpa.free(got);
        try testing.expectEqual(case[1], closeCode(got).?);
    }
}

test "a ping is answered with its payload, and a close with the same code" {
    const gpa = testing.allocator;
    const running = try Running.start(gpa, .of(echo));
    defer running.stop();
    var a: [256]u8 = undefined;
    var b: [256]u8 = undefined;
    var frames: [512]u8 = undefined;
    const ping = clientFrame(&a, 0x89, "are you there");
    const close = clientFrame(&b, 0x88, "\x0f\xa0bye");
    @memcpy(frames[0..ping.len], ping);
    @memcpy(frames[ping.len..][0..close.len], close);
    const got = try rawExchange(running, gpa, frames[0 .. ping.len + close.len]);
    defer gpa.free(got);
    const h, const size = (try wire.ws.parseHeader(got)).?;
    try testing.expectEqual(wire.ws.Opcode.pong, h.opcode);
    try testing.expectEqualStrings("are you there", got[size..][0..@intCast(h.len)]);
    try testing.expectEqual(@as(u16, 4000), closeCode(got).?);
}
