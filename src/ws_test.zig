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

    fn start(gpa: std.mem.Allocator, handler: *const Server.Handler) !*Running {
        return startWith(gpa, .{}, handler);
    }

    fn startWith(gpa: std.mem.Allocator, options: Server.Options, handler: *const Server.Handler) !*Running {
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

/// One end of an HTTP/2 connection over a raw stream, frames read into
/// events as a test asks for them.
const RawH2 = struct {
    const h2 = wire.h2;
    const hpack = wire.hpack;
    streams: [8]h2.Connection.Stream = @splat(.{}),
    block: [4096]u8 = undefined,
    field_bytes: [4096]u8 = undefined,
    fields: [32]hpack.Field = undefined,
    db: [8192]u8 = undefined,
    de: [129]hpack.Table.Entry = undefined,
    eb: [8192]u8 = undefined,
    ee: [129]hpack.Table.Entry = undefined,
    conn: h2.Connection = undefined,
    stream: Io.net.Stream = undefined,
    rbuf: [32 << 10]u8 = undefined,
    wbuf: [32 << 10]u8 = undefined,
    r: Io.net.Stream.Reader = undefined,
    w: Io.net.Stream.Writer = undefined,

    fn open(c: *RawH2, port: u16) !void {
        const io = test_io.io();
        c.stream = try (try Io.net.IpAddress.parse("127.0.0.1", port)).connect(io, .{ .mode = .stream });
        c.r = c.stream.reader(io, &c.rbuf);
        c.w = c.stream.writer(io, &c.wbuf);
        c.conn = .init(.client, .{ .enable_push = false }, .{}, .{ .streams = &c.streams, .block = &c.block, .field_bytes = &c.field_bytes, .fields = &c.fields, .decoder_bytes = &c.db, .decoder_entries = &c.de, .encoder_bytes = &c.eb, .encoder_entries = &c.ee });
        try c.conn.start(&c.w.interface);
        try c.w.interface.flush();
    }

    fn close(c: *RawH2) void {
        c.stream.close(test_io.io());
    }

    /// The next frame's event, the protocol's own answers sent.
    fn next(c: *RawH2) !?h2.Connection.Event {
        const head_bytes = try c.r.interface.peek(h2.head_len);
        const head = h2.Head.parse(head_bytes[0..h2.head_len]);
        const whole = try c.r.interface.peek(h2.head_len + head.len);
        const payload = whole[h2.head_len..];
        const event = try c.conn.receive(&c.w.interface, head, payload);
        try c.w.interface.flush();
        // An event's bytes live in the reader's buffer until the next read.
        c.r.interface.toss(h2.head_len + head.len);
        return event;
    }
};

test "a WebSocket opens over HTTP/2 by an extended CONNECT, its frames the stream's data" {
    const gpa = testing.allocator;
    const running = try Running.startWith(gpa, .{ .h2c = .alongside_http1 }, .of(echo));
    defer running.stop();
    const c = try gpa.create(RawH2);
    defer gpa.destroy(c);
    c.* = .{};
    try c.open(running.port);
    defer c.close();
    // The server's settings allow an extended CONNECT.
    while (!c.conn.remote.enable_connect_protocol) _ = try c.next();
    const id = try c.conn.open();
    var scratch: [1024]u8 = undefined;
    try c.conn.writeHeaders(&c.w.interface, id, &.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":protocol", .value = "websocket" },
        .{ .name = ":scheme", .value = "http" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "127.0.0.1" },
        .{ .name = "sec-websocket-version", .value = "13" },
        .{ .name = "sec-websocket-protocol", .value = "echo" },
    }, false, &scratch);
    try c.w.interface.flush();
    const status, const chosen = while (true) {
        const event = try c.next() orelse continue;
        if (event != .headers) continue;
        var status: []const u8 = "";
        var chosen: []const u8 = "";
        for (event.headers.fields) |f| {
            if (std.mem.eql(u8, f.name, ":status")) status = f.value;
            if (std.mem.eql(u8, f.name, "sec-websocket-protocol")) chosen = f.value;
        }
        break .{ try gpa.dupe(u8, status), try gpa.dupe(u8, chosen) };
    };
    defer gpa.free(status);
    defer gpa.free(chosen);
    try testing.expectEqualStrings("200", status);
    try testing.expectEqualStrings("echo", chosen);
    var frame_buf: [64]u8 = undefined;
    _ = try c.conn.writeData(&c.w.interface, id, clientFrame(&frame_buf, 0x81, "hello over h2"), false);
    try c.w.interface.flush();
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(gpa);
    while (got.items.len < 2 + 13) {
        const event = try c.next() orelse continue;
        if (event == .data) {
            try got.appendSlice(gpa, event.data.bytes);
            try c.conn.giveBack(&c.w.interface, id, event.data.bytes.len);
        }
    }
    const h, const size = (try wire.ws.parseHeader(got.items)).?;
    try testing.expectEqual(wire.ws.Opcode.text, h.opcode);
    try testing.expectEqualStrings("hello over h2", got.items[size..][0..@intCast(h.len)]);
    // A close ends it: the server answers with its own and ends the stream.
    var close_payload: [2]u8 = undefined;
    std.mem.writeInt(u16, &close_payload, 1000, .big);
    _ = try c.conn.writeData(&c.w.interface, id, clientFrame(&frame_buf, 0x88, &close_payload), true);
    try c.w.interface.flush();
    got.clearRetainingCapacity();
    var ended = false;
    while (!ended) {
        const event = try c.next() orelse continue;
        switch (event) {
            .data => |d| {
                try got.appendSlice(gpa, d.bytes);
                ended = d.end_stream;
            },
            .reset => ended = true,
            else => {},
        }
    }
    try testing.expectEqual(@as(?u16, 1000), closeCode(got.items));
}

/// A transport whose stream failed: canceled, or broken.
const Failed = struct {
    canceled: bool,
    in: [64]u8 = undefined,
    reader: Io.Reader = .failing,
    writer: Io.Writer = .failing,
    conn: ws.Conn = undefined,

    /// The connection over the failed stream, held here so its transport
    /// finds this.
    fn open(f: *Failed) *ws.Conn {
        f.reader.buffer = &f.in;
        f.conn = .init(testing.allocator, .server, .{ .reader = &f.reader, .writer = &f.writer, .flushFn = flush, .readableFn = readable, .canceledFn = canceledFn }, .{}, null);
        return &f.conn;
    }

    fn flush(_: *ws.Conn.Transport, _: Io) Io.Writer.Error!void {
        return error.WriteFailed;
    }

    fn readable(_: *ws.Conn.Transport, _: Io, _: Io.Duration) Io.Cancelable!@import("net/Timed.zig").Readiness {
        return .ready;
    }

    fn canceledFn(t: *ws.Conn.Transport) bool {
        const conn: *ws.Conn = @alignCast(@fieldParentPtr("transport", t));
        const f: *Failed = @alignCast(@fieldParentPtr("conn", conn));
        return f.canceled;
    }
};

test "the client opens a WebSocket over HTTP/2 when the server takes an extended CONNECT, and by Upgrade when it does not" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const running = try Running.startWith(gpa, .{ .h2c = .alongside_http1 }, .of(echo));
    defer running.stop();
    var client: Client = .init(gpa, .{ .http2 = .prior_knowledge });
    defer client.deinit(io);
    var url_buf: [64]u8 = undefined;
    const url = running.url(&url_buf, "/");
    // Two at once, each a stream of the one connection.
    var first: ws.Opened = undefined;
    try ws.connect(&first, &client, gpa, io, url, .{ .protocols = &.{"echo"} });
    defer first.deinit(io);
    var second: ws.Opened = undefined;
    try ws.connect(&second, &client, gpa, io, url, .{ .compression = null });
    defer second.deinit(io);
    try testing.expect(first.stream.carrier == .stream);
    try testing.expect(second.stream.carrier == .stream);
    try testing.expectEqual(first.stream.carrier.stream.h2, second.stream.carrier.stream.h2);
    try testing.expectEqualStrings("echo", first.protocol.?);
    const big = try gpa.alloc(u8, 300_000);
    defer gpa.free(big);
    for (big, 0..) |*b, i| b.* = @truncate(i % 251);
    for ([_]*ws.Opened{ &first, &second }) |o| {
        for ([_][]const u8{ "hello over h2", big }) |payload| {
            try o.conn.send(io, .binary, payload);
            _, const back = (try o.conn.readMessage(io, gpa, .limited(1 << 24))).?;
            defer gpa.free(back);
            try testing.expectEqualSlices(u8, payload, back);
        }
    }
    first.conn.close(io, wire.ws.Close.normal, "done");
    try testing.expectEqual(wire.ws.Close.normal, first.conn.peer_close.?.code);
    try testing.expectEqual(@as(u64, 1), client.stats().connections_opened);

    // A client in HTTP/1.1 asks by Upgrade, over a connection of its own.
    var plain: Client = .init(gpa, .{});
    defer plain.deinit(io);
    var upgraded: ws.Opened = undefined;
    try ws.connect(&upgraded, &plain, gpa, io, url, .{});
    defer upgraded.deinit(io);
    try testing.expect(upgraded.stream.carrier == .conn);
    try upgraded.conn.send(io, .text, "hello over 1.1");
    _, const back = (try upgraded.conn.readMessage(io, gpa, .limited(1 << 10))).?;
    defer gpa.free(back);
    try testing.expectEqualStrings("hello over 1.1", back);
}

test "a stream that failed for a cancelation says so on reads and writes, and one that broke does not" {
    const io = test_io.io();
    for ([_]bool{ true, false }) |canceled| {
        var failed: Failed = .{ .canceled = canceled };
        const conn = failed.open();
        defer conn.deinit();
        const want: anyerror = if (canceled) error.Canceled else error.ConnectionFailed;
        var buffer: [64]u8 = undefined;
        try testing.expectError(want, conn.next(io, &buffer));
        try testing.expectError(want, conn.send(io, .text, "hello"));
        // A message written in pieces keeps why a frame it drained failed.
        var piece: [4]u8 = undefined;
        var mw = conn.writer(io, .binary, &piece);
        try testing.expectError(error.WriteFailed, mw.interface.writeAll("more than four bytes"));
        try testing.expectError(want, mw.end());
    }
}
