//! The benchmarks' server: keep-alive HTTP/1.1 on loopback, answering by
//! path with a fixed body, so the client's cost is what is measured. Each
//! connection runs as a task of its own.
//!
//! - `/0`: an empty body.
//! - `/1k`: 1 KiB.
//! - `/big`: 64 MiB, written in 64 KiB pieces.
//! - `/chunked`: 1 MiB in 4 KiB chunks.

const std = @import("std");
const Io = std.Io;

const Server = @This();

io: Io,
listener: Io.net.Server,
port: u16,
task: Io.Future(void) = undefined,
group: Io.Group = .init,

pub const big_len = 64 << 20;

pub fn start(io: Io, s: *Server) !void {
    var listener = try (try Io.net.IpAddress.parse("127.0.0.1", 0)).listen(io, .{ .reuse_address = true });
    errdefer listener.deinit(io);
    s.* = .{ .io = io, .listener = listener, .port = listener.socket.address.getPort() };
    s.task = try io.concurrent(serve, .{s});
}

pub fn stop(s: *Server) void {
    s.task.cancel(s.io);
    s.group.cancel(s.io);
    s.listener.deinit(s.io);
}

fn serve(s: *Server) void {
    while (true) {
        const stream = s.listener.accept(s.io) catch return;
        s.group.concurrent(s.io, handle, .{ s, stream }) catch stream.close(s.io);
    }
}

fn handle(s: *Server, stream: Io.net.Stream) void {
    defer stream.close(s.io);
    var read_buffer: [16 << 10]u8 = undefined;
    var write_buffer: [64 << 10]u8 = undefined;
    var r = stream.reader(s.io, &read_buffer);
    var w = stream.writer(s.io, &write_buffer);
    const kib: [1024]u8 = @splat('k');
    const piece: [64 << 10]u8 = @splat('b');
    while (true) {
        while (std.mem.find(u8, r.interface.buffered(), "\r\n\r\n") == null) r.interface.fillMore() catch return;
        const end = std.mem.find(u8, r.interface.buffered(), "\r\n\r\n").? + 4;
        const head = r.interface.buffered()[0..end];
        const path = head[std.mem.findScalar(u8, head, ' ').? + 1 ..][0 .. std.mem.findScalar(u8, head[std.mem.findScalar(u8, head, ' ').? + 1 ..], ' ') orelse return];
        const which: enum { empty, kib, big, chunked } = if (std.mem.eql(u8, path, "/1k")) .kib else if (std.mem.eql(u8, path, "/big")) .big else if (std.mem.eql(u8, path, "/chunked")) .chunked else .empty;
        r.interface.toss(end);
        (switch (which) {
            .empty => w.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
            .kib => blk: {
                w.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 1024\r\n\r\n") catch |e| break :blk e;
                break :blk w.interface.writeAll(&kib);
            },
            .big => blk: {
                w.interface.print("HTTP/1.1 200 OK\r\nContent-Length: {d}\r\n\r\n", .{big_len}) catch |e| break :blk e;
                for (0..big_len / piece.len) |_| w.interface.writeAll(&piece) catch |e| break :blk e;
                break :blk {};
            },
            .chunked => blk: {
                w.interface.writeAll("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n") catch |e| break :blk e;
                for (0..256) |_| {
                    w.interface.writeAll("1000\r\n") catch |e| break :blk e;
                    w.interface.writeAll(piece[0 .. 4 << 10]) catch |e| break :blk e;
                    w.interface.writeAll("\r\n") catch |e| break :blk e;
                }
                break :blk w.interface.writeAll("0\r\n\r\n");
            },
        }) catch return;
        w.interface.flush() catch return;
    }
}
