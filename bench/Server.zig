//! The benchmarks' server: keep-alive HTTP/1.1 on loopback, answering by
//! path with a fixed body, so the client's cost is what is measured. Each
//! connection runs as a task of its own.
//!
//! - `/0`: an empty body.
//! - `/1k`: 1 KiB.
//! - `/big`: 64 MiB, written in 64 KiB pieces.
//! - `/chunked`: 16 MiB in 4 KiB chunks.
//! - `/gzip`: the text corpus, gzip-compressed once at start.
//! - `/redirect`: a 302 to `/0`.
//! - `/private`: a 401 asking for Basic, unless the request answers it.
//!
//! With credentials it speaks TLS 1.3 (cloak's server) and answers the same.

const std = @import("std");
const Io = std.Io;
const cloak = @import("cloak");

const Server = @This();

io: Io,
listener: Io.net.Server,
port: u16,
task: Io.Future(void) = undefined,
group: Io.Group = .init,
/// The `/gzip` body.
gzip: []const u8 = "",
/// What a connection is served over TLS with; null: plain TCP.
credentials: ?[]const cloak.tls.Credential = null,
gpa: std.mem.Allocator = undefined,

pub const big_len = 64 << 20;
pub const chunked_len = 16 << 20;

/// A server answering `/gzip` with `gzip`, which must outlive it, over TLS with
/// `credentials` when it has them.
pub fn start(gpa: std.mem.Allocator, io: Io, s: *Server, gzip: []const u8, credentials: ?[]const cloak.tls.Credential) !void {
    var listener = try (try Io.net.IpAddress.parse("127.0.0.1", 0)).listen(io, .{ .reuse_address = true });
    errdefer listener.deinit(io);
    s.* = .{ .io = io, .listener = listener, .port = listener.socket.address.getPort(), .gzip = gzip, .credentials = credentials, .gpa = gpa };
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

const Which = enum { empty, kib, big, chunked, gzip, redirect, private, authorized };

fn which(path: []const u8) Which {
    const table = [_]struct { []const u8, Which }{
        .{ "/1k", .kib },            .{ "/big", .big },         .{ "/chunked", .chunked }, .{ "/gzip", .gzip },
        .{ "/redirect", .redirect }, .{ "/private", .private },
    };
    for (table) |t| if (std.mem.eql(u8, path, t[0])) return t[1];
    return .empty;
}

fn handle(s: *Server, stream: Io.net.Stream) void {
    defer stream.close(s.io);
    var read_buffer: [16 << 10]u8 = undefined;
    var write_buffer: [64 << 10]u8 = undefined;
    var r = stream.reader(s.io, &read_buffer);
    var w = stream.writer(s.io, &write_buffer);
    const credentials = s.credentials orelse return s.requests(&r.interface, &w.interface);
    var session: cloak.tls.Session = undefined;
    var plain_in: [16 << 10]u8 = undefined;
    var plain_out: [64 << 10]u8 = undefined;
    session.accept(s.gpa, s.io, &r.interface, &w.interface, &plain_in, &plain_out, .{ .credentials = credentials, .eof = .allow }) catch return;
    defer session.deinit();
    s.requests(session.reader(), session.writer());
}

/// Requests read from `r` and answered on `w` until either ends.
fn requests(s: *Server, r: *Io.Reader, w: *Io.Writer) void {
    while (true) {
        while (std.mem.find(u8, r.buffered(), "\r\n\r\n") == null) r.fillMore() catch return;
        const end = std.mem.find(u8, r.buffered(), "\r\n\r\n").? + 4;
        const head = r.buffered()[0..end];
        const at = (std.mem.findScalar(u8, head, ' ') orelse return) + 1;
        const path = head[at..][0 .. std.mem.findScalar(u8, head[at..], ' ') orelse return];
        var reply = which(path);
        if (reply == .private and std.mem.find(u8, head, "\r\nAuthorization: ") != null) reply = .authorized;
        r.toss(end);
        s.answer(w, reply) catch return;
        w.flush() catch return;
    }
}

fn answer(s: *Server, w: *Io.Writer, a: Which) Io.Writer.Error!void {
    const kib: [1024]u8 = @splat('k');
    const piece: [64 << 10]u8 = @splat('b');
    switch (a) {
        .empty, .authorized => try w.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
        .private => try w.writeAll("HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"bench\"\r\nContent-Length: 0\r\n\r\n"),
        .kib => {
            try w.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 1024\r\n\r\n");
            try w.writeAll(&kib);
        },
        .big => {
            try w.print("HTTP/1.1 200 OK\r\nContent-Length: {d}\r\n\r\n", .{big_len});
            for (0..big_len / piece.len) |_| try w.writeAll(&piece);
        },
        .chunked => {
            try w.writeAll("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
            for (0..chunked_len / (4 << 10)) |_| {
                try w.writeAll("1000\r\n");
                try w.writeAll(piece[0 .. 4 << 10]);
                try w.writeAll("\r\n");
            }
            try w.writeAll("0\r\n\r\n");
        },
        .gzip => {
            try w.print("HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: {d}\r\n\r\n", .{s.gzip.len});
            try w.writeAll(s.gzip);
        },
        .redirect => try w.writeAll("HTTP/1.1 302 Found\r\nLocation: /0\r\nContent-Length: 0\r\n\r\n"),
    }
}
