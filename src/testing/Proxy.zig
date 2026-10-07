//! Test-only: a proxy on 127.0.0.1, as a company runs one. Over HTTP,
//! `CONNECT host:port` opens a tunnel and a request with an absolute URL is
//! passed on to its host; over SOCKS 4, 4a, 5 and 5h, the CONNECT command
//! opens a tunnel. It can require credentials, Basic or Digest for HTTP,
//! RFC 1929's for SOCKS5, and records each request's first line and how it
//! was answered for.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Server = @import("Server.zig");

const Proxy = @This();

io: Io,
gpa: Allocator,
listener: Io.net.Server,
port: u16,
options: Options,
task: Io.Future(void) = undefined,
group: Io.Group = .init,
stopping: std.atomic.Value(bool) = .init(false),
mutex: Io.Mutex = .init,
/// Each request's first line, one to a line; SOCKS requests as `SOCKS <v>
/// <host>:<port>`.
log: std.ArrayList(u8) = .empty,
/// Connections accepted.
accepted: std.atomic.Value(u32) = .init(0),
/// Requests refused for want of credentials.
challenges: std.atomic.Value(u32) = .init(0),

pub const Options = struct {
    kind: Kind = .http,
    /// `user:password` the proxy requires; null takes anyone.
    credential: ?[]const u8 = null,
    /// How an HTTP proxy asks for the credential.
    scheme: enum { basic, digest } = .basic,
    /// What an HTTP proxy asks with, overriding `scheme`: `Negotiate`, say.
    challenge: ?[]const u8 = null,
    /// Refuse every tunnel with this status.
    refuse: ?u16 = null,
};

pub const Kind = enum { http, socks };

pub fn start(gpa: Allocator, io: Io, options: Options) !*Proxy {
    const p = try gpa.create(Proxy);
    errdefer gpa.destroy(p);
    var listener = try (try Io.net.IpAddress.parse("127.0.0.1", 0)).listen(io, .{ .reuse_address = true });
    errdefer listener.deinit(io);
    p.* = .{ .io = io, .gpa = gpa, .listener = listener, .port = listener.socket.address.getPort(), .options = options };
    p.task = io.concurrent(serve, .{p}) catch return error.SkipZigTest;
    return p;
}

pub fn stop(p: *Proxy) void {
    const io = p.io;
    p.stopping.store(true, .release);
    const address = Io.net.IpAddress.parse("127.0.0.1", p.port) catch unreachable; // unreachable: a literal address
    if (address.connect(io, .{ .mode = .stream })) |stream| stream.close(io) else |_| {}
    p.task.await(io);
    p.group.cancel(io);
    p.listener.deinit(io);
    p.log.deinit(p.gpa);
    p.gpa.destroy(p);
}

/// A copy of the log, in `gpa`.
pub fn lines(p: *Proxy, gpa: Allocator) ![]u8 {
    p.mutex.lockUncancelable(p.io);
    defer p.mutex.unlock(p.io);
    return gpa.dupe(u8, p.log.items);
}

fn note(p: *Proxy, comptime format: []const u8, args: anytype) void {
    p.mutex.lockUncancelable(p.io);
    defer p.mutex.unlock(p.io);
    p.log.print(p.gpa, format ++ "\n", args) catch return;
}

fn serve(p: *Proxy) void {
    while (true) {
        const stream = p.listener.accept(p.io) catch return;
        if (p.stopping.load(.acquire)) return stream.close(p.io);
        _ = p.accepted.fetchAdd(1, .monotonic);
        p.group.concurrent(p.io, handle, .{ p, stream }) catch stream.close(p.io);
    }
}

fn handle(p: *Proxy, stream: Io.net.Stream) void {
    defer stream.close(p.io);
    var read_buffer: [16 << 10]u8 = undefined;
    var write_buffer: [1024]u8 = undefined;
    var r = stream.reader(p.io, &read_buffer);
    var w = stream.writer(p.io, &write_buffer);
    switch (p.options.kind) {
        .http => p.handleHttp(&r.interface, &w.interface, stream) catch return,
        .socks => p.handleSocks(&r.interface, &w.interface, stream) catch return,
    }
}

fn handleHttp(p: *Proxy, r: *Io.Reader, w: *Io.Writer, client: Io.net.Stream) !void {
    while (true) {
        while (std.mem.find(u8, r.buffered(), "\r\n\r\n") == null) try r.fillMore();
        const head_len = std.mem.find(u8, r.buffered(), "\r\n\r\n").? + 4;
        const head = r.buffered()[0..head_len];
        const line = head[0 .. std.mem.find(u8, head, "\r\n") orelse head.len];
        const answered = Server.headerValue(head, "proxy-authorization");
        p.note("{s} [{s}]", .{ line, if (answered) |a| a[0..@min(a.len, 6)] else "none" });
        if (!p.authorized(answered)) {
            _ = p.challenges.fetchAdd(1, .monotonic);
            r.toss(head_len);
            try p.challenge(w);
            continue;
        }
        if (p.options.refuse) |status| {
            try w.print("HTTP/1.1 {d} Refused\r\nContent-Length: 0\r\n\r\n", .{status});
            return w.flush();
        }
        const target = line[std.mem.findScalar(u8, line, ' ').? + 1 .. std.mem.findScalarPos(u8, line, std.mem.findScalar(u8, line, ' ').? + 1, ' ').?];
        if (std.mem.startsWith(u8, line, "CONNECT ")) {
            const upstream = try dialAuthority(p.io, target);
            defer upstream.close(p.io);
            r.toss(head_len);
            try w.writeAll("HTTP/1.1 200 Connection established\r\n\r\n");
            try w.flush();
            return relay(p.io, client, r, upstream);
        }
        // Absolute form: the request goes to its host as it came, and the
        // connection becomes a tunnel to that host.
        const after_scheme = (std.mem.find(u8, target, "://") orelse return error.BadRequest) + 3;
        const authority_end = std.mem.findScalarPos(u8, target, after_scheme, '/') orelse target.len;
        const upstream = try dialAuthority(p.io, target[after_scheme..authority_end]);
        defer upstream.close(p.io);
        return relay(p.io, client, r, upstream);
    }
}

fn authorized(p: *Proxy, answered: ?[]const u8) bool {
    const want = p.options.credential orelse return true;
    if (p.options.challenge != null) return false;
    const answer = answered orelse return false;
    switch (p.options.scheme) {
        .basic => {
            var expect_buf: [256]u8 = undefined;
            const encoded = std.base64.standard.Encoder.encode(&expect_buf, want);
            return std.mem.startsWith(u8, answer, "Basic ") and std.mem.eql(u8, answer["Basic ".len..], encoded);
        },
        // The test checks the Digest answer's shape; RFC 7616's arithmetic
        // is proved against its own examples in `wire.auth`.
        .digest => return std.mem.startsWith(u8, answer, "Digest ") and std.mem.find(u8, answer, "nonce=\"proxy-nonce\"") != null,
    }
}

fn challenge(p: *Proxy, w: *Io.Writer) !void {
    const value = p.options.challenge orelse switch (p.options.scheme) {
        .basic => "Basic realm=\"proxy\"",
        .digest => "Digest realm=\"proxy\", nonce=\"proxy-nonce\", qop=\"auth\", algorithm=SHA-256",
    };
    try w.print("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: {s}\r\nContent-Length: 0\r\n\r\n", .{value});
    try w.flush();
}

fn handleSocks(p: *Proxy, r: *Io.Reader, w: *Io.Writer, client: Io.net.Stream) !void {
    const version = try r.takeByte();
    var host_buf: [256]u8 = undefined;
    var host: []const u8 = undefined;
    var port: u16 = undefined;
    if (version == 4) {
        _ = try r.takeByte(); // CONNECT
        port = try r.takeInt(u16, .big);
        const ip = (try r.takeArray(4)).*;
        _ = try r.takeDelimiterInclusive(0); // user
        if (ip[0] == 0 and ip[1] == 0 and ip[2] == 0 and ip[3] != 0) {
            const name = try r.takeDelimiterExclusive(0);
            r.toss(1);
            host = try std.mem.print(&host_buf, "{s}", .{name});
        } else host = try std.mem.print(&host_buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] });
        p.note("SOCKS 4 {s}:{d}", .{ host, port });
        try w.writeAll(&.{ 0, 90, 0, 0, 0, 0, 0, 0 });
        try w.flush();
    } else {
        const methods = try r.take(try r.takeByte());
        const want_auth = p.options.credential != null;
        if (want_auth and std.mem.findScalar(u8, methods, 2) == null) {
            try w.writeAll(&.{ 5, 255 });
            return w.flush();
        }
        try w.writeAll(&.{ 5, if (want_auth) 2 else 0 });
        try w.flush();
        if (want_auth) {
            _ = try r.takeByte();
            const user = try r.take(try r.takeByte());
            var given_buf: [512]u8 = undefined;
            var given: std.ArrayList(u8) = .initBuffer(&given_buf);
            given.appendSliceAssumeCapacity(user);
            given.appendAssumeCapacity(':');
            given.appendSliceAssumeCapacity(try r.take(try r.takeByte()));
            const ok = std.mem.eql(u8, given.items, p.options.credential.?);
            try w.writeAll(&.{ 1, if (ok) 0 else 1 });
            try w.flush();
            if (!ok) return;
        }
        _ = try r.takeArray(3); // version, CONNECT, reserved
        switch (try r.takeByte()) {
            1 => {
                const ip = (try r.takeArray(4)).*;
                host = try std.mem.print(&host_buf, "{d}.{d}.{d}.{d}", .{ ip[0], ip[1], ip[2], ip[3] });
            },
            3 => host = try std.mem.print(&host_buf, "{s}", .{try r.take(try r.takeByte())}),
            4 => {
                const ip = (try r.takeArray(16)).*;
                // The tests' IPv6 targets are all loopback.
                if (!std.mem.eql(u8, &ip, &(@as([15]u8, @splat(0)) ++ .{1}))) return error.BadRequest;
                host = try std.mem.print(&host_buf, "[::1]", .{});
            },
            else => return error.BadRequest,
        }
        port = try r.takeInt(u16, .big);
        p.note("SOCKS 5 {s}:{d}", .{ host, port });
        try w.writeAll(&.{ 5, 0, 0, 1, 127, 0, 0, 1, 0, 0 });
        try w.flush();
    }
    var authority_buf: [300]u8 = undefined;
    const upstream = try dialAuthority(p.io, try std.mem.print(&authority_buf, "{s}:{d}", .{ host, port }));
    defer upstream.close(p.io);
    return relay(p.io, client, r, upstream);
}

fn dialAuthority(io: Io, authority: []const u8) !Io.net.Stream {
    const colon = std.mem.findScalarLast(u8, authority, ':') orelse return error.BadRequest;
    const port = try std.fmt.parseUnsigned(u16, authority[colon + 1 ..], 10);
    var host = authority[0..colon];
    if (host.len >= 2 and host[0] == '[') host = host[1 .. host.len - 1];
    // Names the tests make up all stand for this machine.
    if (std.mem.eql(u8, host, "localhost") or std.mem.eql(u8, host, "::1") or std.mem.endsWith(u8, host, ".test")) host = "127.0.0.1";
    const address = try Io.net.IpAddress.parse(host, port);
    return address.connect(io, .{ .mode = .stream });
}

/// Copy both ways between `client`, whose bytes already read wait in
/// `pending`, and `upstream`, until either side ends.
fn relay(io: Io, client: Io.net.Stream, pending: *Io.Reader, upstream: Io.net.Stream) !void {
    var back = try io.concurrent(copy, .{ io, upstream, client });
    defer back.cancel(io);
    pump(io, pending, upstream);
    back.await(io);
}

fn copy(io: Io, from: Io.net.Stream, to: Io.net.Stream) void {
    var in_buffer: [16 << 10]u8 = undefined;
    var r = from.reader(io, &in_buffer);
    pump(io, &r.interface, to);
}

/// Pass on what `r` gives, each piece as it comes, until it ends; then end
/// `to`'s sending side.
fn pump(io: Io, r: *Io.Reader, to: Io.net.Stream) void {
    var out_buffer: [16 << 10]u8 = undefined;
    var w = to.writer(io, &out_buffer);
    while (true) {
        if (r.bufferedLen() == 0) r.fillMore() catch break;
        w.interface.writeAll(r.buffered()) catch break;
        r.tossBuffered();
        w.interface.flush() catch break;
    }
    // ziglint-ignore: Z026 either side ending ends the tunnel; there is nothing to report
    to.shutdown(io, .send) catch {};
}
