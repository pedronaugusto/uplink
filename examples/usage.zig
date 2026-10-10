//! A client sends a request and reads its response, on a kept connection,
//! through the same calls whether the URL is `http` or `https` and whether
//! a proxy stands between.
//!
//! `zig build examples` builds AND runs this against a server it starts on
//! loopback; `zig build docs -- usage` extracts the region between the
//! usage markers into README.md, so the snippet a reader copies is code CI
//! executes.

const std = @import("std");
const Io = std.Io;
const reactor = @import("reactor");
const uplink = @import("uplink");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    // The example runs evented, on a reactor runtime; `init.io` would do as
    // well.
    var runtime: reactor.Runtime = undefined;
    try runtime.init(gpa, .{ .environ = init.minimal.environ });
    defer runtime.deinit();
    try runtime.start();
    var server: Answering = undefined;
    try server.start(runtime.io());
    defer server.stop(runtime.io());
    var url_buffer: [64]u8 = undefined;
    const url = try std.mem.print(&url_buffer, "http://127.0.0.1:{d}/hello", .{server.port});

    // --- README:usage ---
    // Any `std.Io`: here a reactor runtime's, the evented one.
    const io = runtime.io();

    // One client for the program: it keeps connections for reuse, follows
    // redirects, tries failed requests again where that is safe, and may be
    // shared by several tasks. Cookies go in a jar of the caller's.
    var jar: uplink.CookieJar = .init(gpa, .{});
    defer jar.deinit(io);
    var client: uplink.Client = .init(gpa, .{
        .timeouts = .{ .connect = .fromSeconds(10), .activity = .fromSeconds(30) },
        .cookies = &jar,
        .user_agent = "example/1.0",
    });
    defer client.deinit(io);

    var diagnostics: uplink.Diagnostics = .{};
    var response = client.send(io, .{
        .method = .POST,
        .url = url,
        .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
        .body = .{ .bytes = "ping" },
        // The whole request, retries and redirects included.
        .timeout = .{ .duration = .{ .raw = .fromSeconds(60), .clock = .awake } },
        .diagnostics = &diagnostics,
    }) catch |err| {
        std.log.err("{t} while at {t}", .{ err, diagnostics.stage });
        return err;
    };
    defer response.deinit(io);

    std.debug.assert(response.status == .ok);
    const body = try response.collect(gpa, io, .limited(1 << 20));
    defer gpa.free(body);
    std.debug.assert(std.mem.eql(u8, body, "pong"));
    // --- README:usage ---
}

/// A server that answers `pong` to every request, until stopped.
const Answering = struct {
    listener: Io.net.Server,
    port: u16,
    task: Io.Future(void),

    fn start(a: *Answering, io: Io) !void {
        a.listener = try (try Io.net.IpAddress.parse("127.0.0.1", 0)).listen(io, .{ .reuse_address = true });
        errdefer a.listener.deinit(io);
        a.port = a.listener.socket.address.getPort();
        a.task = try io.concurrent(serve, .{ io, &a.listener });
    }

    fn stop(a: *Answering, io: Io) void {
        a.task.cancel(io);
        a.listener.deinit(io);
    }

    fn serve(io: Io, listener: *Io.net.Server) void {
        const stream = listener.accept(io) catch return;
        defer stream.close(io);
        var read_buffer: [4096]u8 = undefined;
        var write_buffer: [256]u8 = undefined;
        var r = stream.reader(io, &read_buffer);
        var w = stream.writer(io, &write_buffer);
        while (std.mem.find(u8, r.interface.buffered(), "ping") == null) r.interface.fillMore() catch return;
        w.interface.writeAll("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong") catch return;
        w.interface.flush() catch return;
        // Wait for the client to close the connection.
        while (true) r.interface.fillMore() catch return;
    }
};
