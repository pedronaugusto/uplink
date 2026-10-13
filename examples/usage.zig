//! A server answers through a router, and a client calls it: a request
//! with a body sent over a kept connection, through the same calls whether
//! the URL is `http` or `https` and whether a proxy stands between.
//!
//! `zig build examples` builds AND runs this; `zig build docs -- usage`
//! extracts the region between the usage markers into README.md, so the
//! snippet a reader copies is code CI executes.

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

    // --- README:usage ---
    // Any `std.Io`: here a reactor runtime's, the evented one.
    const io = runtime.io();

    // A server: patterns with Go 1.22's semantics, routed to handlers,
    // each given the request, with what the router captured, and the
    // response that answers it.
    const Echo = struct {
        fn handle(hio: Io, request: *uplink.server.Request, response: *uplink.server.Response) anyerror!void {
            var buffer: [256]u8 = undefined;
            const body = try request.reader(hio).readSliceShort(&buffer);
            try response.header("Content-Type", "text/plain");
            const w = try response.writer(hio);
            try w.print("{s}: {s}", .{ request.param("name").?, buffer[0..body] });
            try response.end(hio);
        }
    };
    var router: uplink.server.Router = .init(gpa);
    defer router.deinit();
    try router.add("POST /echo/{name}", .of(Echo.handle));
    var server: uplink.Server = .init(gpa, .{ .compression = .{} }, router.handler());
    defer server.deinit(io);
    var listener = try (try Io.net.IpAddress.parse("127.0.0.1", 0)).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    var serving = try io.concurrent(uplink.Server.serve, .{ &server, io, &listener });
    defer {
        server.shutdown(io);
        serving.await(io) catch |err| std.log.err("serve: {t}", .{err});
    }

    // A client for the program: it keeps connections for reuse, follows
    // redirects, tries failed requests again where that is safe, and may be
    // shared by several tasks. Cookies go in a jar of the caller's.
    var jar: uplink.CookieJar = .init(gpa, .{});
    defer jar.deinit(io);
    var client: uplink.Client = .init(gpa, .{
        .timeouts = .{ .connect = .literal("10s"), .activity = .literal("30s") },
        .cookies = &jar,
        .user_agent = "example/1.0",
    });
    defer client.deinit(io);

    var url_buffer: [64]u8 = undefined;
    const url = try std.mem.print(&url_buffer, "http://127.0.0.1:{d}/echo/ping", .{listener.socket.address.getPort()});
    var diagnostics: uplink.Diagnostics = .{};
    var response = client.send(io, .{
        .method = .POST,
        .url = url,
        .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
        .body = .{ .bytes = "hello" },
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
    std.debug.assert(std.mem.eql(u8, body, "ping: hello"));
    // --- README:usage ---
}
