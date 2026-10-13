//! An HTTP/1.1 conformance tool against uplink's server, from Zig: the
//! server answers on a port of its own, the tool's command runs with
//! `{url}` and `{port}` in its arguments replaced, its report is printed,
//! and the run fails when the tool does. h1spec and Http11Probe are the
//! tools it is run with. The server is an application as a user writes
//! one, a `Router`'s: `/` answers and echoes a body, `/echo` echoes the
//! fields, `/cookie` the cookies, as Http11Probe asks.
//!
//! zig build h1 -- <command> [arguments, {url} and {port} replaced]

const std = @import("std");
const Io = std.Io;
const reactor = @import("reactor");
const uplink = @import("uplink");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const arena = init.arena.allocator();
    const args = try init.minimal.args.toSlice(arena);
    if (args.len < 2) {
        std.log.err("usage: h1 <command> [arguments, {{url}} and {{port}} replaced]", .{});
        return error.Usage;
    }
    var runtime: reactor.Runtime = undefined;
    try runtime.init(gpa, .{ .environ = init.minimal.environ });
    defer runtime.deinit();
    try runtime.start();
    const io = runtime.io();

    var router: uplink.server.Router = .init(gpa);
    defer router.deinit();
    try router.add("/echo", .of(echoFields));
    try router.add("/cookie", .of(echoCookies));
    try router.add("/", .of(answer));
    var server: uplink.Server = .init(gpa, .{}, router.handler());
    defer server.deinit(io);
    var listener = try (try Io.net.IpAddress.parse("127.0.0.1", 0)).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    var serving = try io.concurrent(uplink.Server.serve, .{ &server, io, &listener });
    defer {
        server.shutdown(io);
        serving.await(io) catch |err| std.log.err("serve: {t}", .{err});
    }
    const port = try arena.print("{d}", .{listener.socket.address.getPort()});
    const url = try arena.print("http://127.0.0.1:{s}", .{port});
    var argv: std.ArrayList([]const u8) = .empty;
    for (args[1..]) |arg| {
        const with_url = try std.mem.replaceOwned(u8, arena, arg, "{url}", url);
        try argv.append(arena, try std.mem.replaceOwned(u8, arena, with_url, "{port}", port));
    }
    const result = try std.process.run(gpa, io, .{ .argv = argv.items, .stdout_limit = .limited(16 << 20), .stderr_limit = .limited(16 << 20) });
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);
    say(io, "{s}{s}", .{ result.stdout, result.stderr });
    if (result.term != .exited or result.term.exited != 0) return error.ToolFailed;
}

/// What a conformance tool expects of a server: `GET /` answered 200, and
/// a request's body read and echoed.
fn answer(io: Io, request: *uplink.server.Request, response: *uplink.server.Response) anyerror!void {
    const body = try request.collect(std.heap.smp_allocator, io, .limited(1 << 20));
    defer std.heap.smp_allocator.free(body);
    try response.header("Content-Type", "text/plain");
    if (body.len != 0) return response.send(io, body);
    if (request.method.eql(.HEAD) or request.method.eql(.GET)) return response.send(io, "OK");
    return response.send(io, "");
}

/// The request's fields, a line each.
fn echoFields(io: Io, request: *uplink.server.Request, response: *uplink.server.Response) anyerror!void {
    try response.header("Content-Type", "text/plain");
    const w = try response.writer(io);
    for (request.headers.fields) |f| try w.print("{s}: {s}\n", .{ f.name, f.value });
    try response.end(io);
}

/// The request's cookies, a pair a line.
fn echoCookies(io: Io, request: *uplink.server.Request, response: *uplink.server.Response) anyerror!void {
    try response.header("Content-Type", "text/plain");
    const w = try response.writer(io);
    for (request.headers.fields) |f| {
        if (!std.ascii.eqlIgnoreCase(f.name, "cookie")) continue;
        var pairs: uplink.wire.cookie.Pairs = .init(f.value);
        while (pairs.next()) |p| try w.print("{s}={s}\n", .{ p.name, p.value });
    }
    try response.end(io);
}

/// Write to standard output: the harness's report.
fn say(io: Io, comptime format: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    var w = std.Io.File.stdout().writerStreaming(io, &buf);
    // A report that cannot be written changes nothing the run decides.
    w.interface.print(format, args) catch return;
    w.interface.flush() catch return;
}
