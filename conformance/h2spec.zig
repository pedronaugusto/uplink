//! h2spec against uplink's HTTP/2 server, from Zig: the server serves
//! plain HTTP/2 by prior knowledge, h2spec runs every case of RFC 9113 and
//! RFC 7541 against it, and its summary is printed; the run fails if any
//! case failed. The JUnit report stays under the working directory given.
//!
//! zig build h2spec -- <h2spec> <workdir> [--strict ...]

const std = @import("std");
const Io = std.Io;
const reactor = @import("reactor");
const uplink = @import("uplink");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len < 3) {
        std.log.err("usage: h2spec <h2spec> <workdir> [h2spec's own options]", .{});
        return error.Usage;
    }
    var runtime: reactor.Runtime = undefined;
    try runtime.init(gpa, .{ .environ = init.minimal.environ });
    defer runtime.deinit();
    try runtime.start();
    const io = runtime.io();
    const cwd: Io.Dir = .cwd();
    try cwd.createDirPath(io, args[2]);
    var work = try cwd.openDir(io, args[2], .{});
    defer work.close(io);

    var server: uplink.Server = .init(gpa, .{ .h2c = .only }, .of(answer));
    defer server.deinit(io);
    var listener = try (try Io.net.IpAddress.parse("127.0.0.1", 0)).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    var serving = try io.concurrent(uplink.Server.serve, .{ &server, io, &listener });
    defer {
        server.shutdown(io);
        serving.await(io) catch |err| std.log.err("serve: {t}", .{err});
    }
    var port_buf: [8]u8 = undefined;
    const port = try std.mem.print(&port_buf, "{d}", .{listener.socket.address.getPort()});
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(gpa);
    try argv.appendSlice(gpa, &.{ args[1], "-h", "127.0.0.1", "-p", port, "-o", "3", "-j", "h2spec.xml" });
    try argv.appendSlice(gpa, args[3..]);
    const result = try std.process.run(gpa, io, .{ .argv = argv.items, .cwd = .{ .dir = work } });
    defer gpa.free(result.stdout);
    defer gpa.free(result.stderr);
    // The summary and every failure, as h2spec prints them.
    var lines = std.mem.splitScalar(u8, result.stdout, '\n');
    var failed_case = false;
    while (lines.next()) |line| {
        if (std.mem.find(u8, line, "×") != null or std.mem.find(u8, line, "Expected") != null or std.mem.find(u8, line, "Actual") != null) failed_case = true;
        if (std.mem.find(u8, line, "tests,") != null or std.mem.find(u8, line, "×") != null or std.mem.find(u8, line, "-> ") != null or std.mem.find(u8, line, "Expected:") != null or std.mem.find(u8, line, "Actual:") != null)
            say(io, "{s}\n", .{line});
    }
    if (result.term != .exited or result.term.exited != 0) return error.CasesFailed;
}

/// 200 to anything, with what came: h2spec needs a server that answers.
fn answer(io: Io, request: *uplink.server.Request, response: *uplink.server.Response) anyerror!void {
    var buf: [4096]u8 = undefined;
    const r = request.reader(io);
    while (true) {
        const n = r.readSliceShort(&buf) catch break;
        if (n == 0) break;
    }
    try response.header("Content-Type", "text/plain");
    try response.send(io, "ok");
}

/// Write to standard output: the harness's report.
fn say(io: Io, comptime format: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    var w = std.Io.File.stdout().writerStreaming(io, &buf);
    // A report that cannot be written changes nothing the run decides.
    w.interface.print(format, args) catch return;
    w.interface.flush() catch return;
}
