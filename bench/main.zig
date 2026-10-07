//! uplink's own benchmarks. `zig build bench` runs them in ReleaseFast and
//! writes one JSON line per row to stdout and to
//! zig-out/bench/results.jsonl. They are run by hand, on an idle machine;
//! CI only compiles them.
//!
//!     zig build bench -- [row prefix]
//!
//! Rows:
//! - `wire/parse`: response heads from the seeded corpus (5 to 40 fields,
//!   cookie-heavy), parsed and their framing decided: MB/s and heads/s.
//! - `wire/chunked/<chunk>`: a chunked body decoded, its data copied out
//!   as a reader hands it on: MB/s.
//! - `client/keepalive/<body>`: one task, one kept connection to a server
//!   on loopback, request after request: requests/s, p50, p99 and p99.9.
//! - `client/concurrent/<tasks>`: that many tasks through one client.
//! - `client/download/<framing>`: one body read through: MB/s.
//!
//! Every row names its `Io` (`Threaded`), the host and the Zig version.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const uplink = @import("uplink");
const gen = @import("gen.zig");
const Server = @import("Server.zig");

const Result = struct {
    name: []const u8,
    ops: u64,
    ns: u64,
    /// Bytes moved, for a throughput.
    bytes: u64 = 0,
    p50_ns: ?u64 = null,
    p99_ns: ?u64 = null,
    p999_ns: ?u64 = null,
};

const Out = struct {
    file: *Io.Writer,
    stdout: *Io.Writer,

    fn emit(o: Out, r: Result) !void {
        for ([_]*Io.Writer{ o.file, o.stdout }) |w| {
            try w.print("{{\"row\":\"{s}\",\"ops\":{d},\"ns\":{d},\"per_s\":{d:.0}", .{ r.name, r.ops, r.ns, @as(f64, @floatFromInt(r.ops)) * 1e9 / @as(f64, @floatFromInt(@max(r.ns, 1))) });
            if (r.bytes != 0) try w.print(",\"mb_s\":{d:.1}", .{@as(f64, @floatFromInt(r.bytes)) / 1e6 * 1e9 / @as(f64, @floatFromInt(@max(r.ns, 1)))});
            if (r.p50_ns) |v| try w.print(",\"p50_us\":{d:.2},\"p99_us\":{d:.2},\"p999_us\":{d:.2}", .{ us(v), us(r.p99_ns.?), us(r.p999_ns.?) });
            try w.print(",\"io\":\"Threaded\",\"zig\":\"{s}\",\"host\":\"{t}-{t}\"}}\n", .{ builtin.zig_version_string, builtin.cpu.arch, builtin.os.tag });
            try w.flush();
        }
    }

    fn us(ns: u64) f64 {
        return @as(f64, @floatFromInt(ns)) / 1000.0;
    }
};

fn now(io: Io) u64 {
    return @intCast(Io.Clock.awake.now(io).nanoseconds);
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const prefix: []const u8 = if (args.len > 1) args[1] else "";
    const cwd = Io.Dir.cwd();
    try cwd.createDirPath(io, "zig-out/bench");
    var out_file = try cwd.createFile(io, "zig-out/bench/results.jsonl", .{});
    defer out_file.close(io);
    var file_buffer: [4096]u8 = undefined;
    var file_writer = out_file.writer(io, &file_buffer);
    var stdout_buffer: [4096]u8 = undefined;
    var stdout = Io.File.stdout().writer(io, &stdout_buffer);
    const out: Out = .{ .file = &file_writer.interface, .stdout = &stdout.interface };

    if (std.mem.startsWith(u8, "wire/parse", prefix) or std.mem.startsWith(u8, prefix, "wire/parse")) try parseRow(gpa, io, out);
    for ([_]usize{ 256, 4096, 65536 }) |chunk| {
        var name_buf: [64]u8 = undefined;
        const name = try std.mem.print(&name_buf, "wire/chunked/{d}", .{chunk});
        if (std.mem.startsWith(u8, name, prefix)) try chunkedRow(gpa, io, out, name, chunk);
    }
    if (!std.mem.startsWith(u8, "client", prefix) and !std.mem.startsWith(u8, prefix, "client")) return;
    var server: Server = undefined;
    try Server.start(io, &server);
    defer server.stop();
    for ([_][]const u8{ "0", "1k" }) |body| {
        var name_buf: [64]u8 = undefined;
        const name = try std.mem.print(&name_buf, "client/keepalive/{s}", .{body});
        if (std.mem.startsWith(u8, name, prefix)) try keepAliveRow(gpa, io, out, &server, name, body);
    }
    for ([_]usize{ 16, 128 }) |tasks| {
        var name_buf: [64]u8 = undefined;
        const name = try std.mem.print(&name_buf, "client/concurrent/{d}", .{tasks});
        if (std.mem.startsWith(u8, name, prefix)) try concurrentRow(gpa, io, out, &server, name, tasks);
    }
    for ([_][]const u8{ "big", "chunked" }) |path| {
        var name_buf: [64]u8 = undefined;
        const name = try std.mem.print(&name_buf, "client/download/{s}", .{path});
        if (std.mem.startsWith(u8, name, prefix)) try downloadRow(gpa, io, out, &server, name, path);
    }
}

fn parseRow(gpa: std.mem.Allocator, io: Io, out: Out) !void {
    const corpus = try gen.heads(gpa, 0x5eed, 4096);
    defer gpa.free(corpus);
    const copy = try gpa.alloc(u8, corpus.len);
    defer gpa.free(copy);
    var fields: [64]uplink.wire.fields.Field = undefined;
    var heads: u64 = 0;
    const rounds = 50;
    const start = now(io);
    for (0..rounds) |_| {
        @memcpy(copy, corpus);
        var at: usize = 0;
        while (at < copy.len) {
            const parsed = (try uplink.wire.h1.parseResponse(copy[at..], &fields, .{ .max_fields = 64 })).?;
            std.mem.doNotOptimizeAway(try uplink.wire.h1.responseFraming(.GET, &parsed.head));
            at += parsed.len;
            heads += 1;
        }
    }
    try out.emit(.{ .name = "wire/parse", .ops = heads, .ns = now(io) - start, .bytes = corpus.len * rounds });
}

fn chunkedRow(gpa: std.mem.Allocator, io: Io, out: Out, name: []const u8, chunk: usize) !void {
    const total = 16 << 20;
    const body = try gen.chunked(gpa, total, chunk);
    defer gpa.free(body);
    const rounds = 20;
    var data: u64 = 0;
    // The data is copied out, as a reader hands it to its caller.
    const sink = try gpa.alloc(u8, 64 << 10);
    defer gpa.free(sink);
    const start = now(io);
    for (0..rounds) |_| {
        var d: uplink.wire.h1.ChunkedDecoder = .{};
        var at: usize = 0;
        while (!d.done()) {
            const step = try d.feed(body[at..]);
            at += step.consumed;
            const n = @min(step.data, sink.len);
            @memcpy(sink[0..n], body[at..][0..n]);
            d.take(n);
            at += n;
            data += n;
        }
        std.mem.doNotOptimizeAway(sink);
    }
    try out.emit(.{ .name = name, .ops = rounds, .ns = now(io) - start, .bytes = data });
}

fn keepAliveRow(gpa: std.mem.Allocator, io: Io, out: Out, server: *Server, name: []const u8, path: []const u8) !void {
    var client: uplink.Client = .init(gpa, .{});
    defer client.deinit(io);
    var url_buf: [64]u8 = undefined;
    const url = try std.mem.print(&url_buf, "http://127.0.0.1:{d}/{s}", .{ server.port, path });
    const count = 50_000;
    const samples = try gpa.alloc(u64, count);
    defer gpa.free(samples);
    for (0..1000) |_| try exchange(&client, io, url);
    const start = now(io);
    for (samples) |*s| {
        const t = now(io);
        try exchange(&client, io, url);
        s.* = now(io) - t;
    }
    const elapsed = now(io) - start;
    std.mem.sort(u64, samples, {}, std.sort.asc(u64));
    try out.emit(.{
        .name = name,
        .ops = count,
        .ns = elapsed,
        .p50_ns = samples[count / 2],
        .p99_ns = samples[count * 99 / 100],
        .p999_ns = samples[count * 999 / 1000],
    });
}

fn exchange(client: *uplink.Client, io: Io, url: []const u8) !void {
    var response = try client.send(io, .{ .url = url });
    defer response.deinit(io);
    _ = try response.reader(io).discardRemaining();
}

fn concurrentRow(gpa: std.mem.Allocator, io: Io, out: Out, server: *Server, name: []const u8, tasks: usize) !void {
    var client: uplink.Client = .init(gpa, .{ .pool = .{ .max_idle_per_route = @intCast(tasks), .max_idle = @intCast(tasks) } });
    defer client.deinit(io);
    var url_buf: [64]u8 = undefined;
    const url = try std.mem.print(&url_buf, "http://127.0.0.1:{d}/0", .{server.port});
    const per_task = 2000;
    const Task = struct {
        fn run(c: *uplink.Client, task_io: Io, u: []const u8, n: usize) void {
            for (0..n) |_| exchange(c, task_io, u) catch return;
        }
    };
    var group: Io.Group = .init;
    const start = now(io);
    for (0..tasks) |_| try group.concurrent(io, Task.run, .{ &client, io, url, per_task });
    try group.await(io);
    try out.emit(.{ .name = name, .ops = tasks * per_task, .ns = now(io) - start });
}

fn downloadRow(gpa: std.mem.Allocator, io: Io, out: Out, server: *Server, name: []const u8, path: []const u8) !void {
    var client: uplink.Client = .init(gpa, .{});
    defer client.deinit(io);
    var url_buf: [64]u8 = undefined;
    const url = try std.mem.print(&url_buf, "http://127.0.0.1:{d}/{s}", .{ server.port, path });
    const rounds = 8;
    var bytes: u64 = 0;
    var sink_buffer: [64 << 10]u8 = undefined;
    const start = now(io);
    for (0..rounds) |_| {
        var response = try client.send(io, .{ .url = url });
        defer response.deinit(io);
        var sink: Io.Writer.Discarding = .init(&sink_buffer);
        bytes += try response.reader(io).streamRemaining(&sink.writer);
    }
    try out.emit(.{ .name = name, .ops = rounds, .ns = now(io) - start, .bytes = bytes });
}
