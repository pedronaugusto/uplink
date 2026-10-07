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
//! - `wire/sse`: Server-Sent Events read from a stream: MB/s and events/s.
//! - `wire/set-cookie`: `Set-Cookie` values read: values/s.
//! - `client/keepalive/<body>`: one task, one kept connection to a server
//!   on loopback, request after request: requests/s, p50, p99 and p99.9.
//! - `client/keepalive/cookies`: the same with a jar of 50 cookies, 30 of
//!   them sent with every request.
//! - `client/keepalive/auth`: the same with an answer to a 401 kept and
//!   sent with every request.
//! - `client/redirect`: a request redirected once: requests/s.
//! - `client/concurrent/<tasks>`: that many tasks through one client.
//! - `client/download/<body>`: one body read through: MB/s; `gzip` is
//!   English-like text decoded as it arrives.
//!
//! Throughput rows repeat until a third of a second has passed, so a
//! short row is not measured on a handful of runs. Every row names its
//! `Io` (`Threaded`), the host and the Zig version.

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

/// How long a throughput row repeats for, at least.
const budget_ns = std.time.ns_per_s / 3;

/// Whether `name` is asked for by `prefix`: one starts the other.
fn wanted(name: []const u8, prefix: []const u8) bool {
    return std.mem.startsWith(u8, name, prefix) or std.mem.startsWith(u8, prefix, name);
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

    if (wanted("wire/parse", prefix)) try parseRow(gpa, io, out);
    for ([_]usize{ 256, 4096, 65536 }) |chunk| {
        var name_buf: [64]u8 = undefined;
        const name = try std.mem.print(&name_buf, "wire/chunked/{d}", .{chunk});
        if (std.mem.startsWith(u8, name, prefix)) try chunkedRow(gpa, io, out, name, chunk);
    }
    if (wanted("wire/sse", prefix)) try sseRow(gpa, io, out);
    if (wanted("wire/set-cookie", prefix)) try setCookieRow(gpa, io, out);
    if (!wanted("client", prefix)) return;
    const text = try gen.text(gpa, 0x7e47, 8 << 20);
    defer gpa.free(text);
    const gzip = try compressed(gpa, text);
    defer gpa.free(gzip);
    var server: Server = undefined;
    try Server.start(io, &server, gzip);
    defer server.stop();
    for ([_][]const u8{ "0", "1k" }) |body| {
        var name_buf: [64]u8 = undefined;
        const name = try std.mem.print(&name_buf, "client/keepalive/{s}", .{body});
        if (std.mem.startsWith(u8, name, prefix)) try keepAliveRow(gpa, io, out, &server, name, body, .plain);
    }
    if (wanted("client/keepalive/cookies", prefix)) try keepAliveRow(gpa, io, out, &server, "client/keepalive/cookies", "0", .cookies);
    if (wanted("client/keepalive/auth", prefix)) try keepAliveRow(gpa, io, out, &server, "client/keepalive/auth", "private", .auth);
    if (wanted("client/redirect", prefix)) try keepAliveRow(gpa, io, out, &server, "client/redirect", "redirect", .plain);
    for ([_]usize{ 16, 128 }) |tasks| {
        var name_buf: [64]u8 = undefined;
        const name = try std.mem.print(&name_buf, "client/concurrent/{d}", .{tasks});
        if (std.mem.startsWith(u8, name, prefix)) try concurrentRow(gpa, io, out, &server, name, tasks);
    }
    for ([_][]const u8{ "big", "chunked", "gzip" }) |path| {
        var name_buf: [64]u8 = undefined;
        const name = try std.mem.print(&name_buf, "client/download/{s}", .{path});
        if (std.mem.startsWith(u8, name, prefix)) try downloadRow(gpa, io, out, &server, name, path);
    }
}

fn compressed(gpa: std.mem.Allocator, text: []const u8) ![]u8 {
    var w: Io.Writer.Allocating = .init(gpa);
    defer w.deinit();
    const window = try gpa.alloc(u8, std.compress.flate.max_window_len);
    defer gpa.free(window);
    const state = try gpa.create(std.compress.flate.Compress);
    defer gpa.destroy(state);
    state.* = try .init(&w.writer, window, .gzip, .level_6);
    try state.writer.writeAll(text);
    try state.finish();
    return w.toOwnedSlice();
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
    var rounds: u64 = 0;
    var data: u64 = 0;
    // The data is copied out, as a reader hands it to its caller.
    const sink = try gpa.alloc(u8, 64 << 10);
    defer gpa.free(sink);
    const start = now(io);
    while (now(io) - start < budget_ns) : (rounds += 1) {
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

fn sseRow(gpa: std.mem.Allocator, io: Io, out: Out) !void {
    const stream = try gen.events(gpa, 0x55e, 20_000);
    defer gpa.free(stream);
    var data: [4096]u8 = undefined;
    var events: u64 = 0;
    var bytes: u64 = 0;
    const start = now(io);
    while (now(io) - start < budget_ns) {
        var in: Io.Reader = .fixed(stream);
        var r: uplink.wire.sse.Reader = .init(&in, &data);
        while (try r.next()) |e| {
            std.mem.doNotOptimizeAway(e.data.ptr);
            events += 1;
        }
        bytes += stream.len;
    }
    try out.emit(.{ .name = "wire/sse", .ops = events, .ns = now(io) - start, .bytes = bytes });
}

fn setCookieRow(gpa: std.mem.Allocator, io: Io, out: Out) !void {
    const values = try gen.setCookies(gpa, 0xc00c1e, 4096);
    defer {
        for (values) |v| gpa.free(v);
        gpa.free(values);
    }
    var parsed: u64 = 0;
    const start = now(io);
    while (now(io) - start < budget_ns) {
        for (values) |v| {
            std.mem.doNotOptimizeAway(uplink.wire.cookie.parse(v).?.expires);
            parsed += 1;
        }
    }
    try out.emit(.{ .name = "wire/set-cookie", .ops = parsed, .ns = now(io) - start });
}

const Extra = enum { plain, cookies, auth };

/// Answers every 401 with the same password.
const Answer = struct {
    fn credentials() uplink.Credentials {
        return .{ .context = null, .fillFn = fill };
    }

    fn fill(_: Io, _: ?*anyopaque, _: uplink.Credentials.Query) uplink.Credentials.FillError!?uplink.Credentials.Secret {
        return .{ .password = .{ .user = "bench", .password = "secret" } };
    }
};

fn keepAliveRow(gpa: std.mem.Allocator, io: Io, out: Out, server: *Server, name: []const u8, path: []const u8, extra: Extra) !void {
    var jar: uplink.CookieJar = .init(gpa, .{});
    defer jar.deinit();
    const entries = [_]uplink.net.Resolver.Static.Entry{.{ .host = "www.bench.test", .addresses = &.{.{ .ip4 = .loopback(0) }} }};
    const static: uplink.net.Resolver.Static = .{ .entries = &entries };
    var client: uplink.Client = .init(gpa, .{
        .cookies = if (extra == .cookies) &jar else null,
        .credentials = if (extra == .auth) Answer.credentials() else null,
        .resolver = static.resolver(),
    });
    defer client.deinit(io);
    var url_buf: [64]u8 = undefined;
    // Cookies need a name with domains above it; the rest go by address.
    const host = if (extra == .cookies) "www.bench.test" else "127.0.0.1";
    const url = try std.mem.print(&url_buf, "http://{s}:{d}/{s}", .{ host, server.port, path });
    // The warm-up's first request answers `/private`'s 401; the rest send
    // the kept answer.
    if (extra == .cookies) try fillJar(&jar, io);
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

/// Fifty cookies: thirty for the request's host and the domains above it,
/// twenty for elsewhere.
fn fillJar(jar: *uplink.CookieJar, io: Io) !void {
    const here = try uplink.wire.url.parse("http://www.bench.test/app/page");
    const there = try uplink.wire.url.parse("http://other.test/");
    for (0..50) |i| {
        var buf: [96]u8 = undefined;
        const set = if (i < 30)
            try std.mem.print(&buf, "c{d}=value{d}; Path={s}{s}", .{ i, i, if (i % 3 == 0) "/" else "/app", if (i % 2 == 0) "; Domain=bench.test" else "" })
        else
            try std.mem.print(&buf, "o{d}=value{d}", .{ i, i });
        try jar.store(io, if (i < 30) here else there, set);
    }
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
    var rounds: u64 = 0;
    var bytes: u64 = 0;
    var sink_buffer: [64 << 10]u8 = undefined;
    const start = now(io);
    while (now(io) - start < budget_ns) : (rounds += 1) {
        var response = try client.send(io, .{ .url = url });
        defer response.deinit(io);
        var sink: Io.Writer.Discarding = .init(&sink_buffer);
        bytes += try response.reader(io).streamRemaining(&sink.writer);
    }
    try out.emit(.{ .name = name, .ops = rounds, .ns = now(io) - start, .bytes = bytes });
}
