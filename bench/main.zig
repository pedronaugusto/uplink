//! uplink's own benchmarks, measured through shakedown.bench. `zig build
//! bench` builds them in ReleaseFast and runs them by hand, on an idle
//! machine; CI only compiles them, and `zig build test` runs each row once
//! with `--smoke`.
//!
//!     zig build bench-build && zig-out/bench/uplink-bench --row client/keepalive
//!
//! The rows run on a reactor runtime, the `Io` uplink is built for; `--io
//! threaded` runs them on `Io.Threaded` instead, to put the two side by side,
//! and `--workers N` sets the runtime's worker threads (the default is the
//! logical CPUs less one).
//!
//! Rows:
//! - `wire/parse`: response heads from the seeded corpus (5 to 40 fields,
//!   cookie-heavy), parsed and their framing decided.
//! - `wire/chunked/<chunk>`: a 16 MiB chunked body decoded, its data
//!   copied out as a reader hands it on.
//! - `wire/sse`: a stream of Server-Sent Events read.
//! - `wire/set-cookie`: `Set-Cookie` values read.
//! - `client/keepalive/<body>`: one task, one kept connection to a server
//!   on loopback, request after request.
//! - `client/keepalive/cookies`: the same with a jar of 50 cookies, 30 of
//!   them sent with every request.
//! - `client/keepalive/auth`: the same with an answer to a 401 kept and
//!   sent with every request.
//! - `client/redirect`: a request redirected once.
//! - `client/concurrent/<tasks>`: that many tasks through one client.
//! - `client/download/<body>`: one body read through; `gzip` is
//!   English-like text decoded as it arrives.
//!
//! Corpora, servers and clients are made before measuring; a row's
//! callback only does its units of work. Every client row's first call is
//! its warm-up: the connection is opened and, for `auth`, the 401 answered.

const std = @import("std");
const Io = std.Io;
const uplink = @import("uplink");
const reactor = @import("reactor");
const bench = @import("shakedown").bench;
const provenance = @import("preflight_bench_options");
const gen = @import("gen.zig");
const Server = @import("Server.zig");

/// What a row can fail with: the client's, the readers', and the corpus's.
const WorkloadError = uplink.Client.SendError || Io.Reader.Error || Io.Reader.StreamRemainingError || Io.Writer.Error ||
    uplink.wire.h1.ParseError || uplink.wire.h1.FramingError || uplink.wire.h1.ChunkedDecoder.Error ||
    error{ ConcurrencyUnavailable, DataTooLong, FieldTooLong, MalformedHead, ShortBody };

pub const OptionsError = error{ UnknownArgument, MissingRow, MissingIo, UnknownIo, MissingWorkers, InvalidWorkers, DuplicateArgument };

/// Which `Io` the rows run on.
pub const Backend = enum { reactor, threaded };

pub const Arguments = struct {
    bench: bench.Options = .{},
    io: Backend = .reactor,
    /// The runtime's worker threads; null: its default.
    workers: ?u16 = null,
};

pub fn options(args: []const []const u8) OptionsError!Arguments {
    var result: Arguments = .{};
    var i: usize = 1;
    var row_seen = false;
    var io_seen = false;
    var workers_seen = false;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--smoke")) {
            if (result.bench.smoke) return error.DuplicateArgument;
            result.bench.smoke = true;
        } else if (std.mem.eql(u8, args[i], "--row")) {
            if (row_seen) return error.DuplicateArgument;
            row_seen = true;
            i += 1;
            if (i == args.len or std.mem.startsWith(u8, args[i], "--")) return error.MissingRow;
            result.bench.prefix = args[i];
        } else if (std.mem.eql(u8, args[i], "--io")) {
            if (io_seen) return error.DuplicateArgument;
            io_seen = true;
            i += 1;
            if (i == args.len) return error.MissingIo;
            result.io = std.meta.stringToEnum(Backend, args[i]) orelse return error.UnknownIo;
        } else if (std.mem.eql(u8, args[i], "--workers")) {
            if (workers_seen) return error.DuplicateArgument;
            workers_seen = true;
            i += 1;
            if (i == args.len) return error.MissingWorkers;
            result.workers = std.fmt.parseInt(u16, args[i], 10) catch return error.InvalidWorkers;
        } else return error.UnknownArgument;
    }
    return result;
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const selected = try options(args);
    var output_buffer: [4096]u8 = undefined;
    var output = Io.File.stdout().writerStreaming(init.io, &output_buffer);
    const metadata: bench.Metadata = .{
        .commit = provenance.commit,
        .cpu = provenance.cpu,
        .os = provenance.os,
    };
    switch (selected.io) {
        .threaded => try measure(init.gpa, init.io, &output.interface, selected.bench, metadata),
        .reactor => {
            // The runtime is large, so it lives on the heap; the root runs
            // here, on the home thread, as a program's would.
            const runtime = try init.gpa.create(reactor.Runtime);
            defer init.gpa.destroy(runtime);
            try runtime.init(init.gpa, .{ .environ = init.minimal.environ, .workers = selected.workers });
            defer runtime.deinit();
            try runtime.start();
            try measure(init.gpa, runtime.io(), &output.interface, selected.bench, metadata);
        },
    }
    try output.interface.flush();
}

fn measure(gpa: std.mem.Allocator, io: Io, out: *Io.Writer, selected: bench.Options, metadata: bench.Metadata) !void {
    var context: Context = undefined;
    try context.start(gpa, io, selected.prefix);
    defer context.stop();
    try bench.run(WorkloadError, gpa, io, out, &context, &.{
        .{ .name = "wire/parse", .unit = "head", .initial = 4096, .run = Context.parse },
        .{ .name = "wire/chunked/256", .unit = "body", .run = Context.chunked(0) },
        .{ .name = "wire/chunked/4096", .unit = "body", .run = Context.chunked(1) },
        .{ .name = "wire/chunked/65536", .unit = "body", .run = Context.chunked(2) },
        .{ .name = "wire/sse", .unit = "stream", .run = Context.sse },
        .{ .name = "wire/set-cookie", .unit = "value", .initial = 4096, .run = Context.setCookie },
        .{ .name = "client/keepalive/0", .unit = "request", .initial = 1000, .run = Context.keepAlive(.empty) },
        .{ .name = "client/keepalive/1k", .unit = "request", .initial = 1000, .run = Context.keepAlive(.kib) },
        .{ .name = "client/keepalive/cookies", .unit = "request", .initial = 1000, .run = Context.keepAlive(.cookies) },
        .{ .name = "client/keepalive/auth", .unit = "request", .initial = 1000, .run = Context.keepAlive(.auth) },
        .{ .name = "client/redirect", .unit = "request", .initial = 1000, .run = Context.keepAlive(.redirect) },
        .{ .name = "client/concurrent/16", .unit = "request", .initial = 16 * 64, .smoke = 16, .run = Context.concurrent(0) },
        .{ .name = "client/concurrent/128", .unit = "request", .initial = 128 * 16, .smoke = 128, .run = Context.concurrent(1) },
        .{ .name = "client/download/big", .unit = "body", .run = Context.download(.big) },
        .{ .name = "client/download/chunked", .unit = "body", .run = Context.download(.chunked) },
        .{ .name = "client/download/gzip", .unit = "body", .run = Context.download(.gzip) },
    }, metadata, selected);
}

/// Which request a keep-alive row sends.
const Keep = enum { empty, kib, cookies, auth, redirect };

/// Which body a download row reads.
const Body = enum { big, chunked, gzip };

/// Where `www.bench.test` points; the server's port replaces the 0. A
/// constant of its own, since the resolver entry keeps the slice past `start`.
const bench_address = [_]Io.net.IpAddress{.{ .ip4 = .loopback(0) }};

const chunk_sizes = [_]usize{ 256, 4096, 65536 };
const task_counts = [_]usize{ 16, 128 };

/// Everything a row needs, made once: the corpora, the server and a client
/// for each kind of row. It stays where `start` made it, since the clients
/// point into it.
const Context = struct {
    gpa: std.mem.Allocator,
    io: Io,
    heads: []u8,
    /// Where each head of `heads` ends.
    ends: []usize,
    scratch: []u8,
    bodies: [chunk_sizes.len][]u8,
    sink: []u8,
    events: []u8,
    cookies: [][]u8,
    text: []u8,
    gzip: []u8,
    server: Server,
    plain: uplink.Client,
    jar: uplink.CookieJar,
    jarred: uplink.Client,
    answered: uplink.Client,
    crowd: [task_counts.len]uplink.Client,
    downloads: uplink.Client,
    resolver_entries: [1]uplink.net.Resolver.Static.Entry,
    static: uplink.net.Resolver.Static,
    cursor: usize = 0,

    fn start(c: *Context, gpa: std.mem.Allocator, io: Io, prefix: []const u8) !void {
        _ = prefix;
        c.gpa = gpa;
        c.io = io;
        c.heads = try gen.heads(gpa, 0x5eed, 4096);
        errdefer gpa.free(c.heads);
        c.ends = try gpa.alloc(usize, 4096);
        errdefer gpa.free(c.ends);
        c.scratch = try gpa.alloc(u8, c.heads.len);
        errdefer gpa.free(c.scratch);
        var fields: [64]uplink.wire.fields.Field = undefined;
        var at: usize = 0;
        for (c.ends) |*end| {
            const parsed = (try uplink.wire.h1.parseResponse(c.heads[at..], &fields, .{ .max_fields = 64 })) orelse return error.MalformedHead;
            at += parsed.len;
            end.* = at;
        }
        for (&c.bodies, chunk_sizes, 0..) |*body, size, built| {
            errdefer for (c.bodies[0..built]) |b| gpa.free(b);
            body.* = try gen.chunked(gpa, 16 << 20, size);
        }
        errdefer for (c.bodies) |b| gpa.free(b);
        c.sink = try gpa.alloc(u8, 64 << 10);
        errdefer gpa.free(c.sink);
        c.events = try gen.events(gpa, 0x55e, 20_000);
        errdefer gpa.free(c.events);
        c.cookies = try gen.setCookies(gpa, 0xc00c1e, 4096);
        errdefer freeCookies(gpa, c.cookies);
        c.text = try gen.text(gpa, 0x7e47, 8 << 20);
        errdefer gpa.free(c.text);
        c.gzip = try compressed(gpa, c.text);
        errdefer gpa.free(c.gzip);
        try Server.start(io, &c.server, c.gzip);
        c.cursor = 0;
        // Cookies need a name with domains above it; the rest go by address.
        c.resolver_entries = .{.{ .host = "www.bench.test", .addresses = &bench_address }};
        c.static = .{ .entries = &c.resolver_entries };
        c.plain = .init(gpa, .{});
        c.jar = .init(gpa, .{});
        c.jarred = .init(gpa, .{ .cookies = &c.jar, .resolver = c.static.resolver() });
        c.answered = .init(gpa, .{ .credentials = Answer.credentials() });
        for (&c.crowd, task_counts) |*client, tasks| client.* = .init(gpa, .{ .pool = .{ .max_idle_per_route = @intCast(tasks), .max_idle = @intCast(tasks) } });
        c.downloads = .init(gpa, .{});
        try fillJar(&c.jar, io);
    }

    fn stop(c: *Context) void {
        const io = c.io;
        c.downloads.deinit(io);
        for (&c.crowd) |*client| client.deinit(io);
        c.answered.deinit(io);
        c.jarred.deinit(io);
        c.jar.deinit(io);
        c.plain.deinit(io);
        c.server.stop();
        const gpa = c.gpa;
        gpa.free(c.gzip);
        gpa.free(c.text);
        freeCookies(gpa, c.cookies);
        gpa.free(c.events);
        gpa.free(c.sink);
        for (c.bodies) |b| gpa.free(b);
        gpa.free(c.scratch);
        gpa.free(c.ends);
        gpa.free(c.heads);
    }

    fn freeCookies(gpa: std.mem.Allocator, values: [][]u8) void {
        for (values) |v| gpa.free(v);
        gpa.free(values);
    }

    /// Heads parsed and their framing decided, one after another round the
    /// corpus. A head is parsed in place, so each is copied first.
    fn parse(c: *Context, units: u64) WorkloadError!void {
        var fields: [64]uplink.wire.fields.Field = undefined;
        for (0..units) |_| {
            const from = if (c.cursor == 0) 0 else c.ends[c.cursor - 1];
            const head = c.heads[from..c.ends[c.cursor]];
            const copy = c.scratch[0..head.len];
            @memcpy(copy, head);
            const parsed = (try uplink.wire.h1.parseResponse(copy, &fields, .{ .max_fields = 64 })) orelse return error.MalformedHead;
            std.mem.doNotOptimizeAway(try uplink.wire.h1.responseFraming(.GET, &parsed.head));
            c.cursor = (c.cursor + 1) % c.ends.len;
        }
        c.cursor = 0;
    }

    fn chunked(comptime which: usize) *const fn (*Context, u64) WorkloadError!void {
        return struct {
            fn run(c: *Context, units: u64) WorkloadError!void {
                const body = c.bodies[which];
                for (0..units) |_| {
                    var d: uplink.wire.h1.ChunkedDecoder = .{};
                    var at: usize = 0;
                    while (!d.done()) {
                        const step = try d.feed(body[at..]);
                        at += step.consumed;
                        // The data is copied out, as a reader hands it to its caller.
                        const n = @min(step.data, c.sink.len);
                        @memcpy(c.sink[0..n], body[at..][0..n]);
                        d.take(n);
                        at += n;
                    }
                    std.mem.doNotOptimizeAway(c.sink);
                }
            }
        }.run;
    }

    fn sse(c: *Context, units: u64) WorkloadError!void {
        var data: [4096]u8 = undefined;
        for (0..units) |_| {
            var in: Io.Reader = .fixed(c.events);
            var r: uplink.wire.sse.Reader = .init(&in, &data);
            while (try r.next()) |e| std.mem.doNotOptimizeAway(e.data.ptr);
        }
    }

    fn setCookie(c: *Context, units: u64) WorkloadError!void {
        for (0..units) |i| {
            const value = c.cookies[i % c.cookies.len];
            std.mem.doNotOptimizeAway((uplink.wire.cookie.parse(value) orelse return error.MalformedHead).expires);
        }
    }

    fn keepAlive(comptime which: Keep) *const fn (*Context, u64) WorkloadError!void {
        return struct {
            fn run(c: *Context, units: u64) WorkloadError!void {
                var url_buf: [64]u8 = undefined;
                const client, const host, const path = switch (which) {
                    .empty => .{ &c.plain, "127.0.0.1", "0" },
                    .kib => .{ &c.plain, "127.0.0.1", "1k" },
                    .redirect => .{ &c.plain, "127.0.0.1", "redirect" },
                    // The first request answers `/private`'s 401; the rest
                    // send the kept answer.
                    .auth => .{ &c.answered, "127.0.0.1", "private" },
                    .cookies => .{ &c.jarred, "www.bench.test", "0" },
                };
                const url = std.mem.print(&url_buf, "http://{s}:{d}/{s}", .{ host, c.server.port, path }) catch unreachable; // unreachable: the longest URL is 36 bytes
                for (0..units) |_| try exchange(client, c.io, url);
            }
        }.run;
    }

    fn concurrent(comptime which: usize) *const fn (*Context, u64) WorkloadError!void {
        return struct {
            fn run(c: *Context, units: u64) WorkloadError!void {
                const tasks = task_counts[which];
                var url_buf: [64]u8 = undefined;
                const url = std.mem.print(&url_buf, "http://127.0.0.1:{d}/0", .{c.server.port}) catch unreachable; // unreachable: the URL is under 30 bytes
                var failed: std.atomic.Value(bool) = .init(false);
                var group: Io.Group = .init;
                errdefer group.cancel(c.io);
                for (0..tasks) |_| try group.concurrent(c.io, Task.run, .{ &c.crowd[which], c.io, url, units / tasks, &failed });
                try group.await(c.io);
                if (failed.load(.monotonic)) return error.ShortBody;
            }

            const Task = struct {
                fn run(client: *uplink.Client, io: Io, url: []const u8, n: u64, failed: *std.atomic.Value(bool)) void {
                    for (0..n) |_| exchange(client, io, url) catch {
                        failed.store(true, .monotonic);
                        return;
                    };
                }
            };
        }.run;
    }

    fn download(comptime which: Body) *const fn (*Context, u64) WorkloadError!void {
        return struct {
            fn run(c: *Context, units: u64) WorkloadError!void {
                var url_buf: [64]u8 = undefined;
                const url = std.mem.print(&url_buf, "http://127.0.0.1:{d}/{t}", .{ c.server.port, which }) catch unreachable; // unreachable: the URL is under 40 bytes
                for (0..units) |_| {
                    var response = try c.downloads.send(c.io, .{ .url = url });
                    defer response.deinit(c.io);
                    var sink: Io.Writer.Discarding = .init(c.sink);
                    std.mem.doNotOptimizeAway(try response.reader(c.io).streamRemaining(&sink.writer));
                }
            }
        }.run;
    }
};

/// Answers every 401 with the same password.
const Answer = struct {
    fn credentials() uplink.Credentials {
        return .{ .context = null, .fillFn = fill };
    }

    fn fill(_: Io, _: ?*anyopaque, _: uplink.Credentials.Query) uplink.Credentials.FillError!?uplink.Credentials.Secret {
        return .{ .password = .{ .user = "bench", .password = "secret" } };
    }
};

fn exchange(client: *uplink.Client, io: Io, url: []const u8) WorkloadError!void {
    var response = try client.send(io, .{ .url = url });
    defer response.deinit(io);
    std.mem.doNotOptimizeAway(try response.reader(io).discardRemaining());
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

fn compressed(gpa: std.mem.Allocator, text: []const u8) ![]u8 {
    var w: Io.Writer.Allocating = try .initCapacity(gpa, 1 << 16);
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
