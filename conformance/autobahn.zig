//! Autobahn|Testsuite against uplink's WebSocket, both ends, from Zig.
//!
//! `server`: uplink's server echoes every message, and `wstest -m
//! fuzzingclient` drives every case against it. `client`: `wstest -m
//! fuzzingserver` serves the cases, and uplink's client echoes each. Either
//! way the report's index is read and summed by behaviour, the failures
//! named, and the run fails if any case failed. The reports stay under the
//! working directory given; nothing is written to the repository.
//!
//! zig build autobahn -- server|client <wstest> <workdir>

const std = @import("std");
const Io = std.Io;
const aegis = @import("aegis");
const reactor = @import("reactor");
const uplink = @import("uplink");
const ws = uplink.ws;

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 4) {
        std.log.err("usage: autobahn server|client <wstest> <workdir>", .{});
        return error.Usage;
    }
    var runtime: reactor.Runtime = undefined;
    try runtime.init(gpa, .{ .environ = init.minimal.environ });
    defer runtime.deinit();
    try runtime.start();
    const io = runtime.io();
    const mode = args[1];
    const wstest = args[2];
    const cwd: Io.Dir = .cwd();
    try cwd.createDirPath(io, args[3]);
    var work = try cwd.openDir(io, args[3], .{});
    defer work.close(io);
    if (std.mem.eql(u8, mode, "server")) return againstServer(gpa, io, wstest, work);
    if (std.mem.eql(u8, mode, "client")) return againstClient(gpa, io, wstest, work);
    return error.Usage;
}

/// Echo every message back, as it came, compressed when the client asks.
fn echo(io: Io, request: *uplink.server.Request, response: *uplink.server.Response) anyerror!void {
    var accepted: ws.Accepted = undefined;
    ws.accept(&accepted, std.heap.smp_allocator, io, request, response, .{
        .conn = .{ .max_message = .literal("64MiB"), .max_frame = .literal("64MiB") },
        // Context takeover kept both ways, so every case of 12 and 13 runs.
        .compression = .{},
    }) catch return;
    defer accepted.deinit();
    pump(io, &accepted.conn);
}

fn pump(io: Io, conn: *ws.Conn) void {
    while (true) {
        const message = conn.readMessage(io, std.heap.smp_allocator, .limited(64 << 20)) catch return;
        const kind, const bytes = message orelse return;
        defer std.heap.smp_allocator.free(bytes);
        conn.send(io, kind, bytes) catch return;
    }
}

fn againstServer(gpa: std.mem.Allocator, io: Io, wstest: []const u8, work: Io.Dir) !void {
    var server: uplink.Server = .init(gpa, .{}, .of(echo));
    defer server.deinit(io);
    var listener = try (try Io.net.IpAddress.parse("127.0.0.1", 0)).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    var serving = try io.concurrent(uplink.Server.serve, .{ &server, io, &listener });
    defer {
        server.shutdown(io);
        serving.await(io) catch |err| std.log.err("serve: {t}", .{err});
    }
    var spec_buf: [512]u8 = undefined;
    const spec = try std.mem.print(&spec_buf,
        \\{{"outdir": "./reports/servers", "servers": [{{"agent": "uplink", "url": "ws://127.0.0.1:{d}"}}], "cases": ["*"], "exclude-cases": [], "exclude-agent-cases": {{}}}}
    , .{listener.socket.address.getPort()});
    try work.writeFile(io, .{ .sub_path = "fuzzingclient.json", .data = spec });
    const result = try std.process.run(gpa, io, .{ .argv = &.{ wstest, "-m", "fuzzingclient", "-s", "fuzzingclient.json" }, .cwd = .{ .dir = work } });
    gpa.free(result.stdout);
    gpa.free(result.stderr);
    return summarize(gpa, io, work, "reports/servers/index.json");
}

fn againstClient(gpa: std.mem.Allocator, io: Io, wstest: []const u8, work: Io.Dir) !void {
    const port = 9001;
    try work.writeFile(io, .{ .sub_path = "fuzzingserver.json", .data =
        \\{"url": "ws://127.0.0.1:9001", "outdir": "./reports/clients", "cases": ["*"], "exclude-cases": [], "exclude-agent-cases": {}}
    });
    var child = try std.process.spawn(io, .{ .argv = &.{ wstest, "-m", "fuzzingserver", "-s", "fuzzingserver.json" }, .cwd = .{ .dir = work }, .stdin = .ignore, .stdout = .ignore, .stderr = .ignore });
    defer child.kill(io);
    var client: uplink.Client = .init(gpa, .{});
    defer client.deinit(io);
    var url_buf: [128]u8 = undefined;
    // Wait for the fuzzing server to listen.
    const count = for (0..100) |_| {
        const n = caseCount(&client, gpa, io, try std.mem.print(&url_buf, "ws://127.0.0.1:{d}/getCaseCount", .{port})) catch {
            try io.sleep(.fromMilliseconds(200), .awake);
            continue;
        };
        break n;
    } else return error.FuzzingServerDidNotStart;
    for (1..count + 1) |i| {
        var opened: ws.Opened = undefined;
        ws.connect(&opened, &client, gpa, io, try std.mem.print(&url_buf, "ws://127.0.0.1:{d}/runCase?case={d}&agent=uplink", .{ port, i }), .{
            .conn = .{ .max_message = .literal("64MiB"), .max_frame = .literal("64MiB") },
        }) catch continue;
        defer opened.deinit(io);
        pump(io, &opened.conn);
    }
    var opened: ws.Opened = undefined;
    try ws.connect(&opened, &client, gpa, io, try std.mem.print(&url_buf, "ws://127.0.0.1:{d}/updateReports?agent=uplink", .{port}), .{});
    opened.conn.close(io, 1000, "");
    opened.deinit(io);
    return summarize(gpa, io, work, "reports/clients/index.json");
}

fn caseCount(client: *uplink.Client, gpa: std.mem.Allocator, io: Io, url: []const u8) !usize {
    var opened: ws.Opened = undefined;
    try ws.connect(&opened, client, gpa, io, url, .{ .compression = null });
    defer opened.deinit(io);
    const kind, const bytes = (try opened.conn.readMessage(io, gpa, .limited(64))) orelse return error.NoCount;
    defer gpa.free(bytes);
    _ = kind;
    return std.fmt.parseUnsigned(usize, bytes, 10);
}

/// Sum the report's cases by behaviour and name the failures.
fn summarize(gpa: std.mem.Allocator, io: Io, work: Io.Dir, index: []const u8) !void {
    const text = try aegis.own.readFile(io, work, index, gpa, .literal("16MiB"));
    defer gpa.free(text);
    const parsed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
    defer parsed.deinit();
    const agent = parsed.value.object.get("uplink") orelse return error.NoReport;
    var counts: std.array_hash_map.String(usize) = .empty;
    defer counts.deinit(gpa);
    var failed: usize = 0;
    var it = agent.object.iterator();
    while (it.next()) |entry| {
        const behaviour = entry.value_ptr.object.get("behavior").?.string;
        const close = entry.value_ptr.object.get("behaviorClose").?.string;
        const gop = try counts.getOrPut(gpa, behaviour);
        if (!gop.found_existing) gop.value_ptr.* = 0;
        gop.value_ptr.* += 1;
        if (std.mem.eql(u8, behaviour, "FAILED") or std.mem.eql(u8, close, "FAILED")) {
            failed += 1;
            say(io, "FAILED {s} (behavior {s}, close {s})\n", .{ entry.key_ptr.*, behaviour, close });
        }
    }
    say(io, "{d} cases:", .{agent.object.count()});
    var ci = counts.iterator();
    while (ci.next()) |e| say(io, " {s} {d}", .{ e.key_ptr.*, e.value_ptr.* });
    say(io, "\n", .{});
    if (failed != 0) return error.CasesFailed;
}

/// Write to standard output: the harness's report.
fn say(io: Io, comptime format: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    var w = std.Io.File.stdout().writerStreaming(io, &buf);
    // A report that cannot be written changes nothing the run decides.
    w.interface.print(format, args) catch return;
    w.interface.flush() catch return;
}
