//! uplink on shakedown's simulated network (`Sim.Net`): a client node and a
//! server node, names in the simulation's DNS, latency, loss, resets and
//! partitions drawn from a seed. Each node's `Io` is wrapped in reactor's
//! seam (`reactor.testing`), so reactor's raw socket calls (the options it
//! sets, a peek) ask the test instead of a system the simulated sockets are
//! not in. The suite runs once, in the `Io.Threaded` test binary: a
//! simulation brings its own `Io`, so the evented binaries would only run it
//! again.
const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const shakedown = @import("shakedown");
const Sim = shakedown.Sim;
const Case = shakedown.Case;
const reactor_testing = @import("reactor.testing");
const test_io = @import("testing/io.zig");
const Client = @import("client/Client.zig");
const Server = @import("server/Server.zig");
const Request = @import("server/Request.zig");
const Response = @import("server/Response.zig");

const greeting = "hello over the simulated network";
const url = "http://server.test:8080/";

fn hello(io: Io, _: *Request, response: *Response) anyerror!void {
    try response.send(io, greeting);
}

/// The client node, the server node at 10.8.0.2:8080 known as `server.test`,
/// and the server's address.
const Nodes = struct { client: *Sim.Node, server: *Sim.Node, address: Io.net.IpAddress };

fn twoNodes(sim: *Sim, link: Sim.Net.Link) !Nodes {
    const address = try Io.net.IpAddress.parseIp4("10.8.0.2", 8080);
    const client = try sim.node("client", .{});
    const server = try sim.node("server", .{ .addresses = &.{address} });
    try sim.net().dns("server.test", server);
    try sim.net().link(client, server, link);
    return .{ .client = client, .server = server, .address = address };
}

/// One exchange: a server on the server node answering with `handler`, and
/// `ask` run against it by a client on the client node, each through a seam
/// of its own.
const Exchange = struct {
    sim: *Sim,
    nodes: Nodes,
    handler: *Server.Handler = .of(hello),
    ask: *const fn (e: *Exchange, io: Io, client: *Client) anyerror!void = askHello,
    client_seam: reactor_testing.Seam = undefined,
    server_seam: reactor_testing.Seam = undefined,
    done: bool = false,

    fn serve(server: *Server, io: Io, listener: *Io.net.Server) void {
        // A serve that ends with the shutdown has nothing to say.
        server.serve(io, listener) catch {}; // glint-ignore: Z026 -- serve ends with the test's shutdown
    }

    fn run(e: *Exchange) !void {
        e.client_seam.init(e.nodes.client.io());
        e.server_seam.init(e.nodes.server.io());
        const server_io = e.server_seam.io();
        const client_io = e.client_seam.io();
        var listener = try e.nodes.address.listen(server_io, .{});
        defer listener.deinit(server_io);
        var server: Server = .init(testing.allocator, .{}, e.handler);
        defer server.deinit(server_io);
        var serving = try server_io.concurrent(serve, .{ &server, server_io, &listener });
        defer {
            server.shutdown(server_io);
            serving.await(server_io);
        }
        var client: Client = .init(testing.allocator, .{});
        defer client.deinit(client_io);
        try e.ask(e, client_io, &client);
        e.done = true;
    }
};

fn askHello(_: *Exchange, io: Io, client: *Client) anyerror!void {
    var response = try client.send(io, .{ .url = url });
    defer response.deinit(io);
    try testing.expectEqual(std.http.Status.ok, response.status);
    const body = try response.collect(testing.allocator, io, .limited(1 << 10));
    defer testing.allocator.free(body);
    try testing.expectEqualStrings(greeting, body);
}

/// The run ended with every task finished; anything else is the test's failure.
fn finished(outcome: Sim.Outcome) !void {
    switch (outcome) {
        .finished => {},
        .failed => |err| return err,
        .deadlock => |reports| {
            std.debug.print("deadlock, {d} tasks waiting\n", .{reports.len});
            for (reports) |report| std.debug.print("  node {d}: {f}", .{ report.node.raw(), report });
            return error.TestUnexpectedResult;
        },
        .stuck, .double_close => |report| {
            std.debug.print("{t}: node {d}: {f}", .{ outcome, report.node.raw(), report });
            return error.TestUnexpectedResult;
        },
        else => {
            std.debug.print("{t}\n", .{outcome});
            return error.TestUnexpectedResult;
        },
    }
}

test "an HTTP/1.1 exchange runs on the simulated network, seed by seed, its socket options asked of the seam" {
    if (test_io.evented) return error.SkipZigTest;
    for ([_]u64{ 1, 2, 3, 4 }) |seed| {
        const sim = try Sim.init(testing.allocator, .{ .watchdog = null, .seed = seed });
        defer sim.deinit();
        var e: Exchange = .{ .sim = sim, .nodes = try twoNodes(sim, .{}) };
        try finished(sim.run(Exchange.run, .{&e}));
        try testing.expect(e.done);
        // The client and the server each asked nodelay of their socket; nothing was set on a system.
        try testing.expectEqual(@as(?bool, true), e.client_seam.asked().last.?.nodelay);
        try testing.expectEqual(@as(?bool, true), e.server_seam.asked().last.?.nodelay);
    }
}

test "over a slow link the exchange still ends, live within a virtual bound" {
    if (test_io.evented) return error.SkipZigTest;
    const sim = try Sim.init(testing.allocator, .{ .watchdog = null, .seed = 7 });
    defer sim.deinit();
    var e: Exchange = .{ .sim = sim, .nodes = try twoNodes(sim, .{ .latency = .{ .fixed = .fromMilliseconds(150) } }) };
    try sim.start(Exchange.run, .{&e});
    const settled = try sim.settle(.{ .within = .fromSeconds(30) });
    if (settled != .live) {
        std.debug.print("{f}", .{settled});
        return error.TestUnexpectedResult;
    }
    try testing.expect(e.done);
}

fn lossy(_: void, c: *Case) !void {
    const sim = try c.sim(.{});
    // Up to one segment in five lost, each sent again after a backoff, over a latency drawn too.
    const link: Sim.Net.Link = .{
        .latency = .{ .uniform = .{ .min = .fromMicroseconds(100), .max = .fromMilliseconds(80) } },
        .loss_per_million = @intCast(c.source.integer(200_000)),
    };
    var e: Exchange = .{ .sim = sim, .nodes = try twoNodes(sim, link) };
    try finished(sim.run(Exchange.run, .{&e}));
    try testing.expect(e.done);
}

test "over a lossy link the exchange ends whole, case by case" {
    if (test_io.evented) return error.SkipZigTest;
    try shakedown.check(testing.allocator, {}, lossy, .{ .cases = 64 });
}

const first_part = "the first part of the body, ";
const rest = "and the rest, which a reset cuts off";

/// A body sent in two parts, five virtual seconds apart; the client resets
/// the connection between them.
const Cut = struct {
    exchange: Exchange,
    handler: Server.Handler = .{ .handleFn = handle },
    case: *Case,

    fn handle(_: *Server.Handler, io: Io, _: *Request, response: *Response) anyerror!void {
        const w = try response.writer(io);
        try w.writeAll(first_part);
        try response.flush(io);
        try io.sleep(.fromSeconds(5), .awake);
        try w.writeAll(rest);
        try response.end(io);
    }

    fn ask(e: *Exchange, io: Io, client: *Client) anyerror!void {
        const cut: *Cut = @fieldParentPtr("exchange", e);
        {
            var response = try client.send(io, .{ .url = url });
            defer response.deinit(io);
            try testing.expectEqual(std.http.Status.ok, response.status);
            const body = response.reader(io);
            var part: [first_part.len]u8 = undefined;
            try body.readSliceAll(&part);
            try testing.expectEqualStrings(first_part, &part);
            e.sim.net().resetConnections(e.nodes.client, e.nodes.server);
            if (body.allocRemaining(testing.allocator, .limited(1 << 10))) |whole| {
                testing.allocator.free(whole);
                return error.TestUnexpectedResult;
            } else |err| try testing.expectEqual(error.ReadFailed, err);
            try testing.expectEqual(error.ConnectionFailed, response.failure());
            cut.case.reached("reset arrived mid-body");
        }
        // The reset connection is not kept: the next request dials again and is answered whole.
        var again = try client.send(io, .{ .url = url });
        defer again.deinit(io);
        const whole = try again.collect(testing.allocator, io, .limited(1 << 10));
        defer testing.allocator.free(whole);
        try testing.expectEqualStrings(first_part ++ rest, whole);
    }

    fn property(_: void, c: *Case) !void {
        const sim = try c.sim(.{});
        var cut: Cut = .{ .case = c, .exchange = .{ .sim = sim, .nodes = try twoNodes(sim, .{}) } };
        cut.exchange.handler = &cut.handler;
        cut.exchange.ask = ask;
        try finished(sim.run(Exchange.run, .{&cut.exchange}));
        try testing.expect(cut.exchange.done);
    }
};

test "a reset mid-body fails the read as ConnectionFailed, and the next request dials again" {
    if (test_io.evented) return error.SkipZigTest;
    try shakedown.check(testing.allocator, {}, Cut.property, .{ .cases = 32, .reach = &.{"reset arrived mid-body"} });
}

fn partitioned(_: void, c: *Case) !void {
    const sim = try c.sim(.{});
    var e: Exchange = .{ .sim = sim, .nodes = try twoNodes(sim, .{ .latency = .{ .fixed = .fromMilliseconds(5) } }) };
    sim.net().partition(&.{e.nodes.client}, &.{e.nodes.server});
    try sim.start(Exchange.run, .{&e});
    // The partition stands for up to ten virtual seconds; settle heals it.
    if (sim.runFor(.fromMilliseconds(@intCast(500 + c.source.integer(9_500))))) |outcome| try finished(outcome);
    if (!e.done) c.reached("the exchange waited out a partition");
    const settled = try sim.settle(.{ .within = .fromSeconds(60) });
    if (settled != .live) {
        std.debug.print("{f}", .{settled});
        return error.TestUnexpectedResult;
    }
    try testing.expect(e.done);
}

test "a partition healed by settle lets the exchange end, live within a virtual bound" {
    if (test_io.evented) return error.SkipZigTest;
    try shakedown.check(testing.allocator, {}, partitioned, .{ .cases = 32, .reach = &.{"the exchange waited out a partition"} });
}

// everyFault over one request: one clean run records the calls, then each
// single fault at each step gets a run of its own. The sweep runs inside a
// simulation's root task with a FIFO schedule, so every run makes the same
// calls up to its fault; one side's node `Io` is faulted and the other's is
// not. Every call through the faulted `Io` is made inside `run`, the next
// request and the teardown included: a run is held to the clean run's calls
// when `run` returns, so `check` only judges what `run` kept.

/// The errors a sweep injects where a call can return them: a peer gone, a
/// connection aborted before its accept, a resource short for a moment.
const sweep_errors: []const anyerror = &.{ error.ConnectionResetByPeer, error.ConnectionAborted, error.SystemResources };

/// The full sweep, and the one that injects only cancels.
const full_sweep: shakedown.EveryFaultOptions = .{ .errors = sweep_errors };
const cancel_sweep: shakedown.EveryFaultOptions = .{ .errors = &.{}, .short = false, .alloc = false };

/// Whether `err` is in the error set `E`.
fn inSet(comptime E: type, err: anyerror) bool {
    inline for (@typeInfo(E).error_set.error_names.?) |name| if (err == @field(anyerror, name)) return true;
    return false;
}

/// A body that is not the one sent, read as if it were whole.
const PartialAsWhole = error.PartialAsWhole;

/// A whole answer with an error status: a server that could not serve the
/// request and said so.
const ErrorStatus = error.ErrorStatus;

/// One request for `greeting` from `client` on `io`: a typed error, or the
/// whole body, never less of it presented as whole.
fn askWhole(client: *Client, io: Io) anyerror!void {
    var response = try client.send(io, .{ .url = url });
    defer response.deinit(io);
    const body = try response.collect(testing.allocator, io, .limited(1 << 10));
    defer testing.allocator.free(body);
    if (response.status.class() == .server_error) return ErrorStatus;
    if (response.status != .ok or !std.mem.eql(u8, greeting, body)) return PartialAsWhole;
}

/// `result` is a whole response or one of the client's own errors (or, from
/// a faulted server, a whole error answer); a landed cancel is `Canceled`.
fn typedOrWhole(result: anyerror!void, cancel: bool, server_faulted: bool) !void {
    const err = if (result) |_| return else |e| e;
    if (server_faulted and err == ErrorStatus) return;
    if (!inSet(Client.SendError, err) and !inSet(@import("client/Response.zig").CollectError, err)) return err;
    if (cancel) try testing.expectEqual(error.Canceled, err);
}

/// Whether the run's fault fell before `boundary`, the step the second
/// request began at. A run with no fault, or a cancel that could not land,
/// has none.
fn faultedBefore(injected: ?shakedown.Injected, boundary: u64) bool {
    const i = injected orelse return false;
    return i.step < boundary;
}

fn isCancel(injected: ?shakedown.Injected) bool {
    const i = injected orelse return false;
    return i.fault == .cancel;
}

/// Waits, on `io`, which no fault reaches, until the next whole virtual
/// minute: every run of a sweep shares one simulation, whose time goes on, so
/// each starts at the same point in the minute and whatever reads the time
/// (a date cached by the second, a deadline) reads it alike in every run.
fn alignStart(io: Io) !void {
    const minute: i96 = 60 * std.time.ns_per_s;
    const now = Io.Timestamp.now(io, .awake).nanoseconds;
    try io.sleep(.fromNanoseconds(@intCast(minute - @mod(now, minute))), .awake);
}

/// The sweep's clean steps and its runs; a failed run is printed with its
/// fault and its trace.
const Swept = struct { steps: u64, runs: u64 };

fn sweepWith(base: Io, ctx: anytype, options: shakedown.EveryFaultOptions) !Swept {
    var report: shakedown.EveryFaultReport = .{};
    var with = options;
    with.diagnostics = &report;
    defer report.deinit();
    var done = shakedown.everyFault(testing.allocator, base, ctx, with) catch |err| {
        if (report.failure) |f| std.debug.print("{t} at {any}, first difference {any}\n{s}\n", .{ f.err, f.injected, f.difference, f.trace });
        return err;
    };
    defer done.deinit();
    return .{ .steps = done.steps, .runs = done.runs };
}

/// The test's server, on a node whose `Io` no fault reaches.
const SteadyServer = struct {
    seam: reactor_testing.Seam = undefined,
    listener: Io.net.Server = undefined,
    server: Server = undefined,
    serving: Io.Future(void) = undefined,

    fn start(s: *SteadyServer, node: *Sim.Node, address: Io.net.IpAddress) !void {
        s.seam.init(node.io());
        const io = s.seam.io();
        s.listener = try address.listen(io, .{});
        s.server = .init(testing.allocator, .{}, .of(hello));
        s.serving = try io.concurrent(Exchange.serve, .{ &s.server, io, &s.listener });
    }

    fn stop(s: *SteadyServer) void {
        const io = s.seam.io();
        s.server.shutdown(io);
        s.serving.await(io);
        s.server.deinit(io);
        s.listener.deinit(io);
    }
};

/// The client's node faulted, the server steady. The property: the call
/// returns a typed error or a whole response, never a partial one presented
/// as whole, and the next request on the same client succeeds.
const ClientSweep = struct {
    /// The client node's own `Io`, which no fault reaches.
    steady: Io,
    fio: *shakedown.FaultIo = undefined,
    seam: reactor_testing.Seam = undefined,
    first: anyerror!void = {},
    boundary: u64 = 0,
    next: anyerror!void = {},

    pub fn setUp(c: *ClientSweep, fio: *shakedown.FaultIo) !void {
        try alignStart(c.steady);
        c.fio = fio;
        c.seam.init(fio.io());
    }

    pub fn run(c: *ClientSweep, _: Io) anyerror!void {
        const io = c.seam.io();
        var client: Client = .init(try c.fio.allocator(testing.allocator), .{});
        defer client.deinit(io);
        c.first = askWhole(&client, io);
        c.boundary = c.fio.steps().peek();
        c.next = askWhole(&client, io);
    }

    pub fn check(c: *ClientSweep, _: Io, result: anyerror!void, injected: ?shakedown.Injected) !void {
        try result;
        if (injected == null or faultedBefore(injected, c.boundary)) {
            try typedOrWhole(c.first, isCancel(injected), false);
            try c.next;
        } else {
            try c.first;
            try typedOrWhole(c.next, isCancel(injected), false);
        }
    }

    pub fn tearDown(_: *ClientSweep) void {}

    fn sweep(node: *Sim.Node, server_node: *Sim.Node, address: Io.net.IpAddress, options: shakedown.EveryFaultOptions) !void {
        var server: SteadyServer = .{};
        try server.start(server_node, address);
        defer server.stop();
        var c: ClientSweep = .{ .steady = node.io() };
        const swept = try sweepWith(node.io(), &c, options);
        // Two requests on one connection, and its close: some twenty calls, faulted a run each.
        try testing.expect(swept.steps >= 20 and swept.runs > 5);
    }
};

/// The server's node faulted, the client well behaved. The property: the
/// faulted connection ends, nothing leaks (the testing allocator and the
/// simulation's double-close report agree), and the next connection is served.
const ServerSweep = struct {
    client_node: *Sim.Node,
    address: Io.net.IpAddress,
    fio: *shakedown.FaultIo = undefined,
    steady: reactor_testing.Seam = undefined,
    seam: reactor_testing.Seam = undefined,
    client_seam: reactor_testing.Seam = undefined,
    first: anyerror!void = {},
    first_ended: bool = false,
    boundary: u64 = 0,
    next: anyerror!void = {},
    next_ended: bool = false,
    served: anyerror!void = {},

    fn serve(server: *Server, io: Io, listener: *Io.net.Server, result: *anyerror!void) void {
        result.* = server.serve(io, listener);
    }

    pub fn setUp(s: *ServerSweep, fio: *shakedown.FaultIo) !void {
        try alignStart(s.steady.io());
        s.fio = fio;
        s.seam.init(fio.io());
        s.client_seam.init(s.client_node.io());
    }

    /// One request from a client of its own, its connection closed, then
    /// whether the server's end of it closed too, within a virtual minute.
    fn once(s: *ServerSweep, server: *Server, ended: *bool) anyerror!void {
        const io = s.client_seam.io();
        const result = result: {
            var client: Client = .init(testing.allocator, .{ .timeouts = .{ .connect = .literal("5s"), .activity = .literal("5s") } });
            defer client.deinit(io);
            break :result askWhole(&client, io);
        };
        var waited: u32 = 0;
        while (server.stats(s.steady.io()).open != 0 and waited < 600) : (waited += 1) try io.sleep(.fromMilliseconds(100), .awake);
        ended.* = server.stats(s.steady.io()).open == 0;
        return result;
    }

    pub fn run(s: *ServerSweep, _: Io) anyerror!void {
        const io = s.seam.io();
        // The listener is opened unfaulted; its accepts are the server's, faulted.
        var listener = try s.address.listen(s.steady.io(), .{});
        defer listener.deinit(s.steady.io());
        var server: Server = .init(try s.fio.allocator(testing.allocator), .{}, .of(hello));
        defer server.deinit(io);
        s.served = {};
        var serving = try io.concurrent(serve, .{ &server, io, &listener, &s.served });
        s.first = s.once(&server, &s.first_ended);
        s.boundary = s.fio.steps().peek();
        s.next = s.once(&server, &s.next_ended);
        server.shutdown(io);
        serving.await(io);
    }

    pub fn check(s: *ServerSweep, _: Io, result: anyerror!void, injected: ?shakedown.Injected) !void {
        try result;
        const cancel = isCancel(injected);
        // A cancel that reached the accept loop ends serve, as one from shutdown would.
        if (s.served) |_| {} else |err| {
            try testing.expect(cancel);
            try testing.expectEqual(error.Canceled, err);
        }
        if (injected == null or faultedBefore(injected, s.boundary)) {
            try typedOrWhole(s.first, false, true);
            try testing.expect(s.first_ended);
            if (s.served) |_| try s.next else |_| {}
            try testing.expect(s.next_ended);
        } else {
            try s.first;
            try testing.expect(s.first_ended);
            try typedOrWhole(s.next, false, true);
            try testing.expect(s.next_ended);
        }
    }

    pub fn tearDown(_: *ServerSweep) void {}

    fn sweep(node: *Sim.Node, client_node: *Sim.Node, address: Io.net.IpAddress, options: shakedown.EveryFaultOptions) !void {
        var s: ServerSweep = .{ .client_node = client_node, .address = address };
        s.steady.init(node.io());
        const swept = try sweepWith(node.io(), &s, options);
        try testing.expect(swept.runs > 5);
    }
};

/// A simulation every run of a sweep takes alike: a FIFO schedule and no
/// spurious wakes, which are drawn from a source that goes on from run to run
/// (the seeded exchanges above meet them).
fn sweepSim() !*Sim {
    return Sim.init(testing.allocator, .{ .watchdog = null, .seed = 11, .schedule = .fifo, .spurious_wake_per_million = 0 });
}

test "every single fault on the client's side of one request: a typed error or a whole response, then the next request succeeds" {
    if (test_io.evented) return error.SkipZigTest;
    const sim = try sweepSim();
    defer sim.deinit();
    const nodes = try twoNodes(sim, .{});
    try finished(sim.run(ClientSweep.sweep, .{ nodes.client, nodes.server, nodes.address, full_sweep }));
}

test "every cancel on the client's side of one request is the call's answer, and the next request succeeds" {
    if (test_io.evented) return error.SkipZigTest;
    const sim = try sweepSim();
    defer sim.deinit();
    const nodes = try twoNodes(sim, .{});
    try finished(sim.run(ClientSweep.sweep, .{ nodes.client, nodes.server, nodes.address, cancel_sweep }));
}

test "every single fault on the server's side of one request: the connection ends, nothing leaks, the next is served" {
    if (test_io.evented) return error.SkipZigTest;
    const sim = try sweepSim();
    defer sim.deinit();
    const nodes = try twoNodes(sim, .{});
    try finished(sim.run(ServerSweep.sweep, .{ nodes.server, nodes.client, nodes.address, full_sweep }));
}

test "every cancel on the server's side of one request: the connection ends, nothing leaks, the next is served" {
    if (test_io.evented) return error.SkipZigTest;
    const sim = try sweepSim();
    defer sim.deinit();
    const nodes = try twoNodes(sim, .{});
    try finished(sim.run(ServerSweep.sweep, .{ nodes.server, nodes.client, nodes.address, cancel_sweep }));
}
