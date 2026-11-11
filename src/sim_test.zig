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
