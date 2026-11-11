//! uplink on shakedown's simulated network (`Sim.Net`): a client node and a
//! server node, names in the simulation's DNS, latency, loss and resets drawn
//! from a seed. Each node's `Io` is wrapped in reactor's seam
//! (`reactor.testing`), so reactor's raw socket calls (the options it sets, a
//! peek) ask the test instead of a system the simulated sockets are not in.
//! The suite runs once, in the `Io.Threaded` test binary: a simulation brings
//! its own `Io`, so the evented binaries would only run it again.
const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const shakedown = @import("shakedown");
const Sim = shakedown.Sim;
const reactor_testing = @import("reactor.testing");
const test_io = @import("testing/io.zig");
const Client = @import("client/Client.zig");
const Server = @import("server/Server.zig");
const Request = @import("server/Request.zig");
const Response = @import("server/Response.zig");

const greeting = "hello over the simulated network";

fn hello(io: Io, _: *Request, response: *Response) anyerror!void {
    try response.send(io, greeting);
}

/// One exchange: a server on `server_node`, a client on `client_node` asking
/// it by name, each through a seam of its own.
const Exchange = struct {
    client_seam: reactor_testing.Seam = undefined,
    server_seam: reactor_testing.Seam = undefined,
    done: bool = false,

    fn serve(server: *Server, io: Io, listener: *Io.net.Server) void {
        // A serve that ends with the shutdown has nothing to say.
        server.serve(io, listener) catch {}; // glint-ignore: Z026 -- serve ends with the test's shutdown
    }

    fn run(e: *Exchange, client_node: *Sim.Node, server_node: *Sim.Node, address: Io.net.IpAddress) !void {
        e.client_seam.init(client_node.io());
        e.server_seam.init(server_node.io());
        const server_io = e.server_seam.io();
        const client_io = e.client_seam.io();
        var listener = try address.listen(server_io, .{});
        defer listener.deinit(server_io);
        var server: Server = .init(testing.allocator, .{}, .of(hello));
        defer server.deinit(server_io);
        var serving = try server_io.concurrent(serve, .{ &server, server_io, &listener });
        defer {
            server.shutdown(server_io);
            serving.await(server_io);
        }
        var client: Client = .init(testing.allocator, .{});
        defer client.deinit(client_io);
        var response = try client.send(client_io, .{ .url = "http://server.test:8080/" });
        defer response.deinit(client_io);
        try testing.expectEqual(std.http.Status.ok, response.status);
        const body = try response.collect(testing.allocator, client_io, .limited(1 << 10));
        defer testing.allocator.free(body);
        try testing.expectEqualStrings(greeting, body);
        e.done = true;
    }
};

/// A simulation with a client node, a server node at 10.8.0.2:8080 known as
/// `server.test`, and `link` between them.
fn twoNodes(sim: *Sim, link: Sim.Net.Link) !struct { client: *Sim.Node, server: *Sim.Node, address: Io.net.IpAddress } {
    const address = try Io.net.IpAddress.parseIp4("10.8.0.2", 8080);
    const client = try sim.node("client", .{});
    const server = try sim.node("server", .{ .addresses = &.{address} });
    try sim.net().dns("server.test", server);
    try sim.net().link(client, server, link);
    return .{ .client = client, .server = server, .address = address };
}

test "an HTTP/1.1 exchange runs on the simulated network, seed by seed, its socket options asked of the seam" {
    if (test_io.evented) return error.SkipZigTest;
    for ([_]u64{ 1, 2, 3, 4 }) |seed| {
        const sim = try Sim.init(testing.allocator, .{ .watchdog = null, .seed = seed });
        defer sim.deinit();
        const nodes = try twoNodes(sim, .{});
        var e: Exchange = .{};
        switch (sim.run(Exchange.run, .{ &e, nodes.client, nodes.server, nodes.address })) {
            .finished => {},
            .failed => |err| return err,
            else => |outcome| {
                std.debug.print("seed {d}: {t}\n", .{ seed, outcome });
                return error.TestUnexpectedResult;
            },
        }
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
    const nodes = try twoNodes(sim, .{ .latency = .{ .fixed = .fromMilliseconds(150) } });
    var e: Exchange = .{};
    try sim.start(Exchange.run, .{ &e, nodes.client, nodes.server, nodes.address });
    const settled = try sim.settle(.{ .within = .fromSeconds(30) });
    if (settled != .live) {
        std.debug.print("{f}", .{settled});
        return error.TestUnexpectedResult;
    }
    try testing.expect(e.done);
}
