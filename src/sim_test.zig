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
const cloak = @import("cloak");
const TestProxy = @import("testing/Proxy.zig");
const Proxy = @import("transport/Proxy.zig");

const greeting = "hello over the simulated network";
const plain_url = "http://server.test:8080/";
const secure_url = "https://server.test:8080/";

/// A server certificate for `server.test`, issued here and self-signed, and
/// a client's trust in it: no `openssl`, no file, nothing outside the test.
/// Valid from 2025 to 2036, around the simulation's wall clock (2026).
const Pki = struct {
    key: cloak.PrivateKey,
    leaf: []u8,
    identity: cloak.Identity,
    trust: cloak.Trust.Snapshot,
    credentials: [1]cloak.tls.Credential,

    fn init(p: *Pki) !void {
        const gpa = testing.allocator;
        const io = testing.io;
        p.key = try cloak.PrivateKey.generate(gpa, io, .p256);
        errdefer p.key.deinit();
        var spki: [cloak.PrivateKey.max_public_key_info]u8 = undefined;
        p.leaf = try cloak.certificates.issue(gpa, io, &.{
            .subject = .{ .attributes = &.{.{ .common_name = "server.test" }} },
            .not_before = .fromNanoseconds(@as(i96, 1_735_689_600) * std.time.ns_per_s),
            .not_after = .fromNanoseconds(@as(i96, 2_082_758_400) * std.time.ns_per_s),
            .names = &.{.{ .dns = "server.test" }},
            .key_usage = .{ .digital_signature = true },
            .purposes = &.{.server_auth},
        }, p.key.publicKeyInfo(&spki), .{ .key = p.key });
        errdefer gpa.free(p.leaf);
        p.identity = try cloak.Identity.init(gpa, &.{p.leaf}, p.key, .{});
        errdefer p.identity.deinit();
        var builder: cloak.Trust = .init(gpa);
        defer builder.deinit();
        try builder.addDer(p.leaf, .{});
        p.trust = try builder.freeze();
        p.credentials = .{.{ .identity = p.identity }};
    }

    fn deinit(p: *Pki) void {
        p.trust.deinit();
        p.identity.deinit();
        testing.allocator.free(p.leaf);
        p.key.deinit();
    }

    fn url(pki: ?*const Pki) []const u8 {
        return if (pki == null) plain_url else secure_url;
    }

    /// A simulation's options for an exchange over `pki`: a handshake's key
    /// share (ML-KEM, unoptimized in Debug) needs more than a task's default
    /// stack.
    fn simOptions(pki: ?*const Pki, options: Sim.Options) Sim.Options {
        var with = options;
        if (pki != null) with.stack_size = .fromRaw(tls_stack_size);
        return with;
    }

    const tls_stack_size = 1024 * 1024;
};

/// What an exchange speaks, whether over TLS, and whether through a proxy's
/// tunnel.
const Setup = struct {
    speech: Speech = .http1,
    pki: ?*const Pki = null,
    tunnel: ?TestProxy.Kind = null,

    /// The nodes the exchange runs on: a proxy's between the client's and
    /// the server's when it tunnels.
    fn nodes(setup: Setup, sim: *Sim, link: Sim.Net.Link) !Nodes {
        return if (setup.tunnel != null) threeNodes(sim, link) else twoNodes(sim, link);
    }
};

fn hello(io: Io, _: *Request, response: *Response) anyerror!void {
    try response.send(io, greeting);
}

/// The client node, the server node at 10.8.0.2:8080 known as `server.test`,
/// and the server's address; a proxy's node at 10.8.0.3:3128, `proxy.test`,
/// when the client's way to the server is through it.
const Nodes = struct {
    client: *Sim.Node,
    server: *Sim.Node,
    address: Io.net.IpAddress,
    proxy: ?*Sim.Node = null,

    /// The node at the other end of the client's connection.
    fn near(n: Nodes) *Sim.Node {
        return n.proxy orelse n.server;
    }
};

const proxy_address = "10.8.0.3";
const proxy_port = 3128;

fn twoNodes(sim: *Sim, link: Sim.Net.Link) !Nodes {
    const address = try Io.net.IpAddress.parseIp4("10.8.0.2", 8080);
    const client = try sim.node("client", .{});
    const server = try sim.node("server", .{ .addresses = &.{address} });
    try sim.net().dns("server.test", server);
    try sim.net().link(client, server, link);
    return .{ .client = client, .server = server, .address = address };
}

/// The client linked to the proxy and the proxy to the server, each over
/// `link`, and the client partitioned from the server: a request that
/// reaches it went through the tunnel (until a `settle` heals every
/// partition; `tunneled` checks the proxy's log as well).
fn threeNodes(sim: *Sim, link: Sim.Net.Link) !Nodes {
    const address = try Io.net.IpAddress.parseIp4("10.8.0.2", 8080);
    const client = try sim.node("client", .{});
    const server = try sim.node("server", .{ .addresses = &.{address} });
    const proxy = try sim.node("proxy", .{ .addresses = &.{try Io.net.IpAddress.parseIp4(proxy_address, 0)} });
    try sim.net().dns("server.test", server);
    try sim.net().dns("proxy.test", proxy);
    try sim.net().link(client, proxy, link);
    try sim.net().link(proxy, server, link);
    sim.net().partition(&.{client}, &.{server});
    return .{ .client = client, .server = server, .address = address, .proxy = proxy };
}

/// The HTTP a client and its server speak over plain TCP.
const Speech = enum {
    http1,
    /// HTTP/2 from the first byte (RFC 9113 §3.3).
    h2_prior_knowledge,
    /// HTTP/1.1 asking to switch (`Upgrade: h2c`), HTTP/2 once answered.
    h2c_upgrade,

    fn client(speech: Speech) Client.Options {
        return .{ .http2 = switch (speech) {
            .http1 => .off,
            .h2_prior_knowledge => .prior_knowledge,
            .h2c_upgrade => .upgrade,
        } };
    }

    fn server(speech: Speech) Server.Options {
        return .{ .h2c = if (speech == .http1) .off else .alongside_http1 };
    }
};

/// One exchange: a server on the server node answering with `handler`, and
/// `ask` run against it by a client on the client node, each through a seam
/// of its own.
const Exchange = struct {
    sim: *Sim,
    nodes: Nodes,
    speech: Speech = .http1,
    /// TLS on both ends, with this certificate; plain TCP when null.
    pki: ?*const Pki = null,
    /// Through a proxy of this kind on `nodes.proxy`.
    tunnel: ?TestProxy.Kind = null,
    /// The proxy, while `ask` runs.
    proxy: ?*TestProxy = null,
    /// The server, while `ask` runs.
    server: ?*Server = null,
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
        var server_options = e.speech.server();
        if (e.pki) |p| server_options.tls = .{ .credentials = &p.credentials };
        var server: Server = .init(testing.allocator, server_options, e.handler);
        defer server.deinit(server_io);
        e.server = &server;
        defer e.server = null;
        var serving = try server_io.concurrent(serve, .{ &server, server_io, &listener });
        defer {
            server.shutdown(server_io);
            serving.await(server_io);
        }
        var client_options = e.speech.client();
        if (e.pki) |p| client_options.tls = .{ .trust = p.trust };
        var arena: std.heap.ArenaAllocator = .init(testing.allocator);
        defer arena.deinit();
        if (e.tunnel) |kind| {
            const proxy = try TestProxy.start(testing.allocator, e.nodes.proxy.?.io(), .{
                .kind = kind,
                .listen = try .parseIp4(proxy_address, proxy_port),
                .names = .lookup,
            });
            e.proxy = proxy;
            errdefer {
                proxy.stop();
                e.proxy = null;
            }
            const url = switch (kind) {
                .http => std.fmt.comptimePrint("http://proxy.test:{d}", .{proxy_port}),
                .socks => std.fmt.comptimePrint("socks5h://proxy.test:{d}", .{proxy_port}),
            };
            client_options.proxy = .{ .fixed = try Proxy.parse(arena.allocator(), url, .lowercase) };
        }
        defer if (e.proxy) |proxy| {
            proxy.stop();
            e.proxy = null;
        };
        var client: Client = .init(testing.allocator, client_options);
        defer client.deinit(client_io);
        try e.ask(e, client_io, &client);
        e.done = true;
    }
};

fn askHello(e: *Exchange, io: Io, client: *Client) anyerror!void {
    var response = try client.send(io, .{ .url = Pki.url(e.pki) });
    defer response.deinit(io);
    try testing.expectEqual(std.http.Status.ok, response.status);
    const body = try response.collect(testing.allocator, io, .limited(1 << 10));
    defer testing.allocator.free(body);
    try testing.expectEqualStrings(greeting, body);
}

/// Four requests at once, each answered whole over HTTP/2, on the one
/// connection the server accepted.
fn askMany(e: *Exchange, io: Io, client: *Client) anyerror!void {
    const One = struct {
        fn ask(cl: *Client, one_io: Io, target: []const u8) anyerror!void {
            var response = try cl.send(one_io, .{ .url = target });
            defer response.deinit(one_io);
            try testing.expectEqual(std.http.Status.ok, response.status);
            try testing.expect(response.version == .h2);
            const body = try response.collect(testing.allocator, one_io, .limited(1 << 10));
            defer testing.allocator.free(body);
            try testing.expectEqualStrings(greeting, body);
        }
    };
    // The first request opens the connection (and, under an upgrade, switches it).
    try One.ask(client, io, Pki.url(e.pki));
    var group: Io.Group = .init;
    defer group.cancel(io);
    var results: [3]anyerror!void = @splat({});
    const Each = struct {
        fn ask(cl: *Client, one_io: Io, target: []const u8, result: *anyerror!void) void {
            result.* = One.ask(cl, one_io, target);
        }
    };
    for (&results) |*result| try group.concurrent(io, Each.ask, .{ client, io, Pki.url(e.pki), result });
    try group.await(io);
    for (results) |result| try result;
    try testing.expectEqual(@as(u64, 1), e.server.?.stats(io).accepted);
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

fn lossy(setup: Setup, c: *Case) !void {
    const sim = try c.sim(Pki.simOptions(setup.pki, .{}));
    // Up to one segment in five lost, each sent again after a backoff, over a latency drawn too.
    const link: Sim.Net.Link = .{
        .latency = .{ .uniform = .{ .min = .fromMicroseconds(100), .max = .fromMilliseconds(80) } },
        .loss_per_million = @intCast(c.source.integer(200_000)),
    };
    var e: Exchange = .{ .sim = sim, .nodes = try setup.nodes(sim, link), .speech = setup.speech, .pki = setup.pki, .tunnel = setup.tunnel };
    if (setup.speech != .http1) e.ask = askMany;
    if (setup.tunnel != null) e.ask = if (setup.speech == .http1) askTunneled else askManyTunneled;
    try finished(sim.run(Exchange.run, .{&e}));
    try testing.expect(e.done);
}

test "over a lossy link the exchange ends whole, case by case" {
    if (test_io.evented) return error.SkipZigTest;
    try shakedown.check(testing.allocator, Setup{ .speech = .http1 }, lossy, .{ .cases = 64 });
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
            var response = try client.send(io, .{ .url = Pki.url(e.pki) });
            defer response.deinit(io);
            try testing.expectEqual(std.http.Status.ok, response.status);
            const body = response.reader(io);
            var part: [first_part.len]u8 = undefined;
            try body.readSliceAll(&part);
            try testing.expectEqualStrings(first_part, &part);
            e.sim.net().resetConnections(e.nodes.client, e.nodes.near());
            if (body.allocRemaining(testing.allocator, .limited(1 << 10))) |whole| {
                testing.allocator.free(whole);
                return error.TestUnexpectedResult;
            } else |err| try testing.expectEqual(error.ReadFailed, err);
            try testing.expectEqual(error.ConnectionFailed, response.failure());
            cut.case.reached("reset arrived mid-body");
        }
        // The reset connection is not kept: the next request dials again and is answered whole.
        var again = try client.send(io, .{ .url = Pki.url(e.pki) });
        defer again.deinit(io);
        const whole = try again.collect(testing.allocator, io, .limited(1 << 10));
        defer testing.allocator.free(whole);
        try testing.expectEqualStrings(first_part ++ rest, whole);
    }

    fn property(setup: Setup, c: *Case) !void {
        const sim = try c.sim(Pki.simOptions(setup.pki, .{}));
        var cut: Cut = .{ .case = c, .exchange = .{ .sim = sim, .nodes = try setup.nodes(sim, .{}), .speech = setup.speech, .pki = setup.pki, .tunnel = setup.tunnel } };
        cut.exchange.handler = &cut.handler;
        cut.exchange.ask = ask;
        try finished(sim.run(Exchange.run, .{&cut.exchange}));
        try testing.expect(cut.exchange.done);
    }
};

test "a reset mid-body fails the read as ConnectionFailed, and the next request dials again" {
    if (test_io.evented) return error.SkipZigTest;
    try shakedown.check(testing.allocator, Setup{ .speech = .http1 }, Cut.property, .{ .cases = 32, .reach = &.{"reset arrived mid-body"} });
}

fn partitioned(setup: Setup, c: *Case) !void {
    const sim = try c.sim(Pki.simOptions(setup.pki, .{}));
    var e: Exchange = .{ .sim = sim, .nodes = try setup.nodes(sim, .{ .latency = .{ .fixed = .fromMilliseconds(5) } }), .speech = setup.speech, .pki = setup.pki, .tunnel = setup.tunnel };
    if (setup.speech != .http1) e.ask = askMany;
    if (setup.tunnel != null) e.ask = if (setup.speech == .http1) askTunneled else askManyTunneled;
    sim.net().partition(&.{e.nodes.client}, &.{e.nodes.near()});
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
    try shakedown.check(testing.allocator, Setup{ .speech = .http1 }, partitioned, .{ .cases = 32, .reach = &.{"the exchange waited out a partition"} });
}

test "HTTP/2 by prior knowledge on the simulated network: four requests on one connection, seed by seed" {
    if (test_io.evented) return error.SkipZigTest;
    for ([_]u64{ 1, 2, 3, 4 }) |seed| {
        const sim = try Sim.init(testing.allocator, .{ .watchdog = null, .seed = seed });
        defer sim.deinit();
        var e: Exchange = .{ .sim = sim, .nodes = try twoNodes(sim, .{}), .speech = .h2_prior_knowledge, .ask = askMany };
        try finished(sim.run(Exchange.run, .{&e}));
        try testing.expect(e.done);
    }
}

test "HTTP/2 by an h2c upgrade on the simulated network: the first request switches, the rest share its connection" {
    if (test_io.evented) return error.SkipZigTest;
    for ([_]u64{ 1, 2, 3, 4 }) |seed| {
        const sim = try Sim.init(testing.allocator, .{ .watchdog = null, .seed = seed });
        defer sim.deinit();
        var e: Exchange = .{ .sim = sim, .nodes = try twoNodes(sim, .{}), .speech = .h2c_upgrade, .ask = askMany };
        try finished(sim.run(Exchange.run, .{&e}));
        try testing.expect(e.done);
    }
}

test "HTTP/2 over a lossy link: four requests on one connection end whole, case by case" {
    if (test_io.evented) return error.SkipZigTest;
    try shakedown.check(testing.allocator, Setup{ .speech = .h2_prior_knowledge }, lossy, .{ .cases = 64 });
}

test "HTTP/2: a reset mid-body fails the stream's read as ConnectionFailed, and the next request dials again" {
    if (test_io.evented) return error.SkipZigTest;
    try shakedown.check(testing.allocator, Setup{ .speech = .h2_prior_knowledge }, Cut.property, .{ .cases = 32, .reach = &.{"reset arrived mid-body"} });
}

test "HTTP/2: a partition healed by settle lets four requests on one connection end, live within a virtual bound" {
    if (test_io.evented) return error.SkipZigTest;
    try shakedown.check(testing.allocator, Setup{ .speech = .h2_prior_knowledge }, partitioned, .{ .cases = 32, .reach = &.{"the exchange waited out a partition"} });
}

test "TLS on the simulated network: HTTP/1.1, and HTTP/2 agreed by ALPN, seed by seed" {
    if (test_io.evented) return error.SkipZigTest;
    var pki: Pki = undefined;
    try pki.init();
    defer pki.deinit();
    for ([_]Speech{ .http1, .h2_prior_knowledge }) |speech| for ([_]u64{ 1, 2, 3, 4 }) |seed| {
        const sim = try Sim.init(testing.allocator, Pki.simOptions(&pki, .{ .watchdog = null, .seed = seed }));
        defer sim.deinit();
        var e: Exchange = .{ .sim = sim, .nodes = try twoNodes(sim, .{}), .speech = speech, .pki = &pki };
        if (speech != .http1) e.ask = askMany;
        try finished(sim.run(Exchange.run, .{&e}));
        try testing.expect(e.done);
    };
}

test "TLS over a lossy link: the handshake and the exchange end whole, case by case" {
    if (test_io.evented) return error.SkipZigTest;
    var pki: Pki = undefined;
    try pki.init();
    defer pki.deinit();
    try shakedown.check(testing.allocator, Setup{ .pki = &pki }, lossy, .{ .cases = 32 });
    try shakedown.check(testing.allocator, Setup{ .speech = .h2_prior_knowledge, .pki = &pki }, lossy, .{ .cases = 32 });
}

test "TLS: a reset mid-body fails the read as ConnectionFailed, and the next request dials again" {
    if (test_io.evented) return error.SkipZigTest;
    var pki: Pki = undefined;
    try pki.init();
    defer pki.deinit();
    try shakedown.check(testing.allocator, Setup{ .pki = &pki }, Cut.property, .{ .cases = 32, .reach = &.{"reset arrived mid-body"} });
}

test "TLS: a partition healed by settle lets the handshake and the exchange end, live within a virtual bound" {
    if (test_io.evented) return error.SkipZigTest;
    var pki: Pki = undefined;
    try pki.init();
    defer pki.deinit();
    try shakedown.check(testing.allocator, Setup{ .pki = &pki }, partitioned, .{ .cases = 32, .reach = &.{"the exchange waited out a partition"} });
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

/// One request for `greeting` from `client` on `io`, over TLS when `pki` is
/// set: a typed error, or the whole body, never less of it presented as whole.
fn askWhole(client: *Client, io: Io, pki: ?*const Pki) anyerror!void {
    var response = try client.send(io, .{ .url = Pki.url(pki) });
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

/// The test's server, on a node whose `Io` no fault reaches. Over TLS it
/// draws its random from one seed, on a `FaultIo` that faults nothing: its
/// key share and its signature (an ECDSA signature's length is its draw's)
/// are the same each time it starts, so a server started in each run of a
/// sweep sends the same records.
const SteadyServer = struct {
    seeded: ?*shakedown.FaultIo = null,
    seam: reactor_testing.Seam = undefined,
    listener: Io.net.Server = undefined,
    server: Server = undefined,
    serving: Io.Future(void) = undefined,

    fn start(s: *SteadyServer, node: *Sim.Node, address: Io.net.IpAddress, pki: ?*const Pki) !void {
        var base = node.io();
        if (pki != null) {
            s.seeded = try shakedown.FaultIo.init(testing.allocator, base, .{ .random_seed = 1 });
            base = s.seeded.?.io();
        }
        errdefer if (s.seeded) |f| f.deinit();
        s.seam.init(base);
        const io = s.seam.io();
        s.listener = try address.listen(io, .{});
        errdefer s.listener.deinit(io);
        var options: Server.Options = .{};
        if (pki) |p| options.tls = .{ .credentials = &p.credentials };
        s.server = .init(testing.allocator, options, .of(hello));
        s.serving = try io.concurrent(Exchange.serve, .{ &s.server, io, &s.listener });
    }

    fn stop(s: *SteadyServer) void {
        const io = s.seam.io();
        s.server.shutdown(io);
        s.serving.await(io);
        s.server.deinit(io);
        s.listener.deinit(io);
        if (s.seeded) |f| f.deinit();
    }
};

/// The client's node faulted, the server steady. The property: the call
/// returns a typed error or a whole response, never a partial one presented
/// as whole, and the next request on the same client succeeds. Over TLS the
/// server starts in each run (`SteadyServer`), so every run's handshake reads
/// the same records, and the handshake's calls are swept with the rest.
const ClientSweep = struct {
    /// The client node's own `Io`, which no fault reaches.
    steady: Io,
    /// TLS, with the server started in each run on `server_node`.
    pki: ?*const Pki = null,
    server_node: ?*Sim.Node = null,
    address: Io.net.IpAddress = undefined,
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
        var server: SteadyServer = .{};
        if (c.pki != null) try server.start(c.server_node.?, c.address, c.pki);
        // After the client's close, which runs first.
        defer if (c.pki != null) server.stop();
        var options: Client.Options = .{};
        if (c.pki) |p| options.tls = .{ .trust = p.trust };
        var client: Client = .init(try c.fio.allocator(testing.allocator), options);
        defer client.deinit(io);
        c.first = askWhole(&client, io, c.pki);
        c.boundary = c.fio.steps().peek();
        c.next = askWhole(&client, io, c.pki);
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
        try server.start(server_node, address, null);
        defer server.stop();
        var c: ClientSweep = .{ .steady = node.io() };
        const swept = try sweepWith(node.io(), &c, options);
        // Two requests on one connection, and its close: some twenty calls, faulted a run each.
        try testing.expect(swept.steps >= 20 and swept.runs > 5);
    }

    fn sweepTls(node: *Sim.Node, server_node: *Sim.Node, address: Io.net.IpAddress, pki: *const Pki, options: shakedown.EveryFaultOptions) !void {
        var c: ClientSweep = .{ .steady = node.io(), .pki = pki, .server_node = server_node, .address = address };
        const swept = try sweepWith(node.io(), &c, options);
        // The handshake's calls beside the two requests': some eighty, past plain TCP's twenty.
        try testing.expect(swept.steps >= 60 and swept.runs > 5);
    }
};

/// The server's node faulted, the client well behaved. The property: the
/// faulted connection ends, nothing leaks (the testing allocator and the
/// simulation's double-close report agree), and the next connection is served.
/// Over TLS the client draws its random from one seed each run, on a
/// `FaultIo` that faults nothing, so every run's handshake sends the same
/// records.
const ServerSweep = struct {
    client_node: *Sim.Node,
    address: Io.net.IpAddress,
    pki: ?*const Pki = null,
    seeded: ?*shakedown.FaultIo = null,
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

    /// The client's `Io` for this run: seeded afresh over TLS.
    fn clientIo(s: *ServerSweep) !void {
        if (s.pki == null) return;
        s.seeded = try shakedown.FaultIo.init(testing.allocator, s.client_node.io(), .{ .random_seed = 2 });
        s.client_seam.init(s.seeded.?.io());
    }

    /// One request from a client of its own, its connection closed, then
    /// whether the server's end of it closed too, within a virtual minute.
    fn once(s: *ServerSweep, server: *Server, ended: *bool) anyerror!void {
        const io = s.client_seam.io();
        const result = result: {
            var options: Client.Options = .{ .timeouts = .{ .connect = .literal("5s"), .activity = .literal("5s") } };
            if (s.pki) |p| options.tls = .{ .trust = p.trust };
            var client: Client = .init(testing.allocator, options);
            defer client.deinit(io);
            break :result askWhole(&client, io, s.pki);
        };
        var waited: u32 = 0;
        while (server.stats(s.steady.io()).open != 0 and waited < 600) : (waited += 1) try io.sleep(.fromMilliseconds(100), .awake);
        ended.* = server.stats(s.steady.io()).open == 0;
        return result;
    }

    pub fn run(s: *ServerSweep, _: Io) anyerror!void {
        const io = s.seam.io();
        try s.clientIo();
        defer if (s.seeded) |f| {
            f.deinit();
            s.seeded = null;
        };
        // The listener is opened unfaulted; its accepts are the server's, faulted.
        var listener = try s.address.listen(s.steady.io(), .{});
        defer listener.deinit(s.steady.io());
        var options: Server.Options = .{};
        if (s.pki) |p| options.tls = .{ .credentials = &p.credentials };
        var server: Server = .init(try s.fio.allocator(testing.allocator), options, .of(hello));
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

    fn sweepTls(node: *Sim.Node, client_node: *Sim.Node, address: Io.net.IpAddress, pki: *const Pki, options: shakedown.EveryFaultOptions) !void {
        var s: ServerSweep = .{ .client_node = client_node, .address = address, .pki = pki };
        s.steady.init(node.io());
        const swept = try sweepWith(node.io(), &s, options);
        // The handshake's calls beside the two connections': some hundred and fifty.
        try testing.expect(swept.steps >= 100 and swept.runs > 5);
    }
};

/// A simulation every run of a sweep takes alike: a FIFO schedule and no
/// spurious wakes, which are drawn from a source that goes on from run to run
/// (the seeded exchanges above meet them).
fn sweepSim() !*Sim {
    return sweepSimOver(null);
}

fn sweepSimOver(pki: ?*const Pki) !*Sim {
    return Sim.init(testing.allocator, Pki.simOptions(pki, .{ .watchdog = null, .seed = 11, .schedule = .fifo, .spurious_wake_per_million = 0 }));
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

test "every single fault on the client's side of one request over TLS, the handshake's calls too: a typed error or a whole response, then the next request succeeds" {
    if (test_io.evented) return error.SkipZigTest;
    var pki: Pki = undefined;
    try pki.init();
    defer pki.deinit();
    const sim = try sweepSimOver(&pki);
    defer sim.deinit();
    const nodes = try twoNodes(sim, .{});
    try finished(sim.run(ClientSweep.sweepTls, .{ nodes.client, nodes.server, nodes.address, &pki, full_sweep }));
}

test "every cancel on the client's side of one request over TLS, the handshake's calls too, is the call's answer, and the next request succeeds" {
    if (test_io.evented) return error.SkipZigTest;
    var pki: Pki = undefined;
    try pki.init();
    defer pki.deinit();
    const sim = try sweepSimOver(&pki);
    defer sim.deinit();
    const nodes = try twoNodes(sim, .{});
    try finished(sim.run(ClientSweep.sweepTls, .{ nodes.client, nodes.server, nodes.address, &pki, cancel_sweep }));
}

/// The tunnel was the way: the proxy was asked for the server by name, by
/// `CONNECT` or by SOCKS5h.
fn tunneled(proxy: *TestProxy, kind: TestProxy.Kind) !void {
    const log = try proxy.lines(testing.allocator);
    defer testing.allocator.free(log);
    const asked = switch (kind) {
        .http => "CONNECT server.test:8080 ",
        .socks => "SOCKS 5 server.test:8080",
    };
    if (std.mem.find(u8, log, asked) == null) {
        std.debug.print("proxy log:\n{s}", .{log});
        return error.TestUnexpectedResult;
    }
}

fn askTunneled(e: *Exchange, io: Io, client: *Client) anyerror!void {
    try askHello(e, io, client);
    try tunneled(e.proxy.?, e.tunnel.?);
}

fn askManyTunneled(e: *Exchange, io: Io, client: *Client) anyerror!void {
    try askMany(e, io, client);
    try tunneled(e.proxy.?, e.tunnel.?);
}

test "a proxy's tunnel on the simulated network, by CONNECT and by SOCKS5h, carries TLS: HTTP/1.1, and HTTP/2 agreed by ALPN, seed by seed" {
    if (test_io.evented) return error.SkipZigTest;
    var pki: Pki = undefined;
    try pki.init();
    defer pki.deinit();
    for ([_]TestProxy.Kind{ .http, .socks }) |kind| for ([_]Speech{ .http1, .h2_prior_knowledge }) |speech| for ([_]u64{ 1, 2, 3, 4 }) |seed| {
        const sim = try Sim.init(testing.allocator, Pki.simOptions(&pki, .{ .watchdog = null, .seed = seed }));
        defer sim.deinit();
        var e: Exchange = .{ .sim = sim, .nodes = try threeNodes(sim, .{}), .speech = speech, .pki = &pki, .tunnel = kind };
        e.ask = if (speech == .http1) askTunneled else askManyTunneled;
        try finished(sim.run(Exchange.run, .{&e}));
        try testing.expect(e.done);
    };
}

test "a proxy's tunnel over lossy links: the handshake and the exchange end whole, case by case" {
    if (test_io.evented) return error.SkipZigTest;
    var pki: Pki = undefined;
    try pki.init();
    defer pki.deinit();
    try shakedown.check(testing.allocator, Setup{ .pki = &pki, .tunnel = .http }, lossy, .{ .cases = 32 });
    try shakedown.check(testing.allocator, Setup{ .pki = &pki, .tunnel = .socks }, lossy, .{ .cases = 32 });
}

test "a proxy's tunnel reset mid-body fails the read as ConnectionFailed, and the next request tunnels again" {
    if (test_io.evented) return error.SkipZigTest;
    var pki: Pki = undefined;
    try pki.init();
    defer pki.deinit();
    try shakedown.check(testing.allocator, Setup{ .pki = &pki, .tunnel = .http }, Cut.property, .{ .cases = 32, .reach = &.{"reset arrived mid-body"} });
}

test "a partition between the client and its proxy, healed by settle, lets the tunnel's exchange end, live within a virtual bound" {
    if (test_io.evented) return error.SkipZigTest;
    var pki: Pki = undefined;
    try pki.init();
    defer pki.deinit();
    try shakedown.check(testing.allocator, Setup{ .pki = &pki, .tunnel = .http }, partitioned, .{ .cases = 32, .reach = &.{"the exchange waited out a partition"} });
}

test "every single fault on the server's side of one request over TLS, the handshake's calls too: the connection ends, nothing leaks, the next is served" {
    if (test_io.evented) return error.SkipZigTest;
    var pki: Pki = undefined;
    try pki.init();
    defer pki.deinit();
    const sim = try sweepSimOver(&pki);
    defer sim.deinit();
    const nodes = try twoNodes(sim, .{});
    try finished(sim.run(ServerSweep.sweepTls, .{ nodes.server, nodes.client, nodes.address, &pki, full_sweep }));
}

test "every cancel on the server's side of one request over TLS, the handshake's calls too: the connection ends, nothing leaks, the next is served" {
    if (test_io.evented) return error.SkipZigTest;
    var pki: Pki = undefined;
    try pki.init();
    defer pki.deinit();
    const sim = try sweepSimOver(&pki);
    defer sim.deinit();
    const nodes = try twoNodes(sim, .{});
    try finished(sim.run(ServerSweep.sweepTls, .{ nodes.server, nodes.client, nodes.address, &pki, cancel_sweep }));
}

/// A server whose first entropy draw, its handshake's (no session tickets,
/// whose keys would draw first), is canceled; a client asks once.
const CanceledHandshake = struct {
    fn run(nodes: Nodes, pki: *const Pki) !void {
        const fio = try shakedown.FaultIo.init(testing.allocator, nodes.server.io(), .{ .plan = &.{.{ .at = .{ .nth = .{ .call = .randomSecure, .n = 1 } }, .fault = .cancel }} });
        defer fio.deinit();
        var server_seam: reactor_testing.Seam = undefined;
        server_seam.init(fio.io());
        var client_seam: reactor_testing.Seam = undefined;
        client_seam.init(nodes.client.io());
        const io = server_seam.io();
        var listener = try nodes.address.listen(io, .{});
        defer listener.deinit(io);
        var server: Server = .init(testing.allocator, .{ .tls = .{ .credentials = &pki.credentials, .tickets = .none } }, .of(hello));
        defer server.deinit(io);
        var serving = try io.concurrent(Exchange.serve, .{ &server, io, &listener });
        {
            const client_io = client_seam.io();
            // One connection: a retry's would linger, as a served one does.
            var client: Client = .init(testing.allocator, .{ .tls = .{ .trust = pki.trust }, .retries = .none });
            defer client.deinit(client_io);
            if (askWhole(&client, client_io, pki)) |_| return error.TestUnexpectedResult else |_| {}
        }
        while (server.stats(io).open != 0) try client_seam.io().sleep(.fromMilliseconds(10), .awake);
        server.shutdown(io);
        serving.await(io);
        // The cancel landed in the handshake, and the canceled connection
        // made no call after it but its close: no linger's half close, no
        // read waiting on the client.
        try testing.expectEqual(@as(usize, 1), fio.fired().len);
        try testing.expectEqual(@as(u64, 0), fio.count(.netShutdown));
    }
};

test "a cancel at the server's handshake entropy draw ends the connection there, with no linger after it" {
    if (test_io.evented) return error.SkipZigTest;
    var pki: Pki = undefined;
    try pki.init();
    defer pki.deinit();
    const sim = try Sim.init(testing.allocator, Pki.simOptions(&pki, .{ .watchdog = null, .seed = 1 }));
    defer sim.deinit();
    const nodes = try twoNodes(sim, .{});
    try finished(sim.run(CanceledHandshake.run, .{ nodes, &pki }));
}
