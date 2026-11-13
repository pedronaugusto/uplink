//! dial's tests: connections raced across a name's addresses on a
//! clock the test moves, a dial with no task to spare, socket options, a
//! local address, HTTPS records and Unix sockets.

const std = @import("std");
const reactor = @import("reactor");
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const span = @import("../span.zig");
const Duration = span.Duration;
const dialing = @import("dial.zig");
const Options = dialing.Options;
const Dialed = dialing.Dialed;
const DialError = dialing.DialError;
const dial = dialing.dial;
const dialHttps = dialing.dialHttps;
const dialUnix = dialing.dialUnix;
const interleave = dialing.interleave;
const testing = std.testing;
const test_io = @import("../testing/io.zig");
const shakedown = @import("shakedown");

test "a dial with no task to spare tries a name's addresses one after another" {
    // Reactor makes the socket itself past the Io (a bind, an option before connect), or falls back to the system's getaddrinfo: on the system's sockets.
    const Serial = shakedown.Layer(u8, .{
        .concurrent = struct {
            fn concurrent(_: ?*anyopaque, _: usize, _: std.mem.Alignment, _: []const u8, _: std.mem.Alignment, _: *const fn (*const anyopaque, *anyopaque) void) Io.ConcurrentError!*Io.AnyFuture {
                return error.ConcurrencyUnavailable;
            }
        }.concurrent,
        .groupConcurrent = struct {
            fn groupConcurrent(_: ?*anyopaque, _: *Io.Group, _: []const u8, _: std.mem.Alignment, _: *const fn (*const anyopaque) void) Io.ConcurrentError!void {
                return error.ConcurrencyUnavailable;
            }
        }.groupConcurrent,
    });
    const io = test_io.io();
    var listener = try (try IpAddress.parse("127.0.0.1", 0)).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    var serial: Serial = .init(io, 0);
    const port = listener.socket.address.getPort();
    // An address connects; the connection completes in the backlog.
    var by_address = try dial(serial.io(), "127.0.0.1", port, .{ .timeout = .literal("5s") });
    by_address.stream.deinit(io);
    try testing.expect(!by_address.timeout_enforced);
    // A name is looked up on a target that can do it without a task, and
    // refused on one that cannot; it never waits on itself.
    var by_name = dial(serial.io(), "localhost", port, .{}) catch |err| {
        try testing.expectEqual(error.ConcurrencyUnavailable, err);
        return;
    };
    by_name.stream.deinit(io);
}

test "a connection expires at its controlled connect deadline and cancels the attempt" {
    try test_io.simulated(struct {
        fn inSim() !void {
            const Hang = struct {
                var connecting: Io.Event = .unset;
                var canceled: std.atomic.Value(bool) = .init(false);
                fn connect(_: ?*anyopaque, _: *const IpAddress, _: IpAddress.ConnectOptions) IpAddress.ConnectError!Io.net.Socket {
                    connecting.set(test_io.io());
                    var never: Io.Event = .unset;
                    never.wait(test_io.io()) catch |err| {
                        canceled.store(true, .release);
                        return err;
                    };
                    unreachable; // unreachable: nothing sets `never`
                }
            };
            const Hanging = shakedown.Layer(u8, .{ .netConnectIp = Hang.connect });
            var clock: shakedown.Clock = .init(test_io.io(), .{});
            var hanging: Hanging = .init(clock.io(), 0);
            const Run = struct {
                fn run(io: Io, out: *DialError!Dialed) void {
                    out.* = dial(io, "127.0.0.1", 1, .{ .timeout = .literal("200ms") });
                }
            };
            var result: DialError!Dialed = undefined;
            var task = test_io.io().concurrent(Run.run, .{ hanging.io(), &result }) catch return error.SkipZigTest;
            defer task.cancel(test_io.io());
            try Hang.connecting.waitTimeout(test_io.io(), .{ .duration = .{ .raw = .fromSeconds(10), .clock = .awake } });
            try clock.awaitArmed(1, .{ .duration = .{ .raw = .fromSeconds(10), .clock = .awake } });
            clock.advance(.fromMilliseconds(199));
            try testing.expect(!Hang.canceled.load(.acquire));
            clock.advance(.fromMilliseconds(1));
            task.await(test_io.io());
            try testing.expectError(error.TimedOut, result);
            try testing.expect(Hang.canceled.load(.acquire));
        }
    }.inSim, .{});
}

/// Answers `silent.example` with two addresses, and either hangs every
/// attempt until it is canceled or refuses the first.
const Silent = struct {
    var attempts: std.atomic.Value(u32) = .init(0);
    var canceled: std.atomic.Value(u32) = .init(0);
    var refuse_first = false;

    fn lookup(_: ?*anyopaque, _: Io.net.HostName, results: *Io.Queue(Io.net.HostName.LookupResult), options: Io.net.HostName.LookupOptions) Io.net.HostName.LookupError!void {
        const io = test_io.io();
        defer results.close(io);
        const answers: []const Io.net.HostName.LookupResult = &.{
            .{ .address = .{ .ip6 = .loopback(options.port) } },
            .{ .address = .{ .ip4 = .loopback(options.port) } },
        };
        results.putAll(io, answers) catch return error.Canceled;
    }

    fn connect(_: ?*anyopaque, _: *const IpAddress, _: IpAddress.ConnectOptions) IpAddress.ConnectError!Io.net.Socket {
        const n = attempts.fetchAdd(1, .acq_rel);
        if (refuse_first and n == 0) return error.ConnectionRefused;
        var never: Io.Event = .unset;
        never.wait(test_io.io()) catch |err| {
            _ = canceled.fetchAdd(1, .acq_rel);
            return err;
        };
        unreachable; // unreachable: nothing sets `never`
    }

    const L = shakedown.Layer(u8, .{ .netLookup = lookup, .netConnectIp = connect });

    fn run(io: Io, out: *DialError!Dialed) void {
        out.* = dial(io, "silent.example", 80, .{ .timeout = .literal("200ms"), .attempt_delay = .literal("50ms") });
    }
};

test "a name whose every address stays silent is TimedOut, and so is one whose first is refused" {
    try test_io.simulated(struct {
        fn inSim() !void {
            const io = test_io.io();
            var clock: shakedown.Clock = .init(io, .{});
            var layer: Silent.L = .init(clock.io(), 0);
            const wait: Io.Timeout = .{ .duration = .{ .raw = .fromSeconds(10), .clock = .awake } };
            for ([_]bool{ false, true }) |refuse| {
                Silent.attempts.store(0, .release);
                Silent.canceled.store(0, .release);
                Silent.refuse_first = refuse;
                var result: DialError!Dialed = undefined;
                var task = io.concurrent(Silent.run, .{ layer.io(), &result }) catch return error.SkipZigTest;
                defer task.cancel(io);
                // The first attempt's deadline and the delay before the second; a
                // refusal starts the second at once, and then the second's deadline
                // and the stale delay are what is armed.
                try clock.awaitArmed(2, wait);
                var left: Io.Duration = .fromMilliseconds(200);
                if (!refuse) {
                    // The delay passes, and the second attempt starts beside the
                    // first, to end at the same deadline.
                    clock.advance(.fromMilliseconds(50));
                    left = .fromMilliseconds(150);
                    while (Silent.attempts.load(.acquire) < 2) try io.sleep(.fromMilliseconds(1), .awake);
                    try clock.awaitArmed(2, wait);
                }
                // Both deadlines are the one limit's end.
                clock.advance(left);
                task.await(io);
                try testing.expectError(error.TimedOut, result);
                try testing.expectEqual(@as(u32, 2), Silent.attempts.load(.acquire));
                try testing.expectEqual(@as(u32, if (refuse) 1 else 2), Silent.canceled.load(.acquire));
            }
        }
    }.inSim, .{});
}

test "a dial with a timeout is bounded, on a runtime by the kernel with no fallback path taken" {
    // Each backend's own connect timeout, the kernel's on a runtime: on the system's sockets, on every backend.
    const io = test_io.io();
    var listener = try (try IpAddress.parse("127.0.0.1", 0)).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const before = reactor.fallbacks();
    var dialed = try dial(io, "127.0.0.1", listener.socket.address.getPort(), .{ .timeout = .literal("5s") });
    dialed.stream.deinit(io);
    try testing.expect(dialed.timeout_enforced);
    // The peer is the listener, not the stream's own end.
    try testing.expect(dialed.peer.?.eql(&listener.socket.address));
    if (test_io.evented) try testing.expectEqual(before, reactor.fallbacks());
}

test "addresses are tried with the families alternating from the first's" {
    try test_io.simulated(struct {
        fn inSim() !void {
            const v4 = [_]IpAddress{ .{ .ip4 = .loopback(1) }, .{ .ip4 = .loopback(2) }, .{ .ip4 = .loopback(3) } };
            const v6: IpAddress = .{ .ip6 = .loopback(9) };
            var out: [8]IpAddress = undefined;
            const mixed = interleave(&.{ v6, v4[0], v4[1], v4[2] }, &out);
            const ports = [_]u16{ 9, 1, 2, 3 };
            for (mixed, ports) |a, p| try testing.expectEqual(p, a.getPort());
            const from_four = interleave(&.{ v4[0], v4[1], v6 }, &out);
            for (from_four, [_]u16{ 1, 9, 2 }) |a, p| try testing.expectEqual(p, a.getPort());
            try testing.expectEqual(@as(usize, 0), interleave(&.{}, &out).len);
        }
    }.inSim, .{});
}

/// Answers `stuck.example` with a black-holed address first and a working
/// one second, and records when each attempt starts on the test's clock.
const Eyeballs = struct {
    var listener_port: u16 = 0;
    var clock: *shakedown.Clock = undefined;
    var starts: [4]i96 = undefined;
    var count: std.atomic.Value(u32) = .init(0);
    var abandoned: std.atomic.Value(bool) = .init(false);
    var refuse_first = false;
    /// Set once the first attempt has run: its delay can be armed before it
    /// does.
    var first_ran: Io.Event = .unset;

    fn lookup(_: ?*anyopaque, host: Io.net.HostName, results: *Io.Queue(Io.net.HostName.LookupResult), options: Io.net.HostName.LookupOptions) Io.net.HostName.LookupError!void {
        _ = host;
        const io = test_io.io();
        defer results.close(io);
        const answers: []const Io.net.HostName.LookupResult = &.{
            .{ .address = .{ .ip6 = .loopback(options.port) } },
            .{ .address = .{ .ip4 = .loopback(options.port) } },
        };
        results.putAll(io, answers) catch return error.Canceled;
    }

    fn connect(_: ?*anyopaque, address: *const IpAddress, options: IpAddress.ConnectOptions) IpAddress.ConnectError!Io.net.Socket {
        const n = count.fetchAdd(1, .acq_rel);
        starts[n] = clock.read(.awake).nanoseconds;
        if (n == 0) first_ran.set(test_io.io());
        if (address.* == .ip6) {
            if (refuse_first) return error.ConnectionRefused;
            var never: Io.Event = .unset;
            never.wait(test_io.io()) catch |err| {
                abandoned.store(true, .release);
                return err;
            };
            unreachable; // unreachable: nothing sets `never`
        }
        var real = address.*;
        real.setPort(listener_port);
        return test_io.io().vtable.netConnectIp(test_io.io().userdata, &real, options);
    }

    const L = shakedown.Layer(u8, .{ .netLookup = lookup, .netConnectIp = connect });

    fn run(io: Io, delay: Duration, out: *DialError!Dialed) void {
        out.* = dial(io, "stuck.example", 8080, .{ .attempt_delay = delay });
    }
};

test "a black-holed first address costs one attempt delay, and a refused one none" {
    try test_io.simulated(struct {
        fn inSim() !void {
            const io = test_io.io();
            var listener = try (try IpAddress.parse("127.0.0.1", 0)).listen(io, .{ .reuse_address = true });
            defer listener.deinit(io);
            Eyeballs.listener_port = listener.socket.address.getPort();
            var clock: shakedown.Clock = .init(io, .{});
            Eyeballs.clock = &clock;
            var layer: Eyeballs.L = .init(clock.io(), 0);
            const wait: Io.Timeout = .{ .duration = .{ .raw = .fromSeconds(10), .clock = .awake } };
            for ([_]bool{ false, true }) |refuse| {
                Eyeballs.count.store(0, .release);
                Eyeballs.abandoned.store(false, .release);
                Eyeballs.refuse_first = refuse;
                Eyeballs.first_ran = .unset;
                const delay: Duration = if (refuse) .literal("30s") else .literal("100ms");
                var result: DialError!Dialed = undefined;
                var seamed: test_io.Seamed = .{};
                var task = io.concurrent(Eyeballs.run, .{ seamed.over(layer.io()), delay, &result }) catch return error.SkipZigTest;
                defer task.cancel(io);
                if (!refuse) {
                    // The black hole holds the first attempt, and the delay is
                    // armed beside it, in either order. A step short of the delay
                    // starts nothing.
                    try Eyeballs.first_ran.waitTimeout(io, wait);
                    try clock.awaitArmed(1, wait);
                    clock.advance(.fromMilliseconds(99));
                    try testing.expectEqual(@as(u32, 1), Eyeballs.count.load(.acquire));
                    clock.advance(.fromMilliseconds(1));
                }
                task.await(io);
                var d = try result;
                d.stream.deinit(io);
                try testing.expectEqual(@as(u8, 2), d.addresses);
                try testing.expectEqual(@as(u32, 2), Eyeballs.count.load(.acquire));
                const gap = Eyeballs.starts[1] - Eyeballs.starts[0];
                if (refuse) {
                    // The refusal started the next attempt at once, on a clock
                    // that never moved.
                    try testing.expectEqual(@as(i96, 0), gap);
                } else {
                    try testing.expectEqual(@as(i96, delay.raw()), gap);
                    try testing.expect(Eyeballs.abandoned.load(.acquire));
                }
            }
        }
    }.inSim, .{});
}

test "a Unix socket is connected by its path, and a missing one named" {
    try test_io.simulated(struct {
        fn inSim() !void {
            const io = test_io.io();
            if (!Io.net.has_unix_sockets) return error.SkipZigTest;
            // In the node's own Unix namespace.
            const path = "/run/u.sock";
            const address = try Io.net.UnixAddress.init(path);
            var server = address.listen(io, .{}) catch return error.SkipZigTest;
            defer server.deinit(io);
            var d = try dialUnix(io, path, .{ .timeout = .literal("5s") });
            d.stream.deinit(io);
            try testing.expectError(error.NameNotResolved, dialUnix(io, "/run/none.sock", .{}));
        }
    }.inSim, .{});
}

test "an origin is dialed as it is when its endpoints fail, unless one publishes ECH" {
    try test_io.simulated(struct {
        fn inSim() !void {
            const zone = @import("../testing/zone.zig");
            const Dns = @import("Dns.zig");
            const io = test_io.io();
            const gpa = testing.allocator;
            var listener = try (try IpAddress.parse("127.0.0.1", 0)).listen(io, .{ .reuse_address = true });
            defer listener.deinit(io);
            const port = listener.socket.address.getPort();
            var name_buf: [64]u8 = undefined;
            const name = try std.mem.print(&name_buf, "_{d}._https.origin.test", .{port});
            // The endpoint's name has no address and the record no hints.
            const entries = [_]zone.Entry{
                .{ .name = "origin.test", .a = &.{.{ 127, 0, 0, 1 }} },
                .{ .name = name, .https = &.{.{ .target = "gone.test", .params = &.{.{ .key = .ech, .value = "\x00\x00" }} }} },
            };
            var z: zone.Zone = .{ .entries = &entries };
            var d: Dns = .{ .transport = z.transport() };
            const options: Options = .{ .resolver = d.resolver(), .timeout = .literal("5s") };
            const protocols: []const []const u8 = &.{"http/1.1"};
            var plain = try dialHttps(io, gpa, "origin.test", port, .{ .protocols = protocols, .ech = false }, options);
            plain.dialed.stream.deinit(io);
            try testing.expectEqual(null, plain.binding);
            try testing.expectEqual(null, plain.record);
            try testing.expectError(error.NameNotResolved, dialHttps(io, gpa, "origin.test", port, .{ .protocols = protocols, .ech = true }, options));
        }
    }.inSim, .{});
}

test "an endpoint's hints are dialed when its name has no address" {
    try test_io.simulated(struct {
        fn inSim() !void {
            const zone = @import("../testing/zone.zig");
            const Dns = @import("Dns.zig");
            const io = test_io.io();
            const gpa = testing.allocator;
            var listener = try (try IpAddress.parse("127.0.0.1", 0)).listen(io, .{ .reuse_address = true });
            defer listener.deinit(io);
            var port_value = zone.port(listener.socket.address.getPort());
            const entries = [_]zone.Entry{.{ .name = "hinted.test", .https = &.{.{ .target = "nameless.test", .params = &.{
                .{ .key = .port, .value = &port_value },
                .{ .key = .ipv4hint, .value = "\x7f\x00\x00\x01" },
            } }} }};
            var z: zone.Zone = .{ .entries = &entries };
            var d: Dns = .{ .transport = z.transport() };
            var got = try dialHttps(io, gpa, "hinted.test", 443, .{ .protocols = &.{"http/1.1"}, .ech = false }, .{ .resolver = d.resolver(), .timeout = .literal("5s") });
            defer got.binding.?.deinit(gpa);
            got.dialed.stream.deinit(io);
            try testing.expectEqualStrings("nameless.test", got.record.?.target);
        }
    }.inSim, .{});
}

test "a dial's socket is made with the options it asked for, told to reactor" {
    // An option before the connect makes reactor make the socket itself; on
    // the simulation its seam makes the connection and records the options.
    try test_io.simulated(struct {
        fn inSim() !void {
            const io = test_io.io();
            var listener = try (try IpAddress.parse("127.0.0.1", 0)).listen(io, .{});
            defer listener.deinit(io);
            const before = test_io.asked().count;
            var dialed = try dial(io, "127.0.0.1", listener.socket.address.getPort(), .{ .socket = .{
                .nodelay = true,
                .keepalive = .{ .on = .{ .idle = .literal(45) } },
                .receive_buffer = .fromRaw(96 << 10),
            } });
            defer dialed.stream.deinit(io);
            // The connection is made: the listener accepts it from the dial's own end.
            const accepted = try listener.accept(io);
            defer accepted.close(io);
            try testing.expect(accepted.socket.address.eql(&dialed.stream.borrow().socket.socket.address));
            try testing.expect(dialed.peer.?.eql(&listener.socket.address));
            // The options, told once, as the socket is made.
            const asked = test_io.asked();
            try testing.expectEqual(before + 1, asked.count);
            try testing.expectEqual(@as(?bool, true), asked.last.?.nodelay);
            try testing.expectEqual(@as(?bool, true), asked.last.?.keepalive);
            try testing.expectEqual(@as(?u32, 96 << 10), asked.last.?.receive_buffer);
        }
    }.inSim, .{});
}

test "a dial from a local address goes from it, to the name's addresses of its family only" {
    // A bind makes reactor make the socket itself; on the simulation its seam
    // binds where asked.
    try test_io.simulated(struct {
        fn inSim() !void {
            const io = test_io.io();
            // localhost is 127.0.0.1 first, then ::1: a listener on each.
            var six = try (try IpAddress.parse("::1", 0)).listen(io, .{});
            defer six.deinit(io);
            const port = six.socket.address.getPort();
            var four = try (try IpAddress.parse("127.0.0.1", port)).listen(io, .{});
            defer four.deinit(io);
            const local: IpAddress = try .parse("::1", 4000);
            var dialed = try dial(io, "localhost", port, .{ .local_address = local });
            defer dialed.stream.deinit(io);
            // Both addresses were found; the IPv6 one alone was dialed, from
            // the bound endpoint.
            try testing.expectEqual(@as(u8, 2), dialed.addresses);
            try testing.expect(dialed.peer.?.eql(&six.socket.address));
            const accepted = try six.accept(io);
            defer accepted.close(io);
            try testing.expect(accepted.socket.address.eql(&local));
            try testing.expect(dialed.stream.borrow().socket.socket.address.eql(&local));
            try testing.expectError(error.AddressFamilyMismatch, dial(io, "127.0.0.1", port, .{ .local_address = local }));
        }
    }.inSim, .{});
}
