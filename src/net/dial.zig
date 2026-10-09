//! TCP connections to a host by name or address: the name looked up, its
//! addresses raced by Happy Eyeballs (RFC 8305), the socket tuned, all
//! within one deadline; and connections to a Unix socket.
//!
//! Attempts start one at a time, the families alternating from the one the
//! resolver put first, each `attempt_delay` after the last or at once when
//! the last fails; the first to connect wins and the rest are canceled. A
//! host whose IPv6 path is broken costs a quarter second, not a timeout,
//! and a healthy one is not hit with a connection per address.
//!
//! The deadline needs a task to race the attempts against: std's own
//! connect timeout is not implemented on any system in Zig 0.17, so an
//! attempt that hangs can only be abandoned by canceling the task it runs
//! on. With no task to spare the attempts run in turn on this one, the
//! deadline is not enforced, and the result says so.

const std = @import("std");
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const resolve = @import("resolve.zig");
const sys = @import("sys.zig");
const Resolver = @import("Resolver.zig");

/// How connections are made.
pub const Options = struct {
    /// Turn Nagle's algorithm off on every socket.
    nodelay: bool = true,
    /// Turn TCP keepalive on, probing a connection idle this long; null
    /// leaves the system's setting, which is off.
    keepalive: ?Io.Duration = null,
    /// The name's lookup and every attempt, together.
    timeout: ?Io.Duration = null,
    /// What looks names up.
    resolver: Resolver = .system,
    /// How long an attempt runs alone before the next address is tried
    /// beside it: RFC 8305's recommended Connection Attempt Delay.
    attempt_delay: Io.Duration = .fromMilliseconds(250),
};

/// A connected stream, and what it took.
pub const Dialed = struct {
    stream: Io.net.Stream,
    /// False when a timeout was asked for and no task could keep it.
    timeout_enforced: bool = true,
    /// How long the name's lookup took; zero for an address.
    lookup: Io.Duration = .zero,
    /// How many addresses the name had.
    addresses: u8 = 1,
};

/// Why no connection was made.
pub const DialError = error{
    /// The name is not a host name.
    InvalidHostName,
    /// The name has no address.
    NameNotResolved,
    /// Every address refused or failed.
    ConnectionFailed,
    /// `Options.timeout` ran out.
    TimedOut,
    /// A name was to be looked up with no task to spare, on a target with
    /// no lookup of its own.
    ConcurrencyUnavailable,
    Canceled,
};

/// Connect to `host` on `port`.
pub fn dial(io: Io, host: []const u8, port: u16, options: Options) DialError!Dialed {
    return within(io, options.timeout, dialNow, .{ io, host, port, options });
}

/// Connect to the Unix socket at `path`, within `options.timeout`; the
/// socket options for TCP do not apply.
pub fn dialUnix(io: Io, path: []const u8, options: Options) DialError!Dialed {
    return within(io, options.timeout, unixNow, .{ io, path });
}

/// `function(args)`, abandoned once `limit` runs out: raced against a
/// sleep when a task can be had for it, else run here, unbounded.
fn within(io: Io, limit: ?Io.Duration, comptime function: anytype, args: anytype) DialError!Dialed {
    const l = limit orelse return @call(.auto, function, args);
    const Race = union(enum) {
        connected: DialError!Dialed,
        expired: Io.Cancelable!void,
    };
    var buffer: [2]Race = undefined;
    var race: Io.Select(Race) = .init(io, &buffer);
    defer while (race.cancel()) |late| switch (late) {
        .connected => |result| if (result) |d| d.stream.close(io) else |_| {},
        .expired => {},
    };
    race.concurrent(.connected, function, args) catch {
        var d = try @call(.auto, function, args);
        d.timeout_enforced = false;
        return d;
    };
    race.concurrent(.expired, Io.sleep, .{ io, l, .awake }) catch {
        // The attempt runs already; wait for it, unbounded.
        while (race.cancel()) |late| switch (late) {
            .connected => |result| {
                var d = try result;
                d.timeout_enforced = false;
                return d;
            },
            .expired => {},
        };
        unreachable; // unreachable: the connecting task was started above
    };
    return switch (try race.await()) {
        .connected => |result| result,
        .expired => |result| if (result) |_| error.TimedOut else |err| err,
    };
}

fn dialNow(io: Io, host: []const u8, port: u16, options: Options) DialError!Dialed {
    var storage: [resolve.max_addresses]IpAddress = undefined;
    const literal = resolve.literal(host, port) != null;
    const started = Io.Clock.awake.now(io);
    const addresses = options.resolver.lookup(io, host, port, null, &storage) catch |err| return switch (err) {
        error.InvalidHostName => error.InvalidHostName,
        error.NameNotResolved => error.NameNotResolved,
        error.ConcurrencyUnavailable => error.ConcurrencyUnavailable,
        error.Canceled => error.Canceled,
    };
    const lookup: Io.Duration = if (literal) .zero else started.durationTo(Io.Clock.awake.now(io));
    var ordered: [resolve.max_addresses]IpAddress = undefined;
    const stream = try connectAny(io, interleave(addresses, &ordered), options.attempt_delay);
    sys.tune(io, stream.socket.handle, .{ .nodelay = options.nodelay, .keepalive = options.keepalive });
    return .{ .stream = stream, .lookup = lookup, .addresses = @intCast(addresses.len) };
}

fn unixNow(io: Io, path: []const u8) DialError!Dialed {
    const address = Io.net.UnixAddress.init(path) catch return error.InvalidHostName;
    const stream = address.connect(io) catch |err| return switch (err) {
        error.Canceled => error.Canceled,
        error.FileNotFound, error.NotDir => error.NameNotResolved,
        else => error.ConnectionFailed,
    };
    return .{ .stream = stream };
}

/// The addresses in Happy Eyeballs order (RFC 8305 §4): the resolver's
/// order within each family, the families alternating from the first's.
pub fn interleave(addresses: []const IpAddress, out: []IpAddress) []IpAddress {
    std.debug.assert(out.len >= addresses.len);
    if (addresses.len == 0) return out[0..0];
    const first = std.meta.activeTag(addresses[0]);
    var a: usize = 0;
    var b: usize = 0;
    var n: usize = 0;
    var want_first = true;
    while (n < addresses.len) : (want_first = !want_first) {
        const index = if (want_first) &a else &b;
        while (index.* < addresses.len and (std.meta.activeTag(addresses[index.*]) == first) != want_first) index.* += 1;
        if (index.* == addresses.len) continue;
        out[n] = addresses[index.*];
        index.* += 1;
        n += 1;
    }
    return out[0..n];
}

/// The first of `addresses` to accept a connection, tried in order, each
/// `delay` after the one before or at once when it failed. Those no task
/// could be found for are tried one after another once the racing ones
/// have failed.
fn connectAny(io: Io, addresses: []const IpAddress, delay: Io.Duration) DialError!Io.net.Stream {
    std.debug.assert(addresses.len <= resolve.max_addresses);
    if (addresses.len == 1) return connectOne(io, addresses[0]) catch |err| return mapConnect(err);
    const Event = Attempts.Event;
    // Every attempt arms at most one delay.
    var buffer: [2 * resolve.max_addresses]Event = undefined;
    var race: Io.Select(Event) = .init(io, &buffer);
    defer while (race.cancel()) |late| switch (late) {
        .connected => |result| if (result) |stream| stream.close(io) else |_| {},
        .waited => {},
    };
    var state: Attempts = .{ .race = &race, .io = io, .addresses = addresses, .delay = delay };
    state.startNext();
    while (state.running > 0) {
        switch (try race.await()) {
            .connected => |result| {
                state.running -= 1;
                if (result) |stream| return stream else |err| if (err == error.Canceled) return error.Canceled;
                state.startNext();
            },
            // A delay outrun by a failure is stale: the start that
            // followed the failure armed its own.
            .waited => |result| if ((result catch return error.Canceled) == state.started) state.startNext(),
        }
    }
    for (addresses[state.started..]) |address| {
        if (connectOne(io, address)) |stream| return stream else |err| if (err == error.Canceled) return error.Canceled;
    }
    return error.ConnectionFailed;
}

/// The racing attempts of `connectAny`.
const Attempts = struct {
    race: *Io.Select(Event),
    io: Io,
    addresses: []const IpAddress,
    delay: Io.Duration,
    started: usize = 0,
    running: usize = 0,
    /// False once a task could not be had: the rest go in turn.
    spare: bool = true,

    const Event = union(enum) {
        connected: Io.net.IpAddress.ConnectError!Io.net.Stream,
        /// The delay armed when this many attempts had started.
        waited: Io.Cancelable!usize,
    };

    /// Start the next attempt, and the delay before the one after it.
    fn startNext(a: *Attempts) void {
        if (!a.spare or a.started == a.addresses.len) return;
        a.race.concurrent(.connected, connectOne, .{ a.io, a.addresses[a.started] }) catch {
            a.spare = false;
            return;
        };
        a.started += 1;
        a.running += 1;
        if (a.started < a.addresses.len) {
            // ziglint-ignore: Z026 with no task for the delay, the next attempt starts when this one fails
            a.race.concurrent(.waited, waitFor, .{ a.io, a.delay, a.started }) catch {};
        }
    }
};

fn waitFor(io: Io, delay: Io.Duration, armed_at: usize) Io.Cancelable!usize {
    try io.sleep(delay, .awake);
    return armed_at;
}

fn connectOne(io: Io, address: IpAddress) Io.net.IpAddress.ConnectError!Io.net.Stream {
    return address.connect(io, .{ .mode = .stream });
}

fn mapConnect(err: Io.net.IpAddress.ConnectError) DialError {
    return switch (err) {
        error.Canceled => error.Canceled,
        else => error.ConnectionFailed,
    };
}

const testing = std.testing;
const shakedown = @import("shakedown");

test "a dial with no task to spare tries a name's addresses one after another" {
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
    const io = testing.io;
    var listener = try (try IpAddress.parse("127.0.0.1", 0)).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    var serial: Serial = .init(io, 0);
    const port = listener.socket.address.getPort();
    // An address connects; the connection completes in the backlog.
    const by_address = try dial(serial.io(), "127.0.0.1", port, .{ .timeout = .fromSeconds(5) });
    by_address.stream.close(io);
    try testing.expect(!by_address.timeout_enforced);
    const by_name = dial(serial.io(), "localhost", port, .{}) catch |err| {
        if (!sys.own_lookup and err == error.ConcurrencyUnavailable) return;
        return err;
    };
    by_name.stream.close(io);
    try testing.expect(sys.own_lookup);
}

test "a connection expires at its controlled connect deadline and cancels the attempt" {
    const Hang = struct {
        var connecting: Io.Event = .unset;
        var canceled: std.atomic.Value(bool) = .init(false);
        fn connect(_: ?*anyopaque, _: *const IpAddress, _: IpAddress.ConnectOptions) IpAddress.ConnectError!Io.net.Socket {
            connecting.set(testing.io);
            var never: Io.Event = .unset;
            never.wait(testing.io) catch |err| {
                canceled.store(true, .release);
                return err;
            };
            unreachable; // unreachable: nothing sets `never`
        }
    };
    const Hanging = shakedown.Layer(u8, .{ .netConnectIp = Hang.connect });
    var clock: shakedown.Clock = .init(testing.io, .{});
    var hanging: Hanging = .init(clock.io(), 0);
    const Run = struct {
        fn run(io: Io, out: *DialError!Dialed) void {
            out.* = dial(io, "127.0.0.1", 1, .{ .timeout = .fromMilliseconds(200) });
        }
    };
    var result: DialError!Dialed = undefined;
    var task = testing.io.concurrent(Run.run, .{ hanging.io(), &result }) catch return error.SkipZigTest;
    defer task.cancel(testing.io);
    try Hang.connecting.waitTimeout(testing.io, .{ .duration = .{ .raw = .fromSeconds(10), .clock = .awake } });
    try clock.awaitArmed(1, .{ .duration = .{ .raw = .fromSeconds(10), .clock = .awake } });
    clock.advance(.fromMilliseconds(199));
    try testing.expect(!Hang.canceled.load(.acquire));
    clock.advance(.fromMilliseconds(1));
    task.await(testing.io);
    try testing.expectError(error.TimedOut, result);
    try testing.expect(Hang.canceled.load(.acquire));
}

test "addresses are tried with the families alternating from the first's" {
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
        const io = testing.io;
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
        if (n == 0) first_ran.set(testing.io);
        if (address.* == .ip6) {
            if (refuse_first) return error.ConnectionRefused;
            var never: Io.Event = .unset;
            never.wait(testing.io) catch |err| {
                abandoned.store(true, .release);
                return err;
            };
            unreachable; // unreachable: nothing sets `never`
        }
        var real = address.*;
        real.setPort(listener_port);
        return testing.io.vtable.netConnectIp(testing.io.userdata, &real, options);
    }

    const L = shakedown.Layer(u8, .{ .netLookup = lookup, .netConnectIp = connect });

    fn run(io: Io, delay: Io.Duration, out: *DialError!Dialed) void {
        out.* = dial(io, "stuck.example", 8080, .{ .attempt_delay = delay });
    }
};

test "a black-holed first address costs one attempt delay, and a refused one none" {
    const io = testing.io;
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
        const delay: Io.Duration = if (refuse) .fromSeconds(30) else .fromMilliseconds(100);
        var result: DialError!Dialed = undefined;
        var task = io.concurrent(Eyeballs.run, .{ layer.io(), delay, &result }) catch return error.SkipZigTest;
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
        const d = try result;
        d.stream.close(io);
        try testing.expectEqual(@as(u8, 2), d.addresses);
        try testing.expectEqual(@as(u32, 2), Eyeballs.count.load(.acquire));
        const gap = Eyeballs.starts[1] - Eyeballs.starts[0];
        if (refuse) {
            // The refusal started the next attempt at once, on a clock
            // that never moved.
            try testing.expectEqual(@as(i96, 0), gap);
        } else {
            try testing.expectEqual(@as(i96, delay.nanoseconds), gap);
            try testing.expect(Eyeballs.abandoned.load(.acquire));
        }
    }
}

test "a Unix socket is connected by its path, and a missing one named" {
    const io = testing.io;
    if (!Io.net.has_unix_sockets) return error.SkipZigTest;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var path_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const dir = path_buf[0..try tmp.dir.realPath(io, &path_buf)];
    var sock_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const path = try std.mem.print(&sock_buf, "{s}/u.sock", .{dir});
    if (path.len > Io.net.UnixAddress.max_len) return error.SkipZigTest;
    const address = try Io.net.UnixAddress.init(path);
    var server = address.listen(io, .{}) catch return error.SkipZigTest;
    defer server.deinit(io);
    const d = try dialUnix(io, path, .{ .timeout = .fromSeconds(5) });
    d.stream.close(io);
    var missing_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const missing = try std.mem.print(&missing_buf, "{s}/none.sock", .{dir});
    try testing.expectError(error.NameNotResolved, dialUnix(io, missing, .{}));
}
