//! TCP connections to a host by name or address: the name looked up, its
//! addresses raced by Happy Eyeballs (RFC 8305), the socket tuned, all
//! within one deadline; and connections to a Unix socket.
//!
//! Attempts start one at a time, the families alternating from the one the
//! resolver put first, each `attempt_delay` after the last or at once when
//! the last fails; the first to connect wins and the rest are canceled. A
//! host whose IPv6 path is broken costs a quarter second, not a timeout,
//! and a healthy one is not hit with a connection per address. With a
//! local address only the addresses of its family are tried.
//!
//! The socket's options, its local address and its interface are
//! reactor's (`reactor.net.connect`), set before the connect; a refused
//! option is the same for every address and is returned at once, named.
//!
//! An `https` origin is dialed as its HTTPS records say, when the resolver
//! reads them (`dialHttps`): the endpoints they name, in their order, then
//! the origin itself.
//!
//! The deadline is reactor's: every attempt is a `net.connect` that ends at
//! it. A runtime keeps it in the kernel, so one address is dialed on the
//! caller's own task with nothing beside it. Any other `Io` races the
//! attempt against a sleep as a task of its own; with no task to spare the
//! attempt runs unbounded, and the result says so.

const std = @import("std");
const builtin = @import("builtin");
const reactor = @import("reactor");
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const Allocator = std.mem.Allocator;
const Resolver = @import("Resolver.zig");
const span = @import("../span.zig");
const Duration = span.Duration;

const max_addresses = reactor.net.max_addresses;

/// How connections are made.
pub const Options = struct {
    /// The socket's options, set before it connects: Nagle's algorithm off
    /// unless asked otherwise.
    socket: reactor.net.SocketOptions = .{ .nodelay = true },
    /// Connect from this address (its port 0 for any), and so only to
    /// addresses of its family.
    local_address: ?IpAddress = null,
    /// Send through this interface only.
    interface: Io.net.Interface = .none,
    /// The name's lookup and every attempt, together.
    timeout: ?Duration = null,
    /// What looks names up.
    resolver: Resolver = .system,
    /// How long an attempt runs alone before the next address is tried
    /// beside it: RFC 8305's recommended Connection Attempt Delay.
    attempt_delay: Duration = .literal("250ms"),
};

/// A connected stream, and what it took.
pub const Dialed = struct {
    stream: Io.net.Stream,
    /// The address connected to; null for a Unix socket. (A connected
    /// stream's own `socket.address` is the local end.)
    peer: ?IpAddress = null,
    /// False when a timeout was asked for and no task could keep it.
    timeout_enforced: bool = true,
    /// How long the name's lookup took; zero for an address.
    lookup: Duration = .fromRaw(0),
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
    /// The system has no such socket option, or refuses its value.
    OptionUnsupported,
    /// Every address was refused to this process: an option, the local
    /// address or the interface it may not have, or a firewall rule.
    AccessDenied,
    /// The name has no address of the local address's family.
    AddressFamilyMismatch,
    /// `Options.timeout` ran out.
    TimedOut,
    /// A name was to be looked up with no task to spare, on a target with
    /// no lookup of its own.
    ConcurrencyUnavailable,
    Canceled,
};

/// Connect to `host` on `port`.
pub fn dial(io: Io, host: []const u8, port: u16, options: Options) DialError!Dialed {
    return dialBy(io, host, port, &.{}, options, Io.Clock.awake.now(io));
}

/// Connect to `host` on `port`, within what is left of `options.timeout`
/// counted from `started`; `hints` are tried when the name has no address.
fn dialBy(io: Io, host: []const u8, port: u16, hints: []const IpAddress, options: Options, started: Io.Timestamp) DialError!Dialed {
    var storage: [max_addresses]IpAddress = undefined;
    const literal = reactor.net.literal(host, port) != null;
    const looking = Io.Clock.awake.now(io);
    var bounded = true;
    const addresses = options.resolver.lookupWithin(io, host, port, null, &storage, remaining(io, options.timeout, started), &bounded) catch |err| switch (err) {
        error.NameNotResolved => if (hints.len != 0) hints else return error.NameNotResolved,
        error.InvalidHostName => return error.InvalidHostName,
        error.ConcurrencyUnavailable => return error.ConcurrencyUnavailable,
        error.TimedOut => return error.TimedOut,
        error.Canceled => return error.Canceled,
    };
    const lookup: Duration = if (literal) .fromRaw(0) else span.of(looking.durationTo(Io.Clock.awake.now(io)));
    // The lookup took its share of the one limit; the attempts end at what
    // is left.
    const deadline: Io.Timeout = if (options.timeout) |t| .{ .deadline = .{ .raw = started.addDuration(span.toIo(t)), .clock = .awake } } else .none;
    var same: [max_addresses]IpAddress = undefined;
    const usable = if (options.local_address) |local| ofFamily(addresses, local, &same) else addresses;
    if (usable.len == 0) return error.AddressFamilyMismatch;
    var ordered: [max_addresses]IpAddress = undefined;
    const connected = try connectAny(io, interleave(usable, &ordered), span.toIo(options.attempt_delay), deadline, .of(options));
    return .{
        .stream = connected.stream,
        .peer = connected.address,
        .timeout_enforced = bounded and connected.timeout_enforced,
        .lookup = lookup,
        .addresses = @intCast(addresses.len), // safe: a lookup keeps at most `max_addresses`, 32
    };
}

/// What is left of `timeout` counted from `started`; null for no limit.
fn remaining(io: Io, timeout: ?Duration, started: Io.Timestamp) ?Duration {
    const t = timeout orelse return null;
    return span.of(Io.Clock.awake.now(io).durationTo(started.addDuration(span.toIo(t))));
}

/// What an `https` origin's dial needs to know of the connection.
pub const Https = struct {
    /// The protocols the connection may offer by ALPN: an endpoint that
    /// speaks none of them is passed over.
    protocols: []const []const u8,
    /// Whether the connection takes an endpoint's ECH config. When one an
    /// endpoint the connection can use publishes cannot be reached, the
    /// origin is not dialed bare in its place, which would show the name
    /// ECH hides.
    ech: bool,
};

/// A connection to an `https` origin, and the endpoint it reached.
pub const DialedHttps = struct {
    dialed: Dialed,
    /// The origin's records, which the caller frees; null when it has none.
    binding: ?Resolver.Binding,
    /// The record whose endpoint was reached, in `binding`; null when the
    /// origin was dialed as it is.
    record: ?*const Resolver.Binding.Record,
};

/// Connect to the `https` origin `host` on `port` as its HTTPS records say,
/// when the resolver reads them (RFC 9460 §3, §7): each record in turn that
/// speaks one of `https.protocols`, at its target and port, the target's
/// addresses or else its hints; then, when every one failed and none of
/// them publishes ECH, the origin as it is. The records' lookup and every
/// attempt share `options.timeout`.
pub fn dialHttps(io: Io, gpa: Allocator, host: []const u8, port: u16, https: Https, options: Options) HttpsError!DialedHttps {
    const started = Io.Clock.awake.now(io);
    var bounded = true;
    var binding = try serviceWithin(options.resolver, io, gpa, host, port, options.timeout, &bounded);
    errdefer if (binding) |*b| b.deinit(gpa);
    const looked: Duration = span.of(started.durationTo(Io.Clock.awake.now(io)));
    var reliant = false;
    var last: HttpsError = error.ConnectionFailed;
    if (binding) |b| for (b.records) |*record| {
        if (!speaksAny(record.service, https.protocols)) continue;
        if (https.ech and record.service.ech() != null) reliant = true;
        var hints: [max_addresses]IpAddress = undefined;
        const target_port = record.service.port() orelse port;
        var dialed = dialBy(io, record.target, target_port, hintsOf(record.service, target_port, &hints), options, started) catch |err| switch (err) {
            error.Canceled, error.TimedOut => return err,
            else => {
                last = err;
                continue;
            },
        };
        dialed.lookup = looked.add(dialed.lookup) catch dialed.lookup;
        dialed.timeout_enforced = dialed.timeout_enforced and bounded;
        return .{ .dialed = dialed, .binding = binding, .record = record };
    };
    if (reliant) return last;
    var dialed = try dialBy(io, host, port, &.{}, options, started);
    dialed.lookup = looked.add(dialed.lookup) catch dialed.lookup;
    dialed.timeout_enforced = dialed.timeout_enforced and bounded;
    if (binding) |*b| b.deinit(gpa);
    return .{ .dialed = dialed, .binding = null, .record = null };
}

/// Why an `https` origin could not be reached.
pub const HttpsError = DialError || Allocator.Error;

fn speaksAny(s: @import("uplink.wire").dns.Service, protocols: []const []const u8) bool {
    for (protocols) |p| if (s.speaks(p)) return true;
    return false;
}

/// A record's address hints on `port`, IPv6 first, as many as fit.
fn hintsOf(s: @import("uplink.wire").dns.Service, port: u16, out: *[max_addresses]IpAddress) []const IpAddress {
    var n: usize = 0;
    const six = s.ipv6Hints();
    var at: usize = 0;
    while (at + 16 <= six.len and n < out.len) : (at += 16) {
        out[n] = .{ .ip6 = .{ .bytes = six[at..][0..16].*, .port = port } };
        n += 1;
    }
    const four = s.ipv4Hints();
    at = 0;
    while (at + 4 <= four.len and n < out.len) : (at += 4) {
        out[n] = .{ .ip4 = .{ .bytes = four[at..][0..4].*, .port = port } };
        n += 1;
    }
    return out[0..n];
}

/// `resolver.service`, given up once `timeout` runs out, as
/// `Resolver.lookupWithin` is.
fn serviceWithin(r: Resolver, io: Io, gpa: Allocator, host: []const u8, port: u16, timeout: ?Duration, bounded: *bool) HttpsError!?Resolver.Binding {
    if (r.serviceFn == null) return null;
    const limit = timeout orelse return serviceNow(r, io, gpa, host, port);
    const Race = union(enum) {
        found: HttpsError!?Resolver.Binding,
        expired: Io.Cancelable!void,
    };
    var buffer: [2]Race = undefined;
    var race: Io.Select(Race) = .init(io, &buffer);
    defer while (race.cancel()) |late| switch (late) {
        .found => |result| {
            var found = result catch null;
            if (found) |*b| b.deinit(gpa);
        },
        .expired => {},
    };
    race.concurrent(.found, serviceNow, .{ r, io, gpa, host, port }) catch {
        bounded.* = false;
        return serviceNow(r, io, gpa, host, port);
    };
    race.concurrent(.expired, Io.sleep, .{ io, span.toIo(limit), .awake }) catch {
        bounded.* = false;
        return switch (try race.await()) {
            .found => |result| result,
            .expired => unreachable, // unreachable: no delay was started
        };
    };
    return switch (try race.await()) {
        .found => |result| result,
        .expired => |result| if (result) |_| error.TimedOut else |err| err,
    };
}

fn serviceNow(r: Resolver, io: Io, gpa: Allocator, host: []const u8, port: u16) HttpsError!?Resolver.Binding {
    return r.service(io, gpa, host, port);
}

/// Connect to the Unix socket at `path`, within `options.timeout`; the
/// socket options for TCP do not apply.
///
/// reactor's connect is for IP addresses, so the attempt is raced against a
/// sleep as a task of its own, or run unbounded when none can be had.
pub fn dialUnix(io: Io, path: []const u8, options: Options) DialError!Dialed {
    const limit = options.timeout orelse return unixNow(io, path);
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
    race.concurrent(.connected, unixNow, .{ io, path }) catch {
        var d = try unixNow(io, path);
        d.timeout_enforced = false;
        return d;
    };
    race.concurrent(.expired, Io.sleep, .{ io, span.toIo(limit), .awake }) catch {
        // The attempt runs already; wait for it, unbounded.
        switch (try race.await()) {
            .connected => |result| {
                var d = try result;
                d.timeout_enforced = false;
                return d;
            },
            .expired => unreachable, // unreachable: no delay was started
        }
    };
    return switch (try race.await()) {
        .connected => |result| result,
        .expired => |result| if (result) |_| error.TimedOut else |err| err,
    };
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

/// The addresses of `local`'s family, in their order.
fn ofFamily(addresses: []const IpAddress, local: IpAddress, out: []IpAddress) []IpAddress {
    var n: usize = 0;
    for (addresses) |a| if (std.meta.activeTag(a) == std.meta.activeTag(local)) {
        out[n] = a;
        n += 1;
    };
    return out[0..n];
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
/// `delay` after the one before or at once when it failed, every attempt
/// ending at `deadline`. Those no task could be found for are tried one
/// after another once the racing ones have failed.
/// A connection, and the address it went to.
const Won = struct {
    stream: Io.net.Stream,
    address: IpAddress,
    timeout_enforced: bool,
};

/// What every attempt's socket is made with.
const Local = struct {
    socket: reactor.net.SocketOptions,
    address: ?IpAddress,
    interface: Io.net.Interface,

    fn of(o: Options) Local {
        return .{ .socket = o.socket, .address = o.local_address, .interface = o.interface };
    }
};

/// Why the attempts failed, as they went: an attempt refused to this
/// process counts toward `AccessDenied` only while every one is.
const Failures = struct {
    timed_out: bool = false,
    attempts: usize = 0,
    denied: usize = 0,

    /// Count one attempt's failure: an error to return at once, or null to
    /// try on.
    fn add(f: *Failures, err: reactor.net.ConnectError) ?DialError {
        f.attempts += 1;
        switch (err) {
            error.Canceled => return error.Canceled,
            // The same for every address: the socket's, not the peer's.
            error.OptionUnsupported => return error.OptionUnsupported,
            error.Timeout => f.timed_out = true,
            error.AccessDenied => f.denied += 1,
            else => {},
        }
        return null;
    }

    fn result(f: Failures) DialError {
        if (f.timed_out) return error.TimedOut;
        if (f.attempts > 0 and f.denied == f.attempts) return error.AccessDenied;
        return error.ConnectionFailed;
    }
};

fn connectAny(io: Io, addresses: []const IpAddress, delay: Io.Duration, deadline: Io.Timeout, local: Local) DialError!Won {
    std.debug.assert(addresses.len <= max_addresses);
    var failures: Failures = .{};
    if (addresses.len == 1) return connectOne(io, addresses[0], deadline, local) catch |err| return failures.add(err) orelse failures.result();
    const Event = Attempts.Event;
    // Every attempt arms at most one delay.
    var buffer: [2 * max_addresses]Event = undefined;
    var race: Io.Select(Event) = .init(io, &buffer);
    defer while (race.cancel()) |late| switch (late) {
        .connected => |result| if (result) |c| c.stream.close(io) else |_| {},
        .waited => {},
    };
    var state: Attempts = .{ .race = &race, .io = io, .addresses = addresses, .delay = delay, .deadline = deadline, .local = local };
    state.startNext();
    while (state.running > 0) {
        switch (try race.await()) {
            .connected => |result| {
                state.running -= 1;
                if (result) |connected| return connected else |err| if (failures.add(err)) |now| return now;
                state.startNext();
            },
            // A delay outrun by a failure is stale: the start that
            // followed the failure armed its own.
            .waited => |result| if ((result catch return error.Canceled) == state.started) state.startNext(),
        }
    }
    for (addresses[state.started..]) |address| {
        if (connectOne(io, address, deadline, local)) |connected| return connected else |err| if (failures.add(err)) |now| return now;
    }
    return failures.result();
}

/// The racing attempts of `connectAny`.
const Attempts = struct {
    race: *Io.Select(Event),
    io: Io,
    addresses: []const IpAddress,
    delay: Io.Duration,
    deadline: Io.Timeout,
    local: Local,
    started: usize = 0,
    running: usize = 0,
    /// False once a task could not be had: the rest go in turn.
    spare: bool = true,

    const Event = union(enum) {
        connected: reactor.net.ConnectError!Won,
        /// The delay armed when this many attempts had started.
        waited: Io.Cancelable!usize,
    };

    /// Start the next attempt, and the delay before the one after it.
    fn startNext(a: *Attempts) void {
        if (!a.spare or a.started == a.addresses.len) return;
        a.race.concurrent(.connected, connectOne, .{ a.io, a.addresses[a.started], a.deadline, a.local }) catch {
            a.spare = false;
            return;
        };
        a.started += 1;
        a.running += 1;
        if (a.started < a.addresses.len) {
            // glint-ignore: Z026 -- with no task for the delay, the next attempt starts when this one fails
            a.race.concurrent(.waited, waitFor, .{ a.io, a.delay, a.started }) catch {};
        }
    }
};

fn waitFor(io: Io, delay: Io.Duration, armed_at: usize) Io.Cancelable!usize {
    try io.sleep(delay, .awake);
    return armed_at;
}

fn connectOne(io: Io, address: IpAddress, deadline: Io.Timeout, local: Local) reactor.net.ConnectError!Won {
    const c = try reactor.net.connect(io, &address, .{ .timeout = deadline, .socket = local.socket, .local_address = local.address, .interface = local.interface });
    return .{ .stream = c.stream, .address = address, .timeout_enforced = c.timeout_enforced };
}

const testing = std.testing;
const test_io = @import("../testing/io.zig");
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
    const io = test_io.io();
    var listener = try (try IpAddress.parse("127.0.0.1", 0)).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    var serial: Serial = .init(io, 0);
    const port = listener.socket.address.getPort();
    // An address connects; the connection completes in the backlog.
    const by_address = try dial(serial.io(), "127.0.0.1", port, .{ .timeout = .literal("5s") });
    by_address.stream.close(io);
    try testing.expect(!by_address.timeout_enforced);
    // A name is looked up on a target that can do it without a task, and
    // refused on one that cannot; it never waits on itself.
    if (dial(serial.io(), "localhost", port, .{})) |by_name| {
        by_name.stream.close(io);
    } else |err| try testing.expectEqual(error.ConcurrencyUnavailable, err);
}

test "a connection expires at its controlled connect deadline and cancels the attempt" {
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

test "a dial with a timeout is bounded, on a runtime by the kernel with no fallback path taken" {
    const io = test_io.io();
    var listener = try (try IpAddress.parse("127.0.0.1", 0)).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const before = reactor.fallbacks();
    const dialed = try dial(io, "127.0.0.1", listener.socket.address.getPort(), .{ .timeout = .literal("5s") });
    dialed.stream.close(io);
    try testing.expect(dialed.timeout_enforced);
    // The peer is the listener, not the stream's own end.
    try testing.expect(dialed.peer.?.eql(&listener.socket.address));
    if (test_io.evented) try testing.expectEqual(before, reactor.fallbacks());
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
            try testing.expectEqual(@as(i96, delay.raw()), gap);
            try testing.expect(Eyeballs.abandoned.load(.acquire));
        }
    }
}

test "a Unix socket is connected by its path, and a missing one named" {
    const io = test_io.io();
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
    const d = try dialUnix(io, path, .{ .timeout = .literal("5s") });
    d.stream.close(io);
    var missing_buf: [Io.Dir.max_path_bytes]u8 = undefined;
    const missing = try std.mem.print(&missing_buf, "{s}/none.sock", .{dir});
    try testing.expectError(error.NameNotResolved, dialUnix(io, missing, .{}));
}

test "an origin is dialed as it is when its endpoints fail, unless one publishes ECH" {
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
    const d: Dns = .{ .transport = z.transport() };
    const options: Options = .{ .resolver = d.resolver(), .timeout = .literal("5s") };
    const protocols: []const []const u8 = &.{"http/1.1"};
    var plain = try dialHttps(io, gpa, "origin.test", port, .{ .protocols = protocols, .ech = false }, options);
    plain.dialed.stream.close(io);
    try testing.expectEqual(null, plain.binding);
    try testing.expectEqual(null, plain.record);
    try testing.expectError(error.NameNotResolved, dialHttps(io, gpa, "origin.test", port, .{ .protocols = protocols, .ech = true }, options));
}

test "an endpoint's hints are dialed when its name has no address" {
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
    const d: Dns = .{ .transport = z.transport() };
    var got = try dialHttps(io, gpa, "hinted.test", 443, .{ .protocols = &.{"http/1.1"}, .ech = false }, .{ .resolver = d.resolver(), .timeout = .literal("5s") });
    defer got.binding.?.deinit(gpa);
    got.dialed.stream.close(io);
    try testing.expectEqualStrings("nameless.test", got.record.?.target);
}

/// An integer socket option's value, read back (POSIX).
fn readOption(handle: Io.net.Socket.Handle, level: i32, name: u32) !c_int {
    var value: c_int = 0;
    var len: std.posix.socklen_t = @sizeOf(c_int);
    switch (std.posix.errno(std.posix.system.getsockopt(handle, level, name, @ptrCast(&value), &len))) { // safe: the option is a c_int, its length given
        .SUCCESS => return value,
        else => return error.Unexpected,
    }
}

test "a dial's socket has the options it asked for, set by reactor" {
    if (builtin.os.tag == .windows or builtin.os.tag == .wasi) return error.SkipZigTest;
    const io = test_io.io();
    var listener = try (try IpAddress.parse("127.0.0.1", 0)).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const dialed = try dial(io, "127.0.0.1", listener.socket.address.getPort(), .{ .socket = .{
        .nodelay = true,
        .keepalive = .{ .on = .{ .idle = .literal(45) } },
        .receive_buffer = .fromRaw(96 << 10),
    } });
    defer dialed.stream.close(io);
    const h = dialed.stream.socket.handle;
    const posix = std.posix;
    try testing.expect(try readOption(h, posix.IPPROTO.TCP, posix.TCP.NODELAY) != 0);
    try testing.expect(try readOption(h, posix.SOL.SOCKET, posix.SO.KEEPALIVE) != 0);
    const idle: u32 = if (@hasDecl(posix.TCP, "KEEPIDLE")) posix.TCP.KEEPIDLE else posix.TCP.KEEPALIVE;
    try testing.expectEqual(@as(c_int, 45), try readOption(h, posix.IPPROTO.TCP, idle));
    try testing.expect(try readOption(h, posix.SOL.SOCKET, posix.SO.RCVBUF) >= 96 << 10);
    if (@hasDecl(posix.SO, "NOSIGPIPE")) try testing.expect(try readOption(h, posix.SOL.SOCKET, posix.SO.NOSIGPIPE) != 0);
}

test "a dial from a local address goes from it, to the name's addresses of its family only" {
    const io = test_io.io();
    var listener = try (try IpAddress.parse("127.0.0.1", 0)).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const port = listener.socket.address.getPort();
    const dialed = try dial(io, "127.0.0.1", port, .{ .local_address = .{ .ip4 = .loopback(0) } });
    defer dialed.stream.close(io);
    try testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, &dialed.stream.socket.address.ip4.bytes);
    try testing.expectError(error.AddressFamilyMismatch, dial(io, "::1", port, .{ .local_address = .{ .ip4 = .loopback(0) } }));
}

test "a refused option ends the dial at once, named, and AccessDenied is named only when every address was denied" {
    var once: Failures = .{};
    try testing.expectEqual(@as(?DialError, error.OptionUnsupported), once.add(error.OptionUnsupported));
    var denied: Failures = .{};
    try testing.expectEqual(@as(?DialError, null), denied.add(error.AccessDenied));
    try testing.expectEqual(@as(?DialError, null), denied.add(error.AccessDenied));
    try testing.expectEqual(error.AccessDenied, denied.result());
    var mixed: Failures = .{};
    _ = mixed.add(error.AccessDenied);
    _ = mixed.add(error.ConnectionRefused);
    try testing.expectEqual(error.ConnectionFailed, mixed.result());
}
