//! TCP connections to a host by name or address: the name looked up, its
//! addresses raced, the socket tuned, all within one deadline.
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

/// How connections are made.
pub const Options = struct {
    /// Turn Nagle's algorithm off on every socket.
    nodelay: bool = true,
    /// The name's lookup and every attempt, together.
    timeout: ?Io.Duration = null,
};

/// A connected stream, and whether `Options.timeout` could be kept.
pub const Dialed = struct {
    stream: Io.net.Stream,
    /// False when a timeout was asked for and no task could keep it.
    timeout_enforced: bool = true,
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
    const limit = options.timeout orelse return .{ .stream = try dialNow(io, host, port, options.nodelay) };
    const Race = union(enum) {
        connected: DialError!Io.net.Stream,
        expired: Io.Cancelable!void,
    };
    var buffer: [2]Race = undefined;
    var race: Io.Select(Race) = .init(io, &buffer);
    defer while (race.cancel()) |late| switch (late) {
        .connected => |result| if (result) |stream| stream.close(io) else |_| {},
        .expired => {},
    };
    race.concurrent(.connected, dialNow, .{ io, host, port, options.nodelay }) catch
        return .{ .stream = try dialNow(io, host, port, options.nodelay), .timeout_enforced = false };
    race.concurrent(.expired, Io.sleep, .{ io, limit, .awake }) catch {
        // The attempt runs already; wait for it, unbounded.
        while (race.cancel()) |late| switch (late) {
            .connected => |result| return .{ .stream = try result, .timeout_enforced = false },
            .expired => {},
        };
        unreachable; // unreachable: the connecting task was started above
    };
    return switch (try race.await()) {
        .connected => |result| .{ .stream = try result },
        .expired => |result| if (result) |_| error.TimedOut else |err| err,
    };
}

fn dialNow(io: Io, host: []const u8, port: u16, nodelay: bool) DialError!Io.net.Stream {
    var storage: [resolve.max_addresses]IpAddress = undefined;
    const addresses = resolve.lookup(io, host, port, null, &storage) catch |err| return switch (err) {
        error.InvalidHostName => error.InvalidHostName,
        error.NameNotResolved => error.NameNotResolved,
        error.ConcurrencyUnavailable => error.ConcurrencyUnavailable,
        error.Canceled => error.Canceled,
    };
    const stream = try connectAny(io, addresses);
    if (nodelay) sys.tune(io, stream.socket.handle);
    return stream;
}

/// The first of `addresses` to accept a connection. The attempts race, each
/// a task of its own; those no task could be found for are tried one after
/// another once the racing ones have failed.
fn connectAny(io: Io, addresses: []const IpAddress) DialError!Io.net.Stream {
    std.debug.assert(addresses.len <= resolve.max_addresses);
    if (addresses.len == 1) return connectOne(io, addresses[0]) catch |err| return mapConnect(err);
    const Attempt = union(enum) { connected: Io.net.IpAddress.ConnectError!Io.net.Stream };
    var buffer: [resolve.max_addresses]Attempt = undefined;
    var race: Io.Select(Attempt) = .init(io, &buffer);
    defer while (race.cancel()) |late| switch (late) {
        .connected => |result| if (result) |stream| stream.close(io) else |_| {},
    };
    var started: usize = 0;
    for (addresses) |address| {
        race.concurrent(.connected, connectOne, .{ io, address }) catch break;
        started += 1;
    }
    for (0..started) |_| switch (try race.await()) {
        .connected => |result| if (result) |stream| return stream else |err| if (err == error.Canceled) return error.Canceled,
    };
    for (addresses[started..]) |address| {
        if (connectOne(io, address)) |stream| return stream else |err| if (err == error.Canceled) return error.Canceled;
    }
    return error.ConnectionFailed;
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
