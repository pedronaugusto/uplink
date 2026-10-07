//! Name lookup with no task waiting on work started with `io.async`.
//!
//! std's lookup puts its answers one at a time into a queue. Run inline,
//! with no other task draining the queue, it waits on itself forever once a
//! name has more answers than the queue holds: the `getaddrinfo` path puts
//! every result libc gives, and std's own DNS client puts one per record of
//! an answer and one per line of the hosts file, whatever its documented
//! bound of 16 says. So the lookup runs as a task of its own, started with
//! `io.concurrent`, while this one drains it. Without a task to spare, a
//! libc target calls `getaddrinfo` on this task; any other target returns
//! `error.ConcurrencyUnavailable` for a name. An address needs no lookup.

const std = @import("std");
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const sys = @import("sys.zig");

/// The most addresses one lookup keeps.
pub const max_addresses = 32;

/// Errors from `lookup`.
pub const LookupError = error{
    /// The name is not a host name.
    InvalidHostName,
    /// The name has no address, or the resolver failed.
    NameNotResolved,
    /// No task could run the lookup beside this one, and this target has no
    /// lookup that runs without one.
    ConcurrencyUnavailable,
    Canceled,
};

/// `host`'s addresses on `port`, at most `out.len`, in the resolver's order:
/// the address itself when `host` is one, IPv6 brackets allowed.
pub fn lookup(io: Io, host: []const u8, port: u16, family: ?IpAddress.Family, out: []IpAddress) LookupError![]IpAddress {
    std.debug.assert(out.len != 0);
    if (literal(host, port)) |address| {
        if (family) |f| if (address != f) return error.NameNotResolved;
        out[0] = address;
        return out[0..1];
    }
    const name = Io.net.HostName.init(host) catch return error.InvalidHostName;
    var buffer: [max_addresses]Io.net.HostName.LookupResult = undefined;
    var queue: Io.Queue(Io.net.HostName.LookupResult) = .init(&buffer);
    var future = io.concurrent(Io.net.HostName.lookup, .{ name, io, &queue, .{ .port = port, .family = family } }) catch {
        if (sys.own_lookup) return sys.getaddrinfo(host, port, family, out) catch error.NameNotResolved;
        return error.ConcurrencyUnavailable;
    };
    defer future.cancel(io) catch {};
    var count: usize = 0;
    while (queue.getOne(io)) |result| switch (result) {
        .address => |a| if (count < out.len and (family == null or a == family.?)) {
            out[count] = a;
            count += 1;
        },
        .canonical_name => {},
    } else |err| switch (err) {
        error.Canceled => return error.Canceled,
        error.Closed => {},
    }
    future.await(io) catch |err| return switch (err) {
        error.Canceled => error.Canceled,
        else => error.NameNotResolved,
    };
    if (count == 0) return error.NameNotResolved;
    return out[0..count];
}

/// `host` as an address, IPv6 brackets allowed, or null when it is a name.
pub fn literal(host: []const u8, port: u16) ?IpAddress {
    const bare = if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') host[1 .. host.len - 1] else host;
    return IpAddress.parse(bare, port) catch null;
}

const testing = std.testing;
const shakedown = @import("shakedown");

/// Put `many` addresses one at a time, as std's libc lookup puts what
/// `getaddrinfo` answered.
fn answerMany(results: *Io.Queue(Io.net.HostName.LookupResult), options: Io.net.HostName.LookupOptions) Io.net.HostName.LookupError!void {
    const io = testing.io;
    defer results.close(io);
    for (0..100) |i| {
        results.putOne(io, .{ .address = .{ .ip4 = .{ .bytes = .{ 10, 0, 0, @intCast(i) }, .port = options.port } } }) catch |err| return switch (err) {
            error.Canceled => error.Canceled,
            error.Closed => unreachable, // unreachable: the queue is closed only by this function
        };
    }
}

const ManyAnswers = shakedown.Layer(u8, .{ .netLookup = struct {
    fn lookup(_: ?*anyopaque, _: Io.net.HostName, results: *Io.Queue(Io.net.HostName.LookupResult), options: Io.net.HostName.LookupOptions) Io.net.HostName.LookupError!void {
        return answerMany(results, options);
    }
}.lookup });

/// An `Io` with no task to spare: `concurrent` fails, and the lookup it
/// would have run answers a hundred addresses one at a time.
const Serial = shakedown.Layer(u8, .{
    .concurrent = struct {
        fn concurrent(_: ?*anyopaque, _: usize, _: std.mem.Alignment, _: []const u8, _: std.mem.Alignment, _: *const fn (*const anyopaque, *anyopaque) void) Io.ConcurrentError!*Io.AnyFuture {
            return error.ConcurrencyUnavailable;
        }
    }.concurrent,
    .netLookup = struct {
        fn lookup(_: ?*anyopaque, _: Io.net.HostName, results: *Io.Queue(Io.net.HostName.LookupResult), options: Io.net.HostName.LookupOptions) Io.net.HostName.LookupError!void {
            return answerMany(results, options);
        }
    }.lookup,
});

test "a name with more addresses than a lookup queue holds is resolved without waiting on itself" {
    var many: ManyAnswers = .init(testing.io, 0);
    var storage: [max_addresses]IpAddress = undefined;
    const kept = lookup(many.io(), "many.example", 80, null, &storage) catch |err| switch (err) {
        error.ConcurrencyUnavailable => return error.SkipZigTest,
        else => |e| return e,
    };
    try testing.expectEqual(@as(usize, max_addresses), kept.len);
    try testing.expectEqualSlices(u8, &.{ 10, 0, 0, 0 }, &kept[0].ip4.bytes);

    // Without a task, the lookup is libc's on this task, or none at all;
    // std's lookup run inline would fill its queue and wait forever.
    var serial: Serial = .init(testing.io, 0);
    if (sys.own_lookup) {
        const local = try lookup(serial.io(), "localhost", 80, null, &storage);
        try testing.expectEqual(@as(u16, 80), local[0].getPort());
    } else {
        try testing.expectError(error.ConcurrencyUnavailable, lookup(serial.io(), "localhost", 80, null, &storage));
    }
    // An address needs no lookup, and no task.
    const address = try lookup(serial.io(), "[::1]", 443, null, &storage);
    try testing.expectEqual(@as(u16, 443), address[0].getPort());
    try testing.expectError(error.NameNotResolved, lookup(serial.io(), "127.0.0.1", 1, .ip6, &storage));
    try testing.expectError(error.InvalidHostName, lookup(many.io(), "bad name", 1, null, &storage));
}

test "a family asked for is kept even where the resolver answers both" {
    const Mixed = shakedown.Layer(u8, .{ .netLookup = struct {
        fn lookup(_: ?*anyopaque, _: Io.net.HostName, results: *Io.Queue(Io.net.HostName.LookupResult), options: Io.net.HostName.LookupOptions) Io.net.HostName.LookupError!void {
            const io = testing.io;
            defer results.close(io);
            const answers: []const Io.net.HostName.LookupResult = &.{
                .{ .address = .{ .ip6 = .{ .bytes = @as([15]u8, @splat(0)) ++ .{1}, .port = options.port } } },
                .{ .address = .{ .ip4 = .loopback(options.port) } },
            };
            results.putAll(io, answers) catch return error.Canceled;
        }
    }.lookup });
    var mixed: Mixed = .init(testing.io, 0);
    var storage: [4]IpAddress = undefined;
    const four = lookup(mixed.io(), "dual.example", 80, .ip4, &storage) catch |err| switch (err) {
        error.ConcurrencyUnavailable => return error.SkipZigTest,
        else => |e| return e,
    };
    try testing.expectEqual(@as(usize, 1), four.len);
    try testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, &four[0].ip4.bytes);
}
