//! Which connection serves which exchange: the idle ones, kept per route
//! for the next exchange that goes there. The pool is the only owner of
//! that choice. It holds connections only while they are idle; an exchange
//! holds its own.
//!
//! The idle list is allocated once, at its cap, the first time a connection
//! is kept, so keeping and taking one allocate nothing after that. The most
//! recently used connection is taken first: it is the one most likely still
//! open at the server.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Connection = @import("../transport/Connection.zig");
const Route = @import("../transport/Context.zig").Route;

const Pool = @This();

gpa: Allocator,
/// Private: held for `idle`.
mutex: Io.Mutex = .init,
/// Private: idle connections, the most recently kept last.
idle: []Kind = &.{},
/// Private: how many of `idle` are in use.
len: usize = 0,
/// `len`, readable without the lock.
idle_count: std.atomic.Value(u32) = .init(0),
options: Options,

/// How many connections are kept.
pub const Options = struct {
    /// Idle connections kept for one route; more are closed.
    max_idle_per_route: u16 = 2,
    /// Idle connections kept in all; the oldest is closed for a new one.
    max_idle: u16 = 64,
};

/// A connection of whichever protocol it speaks. HTTP/2 connections join
/// as an arm of their own.
pub const Kind = union(enum) {
    h1: *Connection,

    fn route(k: Kind) Route {
        return switch (k) {
            .h1 => |c| c.route,
        };
    }
};

/// An empty pool.
pub fn init(gpa: Allocator, options: Options) Pool {
    return .{ .gpa = gpa, .options = options };
}

/// Free the idle list; every connection must have been taken out first,
/// as `drain` takes them.
pub fn deinit(p: *Pool) void {
    std.debug.assert(p.len == 0);
    p.gpa.free(p.idle);
    p.* = undefined;
}

/// The idle connection last kept for `route`, taken out of the pool.
pub fn take(p: *Pool, io: Io, route: Route) ?Kind {
    p.mutex.lockUncancelable(io);
    defer p.mutex.unlock(io);
    var i = p.len;
    while (i > 0) {
        i -= 1;
        if (!p.idle[i].route().eql(route)) continue;
        return p.removeAt(i);
    }
    return null;
}

/// Keep `k` idle. Returns the connection to close to make room: the oldest
/// of its route past the route's cap, else the oldest of all past the
/// pool's, or `k` itself when nothing may be kept.
pub fn keep(p: *Pool, io: Io, k: Kind) ?Kind {
    if (p.options.max_idle == 0 or p.options.max_idle_per_route == 0) return k;
    p.mutex.lockUncancelable(io);
    defer p.mutex.unlock(io);
    if (p.idle.len == 0) p.idle = p.gpa.alloc(Kind, p.options.max_idle) catch return k;
    var same: usize = 0;
    var oldest_same: ?usize = null;
    for (p.idle[0..p.len], 0..) |other, i| {
        if (!other.route().eql(k.route())) continue;
        same += 1;
        if (oldest_same == null) oldest_same = i;
    }
    var evicted: ?Kind = null;
    if (same >= p.options.max_idle_per_route) {
        evicted = p.removeAt(oldest_same.?);
    } else if (p.len == p.idle.len) {
        evicted = p.removeAt(0);
    }
    p.idle[p.len] = k;
    p.len += 1;
    p.idle_count.store(@intCast(p.len), .monotonic);
    return evicted;
}

fn removeAt(p: *Pool, i: usize) Kind {
    const k = p.idle[i];
    @memmove(p.idle[i .. p.len - 1], p.idle[i + 1 .. p.len]);
    p.len -= 1;
    p.idle_count.store(@intCast(p.len), .monotonic);
    return k;
}

/// Take every idle connection out, for the caller to close.
pub fn drain(p: *Pool, io: Io) ?Kind {
    p.mutex.lockUncancelable(io);
    defer p.mutex.unlock(io);
    if (p.len == 0) return null;
    return p.removeAt(p.len - 1);
}

/// How many connections are idle, without the lock.
pub fn count(p: *const Pool) u32 {
    return p.idle_count.load(.monotonic);
}

const testing = std.testing;

test "the last kept is taken first, a route keeps its cap, and the pool its own" {
    const io = testing.io;
    var pool: Pool = .init(testing.allocator, .{ .max_idle_per_route = 2, .max_idle = 3 });
    defer pool.deinit();
    var conns: [5]Connection = undefined;
    const routes = [_]Route{
        .{ .secure = false, .host = "a", .port = 80 },
        .{ .secure = false, .host = "a", .port = 80 },
        .{ .secure = false, .host = "A", .port = 80 },
        .{ .secure = true, .host = "b", .port = 443 },
        .{ .secure = false, .host = "c", .port = 80 },
    };
    for (&conns, routes) |*c, r| c.route = r;
    try testing.expectEqual(null, pool.keep(io, .{ .h1 = &conns[0] }));
    try testing.expectEqual(null, pool.keep(io, .{ .h1 = &conns[1] }));
    // A third for route `a` puts out its oldest.
    try testing.expectEqual(&conns[0], pool.keep(io, .{ .h1 = &conns[2] }).?.h1);
    try testing.expectEqual(null, pool.keep(io, .{ .h1 = &conns[3] }));
    // The pool is full: its oldest of all goes.
    try testing.expectEqual(&conns[1], pool.keep(io, .{ .h1 = &conns[4] }).?.h1);
    try testing.expectEqual(&conns[2], pool.take(io, routes[0]).?.h1);
    try testing.expectEqual(null, pool.take(io, routes[0]));
    try testing.expectEqual(@as(u32, 2), pool.count());
    while (pool.drain(io)) |_| {}
    try testing.expectEqual(@as(u32, 0), pool.count());
}

test "a pool that keeps nothing hands every connection back" {
    const io = testing.io;
    var pool: Pool = .init(testing.allocator, .{ .max_idle = 0 });
    defer pool.deinit();
    var conn: Connection = undefined;
    conn.route = .{ .secure = false, .host = "a", .port = 80 };
    try testing.expectEqual(&conn, pool.keep(io, .{ .h1 = &conn }).?.h1);
}
