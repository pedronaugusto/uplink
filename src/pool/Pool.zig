//! Which connection serves which exchange: the idle ones, kept per route
//! for the next exchange that goes there, and, when routes are limited, how
//! many each has open and who waits for one. The pool is the only owner of
//! those choices. It holds connections only while they are idle; an
//! exchange holds its own.
//!
//! The idle list is allocated once, at its cap, the first time a connection
//! is kept, so keeping and taking one allocate nothing after that. The most
//! recently used connection is taken first: it is the one most likely still
//! open at the server. One idle longer than `idle_timeout` is closed rather
//! than used.
//!
//! With `max_per_route` set, an exchange that finds its route full waits,
//! first come first served, for a connection to come back or close; the
//! wait ends at the exchange's deadline or when its task is canceled. A
//! connection given back is handed straight to the first waiter.

const std = @import("std");
const sync = @import("../sync.zig");
const aegis = @import("aegis");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const awake = @import("../transport/awake.zig");
const Duration = @import("../span.zig").Duration;
const Connection = @import("../transport/Connection.zig");
const H2 = @import("../transport/H2.zig");
const Route = @import("../transport/Context.zig").Route;

const Pool = @This();

gpa: Allocator,
/// Private: the idle connections and the limited routes, reached only
/// through the lock beside them.
state: aegis.BlockingGuarded(State),
/// Private: broadcast when a waiter is granted its route, under `state`.
grants: aegis.Condition = .initLimit(std.math.maxInt(usize)),
/// `State.len`, readable without the lock: `Client.stats` reads it on its
/// own, and a counter beside the lock is the design, not a second owner.
idle_count: sync.Gauge = .init(.fromRaw(0)),
options: Options,

/// What the lock guards.
const State = struct {
    /// Idle connections, the most recently kept last.
    idle: []Idle = &.{},
    /// How many of `idle` are in use.
    len: usize = 0,
    /// The limited routes; empty unless `max_per_route` is set.
    routes: std.ArrayList(*RouteState) = .empty,
    /// HTTP/2 connections, shared by every exchange on their route.
    multiplexed: std.ArrayList(Shared) = .empty,
};

/// How many connections are kept, and opened.
pub const Options = struct {
    /// Idle connections kept for one route; more are closed.
    max_idle_per_route: u16 = 2,
    /// Idle connections kept in all; the oldest is closed for a new one.
    max_idle: u16 = 64,
    /// Connections open to one route at once, idle ones included, at least
    /// one; null is no limit. Past it, an exchange waits for one.
    max_per_route: ?u16 = null,
    /// A connection idle longer is closed instead of used; null keeps it
    /// until the server closes it.
    idle_timeout: ?Duration = .literal("90s"),
    /// The most of an unread body a finished response reads to keep its
    /// connection, within the activity timeout; past it, the connection is
    /// closed.
    drain_limit: aegis.units.Bytes(u32) = .literal("64KiB"),
};

/// A connection of whichever protocol it speaks: HTTP/1.1, held by one
/// exchange at a time, or HTTP/2, shared.
pub const Kind = union(enum) {
    h1: *Connection,
    h2: *H2,

    pub fn route(k: Kind) *const Route {
        return switch (k) {
            .h1 => |c| &c.route,
            .h2 => |h| &h.conn.route,
        };
    }
};

const Idle = struct {
    kind: Kind,
    /// When it was kept; null when idle connections do not expire.
    since: ?awake.Instant,
};

/// An HTTP/2 connection the route's exchanges share.
const Shared = struct {
    h: *H2,
    /// When its last exchange ended; null while one uses it, or when idle
    /// connections do not expire.
    since: ?awake.Instant = null,
};

/// A limited route: its connections open, and its waiters.
const RouteState = struct {
    route: Route,
    open: u32 = 0,
    waiters: std.DoublyLinkedList = .{},
};

/// An exchange waiting for its route.
const Waiter = struct {
    node: std.DoublyLinkedList.Node = .{},
    granted: Grant = .none,

    const Grant = union(enum) { none, open, idle: Kind };
};

/// An empty pool.
pub fn init(gpa: Allocator, options: Options) Pool {
    aegis.assert.pre((options.max_per_route orelse 1) != 0, "a route limit allows at least one connection");
    return .{ .gpa = gpa, .state = .init(.{}), .options = options };
}

/// Free what the pool holds; every connection must have been taken out
/// first, as `drain` takes them, and no exchange may wait.
pub fn deinit(p: *Pool, io: Io) void {
    var held = p.state.acquireUncancelable(io);
    const s = held.value();
    aegis.assert.pre(s.len == 0, "every idle connection was drained");
    for (s.routes.items) |r| {
        aegis.assert.pre(r.waiters.first == null, "no exchange waits on a pool being freed");
        p.gpa.destroy(r);
    }
    s.routes.deinit(p.gpa);
    aegis.assert.pre(s.multiplexed.items.len == 0, "every shared connection was drained");
    s.multiplexed.deinit(p.gpa);
    p.gpa.free(s.idle);
    held.deinit(io);
    p.* = undefined;
}

/// What `acquire` found.
pub const Acquired = union(enum) {
    /// An idle connection, now the caller's.
    idle: Kind,
    /// A connection idle past its time: the caller closes it, tells
    /// `closed`, and asks again.
    expired: Kind,
    /// Room for a new connection, which the caller opens; when it cannot,
    /// it tells `closed` with the route.
    open,
    /// An HTTP/2 connection with room for another stream, shared: the
    /// caller gives its use back with `unshare`.
    shared: *H2,
};

/// Errors from `acquire`.
pub const AcquireError = error{
    /// The deadline passed while waiting for the route.
    TimedOut,
    Canceled,
    OutOfMemory,
};

/// A connection for `route`: the idle one last kept, else room for a new
/// one, waiting for either while the route is full, until `deadline` on
/// the awake clock. `waited` is set when it had to wait.
pub fn acquire(p: *Pool, io: Io, route: *const Route, deadline: ?Io.Timestamp, waited: *bool) AcquireError!Acquired {
    waited.* = false;
    var w: Waiter = .{};
    var held = p.state.acquireUncancelable(io);
    defer held.deinit(io);
    const state = enlist: {
        const s = held.value();
        var i: usize = 0;
        while (i < s.multiplexed.items.len) : (i += 1) {
            const m = &s.multiplexed.items[i];
            const h = m.h;
            if (!h.conn.route.eql(route)) continue;
            const unused = h.users.load(.acquire).eql(.fromRaw(0));
            // One idle past its time, or that can carry nothing more, goes.
            if (unused and (!h.usable(io) or p.expiredAt(.{ .kind = .{ .h2 = h }, .since = m.since }, awake.now(io)))) {
                _ = s.multiplexed.swapRemove(i);
                return .{ .expired = .{ .h2 = h } };
            }
            if (!h.canOpen(io)) continue;
            _ = h.users.fetchAddWrapping(.fromRaw(1), .monotonic);
            m.since = null;
            return .{ .shared = h };
        }
        if (p.takeLocked(io, s, route)) |found| return found;
        const max = p.options.max_per_route orelse return .open;
        const state = try p.stateOf(s, route);
        if (state.open < max) {
            state.open += 1;
            return .open;
        }
        state.waiters.append(&w.node);
        break :enlist state;
    };
    waited.* = true;
    const timeout: Io.Timeout = if (deadline) |d| .{ .deadline = .{ .raw = d, .clock = .awake } } else .none;
    while (w.granted == .none) p.grants.wait(io, &held, timeout) catch |err| {
        // Granted as the wait gave up: the grant is taken all the same; a
        // canceled exchange gives it back through the caller's cleanup.
        if (w.granted != .none) break;
        state.waiters.remove(&w.node);
        p.forget(held.value(), state);
        return switch (err) {
            error.Timeout => error.TimedOut,
            error.Canceled => error.Canceled,
            error.WaiterLimit => unreachable, // unreachable: the waiters have no limit
        };
    };
    return switch (w.granted) {
        .none => unreachable, // unreachable: the wait ends granted, or returned above
        .open => .open,
        .idle => |k| .{ .idle = k },
    };
}

/// The idle connection last kept for `route`, under the lock.
fn takeLocked(p: *Pool, io: Io, s: *State, route: *const Route) ?Acquired {
    var i = s.len;
    while (i > 0) {
        i -= 1;
        if (!s.idle[i].kind.route().eql(route)) continue;
        const entry = p.removeAt(s, i);
        if (p.expired(io, entry)) return .{ .expired = entry.kind };
        return .{ .idle = entry.kind };
    }
    return null;
}

fn expired(p: *Pool, io: Io, entry: Idle) bool {
    if (p.options.idle_timeout == null) return false;
    return p.expiredAt(entry, awake.now(io));
}

fn expiredAt(p: *Pool, entry: Idle, now: awake.Instant) bool {
    const limit = p.options.idle_timeout orelse return false;
    const since = entry.since orelse return false;
    // A span too long to hold is far past any timeout, if it is forward.
    const idle = since.durationTo(now) catch |err| return err == error.Overflow;
    return std.math.order(idle.raw(), limit.raw()) != .lt;
}

/// The state of a limited route, made when it is first asked for.
fn stateOf(p: *Pool, s: *State, route: *const Route) Allocator.Error!*RouteState {
    for (s.routes.items) |r| if (r.route.eql(route)) return r;
    const r = try p.gpa.create(RouteState);
    errdefer p.gpa.destroy(r);
    r.* = .{ .route = route.* };
    try s.routes.append(p.gpa, r);
    return r;
}

/// Drop a route's state once nothing is open on it and nobody waits.
fn forget(p: *Pool, s: *State, state: *RouteState) void {
    if (state.open != 0 or state.waiters.first != null) return;
    for (s.routes.items, 0..) |r, i| if (r == state) {
        _ = s.routes.swapRemove(i);
        break;
    };
    p.gpa.destroy(state);
}

/// What `keep` puts out, for the caller to close and tell `closed`.
pub const Kept = struct {
    /// To make room: the oldest of the route past its cap, else the oldest
    /// of all past the pool's, or the connection itself when none may be
    /// kept.
    evicted: ?Kind = null,
    /// The oldest idle connection, when it was idle past its time: one per
    /// keep, so a pool in use never holds an expired one for long.
    expired: ?Kind = null,
};

/// Keep `k` idle, or hand it to an exchange waiting for its route.
pub fn keep(p: *Pool, io: Io, k: Kind) Kept {
    var held = p.state.acquireUncancelable(io);
    defer held.deinit(io);
    const s = held.value();
    if (p.options.max_per_route != null) {
        if (findState(s, k.route())) |state| if (state.waiters.popFirst()) |node| {
            const w: *Waiter = @fieldParentPtr("node", node);
            w.granted = .{ .idle = k };
            p.grants.broadcast(io);
            return .{};
        };
    }
    if (p.options.max_idle == 0 or p.options.max_idle_per_route == 0) return .{ .evicted = k };
    if (s.idle.len == 0) s.idle = p.gpa.alloc(Idle, p.options.max_idle) catch return .{ .evicted = k };
    var kept: Kept = .{};
    const now: ?awake.Instant = if (p.options.idle_timeout != null) awake.now(io) else null;
    if (s.len != 0) if (now) |t| if (p.expiredAt(s.idle[0], t)) {
        kept.expired = p.removeAt(s, 0).kind;
    };
    var same: usize = 0;
    var oldest_same: ?usize = null;
    for (s.idle[0..s.len], 0..) |other, i| {
        if (!other.kind.route().eql(k.route())) continue;
        same += 1;
        if (oldest_same == null) oldest_same = i;
    }
    if (same >= p.options.max_idle_per_route) {
        kept.evicted = p.removeAt(s, oldest_same.?).kind;
    } else if (s.len == s.idle.len) {
        kept.evicted = p.removeAt(s, 0).kind;
    }
    s.idle[s.len] = .{ .kind = k, .since = now };
    s.len += 1;
    p.idle_count.store(.fromRaw(@intCast(s.len)), .monotonic); // safe: `len` is at most `max_idle`, a u16
    return kept;
}

/// Share `h`, just opened by an exchange that uses it, with every exchange
/// on its route.
pub fn share(p: *Pool, io: Io, h: *H2) Allocator.Error!void {
    var held = p.state.acquireUncancelable(io);
    defer held.deinit(io);
    try held.value().multiplexed.append(p.gpa, .{ .h = h });
}

/// An exchange is done with `h`: kept for the next while it can carry one,
/// closed by the last user once it cannot.
pub fn unshare(p: *Pool, io: Io, h: *H2) void {
    const close_it = blk: {
        var held = p.state.acquireUncancelable(io);
        defer held.deinit(io);
        const s = held.value();
        const last = h.users.fetchSubWrapping(.fromRaw(1), .acq_rel).eql(.fromRaw(1));
        if (!last) break :blk false;
        for (s.multiplexed.items, 0..) |*m, i| if (m.h == h) {
            if (h.usable(io)) {
                if (p.options.idle_timeout != null) m.since = awake.now(io);
                break :blk false;
            }
            _ = s.multiplexed.swapRemove(i);
            break :blk true;
        };
        break :blk false;
    };
    if (close_it) p.close(io, .{ .h2 = h });
}

/// Close `k` and give its room on its route to the first exchange waiting
/// for the route, whose copy is taken before the connection is freed.
pub fn close(p: *Pool, io: Io, k: Kind) void {
    switch (k) {
        .h1 => |conn| {
            const route = conn.route;
            conn.close(io);
            p.closed(io, &route);
        },
        .h2 => |h| {
            const route = h.conn.route;
            h.close(io);
            p.closed(io, &route);
        },
    }
}

/// A connection of `route` was closed, or one the pool made room for could
/// not be opened: its room goes to the first exchange waiting for the
/// route.
pub fn closed(p: *Pool, io: Io, route: *const Route) void {
    if (p.options.max_per_route == null) return;
    var held = p.state.acquireUncancelable(io);
    defer held.deinit(io);
    const s = held.value();
    const state = findState(s, route);
    aegis.assert.invariant(state != null, "a limited route keeps its state while anything is open on it");
    const limited = state.?;
    if (limited.waiters.popFirst()) |node| {
        const w: *Waiter = @fieldParentPtr("node", node);
        w.granted = .open;
        p.grants.broadcast(io);
        return;
    }
    limited.open -= 1;
    p.forget(s, limited);
}

fn findState(s: *State, route: *const Route) ?*RouteState {
    for (s.routes.items) |r| if (r.route.eql(route)) return r;
    return null;
}

fn removeAt(p: *Pool, s: *State, i: usize) Idle {
    const entry = s.idle[i];
    @memmove(s.idle[i .. s.len - 1], s.idle[i + 1 .. s.len]);
    s.len -= 1;
    p.idle_count.store(.fromRaw(@intCast(s.len)), .monotonic); // safe: `len` is at most `max_idle`, a u16
    return entry;
}

/// Take every idle connection out, for the caller to close.
pub fn drain(p: *Pool, io: Io) ?Kind {
    var held = p.state.acquireUncancelable(io);
    defer held.deinit(io);
    const s = held.value();
    if (s.multiplexed.pop()) |m| return .{ .h2 = m.h };
    if (s.len == 0) return null;
    return p.removeAt(s, s.len - 1).kind;
}

/// How many connections are idle, without the lock.
pub fn count(p: *const Pool) u32 {
    return p.idle_count.load(.monotonic).raw();
}

const testing = std.testing;
const test_io = @import("../testing/io.zig");
const shakedown = @import("shakedown");

fn connWith(route: Route) Connection {
    var c: Connection = undefined;
    c.route = route;
    return c;
}

test "the last kept is taken first, a route keeps its cap, and the pool its own" {
    const io = test_io.io();
    var pool: Pool = .init(testing.allocator, .{ .max_idle_per_route = 2, .max_idle = 3 });
    defer pool.deinit(io);
    var conns: [5]Connection = undefined;
    const routes = [_]Route{
        try Route.init(false, "a", 80, null),
        try Route.init(false, "a", 80, null),
        try Route.init(false, "A", 80, null),
        try Route.init(true, "b", 443, null),
        try Route.init(false, "c", 80, null),
    };
    for (&conns, routes) |*c, r| c.route = r;
    try testing.expectEqual(null, pool.keep(io, .{ .h1 = &conns[0] }).evicted);
    try testing.expectEqual(null, pool.keep(io, .{ .h1 = &conns[1] }).evicted);
    // A third for route `a` puts out its oldest.
    try testing.expectEqual(&conns[0], pool.keep(io, .{ .h1 = &conns[2] }).evicted.?.h1);
    try testing.expectEqual(null, pool.keep(io, .{ .h1 = &conns[3] }).evicted);
    // The pool is full: its oldest of all goes.
    try testing.expectEqual(&conns[1], pool.keep(io, .{ .h1 = &conns[4] }).evicted.?.h1);
    var waited = false;
    try testing.expectEqual(&conns[2], (try pool.acquire(io, &routes[0], null, &waited)).idle.h1);
    try testing.expectEqual(Acquired.open, try pool.acquire(io, &routes[0], null, &waited));
    try testing.expectEqual(@as(u32, 2), pool.count());
    while (pool.drain(io)) |_| {}
    try testing.expectEqual(@as(u32, 0), pool.count());
}

test "a pool that keeps nothing hands every connection back" {
    const io = test_io.io();
    var pool: Pool = .init(testing.allocator, .{ .max_idle = 0 });
    defer pool.deinit(io);
    var conn = connWith(try Route.init(false, "a", 80, null));
    try testing.expectEqual(&conn, pool.keep(io, .{ .h1 = &conn }).evicted.?.h1);
}

test "a connection idle past its time is handed out to be closed, not used" {
    var clock: shakedown.Clock = .init(test_io.io(), .{});
    const io = clock.io();
    var pool: Pool = .init(testing.allocator, .{ .idle_timeout = .literal("90s") });
    defer pool.deinit(io);
    const route: Route = try .init(false, "a", 80, null);
    var a = connWith(route);
    var b = connWith(try Route.init(false, "b", 80, null));
    var c = connWith(try Route.init(false, "c", 80, null));
    try testing.expectEqual(Kept{}, pool.keep(io, .{ .h1 = &a }));
    clock.advance(.fromSeconds(60));
    try testing.expectEqual(Kept{}, pool.keep(io, .{ .h1 = &b }));
    clock.advance(.fromSeconds(30));
    // Keeping another puts the expired oldest out.
    try testing.expectEqual(&a, pool.keep(io, .{ .h1 = &c }).expired.?.h1);
    clock.advance(.fromSeconds(60));
    var waited = false;
    try testing.expectEqual(&b, (try pool.acquire(io, &b.route, null, &waited)).expired.h1);
    try testing.expectEqual(&c, (try pool.acquire(io, &c.route, null, &waited)).idle.h1);
}

test "a full route makes exchanges wait in order, for a kept connection or for room" {
    const io = test_io.io();
    var pool: Pool = .init(testing.allocator, .{ .max_per_route = 1 });
    defer pool.deinit(io);
    const route: Route = try .init(false, "a", 80, null);
    var waited = false;
    try testing.expectEqual(Acquired.open, try pool.acquire(io, &route, null, &waited));
    try testing.expect(!waited);
    const Wait = struct {
        fn run(pl: *Pool, r: Route, out: *AcquireError!Acquired, flag: *bool) void {
            out.* = pl.acquire(test_io.io(), &r, null, flag);
        }
    };
    var first: AcquireError!Acquired = undefined;
    var second: AcquireError!Acquired = undefined;
    var first_waited = false;
    var second_waited = false;
    var group: Io.Group = .init;
    defer group.cancel(io);
    group.concurrent(io, Wait.run, .{ &pool, route, &first, &first_waited }) catch return error.SkipZigTest;
    try waitForWaiters(&pool, &route, 1);
    group.concurrent(io, Wait.run, .{ &pool, route, &second, &second_waited }) catch return error.SkipZigTest;
    try waitForWaiters(&pool, &route, 2);
    // The connection comes back: the first waiter has it. Then it closes:
    // the second gets room for a new one.
    var conn = connWith(route);
    try testing.expectEqual(Kept{}, pool.keep(io, .{ .h1 = &conn }));
    pool.closed(io, &route);
    try group.await(io);
    try testing.expectEqual(&conn, (try first).idle.h1);
    try testing.expectEqual(Acquired.open, try second);
    try testing.expect(first_waited and second_waited);
    pool.closed(io, &route);
    try testing.expectEqual(@as(usize, 0), routeCount(&pool));
}

test "a wait for a full route ends at its deadline and leaves nothing behind" {
    var clock: shakedown.Clock = .init(test_io.io(), .{});
    const io = clock.io();
    var pool: Pool = .init(testing.allocator, .{ .max_per_route = 1 });
    defer pool.deinit(io);
    const route: Route = try .init(false, "a", 80, null);
    var waited = false;
    try testing.expectEqual(Acquired.open, try pool.acquire(io, &route, null, &waited));
    const Wait = struct {
        fn run(pl: *Pool, wio: Io, r: Route, deadline: Io.Timestamp, out: *AcquireError!Acquired) void {
            var w = false;
            out.* = pl.acquire(wio, &r, deadline, &w);
        }
    };
    var result: AcquireError!Acquired = undefined;
    const deadline = Io.Clock.awake.now(io).addDuration(.fromSeconds(5));
    var task = test_io.io().concurrent(Wait.run, .{ &pool, io, route, deadline, &result }) catch return error.SkipZigTest;
    defer task.cancel(test_io.io());
    try clock.awaitArmed(1, .{ .duration = .{ .raw = .fromSeconds(10), .clock = .awake } });
    clock.advance(.fromSeconds(5));
    task.await(test_io.io());
    try testing.expectError(error.TimedOut, result);
    pool.closed(io, &route);
    try testing.expectEqual(@as(usize, 0), routeCount(&pool));
}

/// How many limited routes the pool keeps state for.
fn routeCount(p: *Pool) usize {
    var held = p.state.acquireUncancelable(test_io.io());
    defer held.deinit(test_io.io());
    return held.value().routes.items.len;
}

/// Wait, briefly, until `n` exchanges wait for `route`.
fn waitForWaiters(p: *Pool, route: *const Route, n: usize) !void {
    for (0..2000) |_| {
        var held = p.state.acquireUncancelable(test_io.io());
        const have = if (findState(held.value(), route)) |state| state.waiters.len() else 0;
        held.deinit(test_io.io());
        if (have == n) return;
        try test_io.io().sleep(.fromMilliseconds(1), .awake);
    }
    return error.TestUnexpectedResult;
}
