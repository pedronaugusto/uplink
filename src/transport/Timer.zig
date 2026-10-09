//! The one task per client that keeps read and write timeouts.
//!
//! Zig 0.17's `Io.Threaded` cannot bound a socket operation by itself
//! everywhere: on Windows a timed read or write is refused outright, and on
//! POSIX a timed write waits only for the socket to take bytes, then blocks
//! in `sendmsg` for as long as the peer leaves its window shut. So a
//! connection with a timeout stores the deadline of the operation it is in
//! — an atomic store, no lock — and this task ends any operation past its
//! deadline by shutting its socket down (an abortive disconnect on Windows,
//! where a graceful one leaves a pending receive waiting for the peer). The
//! connection then reports `TimedOut`.
//!
//! It ticks while operations are armed, at a tenth of the shortest timeout
//! it has been asked to keep, and parks when none has been for a tick, so
//! an idle client costs no wakeups. The first operation armed after that
//! wakes it, and a shorter timeout than any before wakes it to tick faster.

const std = @import("std");
const aegis = @import("aegis");
const Io = std.Io;

const awake = @import("awake.zig");
const sys = @import("../net/sys.zig");

const Timer = @This();

/// Private: the watched connections and the task, reached only through the
/// lock beside them, which the task holds while it scans.
state: aegis.BlockingGuarded(State) = .init(.{}),
// The four below are the arm and disarm of every operation, atomics with no
// lock by design (the hot path of a timed read or write), measured against
// a locked version.
/// Private: how many watches have an operation armed.
armed: std.atomic.Value(u32) = .init(0),
/// Private: 1 while the task waits for an operation to be armed; the futex
/// it waits on.
parked: std.atomic.Value(u32) = .init(0),
/// How often the task looks at the armed deadlines, in nanoseconds.
tick: std.atomic.Value(i64),
/// Private: bumped to cut the task's wait short; the futex it waits on
/// between ticks.
nudge: std.atomic.Value(u32) = .init(0),

/// What the lock guards.
const State = struct {
    /// Every watched connection.
    watches: std.DoublyLinkedList = .{},
    /// The task, once started.
    task: ?Io.Future(void) = null,
};

/// One connection's operation deadline.
pub const Watch = struct {
    /// Private: the connection's place among the watched.
    node: std.DoublyLinkedList.Node = .{},
    /// The socket shut when the deadline passes.
    handle: Io.net.Socket.Handle,
    /// The armed operation's deadline on the awake clock, in nanoseconds;
    /// 0 when none is armed.
    deadline: std.atomic.Value(i64) = .init(0),
    /// Set when this task shut the socket.
    fired: std.atomic.Value(bool) = .init(false),
};

/// A timer for timeouts no shorter than `shortest`, or, null, for none
/// known yet.
pub fn init(shortest: ?Io.Duration) Timer {
    return .{ .tick = .init(tickFor(shortest orelse .fromSeconds(10))) };
}

/// A tenth of `d`, between a millisecond and a second.
fn tickFor(d: Io.Duration) i64 {
    return @intCast(std.math.clamp(@divTrunc(d.nanoseconds, 10), std.time.ns_per_ms, std.time.ns_per_s)); // safe: clamped to between a millisecond and a second
}

/// Keep timeouts as short as `d` too: the tick shortens to match, at once.
pub fn tighten(t: *Timer, io: Io, d: Io.Duration) void {
    const want = tickFor(d);
    var current = t.tick.load(.monotonic);
    while (want < current) {
        current = t.tick.cmpxchgWeak(current, want, .monotonic, .monotonic) orelse {
            _ = t.nudge.fetchAdd(1, .release);
            io.futexWake(u32, &t.nudge.raw, 1);
            return;
        };
    }
}

/// Stop the task. Every watch must have been removed.
pub fn deinit(t: *Timer, io: Io) void {
    // The task is canceled outside the lock, which it may be waiting for.
    var task = task: {
        var held = t.state.acquireUncancelable(io);
        defer held.deinit(io);
        const state = held.value();
        aegis.assert.pre(state.watches.first == null, "every watch was removed");
        break :task state.task;
    };
    if (task) |*running| running.cancel(io);
    t.* = undefined;
}

/// Watch `w`, starting the task if it is not running. False when no task
/// can run beside the caller's: the watch is not added.
pub fn add(t: *Timer, io: Io, w: *Watch) bool {
    var held = t.state.acquireUncancelable(io);
    defer held.deinit(io);
    const state = held.value();
    if (state.task == null) state.task = io.concurrent(run, .{ t, io }) catch return false;
    state.watches.append(&w.node);
    return true;
}

/// Stop watching `w`, which has nothing armed. Once this returns the task
/// never touches `w` or its socket again.
pub fn remove(t: *Timer, io: Io, w: *Watch) void {
    aegis.assert.pre(w.deadline.load(.monotonic) == 0, "nothing is armed on a watch being removed");
    var held = t.state.acquireUncancelable(io);
    defer held.deinit(io);
    held.value().watches.remove(&w.node);
}

/// An operation on `w`'s socket starts, to end by `deadline` (awake clock).
pub fn arm(t: *Timer, io: Io, w: *Watch, deadline: Io.Timestamp) void {
    // A deadline an i64 of nanoseconds cannot hold is the latest instant.
    w.deadline.store(@max(1, awake.of(deadline).raw()), .release);
    if (t.armed.fetchAdd(1, .seq_cst) == 0 and t.parked.load(.seq_cst) == 1) {
        t.parked.store(0, .seq_cst);
        io.futexWake(u32, &t.parked.raw, 1);
    }
}

/// The operation on `w`'s socket ended. Whether its deadline fired is
/// `w.fired`.
pub fn disarm(t: *Timer, w: *Watch) void {
    w.deadline.store(0, .release);
    _ = t.armed.fetchSub(1, .seq_cst);
}

fn run(t: *Timer, io: Io) void {
    var idle_ticks: u32 = 0;
    while (true) {
        if (t.armed.load(.seq_cst) == 0) {
            idle_ticks += 1;
            if (idle_ticks > 1) {
                idle_ticks = 0;
                t.parked.store(1, .seq_cst);
                if (t.armed.load(.seq_cst) == 0) io.futexWait(u32, &t.parked.raw, 1) catch return;
                t.parked.store(0, .seq_cst);
                continue;
            }
        } else idle_ticks = 0;
        const seen = t.nudge.load(.acquire);
        const tick: Io.Duration = .fromNanoseconds(t.tick.load(.monotonic));
        io.futexWaitTimeout(u32, &t.nudge.raw, seen, .{ .duration = .{ .raw = tick, .clock = .awake } }) catch return;
        t.scan(io);
    }
}

fn scan(t: *Timer, io: Io) void {
    var held = t.state.acquireUncancelable(io);
    defer held.deinit(io);
    const now = awake.now(io).raw();
    var it = held.value().watches.first;
    while (it) |node| : (it = node.next) {
        const w: *Watch = @fieldParentPtr("node", node);
        const deadline = w.deadline.load(.acquire);
        if (deadline == 0 or now < deadline or w.fired.load(.acquire)) continue;
        w.fired.store(true, .release);
        sys.abort(io, w.handle);
    }
}

const testing = std.testing;

test "a deadline passed shuts the operation's socket, and one disarmed in time does not" {
    const io = testing.io;
    var listener = try (try Io.net.IpAddress.parse("127.0.0.1", 0)).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var timer: Timer = .init(.fromMilliseconds(20));
    defer timer.deinit(io);
    var watch: Watch = .{ .handle = stream.socket.handle };
    if (!timer.add(io, &watch)) return error.SkipZigTest;
    defer timer.remove(io, &watch);

    // Armed and disarmed long before the deadline: nothing happens.
    timer.arm(io, &watch, Io.Clock.awake.now(io).addDuration(.fromSeconds(60)));
    timer.disarm(&watch);
    try io.sleep(.fromMilliseconds(30), .awake);
    try testing.expect(!watch.fired.load(.acquire));

    // A read that never gets an answer is ended when its deadline passes,
    // after the task parked for want of armed operations.
    timer.arm(io, &watch, Io.Clock.awake.now(io).addDuration(.fromMilliseconds(40)));
    var buffer: [16]u8 = undefined;
    var data: [1][]u8 = .{&buffer};
    // `Stream.read` does not compile in Zig 0.17: the operation is made
    // here as the stream would make it.
    const result = try io.operate(.{ .net_read = .{ .socket_handle = stream.socket.handle, .data = &data } });
    const n = if (result.net_read) |r| r.data_len else |_| 0;
    timer.disarm(&watch);
    try testing.expectEqual(@as(usize, 0), n);
    try testing.expect(watch.fired.load(.acquire));
}

test "the tick is a tenth of the shortest timeout, between a millisecond and a second, and only shortens" {
    try testing.expectEqual(@as(i64, std.time.ns_per_ms), Timer.init(.fromMilliseconds(2)).tick.load(.monotonic));
    try testing.expectEqual(@as(i64, 3 * std.time.ns_per_s / 10), Timer.init(.fromSeconds(3)).tick.load(.monotonic));
    try testing.expectEqual(@as(i64, std.time.ns_per_s), Timer.init(.fromSeconds(300)).tick.load(.monotonic));
    var t: Timer = .init(null);
    t.tighten(testing.io, .fromMilliseconds(50));
    try testing.expectEqual(@as(i64, 5 * std.time.ns_per_ms), t.tick.load(.monotonic));
    t.tighten(testing.io, .fromSeconds(5));
    try testing.expectEqual(@as(i64, 5 * std.time.ns_per_ms), t.tick.load(.monotonic));
}

test "a deadline past what an i64 holds is the latest instant, and never fires" {
    const io = testing.io;
    var timer: Timer = .init(null);
    var watch: Watch = .{ .handle = undefined };
    timer.arm(io, &watch, .fromNanoseconds(std.math.maxInt(i96)));
    try testing.expectEqual(std.math.maxInt(i64), watch.deadline.load(.monotonic));
    timer.disarm(&watch);
    // One at or before the start is the earliest a deadline can be, not none.
    timer.arm(io, &watch, .fromNanoseconds(std.math.minInt(i96)));
    try testing.expectEqual(@as(i64, 1), watch.deadline.load(.monotonic));
    timer.disarm(&watch);
}
