//! The one task per client that keeps read and write timeouts.
//!
//! Zig 0.17's `Io.Threaded` cannot bound a socket operation by itself
//! everywhere: on Windows a timed read or write is refused outright, and on
//! POSIX a timed write waits only for the socket to take bytes, then blocks
//! in `sendmsg` for as long as the peer leaves its window shut. So a
//! connection with a timeout stores the deadline of the operation it is in
//! — an atomic store, no lock — and this task shuts the socket of any
//! operation past its deadline, which ends the operation with the error a
//! closed socket gives. The connection then reports `TimedOut`.
//!
//! It ticks while operations are armed, at a tenth of the shortest timeout,
//! and parks when none has been for a tick, so an idle client costs no
//! wakeups. The first operation armed after that wakes it.

const std = @import("std");
const Io = std.Io;

const Timer = @This();

/// Private: held for `watches`, by the task while it scans.
mutex: Io.Mutex = .init,
/// Private: every watched connection.
watches: std.DoublyLinkedList = .{},
/// Private: how many watches have an operation armed.
armed: std.atomic.Value(u32) = .init(0),
/// Private: 1 while the task waits for an operation to be armed; the futex
/// it waits on.
parked: std.atomic.Value(u32) = .init(0),
/// Private: the task, once started.
task: ?Io.Future(void) = null,
/// How often the task looks at the armed deadlines.
tick: Io.Duration,

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

/// A timer for timeouts no shorter than `shortest`.
pub fn init(shortest: Io.Duration) Timer {
    const tenth = @divTrunc(shortest.nanoseconds, 10);
    return .{ .tick = .fromNanoseconds(std.math.clamp(tenth, std.time.ns_per_ms, std.time.ns_per_s)) };
}

/// Stop the task. Every watch must have been removed.
pub fn deinit(t: *Timer, io: Io) void {
    std.debug.assert(t.watches.first == null);
    if (t.task) |*task| task.cancel(io);
    t.* = undefined;
}

/// Watch `w`, starting the task if it is not running. False when no task
/// can run beside the caller's: the watch is not added.
pub fn add(t: *Timer, io: Io, w: *Watch) bool {
    t.mutex.lockUncancelable(io);
    defer t.mutex.unlock(io);
    if (t.task == null) t.task = io.concurrent(run, .{ t, io }) catch return false;
    t.watches.append(&w.node);
    return true;
}

/// Stop watching `w`, which has nothing armed. Once this returns the task
/// never touches `w` or its socket again.
pub fn remove(t: *Timer, io: Io, w: *Watch) void {
    std.debug.assert(w.deadline.load(.monotonic) == 0);
    t.mutex.lockUncancelable(io);
    defer t.mutex.unlock(io);
    t.watches.remove(&w.node);
}

/// An operation on `w`'s socket starts, to end by `deadline` (awake clock).
pub fn arm(t: *Timer, io: Io, w: *Watch, deadline: Io.Timestamp) void {
    w.deadline.store(@intCast(@max(1, deadline.nanoseconds)), .release);
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
        io.sleep(t.tick, .awake) catch return;
        t.scan(io);
    }
}

fn scan(t: *Timer, io: Io) void {
    t.mutex.lockUncancelable(io);
    defer t.mutex.unlock(io);
    const now: i64 = @intCast(Io.Clock.awake.now(io).nanoseconds);
    var it = t.watches.first;
    while (it) |node| : (it = node.next) {
        const w: *Watch = @fieldParentPtr("node", node);
        const deadline = w.deadline.load(.acquire);
        if (deadline == 0 or now < deadline or w.fired.load(.acquire)) continue;
        w.fired.store(true, .release);
        // ziglint-ignore: Z026 a socket that cannot be shut down is already closed, which ends the operation too
        io.vtable.netShutdown(io.userdata, w.handle, .both) catch {};
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

test "the tick is a tenth of the shortest timeout, between a millisecond and a second" {
    try testing.expectEqual(@as(i96, std.time.ns_per_ms), Timer.init(.fromMilliseconds(2)).tick.nanoseconds);
    try testing.expectEqual(@as(i96, 3 * std.time.ns_per_s / 10), Timer.init(.fromSeconds(3)).tick.nanoseconds);
    try testing.expectEqual(@as(i96, std.time.ns_per_s), Timer.init(.fromSeconds(300)).tick.nanoseconds);
}
