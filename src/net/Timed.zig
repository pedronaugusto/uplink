//! One socket's operations, each ended at its deadline: by reactor's
//! `Deadlines`, which keep it in the kernel on a reactor runtime and by one
//! task on any other `Io`; by the `Io` itself (`operateTimeout`) when no
//! task can be had for that; and not at all when the `Io` cannot bound an
//! operation either, which is counted once and then runs unbounded. An
//! operation with no deadline runs as the `Io` runs it.
//!
//! The client's connections and the server's share it: what differs is
//! which deadline an operation gets, which each finds for itself. A
//! deadline that fires poisons the socket, which `fired` then says.
//!
//! Reads and writes keep their deadlines apart, so one read and one write
//! may be under way at once, from two tasks: an HTTP/2 connection reads in
//! one while its streams write in others. Two reads at once, or two
//! writes, are not allowed.

const std = @import("std");
const aegis = @import("aegis");
const sync = @import("../sync.zig");
const reactor = @import("reactor");
const Io = std.Io;
const Deadlines = reactor.net.Deadlines;
const Endpoint = @import("stream.zig").Endpoint;

const Timed = @This();

/// Private: the reads' deadline.
reads: Side,
/// Private: the writes' deadline.
writes: Side,
/// Private: the socket is counted among those whose deadlines nothing
/// could keep.
counted: sync.Latch = .init(.clear),

/// One direction's operations: the deadline `Deadlines` keeps for the one
/// under way, and how deadlines are kept. Only the task doing that
/// direction's operation touches it.
const Side = struct {
    watch: Deadlines.Watch,
    mode: Modes.Runtime(void) = .init({}),
};

const Mode = enum {
    /// No deadline kept yet: the first operation with one decides.
    unwatched,
    /// `Deadlines` keep them.
    deadlines,
    /// `Io.operateTimeout` keeps them.
    operate,
    /// Asked for, and nothing could keep them.
    unenforced,
};

/// What decides how a side's deadlines are kept.
const Change = enum {
    /// `Deadlines` took the side's watch.
    watched,
    /// `Deadlines` could not: the `Io` keeps them.
    unwatchable,
    /// The `Io` cannot bound the operation either.
    unbounded,
    /// The socket is done with; nothing is under way.
    released,
};

/// How a side's deadlines come to be kept: decided by its first operation
/// with one, given up on only when the `Io` cannot keep them, and forgotten
/// when the socket is.
const Modes = aegis.state.Machine(Mode, Change, .{ .initial = .unwatched, .edges = &.{
    .{ .from = .unwatched, .on = .watched, .to = .deadlines },
    .{ .from = .unwatched, .on = .unwatchable, .to = .operate },
    .{ .from = .operate, .on = .unbounded, .to = .unenforced },
    .{ .from = .deadlines, .on = .released, .to = .unwatched },
    .{ .from = .operate, .on = .released, .to = .unwatched },
    .{ .from = .unenforced, .on = .released, .to = .unwatched },
} });

/// What keeps the deadlines of a set of sockets, and counts the ones that
/// could not be kept.
pub const Keeper = struct {
    deadlines: *Deadlines,
    /// Sockets whose deadlines no task and no `Io` could keep.
    unenforced: *sync.Counter,
};

/// Why an operation did not complete.
pub const Error = error{
    /// The deadline ended it; the socket is poisoned.
    TimedOut,
    Canceled,
};

/// Operations on `endpoint`.
pub fn init(endpoint: Endpoint) Timed {
    return .{ .reads = .{ .watch = endpoint.watch() }, .writes = .{ .watch = endpoint.watch() } };
}

/// Stop keeping deadlines; nothing may be under way.
pub fn deinit(t: *Timed, io: Io, keeper: Keeper) void {
    for ([_]*Side{ &t.reads, &t.writes }) |side| switch (side.mode.current()) {
        .unwatched => {},
        .deadlines => {
            keeper.deadlines.remove(io, &side.watch);
            _ = side.mode.step(.released) catch unreachable; // unreachable: watched until now
        },
        .operate, .unenforced => _ = side.mode.step(.released) catch unreachable, // unreachable: kept until now
    };
}

/// Whether a deadline fired on the socket, which is then never to be used
/// again.
pub fn fired(t: *const Timed) bool {
    return t.reads.watch.fired.load(.acquire) or t.writes.watch.fired.load(.acquire);
}

/// Perform `op`, ended at `deadline` on the awake clock when there is one.
/// A deadline already past ends it before it starts.
pub fn perform(t: *Timed, io: Io, keeper: Keeper, op: Io.Operation, deadline: ?Io.Timestamp) Error!Io.Operation.Result {
    const at = deadline orelse return io.operate(op);
    const side = switch (op) {
        .net_read, .net_receive, .file_read_streaming => &t.reads,
        else => &t.writes,
    };
    if (side.mode.current() == .unenforced) return io.operate(op);
    if (at.nanoseconds <= Io.Clock.awake.now(io).nanoseconds) return error.TimedOut;
    // A deadline that fired on the other side has aborted the socket.
    if (t.fired()) return error.TimedOut;
    if (side.mode.current() == .unwatched) _ = side.mode.step(if (keeper.deadlines.add(io, &side.watch)) .watched else .unwatchable) catch unreachable; // unreachable: unwatched until now
    switch (side.mode.current()) {
        .deadlines => return keeper.deadlines.operate(io, &side.watch, op, .{ .raw = at, .clock = .awake }) catch |err| switch (err) {
            error.Timeout => error.TimedOut,
            error.Canceled => error.Canceled,
        },
        .operate => return io.operateTimeout(op, .{ .deadline = .{ .raw = at, .clock = .awake } }) catch |err| switch (err) {
            error.Timeout => error.TimedOut,
            error.Canceled => error.Canceled,
            error.ConcurrencyUnavailable => {
                // This `Io` cannot bound a socket operation: from here on
                // this side runs unbounded, the socket counted once.
                _ = side.mode.step(.unbounded) catch unreachable; // unreachable: the Io kept them until now
                if (t.counted.swap(.set, .monotonic) == .clear) sync.bump(keeper.unenforced);
                return io.operate(op);
            },
        },
        .unwatched, .unenforced => unreachable, // unreachable: the mode was chosen above, and unenforced returned before it
    }
}

/// What a wait for something to read found.
pub const Readiness = enum {
    /// Bytes came, or the stream's end or an error, which the next read
    /// finds and names.
    ready,
    /// Nothing came within the time.
    timed_out,
    /// This `Io` cannot wait a bounded time on a socket.
    unbounded,
};

/// Wait up to `timeout` for `endpoint` to have something to read, reading
/// it into `r`'s empty buffer, without a deadline that ends the socket
/// when nothing comes: a wait that times out leaves the socket as it was.
pub fn awaitReadable(io: Io, endpoint: Endpoint, r: *Io.Reader, timeout: Io.Duration) Io.Cancelable!Readiness {
    if (r.seek != r.end) return .ready;
    r.seek = 0;
    r.end = 0;
    const handle = switch (endpoint) {
        .socket => |s| s.socket.handle,
        .pipe => |f| {
            const found = reactor.net.pipe.readPipeWithin(io, f, r.buffer, timeout) catch |err| switch (err) {
                error.Canceled => return error.Canceled,
                // A failure is for the reader to find and name.
                else => return .ready,
            };
            return switch (found) {
                .ready => |n| {
                    r.end = n;
                    return .ready;
                },
                .timed_out => .timed_out,
                .unbounded => .unbounded,
            };
        },
    };
    var data: [1][]u8 = .{r.buffer};
    const result = io.operateTimeout(.{ .net_read = .{ .socket_handle = handle, .data = &data } }, .{
        .duration = .{ .raw = timeout, .clock = .awake },
    }) catch |err| return switch (err) {
        error.Timeout => .timed_out,
        error.ConcurrencyUnavailable => .unbounded,
        error.Canceled => error.Canceled,
    };
    // An error or the end is for the reader to find and name.
    const n = (result.net_read catch return .ready).data_len;
    r.end = n;
    return .ready;
}

const testing = std.testing;
const test_io = @import("../testing/io.zig");

fn readUntil(t: *Timed, io: Io, keeper: Keeper, handle: Io.net.Socket.Handle, deadline: Io.Timestamp, done: *std.atomic.Value(bool)) Error!Io.Operation.Result {
    defer done.store(true, .release);
    var buf: [16]u8 = undefined;
    var data: [1][]u8 = .{&buf};
    return t.perform(io, keeper, .{ .net_read = .{ .socket_handle = handle, .data = &data } }, deadline);
}

test "a read and a write under way at once each end at their own deadline" {
    const io = test_io.io();
    var listener = try (try Io.net.IpAddress.parse("127.0.0.1", 0)).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const client = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer client.close(io);
    const server = try listener.accept(io);
    defer server.close(io);
    var deadlines: Deadlines = .init(.fromMilliseconds(20));
    defer deadlines.deinit(io);
    var unenforced: sync.Counter = .init(.fromRaw(0));
    const keeper: Keeper = .{ .deadlines = &deadlines, .unenforced = &unenforced };
    var timed: Timed = .init(.{ .socket = client });
    defer timed.deinit(io, keeper);

    // A read waits for bytes that never come, until its deadline; a write
    // with a far one starts and ends while it waits. The write's deadline
    // neither replaces the read's nor, once the write is done, unarms it.
    var done: std.atomic.Value(bool) = .init(false);
    const read_by = Io.Clock.awake.now(io).addDuration(.fromMilliseconds(300));
    var reading = try io.concurrent(readUntil, .{ &timed, io, keeper, client.socket.handle, read_by, &done });
    try io.sleep(.fromMilliseconds(50), .awake);
    const far = Io.Clock.awake.now(io).addDuration(.fromSeconds(60));
    const wrote = try timed.perform(io, keeper, .{ .net_write = .{ .socket_handle = client.socket.handle, .header = "", .data = &.{"x"}, .splat = 1 } }, far);
    try testing.expectEqual(@as(usize, 1), try wrote.net_write);

    // Ten times the read's deadline, then the test stops waiting.
    var waited: u32 = 0;
    while (!done.load(.acquire) and waited < 300) : (waited += 1) try io.sleep(.fromMilliseconds(10), .awake);
    if (!done.load(.acquire)) {
        // glint-ignore: Z026 -- the read is stopped only so the test ends; it has failed already
        _ = reading.cancel(io) catch {};
        return error.TestUnexpectedResult;
    }
    try testing.expectError(error.TimedOut, reading.await(io));
    try testing.expect(timed.fired());
}
