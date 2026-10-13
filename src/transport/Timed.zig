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

const std = @import("std");
const reactor = @import("reactor");
const Io = std.Io;
const Deadlines = reactor.net.Deadlines;

const Timed = @This();

/// Private: the operation deadline `Deadlines` keeps.
watch: Deadlines.Watch,
/// Private: how deadlines are kept.
mode: Mode = .unwatched,

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

/// What keeps the deadlines of a set of sockets, and counts the ones that
/// could not be kept.
pub const Keeper = struct {
    deadlines: *Deadlines,
    /// Sockets whose deadlines no task and no `Io` could keep.
    unenforced: *std.atomic.Value(u64),
};

/// Why an operation did not complete.
pub const Error = error{
    /// The deadline ended it; the socket is poisoned.
    TimedOut,
    Canceled,
};

/// Operations on `handle`.
pub fn init(handle: Io.net.Socket.Handle) Timed {
    return .{ .watch = .init(handle) };
}

/// Stop keeping deadlines; nothing may be under way.
pub fn deinit(t: *Timed, io: Io, keeper: Keeper) void {
    if (t.mode == .deadlines) keeper.deadlines.remove(io, &t.watch);
    t.mode = .unwatched;
}

/// Whether a deadline fired on the socket, which is then never to be used
/// again.
pub fn fired(t: *const Timed) bool {
    return t.watch.fired.load(.acquire);
}

/// Perform `op`, ended at `deadline` on the awake clock when there is one.
/// A deadline already past ends it before it starts.
pub fn perform(t: *Timed, io: Io, keeper: Keeper, op: Io.Operation, deadline: ?Io.Timestamp) Error!Io.Operation.Result {
    const at = deadline orelse return io.operate(op);
    if (t.mode == .unenforced) return io.operate(op);
    if (at.nanoseconds <= Io.Clock.awake.now(io).nanoseconds) return error.TimedOut;
    if (t.mode == .unwatched) t.mode = if (keeper.deadlines.add(io, &t.watch)) .deadlines else .operate;
    switch (t.mode) {
        .deadlines => return keeper.deadlines.operate(io, &t.watch, op, .{ .raw = at, .clock = .awake }) catch |err| switch (err) {
            error.Timeout => error.TimedOut,
            error.Canceled => error.Canceled,
        },
        .operate => return io.operateTimeout(op, .{ .deadline = .{ .raw = at, .clock = .awake } }) catch |err| switch (err) {
            error.Timeout => error.TimedOut,
            error.Canceled => error.Canceled,
            error.ConcurrencyUnavailable => {
                // This `Io` cannot bound a socket operation: from here on
                // the socket runs unbounded, counted once.
                t.mode = .unenforced;
                _ = keeper.unenforced.fetchAdd(1, .monotonic);
                return io.operate(op);
            },
        },
        .unwatched, .unenforced => unreachable, // unreachable: the mode was chosen above, and unenforced returned before it
    }
}
