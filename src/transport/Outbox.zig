//! The frames an HTTP/2 connection has for its socket, both ends'.
//!
//! Every frame is encoded here, in memory, under the connection's lock, by
//! whichever task makes it: the reading task's answers (acknowledgements,
//! WINDOW_UPDATEs, resets, a GOAWAY) and the streams' own. The socket is
//! written by one task at a time, the one holding the send role, with the
//! lock released, so no task that needs the lock (the reading task above
//! all) waits behind a write the peer is not taking yet. Two ends that each
//! stop reading while one of their writes waits would stop each other as
//! soon as the socket buffers between them fill: a few streams' windows
//! fill Windows' loopback buffers.
//!
//! Frames a task adds while another holds the role go out with that
//! task's next round. Streams wait for room past `high_water`; the
//! reading task never waits: what it adds is bounded by the peer's frames,
//! which the protocol state's limits bound.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const Outbox = @This();

/// Private: frames encoded and not yet taken by a sender.
pending: Io.Writer.Allocating,
/// Private: a task holds the send role.
busy: bool = false,

/// Past this many bytes not yet taken by a sender, a stream waits before
/// it adds data: four frames of the default size.
pub const high_water = 64 << 10;

pub fn init(gpa: Allocator) Outbox {
    return .{ .pending = .init(gpa) };
}

pub fn deinit(o: *Outbox) void {
    o.pending.deinit();
    o.* = undefined;
}

/// Where frames are encoded, under the connection's lock.
pub fn writer(o: *Outbox) *Io.Writer {
    return &o.pending.writer;
}

/// The bytes encoded and not yet taken by a sender.
pub fn backlog(o: *const Outbox) usize {
    return o.pending.writer.end;
}

/// Whether frames wait and no task is sending them: the caller may send.
pub fn ready(o: *const Outbox) bool {
    return !o.busy and o.backlog() != 0;
}

/// Hand what is pending to the sender, as `sending`; the sender's last
/// buffer, emptied, takes new frames from here on.
fn take(o: *Outbox, sending: *std.ArrayList(u8)) void {
    sending.clearRetainingCapacity();
    const full = o.pending.toArrayList();
    o.pending = .fromArrayList(o.pending.allocator, sending);
    sending.* = full;
}

/// Write what is pending to `sink` until nothing is, as the task holding
/// the send role, which the caller must be able to take (`ready`). Called
/// with `held`, the guard of `lock`, whose value has the outbox as
/// `outbox`; the guard is released while each write is under way and held
/// again before this returns. `sending` is the sender's buffer, kept
/// between rounds outside the lock; `sink.transmit(bytes)` writes and
/// flushes, false when that failed. False when a write failed: what was
/// pending is dropped, and the connection is to end.
pub fn send(io: Io, lock: anytype, held: anytype, sending: *std.ArrayList(u8), sink: anytype) bool {
    var o = &held.value().outbox;
    std.debug.assert(!o.busy);
    o.busy = true;
    while (o.backlog() != 0) {
        o.take(sending);
        held.deinit(io);
        const sent = sink.transmit(sending.items);
        held.* = lock.acquireUncancelable(io);
        o = &held.value().outbox;
        if (!sent) {
            o.pending.writer.end = 0;
            o.busy = false;
            return false;
        }
    }
    o.busy = false;
    return true;
}

/// Write what is pending to `sink` with nothing else under way on the
/// connection: before it is shared, or once it is torn down. False when
/// the write failed; what was pending is dropped either way.
pub fn sendAlone(o: *Outbox, sink: anytype) bool {
    std.debug.assert(!o.busy);
    const sent = o.backlog() == 0 or sink.transmit(o.pending.written());
    o.pending.writer.end = 0;
    return sent;
}

const testing = std.testing;
const aegis = @import("aegis");
const test_io = @import("../testing/io.zig");

const Recorder = struct {
    got: std.ArrayList(u8) = .empty,
    fail: bool = false,

    fn transmit(r: *Recorder, bytes: []const u8) bool {
        if (r.fail) return false;
        r.got.appendSlice(testing.allocator, bytes) catch return false;
        return true;
    }
};

const TestShared = struct { outbox: Outbox };

test "a sender writes what was encoded in order, the lock released while it writes, and frames added meanwhile go in its next round" {
    const io = test_io.io();
    var lock: aegis.BlockingGuarded(TestShared) = .init(.{ .outbox = .init(testing.allocator) });
    defer {
        lock.teardown().outbox.deinit();
    }
    var sending: std.ArrayList(u8) = .empty;
    defer sending.deinit(testing.allocator);

    const Sink = struct {
        recorder: Recorder = .{},
        lock: *aegis.BlockingGuarded(TestShared),
        rounds: u32 = 0,

        fn transmit(s: *@This(), bytes: []const u8) bool {
            s.rounds += 1;
            // The lock is free while a round is written: another task
            // adds a frame, which the next round carries.
            if (s.rounds == 1) {
                var other = s.lock.acquireUncancelable(test_io.io());
                defer other.deinit(test_io.io());
                const o = &other.value().outbox;
                std.testing.expect(o.busy) catch return false;
                o.writer().writeAll("third") catch return false;
            }
            return s.recorder.transmit(bytes);
        }
    };
    var sink: Sink = .{ .lock = &lock };
    defer sink.recorder.got.deinit(testing.allocator);

    var held = lock.acquireUncancelable(io);
    defer held.deinit(io);
    try held.value().outbox.writer().writeAll("first ");
    try held.value().outbox.writer().writeAll("second ");
    try testing.expect(held.value().outbox.ready());
    try testing.expect(Outbox.send(io, &lock, &held, &sending, &sink));
    try testing.expect(!held.value().outbox.busy);
    try testing.expectEqual(@as(usize, 0), held.value().outbox.backlog());
    try testing.expectEqualStrings("first second third", sink.recorder.got.items);
    try testing.expectEqual(@as(u32, 2), sink.rounds);
}

test "a failed write drops what was pending and gives the role back" {
    const io = test_io.io();
    var lock: aegis.BlockingGuarded(TestShared) = .init(.{ .outbox = .init(testing.allocator) });
    defer {
        lock.teardown().outbox.deinit();
    }
    var sending: std.ArrayList(u8) = .empty;
    defer sending.deinit(testing.allocator);
    var sink: Recorder = .{ .fail = true };
    var held = lock.acquireUncancelable(io);
    defer held.deinit(io);
    try held.value().outbox.writer().writeAll("lost");
    try testing.expect(!Outbox.send(io, &lock, &held, &sending, &sink));
    try testing.expect(!held.value().outbox.ready());
    try testing.expect(!held.value().outbox.busy);
}
