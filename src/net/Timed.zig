//! One socket's operations, each ended at its deadline: by reactor's
//! `Deadlines`, in the kernel on a reactor runtime and on any other `Io` by
//! running the operation in a task of its own that the deadline cancels, or,
//! with no task to be had, a stream socket's read or write bounded on the
//! calling thread; by the `Io` itself (`operateTimeout`) for what reactor
//! cannot bound so (a named pipe's operation). Where neither can keep it the
//! operation is refused with `ConcurrencyUnavailable` and never runs
//! unbounded. An operation with no
//! deadline runs as the `Io` runs it.
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
const span = @import("../span.zig");
const aegis = @import("aegis");
const reactor = @import("reactor");
const Io = std.Io;
const Deadlines = reactor.net.Deadlines;
const Endpoint = @import("stream.zig").Endpoint;

const Timed = @This();

/// Private: the reads' deadline.
reads: Side,
/// Private: the writes' deadline.
writes: Side,

/// One direction's operations. Only the task doing that direction's
/// operation touches it.
pub const Side = struct {
    watch: Deadlines.Watch,
    mode: Mode = .deadlines,
};

/// How a side's deadlines are kept.
pub const Mode = enum {
    /// `Deadlines` keep them.
    deadlines,
    /// No task could be had for that: `Io.operateTimeout` keeps them.
    operate,
};

/// Why an operation did not complete.
pub const Error = error{
    /// The deadline ended it; the socket is poisoned.
    TimedOut,
    /// Neither a task to race it in nor a bound of the `Io`'s own could be
    /// had: it did not run, and nothing ran unbounded.
    ConcurrencyUnavailable,
    Canceled,
};

/// Operations on `endpoint`.
pub fn init(endpoint: Endpoint) Timed {
    return .{ .reads = .{ .watch = endpoint.watch() }, .writes = .{ .watch = endpoint.watch() } };
}

/// Whether a deadline fired on the socket, which is then never to be used
/// again.
pub fn fired(t: *const Timed) bool {
    return t.reads.watch.fired.raised(.acquire) or t.writes.watch.fired.raised(.acquire);
}

/// Perform `op`, ended at `deadline` on the awake clock when there is one.
/// A deadline already past ends it before it starts.
pub fn perform(t: *Timed, io: Io, op: Io.Operation, deadline: ?Io.Timestamp) Error!Io.Operation.Result {
    const at = deadline orelse return io.operate(op);
    const side = switch (op) {
        .net_read, .net_receive, .file_read_streaming => &t.reads,
        else => &t.writes,
    };
    if (!span.before(Io.Clock.awake.now(io), at)) return error.TimedOut;
    // A deadline that fired on the other side has aborted the socket.
    if (t.fired()) return error.TimedOut;
    const bound: Io.Clock.Timestamp = .{ .raw = at, .clock = .awake };
    if (side.mode == .deadlines) {
        if (Deadlines.operate(io, &side.watch, op, bound)) |result| return result else |err| switch (err) {
            error.Timeout => return error.TimedOut,
            error.Canceled => return error.Canceled,
            // No task to race the operation in, and it did not start: the
            // `Io` keeps this side's deadlines from here on.
            error.ConcurrencyUnavailable => side.mode = .operate,
        }
    }
    return io.operateTimeout(op, .{ .deadline = bound }) catch |err| switch (err) {
        error.Timeout => error.TimedOut,
        error.Canceled => error.Canceled,
        // This `Io` cannot bound a socket operation either: refused.
        error.ConcurrencyUnavailable => error.ConcurrencyUnavailable,
    };
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
        .socket => |s| s.get().socket.handle,
        .pipe => |f| {
            const found = reactor.net.pipe.readPipeWithin(io, f.get(), r.buffer, timeout) catch |err| switch (err) {
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

/// Whether a test's read under way has ended.
const Ended = enum(u32) { no, yes };

fn readUntil(t: *Timed, io: Io, handle: Io.net.Socket.Handle, deadline: Io.Timestamp, done: *aegis.Atomic(Ended)) Error!Io.Operation.Result {
    defer done.store(.yes, .release);
    var buf: [16]u8 = undefined;
    // the kernel writes what a read takes into `buf`; nothing reads it here, the read only waits
    var data: [1][]u8 = .{&buf};
    return t.perform(io, .{ .net_read = .{ .socket_handle = handle, .data = &data } }, deadline);
}

test "a read and a write under way at once each end at their own deadline" {
    const io = test_io.io();
    var listener = try (try Io.net.IpAddress.parse("127.0.0.1", 0)).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const client = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer client.close(io);
    const server = try listener.accept(io);
    defer server.close(io);
    var timed: Timed = .init(.ofSocket(client));

    // A read waits for bytes that never come, until its deadline; a write
    // with a far one starts and ends while it waits. The write's deadline
    // neither replaces the read's nor, once the write is done, unarms it.
    var done: aegis.Atomic(Ended) = .init(.no);
    const read_by = Io.Clock.awake.now(io).addDuration(.fromMilliseconds(300));
    var reading = try io.concurrent(readUntil, .{ &timed, io, client.socket.handle, read_by, &done });
    try io.sleep(.fromMilliseconds(50), .awake);
    const far = Io.Clock.awake.now(io).addDuration(.fromSeconds(60));
    const wrote = try timed.perform(io, .{ .net_write = .{ .socket_handle = client.socket.handle, .header = "", .data = &.{"x"}, .splat = 1 } }, far);
    try testing.expectEqual(@as(usize, 1), try wrote.net_write);

    // Ten times the read's deadline, then the test stops waiting.
    var waited: u32 = 0;
    while (done.load(.acquire) == .no and waited < 300) : (waited += 1) try io.sleep(.fromMilliseconds(10), .awake);
    if (done.load(.acquire) == .no) {
        // the read is stopped only so the test ends; it has failed already
        _ = reading.cancel(io) catch {};
        return error.TestUnexpectedResult;
    }
    try testing.expectError(error.TimedOut, reading.await(io));
    try testing.expect(timed.fired());
}

/// An `Io` with no task to spare and no bound of its own on an operation.
const Unbounding = @import("shakedown").Layer(u8, .{
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
    .batchAwaitConcurrent = struct {
        fn awaitBatch(_: ?*anyopaque, _: *Io.Batch, _: Io.Timeout) Io.Batch.AwaitConcurrentError!void {
            return error.ConcurrencyUnavailable;
        }
    }.awaitBatch,
});

test "with no task to spare and no bound of the Io's own, a write is sent and a read ends at its deadline" {
    const base = test_io.io();
    var layer: Unbounding = .init(base, 0);
    const io = layer.io();
    var listener = try (try Io.net.IpAddress.parse("127.0.0.1", 0)).listen(base, .{ .reuse_address = true });
    defer listener.deinit(base);
    const client = try listener.socket.address.connect(base, .{ .mode = .stream });
    defer client.close(base);
    const server = try listener.accept(base);
    defer server.close(base);
    // reactor bounds a stream socket's operation on the calling thread.
    var timed: Timed = .init(.ofSocket(client));
    const far = Io.Clock.awake.now(base).addDuration(.fromSeconds(60));
    const wrote = try timed.perform(io, .{ .net_write = .{ .socket_handle = client.socket.handle, .header = "", .data = &.{"x"}, .splat = 1 } }, far);
    try testing.expectEqual(@as(usize, 1), try wrote.net_write);
    var peer: Timed = .init(.ofSocket(server));
    var buf: [4]u8 = undefined;
    var data: [1][]u8 = .{&buf};
    const read: Io.Operation = .{ .net_read = .{ .socket_handle = server.socket.handle, .data = &data } };
    const got = try (try peer.perform(io, read, far)).net_read;
    try testing.expectEqualStrings("x", buf[0..got.data_len]);
    // Nothing more comes: the read ends at its deadline.
    const soon = Io.Clock.awake.now(base).addDuration(.fromMilliseconds(50));
    try testing.expectError(error.TimedOut, peer.perform(io, read, soon));
    try testing.expect(peer.fired());
}
