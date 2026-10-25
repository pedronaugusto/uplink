//! One HTTP/2 connection a server serves: the protocol state shared by the
//! task that reads the connection, the tasks that answer its streams and
//! the task that writes it.
//!
//! Only the reading task reads. Every frame, its own answers and the
//! streams' writes alike, is encoded into the outbox under one lock, which
//! the protocol state sits behind, and the sending task writes the outbox
//! to the socket with the lock released: the reading task never waits
//! behind a write the client is not taking yet, so the client's frames are
//! read however long the server's writes wait (`Outbox`). On an `Io` with
//! no task to spare the one task writes as it goes. A stream that waits for
//! its send window, for room in the outbox or for its request's data waits
//! on one condition, which the reading and sending tasks wake when a
//! WINDOW_UPDATE, data, a reset, a write or the connection's end comes. A
//! stream's received data waits in a buffer of its own, never more than the
//! window the server gave it, and its window is given back as the handler
//! reads it.

const std = @import("std");
const place = @import("../../place.zig");
const BufferPool = @import("../../transport/BufferPool.zig");
const aegis = @import("aegis");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const wire = @import("uplink.wire");
const h2 = wire.h2;
const hpack = wire.hpack;
const Field = wire.fields.Field;
const Context = @import("../Context.zig");
const Socket = @import("../Socket.zig");
const Timed = @import("../../net/Timed.zig");
const Outbox = @import("../../transport/Outbox.zig");

const Session = @This();

socket: *Socket,
context: *Context,
/// Private: the protocol state and the streams, behind the write lock.
shared: aegis.BlockingGuarded(Shared),
/// Private: woken when anything a stream may wait for changes.
changed: aegis.Condition = .init(),
/// Private: what `init` allocated.
memory: []align(64) u8,
/// Private: a task of its own writes the outbox (`startSending`); else
/// whoever adds frames writes them at once.
sender: bool = false,
/// Private: the bytes the sending task is writing, outside the lock.
sending: std.ArrayList(u8) = .empty,

pub const Shared = struct {
    conn: h2.Connection,
    /// The frames for the socket.
    outbox: Outbox,
    /// The streams being answered.
    streams: std.ArrayList(*Stream) = .empty,
    /// Where a header block is encoded before it goes.
    scratch: []u8,
    /// The connection ended: nothing more is read or written.
    closed: bool = false,
};

/// The receive window a stream starts with: what its buffer holds.
pub const stream_window: h2.Connection.Limits.Bytes = .literal("256KiB");

/// The memory a session takes, besides its streams' buffers.
const Layout = struct {
    const streams = 128;
    const block = 64 << 10;
    const field_bytes = 64 << 10;
    const fields = 256;
    const table = 4096;
    const scratch = 64 << 10;
};

fn bytesOf(comptime T: type, n: usize) usize {
    return std.mem.alignForward(usize, n * @sizeOf(T), 64);
}

/// A session on `socket`, its memory from `context`'s allocator.
pub fn init(context: *Context, socket: *Socket, max_concurrent: u32) Allocator.Error!Session {
    const sizes = [_]usize{
        bytesOf(h2.Connection.Stream, Layout.streams),
        bytesOf(u8, Layout.block),
        bytesOf(u8, Layout.field_bytes),
        bytesOf(hpack.Field, Layout.fields),
        bytesOf(u8, hpack.Table.bytesFor(Layout.table)),
        bytesOf(hpack.Table.Entry, hpack.Table.entriesFor(Layout.table)),
        bytesOf(u8, hpack.Table.bytesFor(Layout.table)),
        bytesOf(hpack.Table.Entry, hpack.Table.entriesFor(Layout.table)),
        bytesOf(u8, Layout.scratch),
    };
    var total: usize = 0;
    for (sizes) |s| total += s;
    const memory = try context.gpa.alignedAlloc(u8, .@"64", total);
    var at: usize = 0;
    const take = struct {
        fn slice(comptime T: type, m: []align(64) u8, offset: *usize, size: usize, n: usize) []T {
            const p = place.many(T, m, offset.*, n);
            offset.* += size;
            return p;
        }
    }.slice;
    const streams = take(h2.Connection.Stream, memory, &at, sizes[0], Layout.streams);
    @memset(streams, .{});
    const block = take(u8, memory, &at, sizes[1], Layout.block);
    const field_bytes = take(u8, memory, &at, sizes[2], Layout.field_bytes);
    const fields = take(hpack.Field, memory, &at, sizes[3], Layout.fields);
    const db = take(u8, memory, &at, sizes[4], hpack.Table.bytesFor(Layout.table));
    const de = take(hpack.Table.Entry, memory, &at, sizes[5], hpack.Table.entriesFor(Layout.table));
    const eb = take(u8, memory, &at, sizes[6], hpack.Table.bytesFor(Layout.table));
    const ee = take(hpack.Table.Entry, memory, &at, sizes[7], hpack.Table.entriesFor(Layout.table));
    const scratch = take(u8, memory, &at, sizes[8], Layout.scratch);
    const max = @min(max_concurrent, Layout.streams);
    const conn: h2.Connection = .init(.server, .{
        .max_concurrent_streams = max,
        .initial_window_size = stream_window.raw(),
        .max_header_list_size = Layout.field_bytes,
        .enable_connect_protocol = true,
    }, .{
        .max_concurrent_streams = max,
        .max_header_block = .fromRaw(Layout.block),
        .max_header_list = .fromRaw(Layout.field_bytes),
    }, .{
        .streams = streams,
        .block = block,
        .field_bytes = field_bytes,
        .fields = fields,
        .decoder_bytes = db,
        .decoder_entries = de,
        .encoder_bytes = eb,
        .encoder_entries = ee,
    });
    return .{
        .socket = socket,
        .context = context,
        .shared = .init(.{ .conn = conn, .outbox = .init(context.gpa), .scratch = scratch }),
        .memory = memory,
    };
}

/// Free what the session holds; every stream must be done.
pub fn deinit(s: *Session) void {
    const shared = s.shared.teardown();
    shared.streams.deinit(s.context.gpa);
    shared.outbox.deinit();
    s.sending.deinit(s.context.gpa);
    s.context.gpa.free(s.memory);
    s.* = undefined;
}

/// The stream `id` being answered, under the lock.
pub fn find(shared: *Shared, id: u31) ?*Stream {
    for (shared.streams.items) |st| if (st.id == id) return st;
    return null;
}

/// Where frames are encoded, under the lock.
pub fn out(shared: *Shared) *Io.Writer {
    return shared.outbox.writer();
}

/// What was encoded goes: the sending task is woken for it, or with no
/// such task it is written now, under the lock. A write that fails ends
/// the connection.
pub fn post(s: *Session, shared: *Shared) void {
    if (s.sender) return s.changed.broadcast(s.socket.io);
    if (!shared.outbox.sendAlone(SocketSink{ .socket = s.socket })) shared.closed = true;
}

/// Write the outbox to the socket until the connection ends, as its one
/// sender: the sending task's work.
pub fn sendFrames(s: *Session) void {
    const io = s.socket.io;
    var held = s.shared.acquireUncancelable(io);
    defer held.deinit(io);
    while (true) {
        if (held.value().outbox.ready()) {
            if (!Outbox.send(io, &s.shared, &held, &s.sending, SocketSink{ .socket = s.socket })) held.value().closed = true;
            // Room in the outbox, or the connection's end.
            s.changed.broadcast(io);
            continue;
        }
        if (held.value().closed) return;
        s.changed.wait(io, &held, .none) catch return;
    }
}

/// Write the outbox from a task of its own in `group` from here on; before
/// any stream's task. With no task to spare, whoever adds frames writes
/// them.
pub fn startSending(s: *Session, group: *Io.Group) void {
    group.concurrent(s.socket.io, sendFrames, .{s}) catch return;
    s.sender = true;
}

/// Wait, under the lock, until the outbox has room for a stream's frames,
/// the stream is reset or the connection ends.
fn awaitRoom(s: *Session, st: *Stream, io: Io, held: anytype) WriteError!void {
    while (held.value().outbox.backlog() >= Outbox.high_water and st.reset_code == null and !held.value().closed) {
        s.changed.wait(io, held, .none) catch |err| return switch (err) {
            error.Canceled => error.Canceled,
            error.WaiterLimit => error.WriteFailed,
            error.Timeout => unreachable, // unreachable: the wait has no deadline
        };
    }
}

/// The socket, as the outbox writes to it.
pub const SocketSink = struct {
    socket: *Socket,

    pub fn transmit(sink: SocketSink, bytes: []const u8) bool {
        sink.socket.writer().writeAll(bytes) catch return false;
        sink.socket.flush() catch return false;
        return true;
    }
};

/// Why a stream's write failed.
pub const WriteError = error{
    /// The peer reset the stream, or the connection ended.
    StreamClosed,
    WriteFailed,
    Canceled,
};

/// Why a stream's read failed.
pub const ReadError = error{
    /// The peer reset the stream, or the connection ended under it.
    StreamClosed,
    Canceled,
};

/// One stream being answered: its request's head, the data that came for
/// it, and the writes of its response.
pub const Stream = struct {
    session: *Session,
    id: u31,
    /// The request's fields, in a buffer of the server's pool.
    head_buffer: BufferPool.Buffer,
    fields: []Field,
    /// Received data, a ring; at most the stream's window.
    recv: []u8 = &.{},
    recv_start: usize = 0,
    recv_len: usize = 0,
    recv_end: bool = false,
    /// The peer's reset, or the connection's end.
    reset_code: ?h2.ErrorCode = null,
    /// The request's trailer fields, in their own pooled buffer.
    trailer_buffer: BufferPool.Buffer = &.{},
    trailers: ?[]Field = null,
    /// The response's headers have gone.
    responded: bool = false,
    /// The response ended.
    ended: bool = false,
    /// The reader of the request's data.
    interface: Io.Reader,
    read_io: Io = undefined,
    read_failure: ?ReadError = null,

    /// The request's data, as it comes.
    pub fn reader(st: *Stream, io: Io) *Io.Reader {
        st.read_io = io;
        return &st.interface;
    }

    fn streamRead(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const st: *Stream = @alignCast(@fieldParentPtr("interface", r)); // safe: this vtable is installed only on a Stream's interface
        return st.take(w, limit) catch |err| switch (err) {
            error.EndOfStream => error.EndOfStream,
            error.WriteFailed => error.WriteFailed,
            error.StreamClosed, error.Canceled => |e| {
                st.read_failure = e;
                return error.ReadFailed;
            },
        };
    }

    fn take(st: *Stream, w: *Io.Writer, limit: Io.Limit) (ReadError || error{ EndOfStream, WriteFailed })!usize {
        // A read that failed stays failed.
        if (st.read_failure) |err| return err;
        const s = st.session;
        const io = st.read_io;
        var held = s.shared.acquire(io) catch return error.Canceled;
        defer held.deinit(io);
        while (st.recv_len == 0) {
            if (st.recv_end) return error.EndOfStream;
            if (st.reset_code != null or held.value().closed) return error.StreamClosed;
            s.changed.wait(io, &held, .none) catch return error.Canceled;
        }
        const first = @min(st.recv_len, st.recv.len - st.recv_start);
        const n = @min(first, limit.toInt() orelse first);
        try w.writeAll(st.recv[st.recv_start..][0..n]);
        st.recv_start = (st.recv_start + n) % st.recv.len;
        st.recv_len -= n;
        const shared = held.value();
        shared.conn.giveBack(out(shared), st.id, n) catch {
            shared.closed = true;
        };
        s.post(shared);
        return n;
    }

    /// Data for the stream from the reading task, under the lock: copied
    /// into the ring, which the window bounds.
    pub fn deliver(st: *Stream, gpa: Allocator, bytes: []const u8, end: bool) Allocator.Error!void {
        if (bytes.len != 0) {
            if (st.recv.len == 0) st.recv = try gpa.alloc(u8, stream_window.raw());
            std.debug.assert(st.recv_len + bytes.len <= st.recv.len);
            var at = (st.recv_start + st.recv_len) % st.recv.len;
            var rest = bytes;
            while (rest.len != 0) {
                const n = @min(rest.len, st.recv.len - at);
                @memcpy(st.recv[at..][0..n], rest[0..n]);
                rest = rest[n..];
                at = (at + n) % st.recv.len;
            }
            st.recv_len += bytes.len;
        }
        if (end) st.recv_end = true;
    }

    /// Write the response's (or an interim response's) headers.
    pub fn writeHeaders(st: *Stream, io: Io, fields: []const hpack.Field, end_stream: bool) WriteError!void {
        const s = st.session;
        var held = s.shared.acquire(io) catch return error.Canceled;
        defer held.deinit(io);
        try s.awaitRoom(st, io, &held);
        const shared = held.value();
        if (st.reset_code != null or shared.closed) return error.StreamClosed;
        shared.conn.writeHeaders(out(shared), st.id, fields, end_stream, shared.scratch) catch |err| return switch (err) {
            error.WriteFailed => error.WriteFailed,
            else => error.StreamClosed,
        };
        if (end_stream) st.ended = true;
        s.post(shared);
    }

    /// Write `bytes` as DATA, waiting for the windows as they allow, and
    /// end the stream after them when `end_stream`.
    pub fn writeData(st: *Stream, io: Io, bytes: []const u8, end_stream: bool) WriteError!void {
        const s = st.session;
        var held = s.shared.acquire(io) catch return error.Canceled;
        defer held.deinit(io);
        var rest = bytes;
        while (true) {
            try s.awaitRoom(st, io, &held);
            const shared = held.value();
            if (st.reset_code != null or shared.closed) return error.StreamClosed;
            const n = shared.conn.writeData(out(shared), st.id, rest, end_stream) catch |err| return switch (err) {
                error.WriteFailed => error.WriteFailed,
                else => error.StreamClosed,
            };
            rest = rest[n..];
            if (rest.len == 0 and (n != 0 or !end_stream or bytes.len == 0)) {
                if (end_stream) st.ended = true;
                s.post(shared);
                return;
            }
            if (n == 0) {
                // The window is shut: what went goes out, and the reading
                // task wakes this when a WINDOW_UPDATE opens it.
                s.post(shared);
                s.changed.wait(io, &held, .none) catch return error.Canceled;
            } else {
                // The frame goes before the next is encoded.
                s.post(shared);
            }
        }
    }

    /// Wait up to `timeout` for data, the stream's end or its reset; the
    /// wait ends nothing when nothing comes.
    pub fn awaitReadable(st: *Stream, io: Io, timeout: Io.Duration) Io.Cancelable!Timed.Readiness {
        const s = st.session;
        var held = try s.shared.acquire(io);
        defer held.deinit(io);
        const until = Io.Clock.awake.now(io).addDuration(timeout);
        while (st.recv_len == 0 and !st.recv_end and st.reset_code == null and !held.value().closed) {
            s.changed.wait(io, &held, .{ .deadline = .{ .raw = until, .clock = .awake } }) catch |err| switch (err) {
                error.Timeout => return .timed_out,
                error.Canceled => return error.Canceled,
                error.WaiterLimit => return .unbounded,
            };
        }
        return .ready;
    }

    /// Wait up to `timeout` for the peer to reset the stream or for the
    /// connection to end: whether one did. False too when the condition
    /// takes no more waiters.
    pub fn awaitGone(st: *Stream, io: Io, timeout: Io.Timeout) Io.Cancelable!bool {
        const s = st.session;
        var held = try s.shared.acquire(io);
        defer held.deinit(io);
        const deadline = timeout.toDeadline(io);
        while (st.reset_code == null and !held.value().closed) {
            s.changed.wait(io, &held, deadline) catch |err| return switch (err) {
                error.Timeout, error.WaiterLimit => false,
                error.Canceled => error.Canceled,
            };
        }
        return true;
    }

    /// Whether the request's data has ended, all of it delivered (some
    /// perhaps not yet read).
    pub fn dataEnded(st: *Stream) bool {
        const io = st.session.socket.io;
        var held = st.session.shared.acquireUncancelable(io);
        defer held.deinit(io);
        return st.recv_end;
    }

    /// Whether the request's data has ended and been read to its end.
    pub fn drained(st: *Stream) bool {
        const io = st.session.socket.io;
        var held = st.session.shared.acquireUncancelable(io);
        defer held.deinit(io);
        return st.recv_end and st.recv_len == 0;
    }

    /// The request's trailer fields, once they came.
    pub fn trailerFields(st: *Stream) ?[]Field {
        const io = st.session.socket.io;
        var held = st.session.shared.acquireUncancelable(io);
        defer held.deinit(io);
        return st.trailers;
    }

    /// Reset the stream with `code`.
    pub fn reset(st: *Stream, io: Io, code: h2.ErrorCode) void {
        st.resetIf(io, code, false);
    }

    /// The response ended with the request's data still coming: tell the
    /// client to stop sending it (`NO_ERROR`, RFC 9113 §8.1).
    pub fn refuseRest(st: *Stream, io: Io) void {
        st.resetIf(io, .no_error, true);
    }

    fn resetIf(st: *Stream, io: Io, code: h2.ErrorCode, only_unended: bool) void {
        const s = st.session;
        var held = s.shared.acquireUncancelable(io);
        defer held.deinit(io);
        const shared = held.value();
        if (shared.closed or st.reset_code != null) return;
        if (only_unended and st.recv_end) return;
        // A reset that cannot be written: the connection has failed, which ends the stream too.
        shared.conn.reset(out(shared), st.id, code) catch {
            shared.closed = true;
        };
        st.reset_code = code;
        s.post(shared);
    }

    pub fn initReader(st: *Stream) void {
        st.interface = .{ .vtable = &.{ .stream = streamRead }, .buffer = &.{}, .seek = 0, .end = 0 };
    }
};
