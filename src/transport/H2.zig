//! One HTTP/2 connection a client multiplexes its requests over (RFC 9113):
//! the socket and its layers (a `Connection`), the protocol state, and the
//! streams of the requests using it.
//!
//! No task reads the connection on its own. A request that waits for its
//! response's head or data takes the reading token when no one holds it,
//! reads one frame, hands it to the protocol state, delivers what it
//! carries to whichever stream it is for, and gives the token back, waking
//! the others; one that finds the token taken waits to be woken. A frame is
//! read only once the socket has something, so a reader whose own deadline
//! passes gives up its turn, and no deadline ends the socket the other
//! streams share. Frames are encoded into the outbox under one lock, the
//! protocol state behind it, and written by whichever task finds no other
//! writing, with the lock released (`Outbox`): a reader never waits behind
//! a write the server is not taking yet.

const std = @import("std");
const sync = @import("../sync.zig");
const aegis = @import("aegis");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const wire = @import("uplink.wire");
const h2 = wire.h2;
const hpack = wire.hpack;
const Field = wire.fields.Field;
const Connection = @import("Connection.zig");
const Context = @import("Context.zig");
const BufferPool = @import("BufferPool.zig");
const span = @import("../span.zig");
const Outbox = @import("Outbox.zig");

const H2 = @This();

conn: *Connection,
ctx: *Context,
/// Private: the protocol state and the streams, behind the write lock.
shared: aegis.BlockingGuarded(Shared),
/// Private: woken when the token is given back or a stream's state moves.
changed: aegis.Condition = .init(),
/// The exchanges using the connection now.
users: sync.Gauge = .init(.fromRaw(0)),
/// Private: what `create` allocated besides this value.
memory: []u8,
/// Private: the bytes the task holding the send role is writing, outside
/// the lock.
sending: std.ArrayList(u8) = .empty,

const Shared = struct {
    proto: h2.Connection,
    /// The frames for the socket.
    outbox: Outbox,
    streams: std.ArrayList(*Stream) = .empty,
    scratch: []u8,
    /// A task holds the reading token.
    reading: bool = false,
    /// Why the connection can carry nothing more.
    failure: ?Failure = null,
};

pub const Failure = union(enum) {
    /// The peer broke the protocol, or this end did and said so.
    protocol,
    /// The socket or its TLS failed, as the connection names it.
    io: Connection.IoError,
    /// The peer went away with an error.
    going_away,
};

/// How long a reader without a deadline waits for a frame at a time.
const idle_wait: Io.Duration = .fromSeconds(3600);

/// The receive window each stream gets: what its buffer may hold.
pub const stream_window: h2.Connection.Limits.Bytes = .literal("1MiB");

/// The settings a client sends.
const settings: h2.Settings = .{
    .enable_push = false,
    .initial_window_size = stream_window.raw(),
    .max_header_list_size = Layout.field_bytes,
};

/// The value of `HTTP2-Settings` on a request that asks to upgrade: the
/// settings the connection then sends, base64url-encoded without padding
/// (RFC 7540 §3.2.1).
pub fn upgradeSettings(out: *[upgrade_settings_len]u8) []const u8 {
    var buf: [64]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    settings.write(&w) catch unreachable; // unreachable: the settings are under 64 bytes
    return std.base64.url_safe_no_pad.Encoder.encode(out, w.buffered());
}

/// The longest `upgradeSettings`.
pub const upgrade_settings_len = std.base64.url_safe_no_pad.Encoder.calcSize(64);

const Layout = struct {
    const streams = 128;
    const block = 64 << 10;
    const field_bytes = 64 << 10;
    const fields = 256;
    const table = 4096;
    const scratch = 64 << 10;
};

fn partSize(comptime T: type, n: usize) usize {
    return std.mem.alignForward(usize, n * @sizeOf(T), 64);
}

/// Speak HTTP/2 on `conn`, whose TLS agreed `h2` by ALPN or which goes by
/// prior knowledge: the preface and settings go out now.
pub fn create(ctx: *Context, io: Io, conn: *Connection) (Allocator.Error || error{ConnectionFailed})!*H2 {
    const h = try allocate(ctx, conn);
    errdefer h.abandon();
    try h.begin(io);
    return h;
}

/// What `upgraded` gives: the connection, and the stream the upgraded
/// request's response comes on.
pub const Upgraded = struct { h2: *H2, stream: *Stream };

/// Speak HTTP/2 on `conn`, whose server answered its HTTP/1.1 request's
/// `Upgrade: h2c` with a 101 (RFC 7540 §3.2): the preface and settings go
/// out now, and that request, sent whole, is stream 1, whose response
/// comes on it; `head` for a `HEAD`.
pub fn upgraded(ctx: *Context, io: Io, conn: *Connection, head: bool) (Allocator.Error || error{ConnectionFailed})!Upgraded {
    const h = try allocate(ctx, conn);
    errdefer h.abandon();
    const st = try ctx.gpa.create(Stream);
    st.* = .{ .h2 = h, .id = 1, .sent_end = true, .expects_body = !head, .interface = .{ .vtable = &.{ .stream = Stream.streamRead }, .buffer = &.{}, .seek = 0, .end = 0 } };
    {
        var held = h.shared.acquireUncancelable(io);
        defer held.deinit(io);
        const shared = held.value();
        shared.proto.upgradeClient();
        // From here `abandon` destroys it with the others.
        shared.streams.append(ctx.gpa, st) catch |err| {
            ctx.gpa.destroy(st);
            return err;
        };
    }
    try h.begin(io);
    return .{ .h2 = h, .stream = st };
}

/// The connection's memory and state, nothing sent yet.
fn allocate(ctx: *Context, conn: *Connection) Allocator.Error!*H2 {
    const sizes = [_]usize{
        partSize(h2.Connection.Stream, Layout.streams),
        partSize(u8, Layout.block),
        partSize(u8, Layout.field_bytes),
        partSize(hpack.Field, Layout.fields),
        partSize(u8, hpack.Table.bytesFor(Layout.table)),
        partSize(hpack.Table.Entry, hpack.Table.entriesFor(Layout.table)),
        partSize(u8, hpack.Table.bytesFor(Layout.table)),
        partSize(hpack.Table.Entry, hpack.Table.entriesFor(Layout.table)),
        partSize(u8, Layout.scratch),
    };
    var total: usize = 0;
    for (sizes) |s| total += s;
    const memory = try ctx.gpa.alignedAlloc(u8, .@"64", total);
    errdefer ctx.gpa.free(memory);
    var at: usize = 0;
    const take = struct {
        fn slice(comptime T: type, m: []u8, offset: *usize, size: usize, n: usize) []T {
            const p: [*]T = @ptrCast(@alignCast(m.ptr + offset.*)); // safe: each part starts 64-aligned inside the block
            offset.* += size;
            return p[0..n];
        }
    }.slice;
    const streams = take(h2.Connection.Stream, memory, &at, sizes[0], Layout.streams);
    @memset(streams, .{});
    const mem: h2.Connection.Memory = .{
        .streams = streams,
        .block = take(u8, memory, &at, sizes[1], Layout.block),
        .field_bytes = take(u8, memory, &at, sizes[2], Layout.field_bytes),
        .fields = take(hpack.Field, memory, &at, sizes[3], Layout.fields),
        .decoder_bytes = take(u8, memory, &at, sizes[4], hpack.Table.bytesFor(Layout.table)),
        .decoder_entries = take(hpack.Table.Entry, memory, &at, sizes[5], hpack.Table.entriesFor(Layout.table)),
        .encoder_bytes = take(u8, memory, &at, sizes[6], hpack.Table.bytesFor(Layout.table)),
        .encoder_entries = take(hpack.Table.Entry, memory, &at, sizes[7], hpack.Table.entriesFor(Layout.table)),
    };
    const scratch = take(u8, memory, &at, sizes[8], Layout.scratch);
    const h = try ctx.gpa.create(H2);
    errdefer ctx.gpa.destroy(h);
    h.* = .{
        .conn = conn,
        .ctx = ctx,
        .memory = memory,
        .shared = .init(.{
            .proto = .init(.client, settings, .{
                .max_concurrent_streams = Layout.streams,
                .max_header_block = .fromRaw(Layout.block),
                .max_header_list = .fromRaw(Layout.field_bytes),
            }, mem),
            .outbox = .init(ctx.gpa),
            .scratch = scratch,
        }),
    };
    return h;
}

/// Send the preface and settings, sharing the connection from here on.
fn begin(h: *H2, io: Io) error{ConnectionFailed}!void {
    h.conn.io = io;
    // The connection is shared: no exchange's deadline bounds its socket,
    // and its `Io` stays this one.
    h.conn.share();
    var held = h.shared.acquireUncancelable(io);
    defer held.deinit(io);
    const shared = held.value();
    shared.proto.start(shared.outbox.writer()) catch return error.ConnectionFailed;
    if (!shared.outbox.sendAlone(ConnSink{ .conn = h.conn })) return error.ConnectionFailed;
}

/// Free what `allocate` took, the connection left to the caller: for one
/// that failed to start, or that `upgraded` made and nothing shared.
pub fn abandon(h: *H2) void {
    const shared = h.shared.teardown();
    for (shared.streams.items) |st| h.ctx.gpa.destroy(st);
    shared.streams.deinit(h.ctx.gpa);
    shared.outbox.deinit();
    h.ctx.gpa.free(@as([]align(64) u8, @alignCast(h.memory))); // safe: `allocate` allocated it 64-aligned
    h.ctx.gpa.destroy(h);
}

/// Close the connection, telling the peer when it can still hear, and free
/// what it held. No exchange may be using it.
pub fn close(h: *H2, io: Io) void {
    const shared = h.shared.teardown();
    if (shared.failure == null) {
        h.conn.io = io;
        // glint-ignore: Z026 -- the GOAWAY is a courtesy; the socket closes whether or not it went
        shared.proto.goaway(shared.outbox.writer(), .no_error) catch {};
        _ = shared.outbox.sendAlone(ConnSink{ .conn = h.conn });
    }
    shared.streams.deinit(h.ctx.gpa);
    shared.outbox.deinit();
    h.sending.deinit(h.ctx.gpa);
    h.conn.close(io);
    h.ctx.gpa.free(@as([]align(64) u8, @alignCast(h.memory))); // safe: `create` allocated it 64-aligned
    h.ctx.gpa.destroy(h);
}

/// Whether a new exchange can go on the connection now.
pub fn canOpen(h: *H2, io: Io) bool {
    var held = h.shared.acquireUncancelable(io);
    defer held.deinit(io);
    const shared = held.value();
    if (shared.failure != null or shared.proto.goaway_received != null) return false;
    const max = shared.proto.remote.max_concurrent_streams orelse Layout.streams;
    return shared.streams.items.len < @min(max, Layout.streams);
}

/// Whether the connection can carry exchanges still.
pub fn usable(h: *H2, io: Io) bool {
    var held = h.shared.acquireUncancelable(io);
    defer held.deinit(io);
    const shared = held.value();
    return shared.failure == null and shared.proto.goaway_received == null;
}

/// Why an exchange's stream failed.
pub const Error = error{
    /// The connection failed, or the peer reset the stream.
    ConnectionFailed,
    TlsFailed,
    ClientCertificateRejected,
    /// The peer went away before it processed the stream: it may go again.
    Refused,
    TimedOut,
    Canceled,
    OutOfMemory,
};

/// One exchange's stream.
pub const Stream = struct {
    h2: *H2,
    id: u31,
    /// The response's head, its fields in a pooled buffer, once it came.
    status: ?u10 = null,
    head_buffer: []u8 = &.{},
    fields: []const Field = &.{},
    /// Interim heads seen and dropped.
    interim: u8 = 0,
    /// Received data, a ring no larger than the window.
    recv: []u8 = &.{},
    recv_start: usize = 0,
    recv_len: usize = 0,
    recv_end: bool = false,
    reset_code: ?h2.ErrorCode = null,
    refused: bool = false,
    trailer_buffer: []u8 = &.{},
    trailers: ?[]Field = null,
    /// The request's end went.
    sent_end: bool = false,
    /// A response with a body may come: not to a `HEAD`.
    expects_body: bool = true,
    /// The reader of the response's data.
    interface: Io.Reader,
    read_io: Io = undefined,
    read_deadline: ?Io.Timestamp = null,
    read_failure: ?Error = null,

    /// The response's data, as it comes.
    pub fn reader(st: *Stream, io: Io) *Io.Reader {
        st.read_io = io;
        return &st.interface;
    }

    fn streamRead(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const st: *Stream = @alignCast(@fieldParentPtr("interface", r)); // safe: this vtable is installed only on a Stream's interface
        return st.take(w, limit) catch |err| switch (err) {
            error.EndOfStream => error.EndOfStream,
            error.WriteFailed => error.WriteFailed,
            else => |e| {
                st.read_failure = e;
                return error.ReadFailed;
            },
        };
    }

    fn take(st: *Stream, w: *Io.Writer, limit: Io.Limit) (Error || error{ EndOfStream, WriteFailed })!usize {
        const h = st.h2;
        const io = st.read_io;
        var held = h.shared.acquire(io) catch return error.Canceled;
        defer held.deinit(io);
        const until = h.waitUntil(io, st.read_deadline);
        while (st.recv_len == 0) {
            if (st.recv_end) return error.EndOfStream;
            try h.failed(st, held.value());
            try h.pump(io, &held, until);
        }
        const first = @min(st.recv_len, st.recv.len - st.recv_start);
        const n = @min(first, limit.toInt() orelse first);
        try w.writeAll(st.recv[st.recv_start..][0..n]);
        st.recv_start = (st.recv_start + n) % st.recv.len;
        st.recv_len -= n;
        const shared = held.value();
        shared.proto.giveBack(shared.outbox.writer(), st.id, n) catch {
            shared.failure = .{ .io = h.conn.writeError() };
        };
        h.post(io, &held);
        return n;
    }
};

/// What was encoded goes: this task writes it, with the lock released while
/// it does, unless another task is writing already, whose next round takes
/// it. Called and returns with the lock held. A write that fails fails the
/// connection.
fn post(h: *H2, io: Io, held: anytype) void {
    if (!held.value().outbox.ready()) return;
    if (!Outbox.send(io, &h.shared, held, &h.sending, ConnSink{ .conn = h.conn })) {
        const shared = held.value();
        if (shared.failure == null) shared.failure = .{ .io = h.conn.writeError() };
    }
    // Room in the outbox for the streams that wait for it.
    h.changed.broadcast(io);
}

/// The connection, as the outbox writes to it.
pub const ConnSink = struct {
    conn: *Connection,

    pub fn transmit(sink: ConnSink, bytes: []const u8) bool {
        sink.conn.writer().writeAll(bytes) catch return false;
        sink.conn.flush() catch return false;
        return true;
    }
};

/// The error a stream that cannot go on reports, or none.
fn failed(h: *H2, st: *const Stream, shared: *const Shared) Error!void {
    _ = h;
    if (st.refused) return error.Refused;
    if (st.reset_code) |code| return if (code == .refused_stream) error.Refused else error.ConnectionFailed;
    if (shared.failure) |f| return switch (f) {
        .going_away => error.Refused,
        .protocol => error.ConnectionFailed,
        .io => |err| err,
    };
}

/// Open a stream with the request's head `fields`; `end_stream` when no
/// body follows; `head` for a `HEAD`, whose response has no body.
pub fn open(h: *H2, io: Io, fields: []const hpack.Field, end_stream: bool, head: bool) Error!*Stream {
    var held = h.shared.acquire(io) catch return error.Canceled;
    defer held.deinit(io);
    const shared = held.value();
    if (shared.failure != null) return error.ConnectionFailed;
    const id = shared.proto.open() catch return error.Refused;
    const st = try h.ctx.gpa.create(Stream);
    errdefer h.ctx.gpa.destroy(st);
    st.* = .{ .h2 = h, .id = id, .sent_end = end_stream, .expects_body = !head, .interface = .{ .vtable = &.{ .stream = Stream.streamRead }, .buffer = &.{}, .seek = 0, .end = 0 } };
    try shared.streams.append(h.ctx.gpa, st);
    shared.proto.writeHeaders(shared.outbox.writer(), id, fields, end_stream, shared.scratch) catch {
        shared.failure = .{ .io = h.conn.writeError() };
        return error.ConnectionFailed;
    };
    h.post(io, &held);
    return st;
}

/// Send `bytes` of the request's body, waiting for the windows; the body
/// ends after them when `end_stream`.
pub fn send(h: *H2, io: Io, st: *Stream, bytes: []const u8, end_stream: bool, deadline: ?Io.Timestamp) Error!void {
    var held = h.shared.acquire(io) catch return error.Canceled;
    defer held.deinit(io);
    var until = h.waitUntil(io, deadline);
    var rest = bytes;
    while (true) {
        try h.failed(st, held.value());
        if (held.value().outbox.backlog() >= Outbox.high_water) {
            // Room comes as the task writing takes what waits, or as this
            // one does when no one is writing.
            h.post(io, &held);
            if (held.value().outbox.backlog() >= Outbox.high_water) try h.awaitChange(io, &held, until);
            continue;
        }
        const shared = held.value();
        const n = shared.proto.writeData(shared.outbox.writer(), st.id, rest, end_stream) catch {
            return error.ConnectionFailed;
        };
        rest = rest[n..];
        if (rest.len == 0 and (n != 0 or !end_stream or bytes.len == 0)) {
            if (end_stream) st.sent_end = true;
            h.post(io, &held);
            return;
        }
        h.post(io, &held);
        if (n == 0) {
            // The window opens when a WINDOW_UPDATE is read: by this task
            // if no one else is reading.
            try h.pump(io, &held, until);
        } else {
            until = h.waitUntil(io, deadline);
        }
    }
}

/// Wait for the response's head on `st`, reading frames for every stream
/// when this task holds the token, no longer than `deadline` or the
/// activity timeout.
pub fn awaitHead(h: *H2, io: Io, st: *Stream, deadline: ?Io.Timestamp) Error!void {
    var held = h.shared.acquire(io) catch return error.Canceled;
    defer held.deinit(io);
    const until = h.waitUntil(io, deadline);
    while (st.status == null) {
        try h.failed(st, held.value());
        try h.pump(io, &held, until);
    }
}

/// Wait until `deadline` for a word on a request that asked
/// `Expect: 100-continue`: an interim head, or the final one, which then
/// is the answer. Nothing coming in time is no error.
pub fn awaitInterim(h: *H2, io: Io, st: *Stream, deadline: Io.Timestamp) Error!void {
    var held = h.shared.acquire(io) catch return error.Canceled;
    defer held.deinit(io);
    while (st.status == null and st.interim == 0) {
        try h.failed(st, held.value());
        h.pump(io, &held, deadline) catch |err| switch (err) {
            error.TimedOut => return,
            else => |e| return e,
        };
    }
}

/// The earlier of `deadline` and the activity timeout from now.
fn waitUntil(h: *const H2, io: Io, deadline: ?Io.Timestamp) ?Io.Timestamp {
    const activity = h.ctx.timeouts.activity orelse return deadline;
    const by_activity = Io.Clock.awake.now(io).addDuration(span.toIo(activity));
    const d = deadline orelse return by_activity;
    return if (by_activity.nanoseconds < d.nanoseconds) by_activity else d;
}

/// Wait for a stream's state, the outbox or the reading token to change,
/// no longer than `deadline`. Called and returns with the lock held.
fn awaitChange(h: *H2, io: Io, held: anytype, deadline: ?Io.Timestamp) Error!void {
    const timeout: Io.Timeout = if (deadline) |d| .{ .deadline = .{ .raw = d, .clock = .awake } } else .none;
    h.changed.wait(io, held, timeout) catch |err| return switch (err) {
        error.Timeout => if (deadline != null and Io.Clock.awake.now(io).nanoseconds >= deadline.?.nanoseconds) error.TimedOut else {},
        error.Canceled => error.Canceled,
        error.WaiterLimit => error.ConnectionFailed,
    };
}

/// Take a turn: read one frame if no one is reading, else wait for whoever
/// is. Called and returns with the lock held.
fn pump(h: *H2, io: Io, held: anytype, deadline: ?Io.Timestamp) Error!void {
    if (held.value().reading) return h.awaitChange(io, held, deadline);
    held.value().reading = true;
    held.deinit(io);
    const read = h.readFrame(io, deadline);
    held.* = h.shared.acquireUncancelable(io);
    const handled = h.handleFrame(io, held.value(), read);
    // The token goes back once the frame is handled and taken off the
    // stream, so the next reader starts at the next frame; what the frame
    // asked to be written goes after.
    held.value().reading = false;
    h.changed.broadcast(io);
    h.post(io, held);
    return handled;
}

/// Hand a frame read to the protocol state and its event to the streams,
/// then take it off the reader; under the lock, with the reading token.
fn handleFrame(h: *H2, io: Io, shared: *Shared, read: Error!struct { h2.Head, []const u8 }) Error!void {
    const head, const payload = try read;
    defer h.conn.reader().toss(h2.head_len + payload.len);
    const event = shared.proto.receive(shared.outbox.writer(), head, payload) catch {
        shared.failure = .protocol;
        return error.ConnectionFailed;
    };
    // Out of memory for a stream's data: the stream cannot be given what
    // the protocol state took, so the connection ends.
    if (event) |e| h.dispatch(io, shared, e) catch {
        shared.failure = .{ .io = error.ConnectionFailed };
    };
}

/// Read one whole frame, waiting no longer than `deadline` for it to
/// start, and leave it in the reader's buffer.
fn readFrame(h: *H2, io: Io, deadline: ?Io.Timestamp) Error!struct { h2.Head, []const u8 } {
    const conn = h.conn;
    const r = conn.reader();
    // Wait for the frame to start without a read that ends the socket on
    // cancelation or time: either leaves the connection whole for the
    // other streams.
    while (r.bufferedLen() < h2.head_len) {
        const left: Io.Duration = if (deadline) |d| Io.Clock.awake.now(io).durationTo(d) else idle_wait;
        if (left.nanoseconds <= 0) return error.TimedOut;
        switch (conn.awaitReadable(io, left) catch return error.Canceled) {
            .ready, .unbounded => break,
            .timed_out => if (deadline != null) return error.TimedOut,
        }
    }
    const head_bytes = r.peek(h2.head_len) catch {
        return h.readFailed(io);
    };
    const head = h2.Head.parse(head_bytes[0..h2.head_len]);
    const whole = h2.head_len + @as(usize, head.len);
    if (whole > r.buffer.len) {
        // Past any frame this end allows: the protocol state refuses it
        // from its head.
        return .{ head, &.{} };
    }
    const bytes = r.peek(whole) catch {
        return h.readFailed(io);
    };
    return .{ head, bytes[h2.head_len..] };
}

/// A read of the connection failed: it fails for every stream, as the
/// connection names the failure; a canceled read only for the reader.
fn readFailed(h: *H2, io: Io) Error {
    const err = h.conn.readError();
    var held = h.shared.acquireUncancelable(io);
    defer held.deinit(io);
    const shared = held.value();
    if (shared.failure == null) shared.failure = .{ .io = if (err == error.Canceled) error.ConnectionFailed else err };
    return err;
}

/// What a frame's event means for the streams, under the lock.
fn dispatch(h: *H2, io: Io, shared: *Shared, event: h2.Connection.Event) Allocator.Error!void {
    switch (event) {
        .headers => |hd| {
            const st = find(shared, hd.stream) orelse return;
            const class = BufferPool.Class.fitting(h2.message.copySize(hd.fields)) orelse return h.malformed(shared, st);
            const buffer = h.ctx.buffers.acquire(io, class) catch return error.OutOfMemory;
            const kept = h2.message.copy(buffer, hd.fields) catch unreachable; // unreachable: the class fits the fields
            if (st.status == null) {
                const head = h2.message.checkResponse(kept) orelse {
                    h.ctx.buffers.release(io, buffer);
                    return h.malformed(shared, st);
                };
                // No upgrade over HTTP/2 (RFC 9113 §8.6).
                if (head.status == 101) {
                    h.ctx.buffers.release(io, buffer);
                    return h.malformed(shared, st);
                }
                if (head.status / 100 == 1) {
                    h.ctx.buffers.release(io, buffer);
                    if (hd.end_stream) return h.malformed(shared, st);
                    st.interim +|= 1;
                    return;
                }
                st.head_buffer = buffer;
                st.fields = head.fields;
                st.status = head.status;
                if (st.expects_body and head.status != 204 and head.status != 304) {
                    if (shared.proto.stream(st.id)) |s| s.content_length = head.content_length;
                }
            } else {
                if (!hd.end_stream or !h2.message.checkTrailers(kept)) {
                    h.ctx.buffers.release(io, buffer);
                    return h.malformed(shared, st);
                }
                st.trailer_buffer = buffer;
                st.trailers = kept;
            }
            if (hd.end_stream) st.recv_end = true;
        },
        .data => |d| {
            const st = find(shared, d.stream) orelse return;
            if (d.bytes.len != 0) {
                if (st.recv.len == 0) st.recv = try h.ctx.gpa.alloc(u8, stream_window.raw());
                var at = (st.recv_start + st.recv_len) % st.recv.len;
                var rest = d.bytes;
                while (rest.len != 0) {
                    const n = @min(rest.len, st.recv.len - at);
                    @memcpy(st.recv[at..][0..n], rest[0..n]);
                    rest = rest[n..];
                    at = (at + n) % st.recv.len;
                }
                st.recv_len += d.bytes.len;
            }
            if (d.end_stream) st.recv_end = true;
        },
        .reset => |rs| if (find(shared, rs.stream)) |st| {
            st.reset_code = rs.code;
        },
        .reset_sent => |rs| if (find(shared, rs.stream)) |st| {
            st.reset_code = rs.code;
        },
        .goaway => |g| {
            // Streams past the last the server processed may go again on
            // another connection.
            for (shared.streams.items) |st| if (st.id > g.last_stream) {
                st.refused = true;
            };
            if (g.code != .no_error) shared.failure = .going_away;
        },
        .window, .settings, .settings_ack, .ping_ack => {},
    }
}

/// A response the client cannot take: its stream is reset (RFC 9113
/// §8.1.1) and its exchange fails.
fn malformed(h: *H2, shared: *Shared, st: *Stream) void {
    // A reset that cannot be written: the connection has failed, which ends the stream too.
    shared.proto.reset(shared.outbox.writer(), st.id, .protocol_error) catch {
        shared.failure = .{ .io = h.conn.writeError() };
    };
    st.reset_code = .protocol_error;
}

fn find(shared: *Shared, id: u31) ?*Stream {
    for (shared.streams.items) |st| if (st.id == id) return st;
    return null;
}

/// The exchange on `st` is done: a stream still open is reset (CANCEL),
/// and its memory goes back.
pub fn finish(h: *H2, io: Io, st: *Stream) void {
    {
        var held = h.shared.acquireUncancelable(io);
        defer held.deinit(io);
        const shared = held.value();
        if (shared.failure == null and st.reset_code == null and !(st.recv_end and st.sent_end)) {
            // glint-ignore: Z026 -- a reset that cannot be written leaves a failed connection, which ends the stream too
            shared.proto.reset(shared.outbox.writer(), st.id, .cancel) catch {};
        }
        shared.proto.release(st.id);
        for (shared.streams.items, 0..) |s, i| if (s == st) {
            _ = shared.streams.swapRemove(i);
            break;
        };
        h.post(io, &held);
    }
    if (st.head_buffer.len != 0) h.ctx.buffers.release(io, st.head_buffer);
    if (st.trailer_buffer.len != 0) h.ctx.buffers.release(io, st.trailer_buffer);
    if (st.recv.len != 0) h.ctx.gpa.free(st.recv);
    h.ctx.gpa.destroy(st);
    h.changed.broadcast(io);
}
