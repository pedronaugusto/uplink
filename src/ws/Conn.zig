//! A WebSocket connection (RFC 6455) over the stream an HTTP upgrade left:
//! messages read as streams of their own, across fragments and with control
//! frames between them answered, and written whole or in pieces.
//!
//! One task reads and one writes at a time; the two may be different tasks.
//! A ping is answered with a pong and a close with a close, on the reading
//! task, the write lock shared with the writer's frames. Text is checked as
//! UTF-8 as it arrives, failing at the frame that breaks it (1007). A frame
//! or message past its limit is refused with 1009, and anything RFC 6455
//! forbids (a reserved bit or opcode, an unmasked frame from a client, a
//! masked one from a server, a long or fragmented control frame, a lone
//! continuation) with 1002. With permessage-deflate negotiated (RFC 7692),
//! messages are compressed and decompressed by warp, with or without
//! context takeover as agreed.
//!
//! No task watches the connection: with `ping_interval` set, a reader that
//! waits that long for a frame sends a ping, and closes after twice that.
//!
//! A connection must not move once it is used.

const std = @import("std");
const aegis = @import("aegis");
const warp = @import("warp");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const wire = @import("uplink.wire");
const ws = wire.ws;
const span = @import("../span.zig");
const Timed = @import("../transport/Timed.zig");
const Duration = span.Duration;

const Conn = @This();

gpa: Allocator,
role: Role,
transport: Transport,
options: Options,
/// The permessage-deflate parameters agreed, if any.
deflate: ?ws.Deflate,
/// Private: what the reading task keeps.
reading: Reading = .{},
/// Private: what writers share, under its lock.
writing: aegis.BlockingGuarded(Writing),
/// Private: a close frame was sent.
close_sent: std.atomic.Value(bool) = .init(false),
/// The close the peer sent, once it has: its code (1005 when it gave
/// none) and reason.
peer_close: ?PeerClose = null,
/// Why the connection failed, once it has: the close code sent for it.
failure: ?u16 = null,
/// The message being read, whose reader `next` handed out.
message: Message = undefined,
/// Private: the `Io` of the reading task, for the message reader, which
/// cannot take one per call.
read_io: Io = undefined,

/// Which end of the connection this is: a client masks what it sends,
/// and a server refuses what is not masked.
pub const Role = enum { client, server };

/// What a message holds.
pub const Kind = enum { text, binary };

pub const PeerClose = struct {
    code: u16,
    reason_buffer: [123]u8 = undefined,
    reason_len: u8 = 0,

    pub fn reason(p: *const PeerClose) []const u8 {
        return p.reason_buffer[0..p.reason_len];
    }
};

/// How a connection reads and limits.
pub const Options = struct {
    /// The largest message, decompressed: past it, the connection closes
    /// with 1009.
    max_message: aegis.units.Bytes(u64) = .literal("16MiB"),
    /// The largest frame on the wire.
    max_frame: aegis.units.Bytes(u64) = .literal("16MiB"),
    /// How long `close` waits for the peer's close.
    close_timeout: Duration = .literal("5s"),
    /// Ping after this much silence, and close after twice it; null never
    /// pings.
    ping_interval: ?Duration = null,
    /// The level messages are compressed at, 1-9, when compression is
    /// agreed.
    deflate_level: u4 = 6,
};

/// The stream under the connection and what it can do.
pub const Transport = struct {
    reader: *Io.Reader,
    writer: *Io.Writer,
    context: ?*anyopaque,
    /// Push what was written to the peer.
    flushFn: *const fn (context: ?*anyopaque, io: Io) Io.Writer.Error!void,
    /// Wait up to the duration for something to read, without ending the
    /// stream when nothing comes.
    readableFn: *const fn (context: ?*anyopaque, io: Io, timeout: Io.Duration) Io.Cancelable!Timed.Readiness,
};

/// Why a read failed.
pub const ReadError = error{
    /// The peer broke the protocol, or a limit; `failure` holds the close
    /// code sent.
    ProtocolError,
    /// The stream failed or ended without a close.
    ConnectionFailed,
    /// No frame came within twice `ping_interval`.
    TimedOut,
    Canceled,
    OutOfMemory,
};

/// Why a write failed.
pub const WriteError = error{
    ConnectionFailed,
    /// A close was sent: nothing more goes.
    Closed,
    /// A control frame's payload past 125 bytes.
    PayloadTooLarge,
    Canceled,
    OutOfMemory,
};

const Reading = struct {
    /// The frame being read.
    header: ws.Header = .{ .opcode = .continuation, .len = 0 },
    /// Its payload bytes still to come, and how many have.
    remaining: u64 = 0,
    offset: u64 = 0,
    /// A message is open: its frames are being read.
    open: bool = false,
    kind: Kind = .binary,
    compressed: bool = false,
    total: u64 = 0,
    utf8: ws.Utf8 = .{},
    /// How much of the sync-flush tail a compressed message's end feeds
    /// the decoder has gone through it.
    tail_fed: u8 = 0,
    /// Payload bytes at the front of the stream's buffer already unmasked.
    clear: usize = 0,
    inflate: ?*Inflater = null,
};

const Inflater = struct {
    state: warp.Inflate,
    window: [32 << 10]u8,
};

const Writing = struct {
    deflate: ?warp.Deflate = null,
    /// A message's compressed bytes, before they go.
    compressed: std.ArrayList(u8) = .empty,
    /// A client's masked copy of a frame's payload.
    scratch: std.ArrayList(u8) = .empty,
    /// A fragment's pieces gathered into one payload.
    gathered: std.ArrayList(u8) = .empty,
};

/// A connection over `transport`, as `role`, with `deflate` the
/// parameters agreed, if any.
pub fn init(gpa: Allocator, role: Role, transport: Transport, options: Options, deflate: ?ws.Deflate) Conn {
    return .{ .gpa = gpa, .role = role, .transport = transport, .options = options, .deflate = deflate, .writing = .init(.{}) };
}

/// Free what the connection holds. The stream under it is its owner's to
/// close.
pub fn deinit(c: *Conn) void {
    if (c.reading.inflate) |i| c.gpa.destroy(i);
    const w = c.writing.teardown();
    if (w.deflate) |*d| d.deinit();
    w.scratch.deinit(c.gpa);
    w.compressed.deinit(c.gpa);
    w.gathered.deinit(c.gpa);
    c.* = undefined;
}

/// A message being read: its kind, and its payload through `reader`.
pub const Message = struct {
    kind: Kind,
    conn: *Conn,
    interface: Io.Reader,

    /// The payload, decompressed and, for text, checked as UTF-8 as it
    /// comes. A read that fails says why in the connection's `failure`.
    pub fn reader(m: *Message) *Io.Reader {
        return &m.interface;
    }
};

/// The next message, answering the control frames before it; null once
/// the peer closed, its close answered. The previous message's unread
/// payload is skipped. `buffer` is the message reader's own.
pub fn next(c: *Conn, io: Io, buffer: []u8) ReadError!?*Message {
    c.read_io = io;
    if (c.reading.open) {
        var discard: [512]u8 = undefined;
        var r = &c.message.interface;
        while (true) {
            _ = r.readSliceShort(&discard) catch return c.readError();
            if (!c.reading.open) break;
        }
    }
    while (true) {
        if (c.peer_close != null) return null;
        const h = try c.readHeader(io);
        switch (h.opcode) {
            .ping, .pong, .close => {
                if (try c.control(io, h)) |_| return null;
            },
            .text, .binary => {
                c.reading.open = true;
                c.reading.kind = if (h.opcode == .text) .text else .binary;
                c.reading.compressed = h.rsv1;
                c.reading.total = 0;
                c.reading.utf8 = .{};
                c.reading.tail_fed = 0;
                c.reading.clear = 0;
                if (h.rsv1) try c.startInflate();
                c.message = .{
                    .kind = c.reading.kind,
                    .conn = c,
                    .interface = .{ .vtable = &.{ .stream = streamMessage }, .buffer = buffer, .seek = 0, .end = 0 },
                };
                return &c.message;
            },
            .continuation => return c.fail(io, ws.Close.protocol_error),
            _ => unreachable, // unreachable: `readHeader` refuses unknown opcodes
        }
    }
}

/// The next message whole, at most `limit` bytes, in `gpa`; null once the
/// peer closed.
pub fn readMessage(c: *Conn, io: Io, gpa: Allocator, limit: Io.Limit) (ReadError || error{StreamTooLong})!?struct { Kind, []u8 } {
    var buffer: [4096]u8 = undefined;
    const m = try c.next(io, &buffer) orelse return null;
    const bytes = m.reader().allocRemaining(gpa, limit) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.StreamTooLong => error.StreamTooLong,
        error.ReadFailed => c.readError(),
    };
    return .{ m.kind, bytes };
}

fn readError(c: *const Conn) ReadError {
    if (c.failure) |code| return if (code == ws.Close.abnormal) error.ConnectionFailed else error.ProtocolError;
    return error.ConnectionFailed;
}

/// Read a frame head, waiting with pings when `ping_interval` asks, and
/// check it against the protocol and the limits.
fn readHeader(c: *Conn, io: Io) ReadError!ws.Header {
    const in = c.transport.reader;
    if (in.bufferedLen() == 0) try c.waitForFrame(io);
    while (true) {
        const parsed = ws.parseHeader(in.buffered()) catch return c.fail(io, ws.Close.protocol_error);
        if (parsed) |p| {
            const h, const size = p;
            in.toss(size);
            try c.check(io, h);
            c.reading.header = h;
            c.reading.remaining = h.len;
            c.reading.offset = 0;
            c.reading.clear = 0;
            return h;
        }
        in.fillMore() catch |err| return c.lost(err);
    }
}

/// Wait for the next frame: with `ping_interval`, a ping after one interval
/// of silence and a close after the second.
fn waitForFrame(c: *Conn, io: Io) ReadError!void {
    const interval = c.options.ping_interval orelse return;
    // An `Io` that cannot wait a bounded time just reads.
    if (try c.transport.readableFn(c.transport.context, io, span.toIo(interval)) != .timed_out) return;
    c.ping(io, "") catch return error.ConnectionFailed;
    if (try c.transport.readableFn(c.transport.context, io, span.toIo(interval)) != .timed_out) return;
    c.failure = ws.Close.going_away;
    // glint-ignore: Z026 -- the peer is gone or silent; the close is a courtesy
    c.sendClose(io, ws.Close.going_away, "") catch {};
    return error.TimedOut;
}

fn lost(c: *Conn, err: Io.Reader.Error) ReadError {
    return switch (err) {
        error.EndOfStream, error.ReadFailed => {
            if (c.failure == null) c.failure = ws.Close.abnormal;
            return error.ConnectionFailed;
        },
    };
}

/// RFC 6455's rules for a frame head, and the limits.
fn check(c: *Conn, io: Io, h: ws.Header) ReadError!void {
    if (h.rsv2 or h.rsv3) return c.fail(io, ws.Close.protocol_error);
    if (!h.opcode.known()) return c.fail(io, ws.Close.protocol_error);
    const masked = h.mask != null;
    if (masked != (c.role == .server)) return c.fail(io, ws.Close.protocol_error);
    if (h.opcode.control()) {
        if (!h.fin or h.len > 125 or h.rsv1) return c.fail(io, ws.Close.protocol_error);
        return;
    }
    if (h.rsv1 and (c.deflate == null or h.opcode == .continuation)) return c.fail(io, ws.Close.protocol_error);
    if (aegis.units.Bytes(u64).fromRaw(h.len).compare(c.options.max_frame) == .gt) return c.fail(io, ws.Close.too_big);
}

/// A control frame: a ping answered, a pong taken, a close answered. The
/// close's code, when the frame was one.
fn control(c: *Conn, io: Io, h: ws.Header) ReadError!?u16 {
    var payload: [125]u8 = undefined;
    const n: usize = @intCast(h.len); // safe: a control frame is at most 125 bytes, checked
    try c.readPayload(payload[0..n]);
    switch (h.opcode) {
        .ping => {
            c.pong(io, payload[0..n]) catch |err| switch (err) {
                // A close already went: the pong is moot.
                error.Closed => {},
                else => return error.ConnectionFailed,
            };
            return null;
        },
        .pong => return null,
        .close => {
            var peer: PeerClose = .{ .code = ws.Close.no_status };
            if (n == 1) return c.fail(io, ws.Close.protocol_error);
            if (n >= 2) {
                peer.code = std.mem.readInt(u16, payload[0..2], .big);
                if (!ws.Close.sendable(peer.code)) return c.fail(io, ws.Close.protocol_error);
                const reason = payload[2..n];
                if (!std.unicode.utf8ValidateSlice(reason)) return c.fail(io, ws.Close.invalid_payload);
                @memcpy(peer.reason_buffer[0..reason.len], reason);
                peer.reason_len = @intCast(reason.len);
            }
            c.peer_close = peer;
            // Answer with the same code, unless one went already.
            const answer = if (peer.code == ws.Close.no_status) ws.Close.normal else peer.code;
            c.sendClose(io, answer, "") catch |err| switch (err) {
                error.Closed => {},
                else => return error.ConnectionFailed,
            };
            return peer.code;
        },
        else => unreachable, // unreachable: called for control frames
    }
}

/// Read the current frame's whole payload into `out`, unmasked.
fn readPayload(c: *Conn, out: []u8) ReadError!void {
    std.debug.assert(out.len == c.reading.remaining);
    c.transport.reader.readSliceAll(out) catch |err| return c.lost(switch (err) {
        error.EndOfStream => error.EndOfStream,
        error.ReadFailed => error.ReadFailed,
    });
    if (c.reading.header.mask) |key| ws.mask(key, c.reading.offset, out);
    c.reading.offset += out.len;
    c.reading.remaining = 0;
}

/// Fail the connection: send a close with `code` and report the error.
fn fail(c: *Conn, io: Io, code: u16) ReadError {
    if (c.failure == null) c.failure = code;
    c.reading.open = false;
    // glint-ignore: Z026 -- the connection has failed; the close tells the peer why if it can still hear
    c.sendClose(io, code, "") catch {};
    return error.ProtocolError;
}

fn startInflate(c: *Conn) ReadError!void {
    const params = c.deflate.?;
    // What the peer compresses with: its window, and whether it keeps it.
    const bits: u4 = (if (c.role == .server) params.client_max_window_bits else params.server_max_window_bits) orelse 15;
    const fresh = if (c.role == .server) params.client_no_context_takeover else params.server_no_context_takeover;
    if (c.reading.inflate) |i| {
        if (fresh) i.state.reset(.nothing);
        return;
    }
    const i = try c.gpa.create(Inflater);
    // The window kept is 32 KiB whatever the peer's, which reaches no
    // farther than it says; a decoder needs at least the peer's.
    _ = bits;
    i.state = .init(&i.window, .{ .accept = .raw, .window_bits = 15 });
    c.reading.inflate = i;
}

/// The message reader: frame payloads, the next frames fetched as they
/// end, control frames between them answered.
fn streamMessage(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
    const m: *Message = @alignCast(@fieldParentPtr("interface", r)); // safe: this vtable is installed only on a Message's interface
    const c = m.conn;
    return c.streamPayload(w, limit) catch |err| switch (err) {
        error.WriteFailed => error.WriteFailed,
        error.EndOfStream => error.EndOfStream,
        else => error.ReadFailed,
    };
}

const StreamError = ReadError || error{ WriteFailed, EndOfStream };

fn streamPayload(c: *Conn, w: *Io.Writer, limit: Io.Limit) StreamError!usize {
    const io = c.read_io;
    const rd = &c.reading;
    if (!rd.open) return error.EndOfStream;
    if (limit == .nothing) return 0;
    const in = c.transport.reader;
    while (true) {
        if (rd.remaining == 0) {
            if (rd.header.fin) {
                if (rd.compressed and rd.tail_fed < 4) {
                    const n = try c.inflateInto(w, limit, sync_tail[rd.tail_fed..], .tail);
                    if (n != 0) return n;
                    continue;
                }
                if (rd.kind == .text and !rd.utf8.feed(&.{}, true)) return c.fail(io, ws.Close.invalid_payload);
                rd.open = false;
                return error.EndOfStream;
            }
            const h = try c.readHeader(io);
            switch (h.opcode) {
                .continuation => continue,
                .ping, .pong, .close => {
                    if (try c.control(io, h)) |_| {
                        // A close inside a message: the message is cut.
                        rd.open = false;
                        return error.ConnectionFailed;
                    }
                    // A control frame between fragments: the message's
                    // frame was the one before it, which did not end it.
                    rd.header.fin = false;
                    rd.remaining = 0;
                    continue;
                },
                else => return c.fail(io, ws.Close.protocol_error),
            }
        }
        if (in.bufferedLen() == 0) in.fillMore() catch |err| return c.lost(err);
        const avail = in.buffered();
        const take: usize = @intCast(@min(avail.len, rd.remaining));
        // Unmask what has not been, in place.
        if (rd.header.mask) |key| if (rd.clear < take) {
            ws.mask(key, rd.offset + rd.clear, avail[rd.clear..take]);
            rd.clear = take;
        };
        const payload = avail[0..take];
        if (rd.compressed) {
            const n = try c.inflateInto(w, limit, payload, .payload);
            if (n != 0) return n;
            continue;
        }
        const n = @min(payload.len, limit.toInt() orelse payload.len);
        try c.deliver(io, payload[0..n]);
        w.writeAll(payload[0..n]) catch return error.WriteFailed;
        c.consume(n);
        return n;
    }
}

/// The tail a compressed message's sender strips (RFC 7692 §7.2.1), fed
/// back to the decoder at the message's end.
const sync_tail = [4]u8{ 0x00, 0x00, 0xff, 0xff };

/// `n` bytes of the current frame's payload taken from the stream.
fn consume(c: *Conn, n: usize) void {
    const rd = &c.reading;
    c.transport.reader.toss(n);
    rd.remaining -= n;
    rd.offset += n;
    rd.clear -|= n;
}

/// Count and check bytes of the message as the caller gets them.
fn deliver(c: *Conn, io: Io, bytes: []const u8) ReadError!void {
    const rd = &c.reading;
    rd.total += bytes.len;
    if (aegis.units.Bytes(u64).fromRaw(rd.total).compare(c.options.max_message) == .gt) return c.fail(io, ws.Close.too_big);
    if (rd.kind == .text and !rd.utf8.feed(bytes, false)) return c.fail(io, ws.Close.invalid_payload);
}

/// Decompress `input`, payload bytes or the sync tail, into `w`; the bytes
/// written, which may be none when the decoder took input only.
fn inflateInto(c: *Conn, w: *Io.Writer, limit: Io.Limit, input: []const u8, what: enum { payload, tail }) StreamError!usize {
    const io = c.read_io;
    const rd = &c.reading;
    const dest = limit.slice(w.writableSliceGreedy(1) catch return error.WriteFailed);
    const step = rd.inflate.?.state.decode(input, dest) catch return c.fail(io, ws.Close.invalid_payload);
    switch (what) {
        .payload => c.consume(step.in_len),
        .tail => {
            rd.tail_fed += @intCast(step.in_len);
            // The tail ends the message's stream at a block's end.
            if (rd.tail_fed == 4 and step.out_len == 0 and step.status != .output_full) rd.tail_fed = 4;
        },
    }
    if (step.out_len != 0) {
        try c.deliver(io, dest[0..step.out_len]);
        w.advance(step.out_len);
    } else if (step.in_len == 0 and what == .payload and step.status == .done) {
        // A peer that ended the stream with a final block: nothing more
        // decodes, and more payload is an error.
        return c.fail(io, ws.Close.invalid_payload);
    }
    return step.out_len;
}

/// Send a message whole, compressed when compression was agreed.
pub fn send(c: *Conn, io: Io, kind: Kind, payload: []const u8) WriteError!void {
    var held = c.writing.acquire(io) catch return error.Canceled;
    defer held.deinit(io);
    const w = held.value();
    if (c.close_sent.load(.acquire)) return error.Closed;
    const opcode: ws.Opcode = if (kind == .text) .text else .binary;
    if (c.deflate != null) {
        const coded = try c.compress(w, payload, true);
        try c.frame(io, w, .{ .opcode = opcode, .rsv1 = true, .len = coded.len }, coded);
    } else {
        try c.frame(io, w, .{ .opcode = opcode, .len = payload.len }, payload);
    }
    c.transport.flushFn(c.transport.context, io) catch return error.ConnectionFailed;
}

/// `input` compressed onto the message's stream into `w.compressed`; at
/// the message's end, flushed and its sync tail stripped.
fn compress(c: *Conn, w: *Writing, input: []const u8, end: bool) WriteError![]const u8 {
    const params = c.deflate.?;
    if (w.deflate == null) {
        const bits: u4 = (if (c.role == .server) params.server_max_window_bits else params.client_max_window_bits) orelse 15;
        w.deflate = try warp.Deflate.init(c.gpa, .{ .level = c.options.deflate_level, .max_level = c.options.deflate_level, .container = .raw, .window_bits = @max(bits, 9) });
    }
    const d = &w.deflate.?;
    w.compressed.clearRetainingCapacity();
    var at: usize = 0;
    while (at < input.len) {
        try w.compressed.ensureUnusedCapacity(c.gpa, 4096);
        const out = w.compressed.unusedCapacitySlice();
        const step = d.write(input[at..], out);
        w.compressed.items.len += step.out_len;
        at += step.in_len;
    }
    if (end) {
        while (true) {
            try w.compressed.ensureUnusedCapacity(c.gpa, 4096);
            const drained = d.flush(.sync, w.compressed.unusedCapacitySlice());
            w.compressed.items.len += drained.out_len;
            if (drained.done) break;
        }
        std.debug.assert(std.mem.endsWith(u8, w.compressed.items, &sync_tail));
        w.compressed.items.len -= 4;
        // An empty message compresses to one empty stored block's byte.
        if (w.compressed.items.len == 0) try w.compressed.append(c.gpa, 0x00);
        const fresh = if (c.role == .server) params.server_no_context_takeover else params.client_no_context_takeover;
        if (fresh) d.reset(.nothing);
    }
    return w.compressed.items;
}

/// A message written in pieces: each drain of its buffer is a frame, and
/// `end` sends the last. Control frames may go between its frames.
pub const MessageWriter = struct {
    conn: *Conn,
    io: Io,
    opcode: ws.Opcode,
    interface: Io.Writer,

    /// Send what is buffered as the message's last frame.
    pub fn end(mw: *MessageWriter) WriteError!void {
        try mw.conn.fragment(mw.io, mw, &.{mw.interface.buffered()}, 1, true);
        mw.interface.end = 0;
    }

    fn drain(io_w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const mw: *MessageWriter = @alignCast(@fieldParentPtr("interface", io_w)); // safe: this vtable is installed only on a MessageWriter's interface
        // The buffer's bytes and the data go as one frame.
        var parts: [9][]const u8 = undefined;
        parts[0] = io_w.buffered();
        const n = @min(data.len, parts.len - 1);
        @memcpy(parts[1..][0..n], data[0..n]);
        const last_splat = if (n == data.len) splat else 1;
        mw.conn.fragment(mw.io, mw, parts[0 .. n + 1], last_splat, false) catch return error.WriteFailed;
        var consumed: usize = 0;
        for (data[0..n], 0..) |d, i| consumed += if (i == n - 1) d.len * last_splat else d.len;
        io_w.end = 0;
        return consumed;
    }
};

/// A writer for one message of `kind`, buffered through `buffer`.
pub fn writer(c: *Conn, io: Io, kind: Kind, buffer: []u8) MessageWriter {
    return .{ .conn = c, .io = io, .opcode = if (kind == .text) .text else .binary, .interface = .{ .vtable = &.{ .drain = MessageWriter.drain }, .buffer = buffer } };
}

/// One frame of a message written in pieces: `parts`, the last repeated
/// `splat` times.
fn fragment(c: *Conn, io: Io, mw: *MessageWriter, parts: []const []const u8, splat: usize, last: bool) WriteError!void {
    var held = c.writing.acquire(io) catch return error.Canceled;
    defer held.deinit(io);
    const w = held.value();
    if (c.close_sent.load(.acquire)) return error.Closed;
    const first = mw.opcode != .continuation;
    // The frame's payload in one piece: compressed, or gathered.
    w.gathered.clearRetainingCapacity();
    for (parts, 0..) |part, i| {
        const times = if (i == parts.len - 1) splat else 1;
        for (0..times) |_| try w.gathered.appendSlice(c.gpa, part);
    }
    if (c.deflate != null) {
        const coded = try c.compress(w, w.gathered.items, last);
        try c.frame(io, w, .{ .fin = last, .rsv1 = first, .opcode = mw.opcode, .len = coded.len }, coded);
    } else {
        try c.frame(io, w, .{ .fin = last, .opcode = mw.opcode, .len = w.gathered.items.len }, w.gathered.items);
    }
    mw.opcode = .continuation;
    if (last) c.transport.flushFn(c.transport.context, io) catch return error.ConnectionFailed;
}

/// Close: send a close with `code` and `reason`, then wait up to
/// `close_timeout` for the peer's, skipping what comes before it. Call it
/// while no other task reads.
pub fn close(c: *Conn, io: Io, code: u16, reason: []const u8) void {
    c.sendClose(io, code, reason) catch |err| switch (err) {
        error.Closed => {},
        // The stream is gone: there is nothing to wait for.
        else => return,
    };
    const until = Io.Clock.awake.now(io).addDuration(span.toIo(c.options.close_timeout));
    var buffer: [512]u8 = undefined;
    while (c.peer_close == null and c.failure == null) {
        const left = Io.Clock.awake.now(io).durationTo(until);
        if (left.nanoseconds <= 0) return;
        const ready = c.transport.readableFn(c.transport.context, io, left) catch return;
        if (ready == .timed_out) return;
        _ = c.next(io, &buffer) catch return;
    }
}

/// Send a ping.
pub fn ping(c: *Conn, io: Io, payload: []const u8) WriteError!void {
    return c.sendControl(io, .ping, payload);
}

/// Send a pong.
pub fn pong(c: *Conn, io: Io, payload: []const u8) WriteError!void {
    return c.sendControl(io, .pong, payload);
}

fn sendControl(c: *Conn, io: Io, opcode: ws.Opcode, payload: []const u8) WriteError!void {
    if (payload.len > 125) return error.PayloadTooLarge;
    var held = c.writing.acquire(io) catch return error.Canceled;
    defer held.deinit(io);
    if (c.close_sent.load(.acquire)) return error.Closed;
    try c.frame(io, held.value(), .{ .opcode = opcode, .len = payload.len }, payload);
    c.transport.flushFn(c.transport.context, io) catch return error.ConnectionFailed;
}

fn sendClose(c: *Conn, io: Io, code: u16, reason: []const u8) WriteError!void {
    var payload: [125]u8 = undefined;
    std.mem.writeInt(u16, payload[0..2], code, .big);
    const n = @min(reason.len, 123);
    @memcpy(payload[2..][0..n], reason[0..n]);
    var held = c.writing.acquire(io) catch return error.Canceled;
    defer held.deinit(io);
    if (c.close_sent.swap(true, .acq_rel)) return error.Closed;
    try c.frame(io, held.value(), .{ .opcode = .close, .len = 2 + n }, payload[0 .. 2 + n]);
    c.transport.flushFn(c.transport.context, io) catch return error.ConnectionFailed;
}

/// Write one frame, masked when this end is a client.
fn frame(c: *Conn, io: Io, w: *Writing, head: ws.Header, payload: []const u8) WriteError!void {
    var h = head;
    const out = c.transport.writer;
    if (c.role == .client) {
        var key: [4]u8 = undefined;
        io.random(&key);
        h.mask = key;
    }
    var head_buf: [ws.Header.max_len]u8 = undefined;
    out.writeAll(ws.writeHeader(&head_buf, h)) catch return error.ConnectionFailed;
    if (h.mask) |key| {
        // The caller's bytes stay as they were: a masked copy goes.
        w.scratch.clearRetainingCapacity();
        try w.scratch.appendSlice(c.gpa, payload);
        ws.mask(key, 0, w.scratch.items);
        out.writeAll(w.scratch.items) catch return error.ConnectionFailed;
    } else {
        out.writeAll(payload) catch return error.ConnectionFailed;
    }
}
