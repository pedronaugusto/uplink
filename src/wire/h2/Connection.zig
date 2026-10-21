//! One HTTP/2 connection's protocol state, sans I/O (RFC 9113): the
//! settings both ways, the streams and their states, flow control both
//! ways, the HPACK tables, header blocks across CONTINUATION frames, and
//! the limits that keep a peer from spending this end's memory and time.
//!
//! The driver reads whole frames and hands each to `receive`, which
//! answers what the protocol answers by itself (a SETTINGS or PING
//! acknowledgement, a WINDOW_UPDATE, a RST_STREAM or GOAWAY for an error)
//! onto the writer it is given, and returns what the application must
//! know: a header block, data, a reset, a GOAWAY, a window that opened.
//! The driver writes its own frames through `writeHeaders`, `writeData`,
//! `reset` and `goaway`, which keep the state and the windows.
//!
//! A peer that breaks the protocol gets a GOAWAY with the error's code and
//! `receive` fails with `error.ConnectionError`; one that breaks a stream
//! gets that stream reset and an event saying so. The limits (RFC 9113
//! §10.5 and the attacks since): the streams open at once, a header block's
//! bytes across its CONTINUATION frames (VU#421644), the decoded header
//! list (the HPACK bomb), resets per window (Rapid Reset, CVE-2023-44487),
//! and SETTINGS, PING and empty frames per window.
//!
//! All memory is the caller's, given at `init`.

const std = @import("std");
const aegis = @import("aegis");
const Io = std.Io;
const h2 = @import("frame.zig");
const hpack = @import("../hpack.zig");
const Head = h2.Head;
const Flags = h2.Flags;
const ErrorCode = h2.ErrorCode;

const Connection = @This();

pub const Role = enum { client, server };

role: Role,
/// The settings this end sent, and which the peer has acknowledged.
local: h2.Settings,
/// The settings this end sent and the peer has not acknowledged yet.
local_pending: ?h2.Settings = null,
remote: h2.Settings = .{},
limits: Limits,
decoder: hpack.Decoder,
encoder: hpack.Encoder,
/// Private: the streams this end knows of.
streams: []Stream,
/// Private: a header block gathered across CONTINUATION frames.
block: []u8,
block_len: usize = 0,
/// Private: the stream whose header block is being gathered.
continuing: ?u31 = null,
continuing_end_stream: bool = false,
/// Private: where decoded fields go, valid until the next `receive`.
field_bytes: []u8,
fields: []hpack.Field,
/// Flow control of the connection as a whole.
send_window: i64 = 65535,
recv_window: i64 = 65535,
/// Bytes received and handed over that no WINDOW_UPDATE has given back.
recv_unacked: u64 = 0,
/// The highest stream the peer opened, and the next this end opens.
last_peer_stream: u31 = 0,
next_stream: u31,
/// After a GOAWAY: the last stream the peer will process, and the last
/// this end will.
goaway_received: ?u31 = null,
goaway_sent: ?u31 = null,
/// The server has seen the client's preface (always true for a client).
preface_seen: bool,
/// Private: the counts of the abuse limits, per window of `limits.window`
/// frames.
frames: u32 = 0,
resets: u32 = 0,
settings_seen: u32 = 0,
pings: u32 = 0,
empty: u32 = 0,
/// The code a `ConnectionError` sent.
closed_with: ErrorCode = .no_error,

/// What a peer may spend.
pub const Limits = struct {
    /// Streams the peer may have open at once; one more is refused.
    max_concurrent_streams: u32 = 100,
    /// A header block's bytes, across its frames.
    max_header_block: Bytes = .literal("64KiB"),
    /// The decoded header list's bytes (RFC 9113's SETTINGS_MAX_HEADER_LIST_SIZE).
    max_header_list: Bytes = .literal("64KiB"),
    /// The frames over which the counts below are kept.
    window: u32 = 1000,
    /// Streams the peer may reset per window.
    max_resets: u32 = 200,
    /// SETTINGS and PING frames per window.
    max_settings: u32 = 100,
    max_pings: u32 = 100,
    /// Frames that carry nothing (empty DATA without END_STREAM, empty
    /// CONTINUATION) per window.
    max_empty: u32 = 100,
    /// The connection's receive window, raised to at `start`, at most
    /// 2^31-1 bytes (RFC 9113 §6.9.1); a stream's is the local SETTINGS'
    /// `initial_window_size`.
    connection_window: Bytes = .literal("16MiB"),

    pub const Bytes = aegis.units.Bytes(u32);
    /// The largest flow-control window.
    pub const max_window: Bytes = .fromRaw(std.math.maxInt(u31));
};

/// A stream's states (RFC 9113 §5.1; no push, so no reserved ones).
pub const StreamState = enum { idle, open, half_closed_local, half_closed_remote, closed };
/// What moves a stream: its head going either way, its end sent or
/// received, a reset either way.
pub const StreamEvent = enum { opened, end_local, end_remote, reset };
/// The edges a stream's state takes, checked whole when analyzed: a stream
/// receives where its end can still come, and sends where its own can.
pub const Lifecycle = aegis.state.Machine(StreamState, StreamEvent, .{
    .initial = .idle,
    .terminal = &.{.closed},
    .edges = &.{
        .{ .from = .idle, .on = .opened, .to = .open },
        .{ .from = .open, .on = .end_local, .to = .half_closed_local },
        .{ .from = .open, .on = .end_remote, .to = .half_closed_remote },
        .{ .from = .open, .on = .reset, .to = .closed },
        .{ .from = .half_closed_local, .on = .end_remote, .to = .closed },
        .{ .from = .half_closed_local, .on = .reset, .to = .closed },
        .{ .from = .half_closed_remote, .on = .end_local, .to = .closed },
        .{ .from = .half_closed_remote, .on = .reset, .to = .closed },
    },
});

/// Whether a stream in `state` may still receive frames of its own.
fn receives(state: StreamState) bool {
    return Lifecycle.next(state, .end_remote) != null;
}

/// Whether a stream in `state` may still send.
fn sends(state: StreamState) bool {
    return Lifecycle.next(state, .end_local) != null;
}

/// Move `s` along `event`'s edge, which its caller found there.
fn move(s: *Stream, event: StreamEvent) void {
    s.state = Lifecycle.next(s.state, event) orelse aegis.assert.never("a stream moves only along an edge its state has");
}

pub const Stream = struct {
    id: u31 = 0,
    state: StreamState = .idle,
    send_window: i64 = 0,
    recv_window: i64 = 0,
    /// Received bytes handed over and not yet given back.
    recv_unacked: u64 = 0,
    /// The request's or response's head has been received.
    headers_received: bool = false,
    /// A `content-length` the peer declared, and the data counted against it.
    content_length: ?u64 = null,
    data_received: u64 = 0,
    /// The driver's own, for what it keeps per stream.
    user: usize = 0,
};

/// What `receive` tells the driver.
pub const Event = union(enum) {
    /// A header block: a request or response head, an interim one, or
    /// trailers. The fields are valid until the next `receive`.
    headers: struct { stream: u31, fields: []const hpack.Field, end_stream: bool },
    /// Data for a stream; the bytes are the frame's, valid while it is.
    data: struct { stream: u31, bytes: []const u8, end_stream: bool },
    /// The peer reset a stream.
    reset: struct { stream: u31, code: ErrorCode },
    /// This end reset a stream for the peer's error.
    reset_sent: struct { stream: u31, code: ErrorCode },
    /// The peer is going away.
    goaway: struct { last_stream: u31, code: ErrorCode },
    /// A send window opened: a stream's, or the connection's (0).
    window: u31,
    /// The peer's settings changed.
    settings,
    /// The peer acknowledged a ping.
    ping_ack: [8]u8,
    /// The peer acknowledged this end's settings.
    settings_ack,
};

/// Why `receive` failed.
pub const Error = error{
    /// The peer broke the connection: a GOAWAY went with the code in
    /// `closed_with`. Close it once the writer is flushed.
    ConnectionError,
    /// The writer failed.
    WriteFailed,
};

/// The memory a connection takes: streams, header block, decoded fields,
/// and both HPACK tables.
pub const Memory = struct {
    streams: []Stream,
    block: []u8,
    field_bytes: []u8,
    fields: []hpack.Field,
    decoder_bytes: []u8,
    decoder_entries: []hpack.Table.Entry,
    encoder_bytes: []u8,
    encoder_entries: []hpack.Table.Entry,
};

/// A connection as `role`, advertising `local` (whose header table size
/// sizes the decoder's table), within `limits`.
pub fn init(role: Role, local: h2.Settings, limits: Limits, memory: Memory) Connection {
    aegis.assert.pre(limits.connection_window.compare(Limits.max_window) != .gt, "a window is at most 2^31-1 bytes");
    return .{
        .role = role,
        .local = .{},
        .local_pending = local,
        .limits = limits,
        .decoder = .init(.init(memory.decoder_bytes, memory.decoder_entries, local.header_table_size)),
        .encoder = .init(.init(memory.encoder_bytes, memory.encoder_entries, 4096)),
        .streams = memory.streams,
        .block = memory.block,
        .field_bytes = memory.field_bytes,
        .fields = memory.fields,
        .next_stream = if (role == .client) 1 else 2,
        .preface_seen = role == .client,
    };
}

/// Start the connection: a client's preface, then this end's SETTINGS and
/// the connection window raised to the limit.
pub fn start(c: *Connection, w: *Io.Writer) Io.Writer.Error!void {
    if (c.role == .client) try w.writeAll(h2.preface);
    var buf: [64]u8 = undefined;
    var sw: Io.Writer = .fixed(&buf);
    c.local_pending.?.write(&sw) catch unreachable; // unreachable: the settings are under 64 bytes
    try h2.writeFrame(w, .{ .len = @intCast(sw.end), .type = .settings, .flags = 0, .stream = 0 }, &.{sw.buffered()});
    const raise = @as(i64, c.limits.connection_window.raw()) - c.recv_window;
    if (raise > 0) {
        try windowUpdate(w, 0, @intCast(raise));
        c.recv_window += raise;
    }
}

/// A client's connection that an HTTP/1.1 request upgraded (`Upgrade: h2c`,
/// RFC 7540 §3.2): stream 1 is that request, ended on this side, whose
/// response comes on it; the next stream is 3.
pub fn upgradeClient(c: *Connection) void {
    aegis.assert.pre(c.role == .client and c.next_stream == 1, "a client's connection upgrades before any stream");
    c.next_stream = 3;
    c.openUpgraded(.end_local);
}

/// A server's connection that answered an HTTP/1.1 request's upgrade:
/// `client_settings` are the settings the request's `HTTP2-Settings`
/// carried, taken as the client's as if a SETTINGS frame had brought them,
/// and stream 1 is the request, ended on the client's side.
pub fn upgradeServer(c: *Connection, client_settings: []const u8) h2.Settings.Error!void {
    aegis.assert.pre(c.role == .server and c.last_peer_stream == 0, "a server's connection upgrades before any stream");
    try c.remote.apply(client_settings, false);
    c.last_peer_stream = 1;
    c.openUpgraded(.end_remote);
    c.stream(1).?.headers_received = true;
}

fn openUpgraded(c: *Connection, end: StreamEvent) void {
    const s = c.freeSlot() orelse aegis.assert.never("a new connection has a free stream slot");
    s.* = .{ .id = 1, .state = .idle, .send_window = c.remote.initial_window_size, .recv_window = c.localSettings().initial_window_size };
    move(s, .opened);
    move(s, end);
}

/// The server's check of the client's preface, the first bytes of the
/// connection.
pub fn checkPreface(c: *Connection, bytes: []const u8) bool {
    c.preface_seen = std.mem.eql(u8, bytes, h2.preface);
    return c.preface_seen;
}

fn windowUpdate(w: *Io.Writer, id: u31, increment: u31) Io.Writer.Error!void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, increment, .big);
    try h2.writeFrame(w, .{ .len = 4, .type = .window_update, .flags = 0, .stream = id }, &.{&b});
}

/// The stream `id`, or null when this end keeps no state for it.
pub fn stream(c: *Connection, id: u31) ?*Stream {
    for (c.streams) |*s| if (s.id == id and s.state != .idle) return s;
    return null;
}

/// How many streams are open (not idle, not closed) on `side`'s count.
fn openCount(c: *const Connection, peer: bool) u32 {
    var n: u32 = 0;
    for (c.streams) |s| {
        if (s.state == .idle or s.state == .closed) continue;
        const ours = (s.id % 2 == 1) == (c.role == .client);
        if (ours != peer) n += 1;
    }
    return n;
}

fn freeSlot(c: *Connection) ?*Stream {
    for (c.streams) |*s| if (s.state == .idle or s.state == .closed) return s;
    return null;
}

/// Whether `id` is one the peer opens.
fn peers(c: *const Connection, id: u31) bool {
    return (id % 2 == 1) == (c.role == .server);
}

/// End the connection for the peer's error: GOAWAY with `code`.
fn connectionError(c: *Connection, w: *Io.Writer, code: ErrorCode) Error {
    c.closed_with = code;
    c.goawayWrite(w, code, "") catch return error.WriteFailed;
    return error.ConnectionError;
}

/// Reset stream `id` for the peer's error with `code`, as an event.
fn streamError(c: *Connection, w: *Io.Writer, id: u31, code: ErrorCode) Error!?Event {
    try c.rstWrite(w, id, code);
    if (c.stream(id)) |s| if (s.state != .closed) move(s, .reset);
    return .{ .reset_sent = .{ .stream = id, .code = code } };
}

fn rstWrite(c: *Connection, w: *Io.Writer, id: u31, code: ErrorCode) Error!void {
    _ = c;
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, @backingInt(code), .big);
    h2.writeFrame(w, .{ .len = 4, .type = .rst_stream, .flags = 0, .stream = id }, &.{&b}) catch return error.WriteFailed;
}

fn goawayWrite(c: *Connection, w: *Io.Writer, code: ErrorCode, debug: []const u8) Io.Writer.Error!void {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u32, b[0..4], c.last_peer_stream, .big);
    std.mem.writeInt(u32, b[4..8], @backingInt(code), .big);
    try h2.writeFrame(w, .{ .len = @intCast(8 + debug.len), .type = .goaway, .flags = 0, .stream = 0 }, &.{ &b, debug });
    c.goaway_sent = c.last_peer_stream;
}

/// Count a frame against the abuse limits' window.
fn tick(c: *Connection) void {
    c.frames += 1;
    if (c.frames < c.limits.window) return;
    c.frames = 0;
    c.resets = 0;
    c.settings_seen = 0;
    c.pings = 0;
    c.empty = 0;
}

/// Handle one whole frame from the peer. Answers the protocol owes go to
/// `w`; what the driver must know comes back.
pub fn receive(c: *Connection, w: *Io.Writer, h: Head, payload: []const u8) Error!?Event {
    c.tick();
    if (h.len > c.local.max_frame_size and (c.local_pending == null or h.len > c.local_pending.?.max_frame_size)) return c.connectionError(w, .frame_size_error);
    // A header block is gathered whole: nothing may come between its frames.
    if (c.continuing) |id| {
        if (h.type != .continuation or h.stream != id) return c.connectionError(w, .protocol_error);
        return c.continuation(w, h, payload);
    }
    return switch (h.type) {
        .data => c.data(w, h, payload),
        .headers => c.headers(w, h, payload),
        .priority => c.priority(w, h, payload),
        .rst_stream => c.rstStream(w, h, payload),
        .settings => c.settings(w, h, payload),
        .push_promise => c.connectionError(w, .protocol_error),
        .ping => c.ping(w, h, payload),
        .goaway => c.goawayFrame(w, h, payload),
        .window_update => c.windowUpdateFrame(w, h, payload),
        .continuation => c.connectionError(w, .protocol_error),
        .priority_update => if (h.stream != 0) c.connectionError(w, .protocol_error) else null,
        // An unknown frame type is ignored (RFC 9113 §4.1).
        _ => null,
    };
}

fn settings(c: *Connection, w: *Io.Writer, h: Head, payload: []const u8) Error!?Event {
    if (h.stream != 0) return c.connectionError(w, .protocol_error);
    if (h.has(Flags.ack)) {
        if (payload.len != 0) return c.connectionError(w, .frame_size_error);
        if (c.local_pending) |pending| {
            c.local = pending;
            c.local_pending = null;
        }
        return .settings_ack;
    }
    c.settings_seen += 1;
    if (c.settings_seen > c.limits.max_settings) return c.connectionError(w, .enhance_your_calm);
    const old_window = c.remote.initial_window_size;
    c.remote.apply(payload, c.role == .client) catch |err| return c.connectionError(w, switch (err) {
        error.ProtocolError => .protocol_error,
        error.FlowControlError => .flow_control_error,
        error.FrameSizeError => .frame_size_error,
    });
    // A changed initial window moves every stream's send window by the
    // difference (RFC 9113 §6.9.2).
    const delta = @as(i64, c.remote.initial_window_size) - old_window;
    if (delta != 0) for (c.streams) |*s| {
        if (s.state == .idle or s.state == .closed) continue;
        s.send_window += delta;
        if (s.send_window > std.math.maxInt(u31)) return c.connectionError(w, .flow_control_error);
    };
    c.encoder.setLimit(c.remote.header_table_size);
    h2.writeFrame(w, .{ .len = 0, .type = .settings, .flags = Flags.ack, .stream = 0 }, &.{}) catch return error.WriteFailed;
    return .settings;
}

fn ping(c: *Connection, w: *Io.Writer, h: Head, payload: []const u8) Error!?Event {
    if (h.stream != 0) return c.connectionError(w, .protocol_error);
    if (payload.len != 8) return c.connectionError(w, .frame_size_error);
    if (h.has(Flags.ack)) return .{ .ping_ack = payload[0..8].* };
    c.pings += 1;
    if (c.pings > c.limits.max_pings) return c.connectionError(w, .enhance_your_calm);
    h2.writeFrame(w, .{ .len = 8, .type = .ping, .flags = Flags.ack, .stream = 0 }, &.{payload}) catch return error.WriteFailed;
    return null;
}

fn goawayFrame(c: *Connection, w: *Io.Writer, h: Head, payload: []const u8) Error!?Event {
    if (h.stream != 0) return c.connectionError(w, .protocol_error);
    const g = h2.Goaway.parse(payload) catch return c.connectionError(w, .frame_size_error);
    c.goaway_received = g.last_stream;
    return .{ .goaway = .{ .last_stream = g.last_stream, .code = g.code } };
}

fn windowUpdateFrame(c: *Connection, w: *Io.Writer, h: Head, payload: []const u8) Error!?Event {
    const inc = h2.windowIncrement(payload) catch return c.connectionError(w, .frame_size_error);
    if (h.stream == 0) {
        if (inc == 0) return c.connectionError(w, .protocol_error);
        c.send_window += inc;
        if (c.send_window > std.math.maxInt(u31)) return c.connectionError(w, .flow_control_error);
        return .{ .window = 0 };
    }
    if (c.idle(h.stream)) return c.connectionError(w, .protocol_error);
    const s = c.stream(h.stream) orelse return null;
    if (inc == 0) return c.streamError(w, h.stream, .protocol_error);
    if (s.state == .closed) return null;
    s.send_window += inc;
    if (s.send_window > std.math.maxInt(u31)) return c.streamError(w, h.stream, .flow_control_error);
    return .{ .window = h.stream };
}

/// Whether `id` is a stream no one has opened yet.
fn idle(c: *const Connection, id: u31) bool {
    if (c.peers(id)) return id > c.last_peer_stream;
    return id >= c.next_stream;
}

fn rstStream(c: *Connection, w: *Io.Writer, h: Head, payload: []const u8) Error!?Event {
    if (h.stream == 0) return c.connectionError(w, .protocol_error);
    const code = h2.rstCode(payload) catch return c.connectionError(w, .frame_size_error);
    if (c.idle(h.stream)) return c.connectionError(w, .protocol_error);
    c.resets += 1;
    if (c.resets > c.limits.max_resets) return c.connectionError(w, .enhance_your_calm);
    const s = c.stream(h.stream) orelse return null;
    if (s.state == .closed) return null;
    move(s, .reset);
    return .{ .reset = .{ .stream = h.stream, .code = code } };
}

fn priority(c: *Connection, w: *Io.Writer, h: Head, payload: []const u8) Error!?Event {
    if (h.stream == 0) return c.connectionError(w, .protocol_error);
    if (payload.len != 5) return c.streamError(w, h.stream, .frame_size_error);
    const p = h2.Priority.parse(payload[0..5]);
    if (p.dependency == h.stream) return c.streamError(w, h.stream, .protocol_error);
    // RFC 7540 priorities are deprecated (RFC 9113 §5.3.2): taken, not used.
    return null;
}

fn data(c: *Connection, w: *Io.Writer, h: Head, payload: []const u8) Error!?Event {
    if (h.stream == 0) return c.connectionError(w, .protocol_error);
    if (c.idle(h.stream)) return c.connectionError(w, .protocol_error);
    // Flow control counts the whole payload, padding included.
    c.recv_window -= @intCast(payload.len); // safe: a frame is under 2^24 bytes
    if (c.recv_window < 0) return c.connectionError(w, .flow_control_error);
    const body = h2.unpad(h, payload) catch |err| return c.connectionError(w, switch (err) {
        error.ProtocolError => .protocol_error,
        error.FrameSizeError => .frame_size_error,
    });
    // The padding is given back at once.
    c.recv_unacked += payload.len - body.len;
    const s = c.stream(h.stream) orelse {
        try c.giveBack(w, null, payload.len);
        return c.streamError(w, h.stream, .stream_closed);
    };
    if (!receives(s.state)) {
        try c.giveBack(w, null, payload.len);
        return c.streamError(w, h.stream, .stream_closed);
    }
    if (!s.headers_received) return c.streamError(w, h.stream, .protocol_error);
    s.recv_window -= @intCast(payload.len); // safe: a frame is under 2^24 bytes
    if (s.recv_window < 0) return c.streamError(w, h.stream, .flow_control_error);
    s.recv_unacked += payload.len - body.len;
    if (body.len == 0 and !h.has(Flags.end_stream)) {
        c.empty += 1;
        if (c.empty > c.limits.max_empty) return c.connectionError(w, .enhance_your_calm);
    }
    s.data_received += body.len;
    const end = h.has(Flags.end_stream);
    if (s.content_length) |n| if (s.data_received > n or (end and s.data_received != n)) return c.streamError(w, h.stream, .protocol_error);
    if (end) c.endRemote(s);
    return .{ .data = .{ .stream = h.stream, .bytes = body, .end_stream = end } };
}

fn endRemote(c: *Connection, s: *Stream) void {
    _ = c;
    move(s, .end_remote);
}

fn headers(c: *Connection, w: *Io.Writer, h: Head, payload: []const u8) Error!?Event {
    if (h.stream == 0) return c.connectionError(w, .protocol_error);
    const prio, const fragment = h2.headersPayload(h, payload) catch |err| return c.connectionError(w, switch (err) {
        error.ProtocolError => .protocol_error,
        error.FrameSizeError => .frame_size_error,
    });
    if (prio) |p| if (p.dependency == h.stream) return c.connectionError(w, .protocol_error);
    if (fragment.len > c.block.len or past(fragment.len, c.limits.max_header_block)) return c.connectionError(w, .enhance_your_calm);
    @memcpy(c.block[0..fragment.len], fragment);
    c.block_len = fragment.len;
    c.continuing_end_stream = h.has(Flags.end_stream);
    if (!h.has(Flags.end_headers)) {
        c.continuing = h.stream;
        return null;
    }
    return c.headerBlock(w, h.stream);
}

fn continuation(c: *Connection, w: *Io.Writer, h: Head, payload: []const u8) Error!?Event {
    if (payload.len == 0 and !h.has(Flags.end_headers)) {
        c.empty += 1;
        if (c.empty > c.limits.max_empty) return c.connectionError(w, .enhance_your_calm);
    }
    if (c.block_len + payload.len > c.block.len or past(c.block_len + payload.len, c.limits.max_header_block)) return c.connectionError(w, .enhance_your_calm);
    @memcpy(c.block[c.block_len..][0..payload.len], payload);
    c.block_len += payload.len;
    if (!h.has(Flags.end_headers)) return null;
    c.continuing = null;
    return c.headerBlock(w, h.stream);
}

/// Whether `n` bytes are past `limit`.
fn past(n: usize, limit: Limits.Bytes) bool {
    return aegis.units.Bytes(usize).fromRaw(n).compare(limit.convert(usize)) == .gt;
}

/// A whole header block for stream `id`: decoded, and the stream opened
/// or moved on.
fn headerBlock(c: *Connection, w: *Io.Writer, id: u31) Error!?Event {
    const end_stream = c.continuing_end_stream;
    const list_limit = @min(c.field_bytes.len, c.limits.max_header_list.raw());
    // The block is decoded whatever becomes of the stream: the decoder's
    // table must see every block (RFC 9113 §4.3).
    const decoded = c.decoder.decode(c.block[0..c.block_len], c.field_bytes[0..list_limit], c.fields);
    const fields = decoded catch |err| switch (err) {
        error.Compression => return c.connectionError(w, .compression_error),
        // Too large to keep: the stream is refused, the connection kept.
        error.HeaderListTooLarge, error.TooManyFields => null,
    };
    if (c.stream(id)) |s| {
        // Trailers, or a response after its interim ones.
        if (!receives(s.state)) return if (s.state == .closed) c.streamError(w, id, .stream_closed) else c.connectionError(w, .stream_closed);
        if (s.headers_received and c.role == .server and !end_stream) return c.streamError(w, id, .protocol_error);
        const f = fields orelse return c.streamError(w, id, .refused_stream);
        s.headers_received = true;
        if (end_stream) c.endRemote(s);
        return .{ .headers = .{ .stream = id, .fields = f, .end_stream = end_stream } };
    }
    if (!c.peers(id)) {
        // A response on a stream this end never opened, or one it forgot.
        if (c.idle(id)) return c.connectionError(w, .protocol_error);
        return c.streamError(w, id, .stream_closed);
    }
    if (id <= c.last_peer_stream) return c.connectionError(w, .stream_closed);
    c.last_peer_stream = id;
    if (c.goaway_sent) |last| if (id > last) return null;
    if (c.openCount(true) >= c.limits.max_concurrent_streams) return c.streamError(w, id, .refused_stream);
    const f = fields orelse return c.streamError(w, id, .refused_stream);
    const s = c.freeSlot() orelse return c.streamError(w, id, .refused_stream);
    s.* = .{
        .id = id,
        .send_window = c.remote.initial_window_size,
        .recv_window = c.localSettings().initial_window_size,
        .headers_received = true,
    };
    move(s, .opened);
    if (end_stream) c.endRemote(s);
    return .{ .headers = .{ .stream = id, .fields = f, .end_stream = end_stream } };
}

/// The settings in force for what the peer sends: the pending ones once
/// sent, since a peer may act on them before it acknowledges.
fn localSettings(c: *const Connection) h2.Settings {
    return c.local_pending orelse c.local;
}

/// The data the application took off `id` (null for data no stream
/// keeps): given back to the windows, a WINDOW_UPDATE sent once half a
/// window is owed.
pub fn giveBack(c: *Connection, w: *Io.Writer, id: ?u31, n: usize) Error!void {
    c.recv_unacked += n;
    // Twice what is owed fits: it is within a window, under 2^31 bytes.
    const owed_twice = aegis.units.Bytes(u64).fromRaw(c.recv_unacked).mul(2) catch unreachable; // unreachable: see above
    if (owed_twice.compare(c.limits.connection_window.convert(u64)) != .lt) {
        windowUpdate(w, 0, @intCast(c.recv_unacked)) catch return error.WriteFailed;
        c.recv_window += @intCast(c.recv_unacked);
        c.recv_unacked = 0;
    }
    const s = c.stream(id orelse return) orelse return;
    s.recv_unacked += n;
    if (!receives(s.state)) return;
    if (s.recv_unacked >= c.localSettings().initial_window_size / 2) {
        windowUpdate(w, s.id, @intCast(s.recv_unacked)) catch return error.WriteFailed;
        s.recv_window += @intCast(s.recv_unacked);
        s.recv_unacked = 0;
    }
}

/// Why a write was refused.
pub const WriteError = error{
    /// The stream is not one this end may write on now.
    StreamClosed,
    /// No stream slot is free, or the peer allows no more.
    TooManyStreams,
    /// The peer is going away: no new stream.
    GoingAway,
    WriteFailed,
};

/// Open a stream for a request (a client's); its id.
pub fn open(c: *Connection) WriteError!u31 {
    if (c.goaway_received != null) return error.GoingAway;
    if (c.remote.max_concurrent_streams) |max| if (c.openCount(false) >= max) return error.TooManyStreams;
    const s = c.freeSlot() orelse return error.TooManyStreams;
    const id = c.next_stream;
    c.next_stream += 2;
    s.* = .{ .id = id, .state = .idle, .send_window = c.remote.initial_window_size, .recv_window = c.localSettings().initial_window_size };
    // Open before its headers go, so `stream` finds it.
    move(s, .opened);
    return id;
}

/// Write a header block on `id`, split into HEADERS and CONTINUATION frames
/// as the peer's frame size allows. `scratch` holds the encoded block.
pub fn writeHeaders(c: *Connection, w: *Io.Writer, id: u31, fields: []const hpack.Field, end_stream: bool, scratch: []u8) WriteError!void {
    const s = c.stream(id) orelse return error.StreamClosed;
    if (!sends(s.state)) return error.StreamClosed;
    var bw: Io.Writer = .fixed(scratch);
    c.encoder.encode(&bw, fields) catch return error.WriteFailed;
    const block = bw.buffered();
    const max: usize = c.remote.max_frame_size;
    var at: usize = 0;
    var first = true;
    while (true) {
        const n = @min(block.len - at, max);
        const last = at + n == block.len;
        var flags: u8 = if (last) Flags.end_headers else 0;
        if (first and end_stream) flags |= Flags.end_stream;
        h2.writeFrame(w, .{ .len = @intCast(n), .type = if (first) .headers else .continuation, .flags = flags, .stream = id }, &.{block[at..][0..n]}) catch return error.WriteFailed;
        at += n;
        first = false;
        if (last) break;
    }
    if (end_stream) c.endLocal(s);
}

fn endLocal(c: *Connection, s: *Stream) void {
    _ = c;
    move(s, .end_local);
}

/// How much `id` may send now: the smaller of its window and the
/// connection's, and at most one frame.
pub fn sendable(c: *Connection, id: u31) usize {
    const s = c.stream(id) orelse return 0;
    const window = @min(s.send_window, c.send_window);
    if (window <= 0) return 0;
    return @min(@as(usize, @intCast(window)), c.remote.max_frame_size);
}

/// Write data on `id`: as much of `bytes` as the windows allow now, in
/// one frame; the bytes written. With `end_stream`, the stream ends once
/// all of `bytes` has gone.
pub fn writeData(c: *Connection, w: *Io.Writer, id: u31, bytes: []const u8, end_stream: bool) WriteError!usize {
    const s = c.stream(id) orelse return error.StreamClosed;
    if (!sends(s.state)) return error.StreamClosed;
    const n = @min(bytes.len, c.sendable(id));
    if (n == 0 and bytes.len != 0) return 0;
    const last = end_stream and n == bytes.len;
    h2.writeFrame(w, .{ .len = @intCast(n), .type = .data, .flags = if (last) Flags.end_stream else 0, .stream = id }, &.{bytes[0..n]}) catch return error.WriteFailed;
    s.send_window -= @intCast(n);
    c.send_window -= @intCast(n);
    if (last) c.endLocal(s);
    return n;
}

/// Reset `id` with `code`.
pub fn reset(c: *Connection, w: *Io.Writer, id: u31, code: ErrorCode) WriteError!void {
    c.rstWrite(w, id, code) catch return error.WriteFailed;
    if (c.stream(id)) |s| if (s.state != .closed) move(s, .reset);
}

/// Tell the peer this end is going away: no stream past the last it
/// opened will be processed.
pub fn goaway(c: *Connection, w: *Io.Writer, code: ErrorCode) WriteError!void {
    c.goawayWrite(w, code, "") catch return error.WriteFailed;
}

/// Forget `id` once its exchange is done both ways, freeing its slot.
pub fn release(c: *Connection, id: u31) void {
    if (c.stream(id)) |s| s.* = .{};
}

const testing = std.testing;

test "an upgraded connection's stream 1 is the request, ended on the client's side" {
    var cm: TestMemory = .{};
    var client: Connection = .init(.client, .{}, .{}, cm.memory());
    client.upgradeClient();
    try testing.expectEqual(StreamState.half_closed_local, client.stream(1).?.state);
    try testing.expectEqual(@as(u31, 3), try client.open());

    var sm: TestMemory = .{};
    var server: Connection = .init(.server, .{}, .{}, sm.memory());
    // INITIAL_WINDOW_SIZE of 1000, as the request's `HTTP2-Settings` said.
    try server.upgradeServer(&.{ 0, 4, 0, 0, 0x03, 0xe8 });
    const one = server.stream(1).?;
    try testing.expectEqual(StreamState.half_closed_remote, one.state);
    try testing.expectEqual(@as(i64, 1000), one.send_window);
    try testing.expectEqual(@as(u31, 1), server.last_peer_stream);

    var bad: TestMemory = .{};
    var refused: Connection = .init(.server, .{}, .{}, bad.memory());
    try testing.expectError(error.FrameSizeError, refused.upgradeServer(&.{ 0, 4, 0, 0, 0 }));
}

const TestMemory = struct {
    streams: [8]Stream = @splat(.{}),
    block: [1024]u8 = undefined,
    field_bytes: [1024]u8 = undefined,
    fields: [32]hpack.Field = undefined,
    db: [8192]u8 = undefined,
    de: [129]hpack.Table.Entry = undefined,
    eb: [8192]u8 = undefined,
    ee: [129]hpack.Table.Entry = undefined,

    fn memory(m: *TestMemory) Memory {
        return .{ .streams = &m.streams, .block = &m.block, .field_bytes = &m.field_bytes, .fields = &m.fields, .decoder_bytes = &m.db, .decoder_entries = &m.de, .encoder_bytes = &m.eb, .encoder_entries = &m.ee };
    }
};

/// The frames in `bytes`, each fed to `to`.
fn feed(to: *Connection, w: *Io.Writer, bytes: []const u8, events: []?Event) !usize {
    var at: usize = 0;
    var n: usize = 0;
    while (at + h2.head_len <= bytes.len) {
        const h = Head.parse(bytes[at..][0..h2.head_len]);
        const payload = bytes[at + h2.head_len ..][0..h.len];
        events[n] = try to.receive(w, h, payload);
        n += 1;
        at += h2.head_len + h.len;
    }
    return n;
}

test "a request and its response pass between a client and a server, settings and windows exchanged" {
    var cm: TestMemory = .{};
    var sm: TestMemory = .{};
    var client: Connection = .init(.client, .{ .enable_push = false }, .{}, cm.memory());
    var server: Connection = .init(.server, .{ .max_concurrent_streams = 100 }, .{}, sm.memory());
    var to_server_buf: [4096]u8 = undefined;
    var to_client_buf: [4096]u8 = undefined;
    var to_server: Io.Writer = .fixed(&to_server_buf);
    var to_client: Io.Writer = .fixed(&to_client_buf);
    try client.start(&to_server);
    try server.start(&to_client);
    try testing.expect(server.checkPreface(to_server.buffered()[0..h2.preface.len]));
    var events: [16]?Event = undefined;
    _ = try feed(&server, &to_client, to_server.buffered()[h2.preface.len..], &events);
    to_server.end = 0;
    const id = try client.open();
    var scratch: [512]u8 = undefined;
    try client.writeHeaders(&to_server, id, &.{ .{ .name = ":method", .value = "POST" }, .{ .name = ":path", .value = "/x" }, .{ .name = ":scheme", .value = "https" }, .{ .name = ":authority", .value = "a" } }, false, &scratch);
    _ = try client.writeData(&to_server, id, "body", true);
    var n = try feed(&server, &to_client, to_server.buffered(), &events);
    try testing.expectEqual(@as(usize, 2), n);
    try testing.expectEqualStrings("/x", events[0].?.headers.fields[1].value);
    try testing.expectEqualStrings("body", events[1].?.data.bytes);
    try testing.expect(events[1].?.data.end_stream);
    try server.writeHeaders(&to_client, id, &.{.{ .name = ":status", .value = "200" }}, true, &scratch);
    n = try feed(&client, &to_server, to_client.buffered(), &events);
    var saw_response = false;
    for (events[0..n]) |e| if (e) |ev| switch (ev) {
        .headers => |hd| {
            try testing.expectEqualStrings("200", hd.fields[0].value);
            try testing.expect(hd.end_stream);
            saw_response = true;
        },
        else => {},
    };
    try testing.expect(saw_response);
    try testing.expectEqual(StreamState.closed, client.stream(id).?.state);
}

test "a frame on stream 0 that belongs to a stream, a lone CONTINUATION, and a flood each end the connection" {
    var sm: TestMemory = .{};
    var server: Connection = .init(.server, .{}, .{ .max_pings = 2 }, sm.memory());
    var out_buf: [1024]u8 = undefined;
    var out: Io.Writer = .fixed(&out_buf);
    try testing.expectError(error.ConnectionError, server.receive(&out, .{ .len = 0, .type = .data, .flags = 0, .stream = 0 }, ""));
    try testing.expectEqual(ErrorCode.protocol_error, server.closed_with);
    var sm2: TestMemory = .{};
    var s2: Connection = .init(.server, .{}, .{ .max_pings = 2 }, sm2.memory());
    try testing.expectError(error.ConnectionError, s2.receive(&out, .{ .len = 0, .type = .continuation, .flags = Flags.end_headers, .stream = 1 }, ""));
    var sm3: TestMemory = .{};
    var s3: Connection = .init(.server, .{}, .{ .max_pings = 2 }, sm3.memory());
    const p: [8]u8 = @splat(0);
    _ = try s3.receive(&out, .{ .len = 8, .type = .ping, .flags = 0, .stream = 0 }, &p);
    _ = try s3.receive(&out, .{ .len = 8, .type = .ping, .flags = 0, .stream = 0 }, &p);
    try testing.expectError(error.ConnectionError, s3.receive(&out, .{ .len = 8, .type = .ping, .flags = 0, .stream = 0 }, &p));
    try testing.expectEqual(ErrorCode.enhance_your_calm, s3.closed_with);
}

test "fuzz: any frames after the preface are taken or end the connection, and nothing more" {
    const shakedown = @import("shakedown");
    const inputs = @import("../../testing/inputs.zig");
    const seeds = [_][]const u8{
        "\x00\x00\x06\x04\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x64",
        "\x00\x00\x05\x01\x05\x00\x00\x00\x01\x82\x86\x84\x41\x80",
        "\x00\x00\x04\x00\x01\x00\x00\x00\x01body\x00\x00\x08\x06\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08",
        "\x00\x00\x04\x08\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x04\x03\x00\x00\x00\x01\x00\x00\x00\x08",
    };
    try shakedown.check(testing.allocator, {}, struct {
        fn one(_: void, case: *shakedown.Case) anyerror!void {
            var buf: [512]u8 = undefined;
            const bytes = inputs.draw(case, &buf, &seeds, 96);
            var m: TestMemory = .{};
            var server: Connection = .init(.server, .{ .max_concurrent_streams = 4 }, .{ .max_concurrent_streams = 4 }, m.memory());
            var out_buf: [16 << 10]u8 = undefined;
            var out: Io.Writer = .fixed(&out_buf);
            var at: usize = 0;
            while (at + h2.head_len <= bytes.len) {
                const h = Head.parse(bytes[at..][0..h2.head_len]);
                const end = @min(bytes.len, at + h2.head_len + h.len);
                const payload = bytes[at + h2.head_len .. end];
                at = end;
                out.end = 0;
                const event = server.receive(&out, h, payload) catch break;
                // What a stream's reader would take, given back.
                if (event) |e| switch (e) {
                    .data => |d| server.giveBack(&out, d.stream, d.bytes.len) catch break,
                    else => {},
                };
            }
        }
    }.one, .{});
}

test "a stream receives until its peer ends it, and sends until it ends it itself" {
    const Case = struct { state: StreamState, receives: bool, sends: bool };
    for ([_]Case{
        .{ .state = .idle, .receives = false, .sends = false },
        .{ .state = .open, .receives = true, .sends = true },
        .{ .state = .half_closed_local, .receives = true, .sends = false },
        .{ .state = .half_closed_remote, .receives = false, .sends = true },
        .{ .state = .closed, .receives = false, .sends = false },
    }) |case| {
        try testing.expectEqual(case.receives, receives(case.state));
        try testing.expectEqual(case.sends, sends(case.state));
    }
    // Both ends, in either order, close it; a reset closes it from any open state.
    try testing.expectEqual(StreamState.closed, Lifecycle.next(Lifecycle.next(.open, .end_local).?, .end_remote).?);
    try testing.expectEqual(StreamState.closed, Lifecycle.next(Lifecycle.next(.open, .end_remote).?, .end_local).?);
    try testing.expectEqual(null, Lifecycle.next(.closed, .reset));
}
