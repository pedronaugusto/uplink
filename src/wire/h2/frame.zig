//! HTTP/2's frames (RFC 9113): the connection preface, frame heads read
//! and written, the payloads of each frame type parsed with their padding
//! and priority stripped, settings, and error codes. Sans I/O: the
//! connection that uses them is `h2.Connection`.

const std = @import("std");
const Io = std.Io;

/// The client's connection preface.
pub const preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// The bytes of a frame head.
pub const head_len = 9;

pub const FrameType = enum(u8) {
    data = 0,
    headers = 1,
    priority = 2,
    rst_stream = 3,
    settings = 4,
    push_promise = 5,
    ping = 6,
    goaway = 7,
    window_update = 8,
    continuation = 9,
    /// RFC 9218.
    priority_update = 0x10,
    _,
};

pub const Flags = struct {
    pub const end_stream: u8 = 0x1;
    pub const ack: u8 = 0x1;
    pub const end_headers: u8 = 0x4;
    pub const padded: u8 = 0x8;
    pub const priority: u8 = 0x20;
};

/// A frame's head.
pub const Head = struct {
    len: u24,
    type: FrameType,
    flags: u8,
    stream: u31,

    pub fn has(h: Head, flag: u8) bool {
        return h.flags & flag != 0;
    }

    /// Read a head from its nine bytes; the reserved bit is ignored, as RFC
    /// 9113 §4.1 asks.
    pub fn parse(bytes: *const [head_len]u8) Head {
        return .{
            .len = std.mem.readInt(u24, bytes[0..3], .big),
            .type = @fromBackingInt(@intCast(bytes[3])),
            .flags = bytes[4],
            .stream = @truncate(std.mem.readInt(u32, bytes[5..9], .big) & 0x7fff_ffff),
        };
    }

    pub fn write(h: Head, out: *[head_len]u8) void {
        std.mem.writeInt(u24, out[0..3], h.len, .big);
        out[3] = @backingInt(h.type);
        out[4] = h.flags;
        std.mem.writeInt(u32, out[5..9], h.stream, .big);
    }
};

/// Error codes (RFC 9113 §7).
pub const ErrorCode = enum(u32) {
    no_error = 0x0,
    protocol_error = 0x1,
    internal_error = 0x2,
    flow_control_error = 0x3,
    settings_timeout = 0x4,
    stream_closed = 0x5,
    frame_size_error = 0x6,
    refused_stream = 0x7,
    cancel = 0x8,
    compression_error = 0x9,
    connect_error = 0xa,
    enhance_your_calm = 0xb,
    inadequate_security = 0xc,
    http_1_1_required = 0xd,
    _,
};

/// Setting identifiers.
pub const Setting = enum(u16) {
    header_table_size = 0x1,
    enable_push = 0x2,
    max_concurrent_streams = 0x3,
    initial_window_size = 0x4,
    max_frame_size = 0x5,
    max_header_list_size = 0x6,
    /// RFC 8441: extended CONNECT.
    enable_connect_protocol = 0x8,
    /// RFC 9218: no RFC 7540 priorities.
    no_rfc7540_priorities = 0x9,
    _,
};

/// One side's settings, with RFC 9113's initial values.
pub const Settings = struct {
    header_table_size: u32 = 4096,
    enable_push: bool = true,
    max_concurrent_streams: ?u32 = null,
    initial_window_size: u31 = 65535,
    max_frame_size: u24 = 16384,
    max_header_list_size: ?u32 = null,
    enable_connect_protocol: bool = false,

    /// Why a SETTINGS frame is refused, and the connection error it is.
    pub const Error = error{
        /// A boolean not 0 or 1, or `enable_push` from a server.
        ProtocolError,
        /// A window size past 2^31-1.
        FlowControlError,
        /// A frame size outside 2^14 to 2^24-1, or a payload not a multiple
        /// of six.
        FrameSizeError,
    };

    /// Apply a SETTINGS payload; unknown settings are ignored.
    pub fn apply(s: *Settings, payload: []const u8, from_server: bool) Error!void {
        if (payload.len % 6 != 0) return error.FrameSizeError;
        var i: usize = 0;
        while (i < payload.len) : (i += 6) {
            const id: Setting = @fromBackingInt(@intCast(std.mem.readInt(u16, payload[i..][0..2], .big)));
            const value = std.mem.readInt(u32, payload[i + 2 ..][0..4], .big);
            switch (id) {
                .header_table_size => s.header_table_size = value,
                .enable_push => {
                    if (value > 1 or (from_server and value != 0)) return error.ProtocolError;
                    s.enable_push = value == 1;
                },
                .max_concurrent_streams => s.max_concurrent_streams = value,
                .initial_window_size => {
                    if (value > std.math.maxInt(u31)) return error.FlowControlError;
                    s.initial_window_size = @intCast(value);
                },
                .max_frame_size => {
                    if (value < 16384 or value > std.math.maxInt(u24)) return error.ProtocolError;
                    s.max_frame_size = @intCast(value);
                },
                .max_header_list_size => s.max_header_list_size = value,
                .enable_connect_protocol => {
                    if (value > 1) return error.ProtocolError;
                    s.enable_connect_protocol = value == 1;
                },
                .no_rfc7540_priorities => if (value > 1) return error.ProtocolError,
                _ => {},
            }
        }
    }

    /// Write the settings that differ from the initial values, as a
    /// SETTINGS payload.
    pub fn write(s: Settings, w: *Io.Writer) Io.Writer.Error!void {
        const initial: Settings = .{};
        if (s.header_table_size != initial.header_table_size) try pair(w, .header_table_size, s.header_table_size);
        if (s.enable_push != initial.enable_push) try pair(w, .enable_push, @intFromBool(s.enable_push));
        if (s.max_concurrent_streams) |n| try pair(w, .max_concurrent_streams, n);
        if (s.initial_window_size != initial.initial_window_size) try pair(w, .initial_window_size, s.initial_window_size);
        if (s.max_frame_size != initial.max_frame_size) try pair(w, .max_frame_size, s.max_frame_size);
        if (s.max_header_list_size) |n| try pair(w, .max_header_list_size, n);
        if (s.enable_connect_protocol) try pair(w, .enable_connect_protocol, 1);
    }

    fn pair(w: *Io.Writer, id: Setting, value: u32) Io.Writer.Error!void {
        var b: [6]u8 = undefined;
        std.mem.writeInt(u16, b[0..2], @backingInt(id), .big);
        std.mem.writeInt(u32, b[2..6], value, .big);
        try w.writeAll(&b);
    }
};

/// Why a frame's payload is refused.
pub const PayloadError = error{
    /// Padding as long as the payload or longer.
    ProtocolError,
    /// A payload too short for its type.
    FrameSizeError,
};

/// A DATA, HEADERS or PUSH_PROMISE payload without its padding.
pub fn unpad(h: Head, payload: []const u8) PayloadError![]const u8 {
    if (!h.has(Flags.padded)) return payload;
    if (payload.len < 1) return error.FrameSizeError;
    const pad = payload[0];
    if (pad >= payload.len) return error.ProtocolError;
    return payload[1 .. payload.len - pad];
}

/// RFC 7540's priority fields, still carried by HEADERS and PRIORITY.
pub const Priority = struct {
    exclusive: bool,
    dependency: u31,
    weight: u8,

    pub fn parse(bytes: *const [5]u8) Priority {
        const word = std.mem.readInt(u32, bytes[0..4], .big);
        return .{ .exclusive = word >> 31 != 0, .dependency = @truncate(word & 0x7fff_ffff), .weight = bytes[4] };
    }
};

/// A HEADERS payload: its priority if flagged, and its header block
/// fragment.
pub fn headersPayload(h: Head, payload: []const u8) PayloadError!struct { ?Priority, []const u8 } {
    const body = try unpad(h, payload);
    if (!h.has(Flags.priority)) return .{ null, body };
    if (body.len < 5) return error.FrameSizeError;
    return .{ Priority.parse(body[0..5]), body[5..] };
}

/// A GOAWAY payload.
pub const Goaway = struct {
    last_stream: u31,
    code: ErrorCode,
    debug: []const u8,

    pub fn parse(payload: []const u8) PayloadError!Goaway {
        if (payload.len < 8) return error.FrameSizeError;
        return .{
            .last_stream = @truncate(std.mem.readInt(u32, payload[0..4], .big) & 0x7fff_ffff),
            .code = @fromBackingInt(@intCast(std.mem.readInt(u32, payload[4..8], .big))),
            .debug = payload[8..],
        };
    }
};

/// A WINDOW_UPDATE's increment; 0 is the caller's to refuse.
pub fn windowIncrement(payload: []const u8) PayloadError!u31 {
    if (payload.len != 4) return error.FrameSizeError;
    return @truncate(std.mem.readInt(u32, payload[0..4], .big) & 0x7fff_ffff);
}

/// A RST_STREAM's code.
pub fn rstCode(payload: []const u8) PayloadError!ErrorCode {
    if (payload.len != 4) return error.FrameSizeError;
    return @fromBackingInt(@intCast(std.mem.readInt(u32, payload[0..4], .big)));
}

/// Write a frame head and payload pieces onto `w`.
pub fn writeFrame(w: *Io.Writer, h: Head, payload: []const []const u8) Io.Writer.Error!void {
    var head: [head_len]u8 = undefined;
    h.write(&head);
    try w.writeAll(&head);
    for (payload) |p| try w.writeAll(p);
}

const testing = std.testing;

test "frame heads round-trip, the reserved bit ignored" {
    var buf: [head_len]u8 = undefined;
    const h: Head = .{ .len = 0x123456, .type = .headers, .flags = Flags.end_headers | Flags.end_stream, .stream = 0x7fffffff };
    h.write(&buf);
    try testing.expectEqual(h, Head.parse(&buf));
    buf[5] |= 0x80;
    try testing.expectEqual(@as(u31, 0x7fffffff), Head.parse(&buf).stream);
}

test "settings are applied and refused as RFC 9113 says" {
    var s: Settings = .{};
    var w_buf: [64]u8 = undefined;
    var w: Io.Writer = .fixed(&w_buf);
    try (Settings{ .enable_push = false, .initial_window_size = 1 << 20, .max_concurrent_streams = 100 }).write(&w);
    try s.apply(w.buffered(), false);
    try testing.expect(!s.enable_push);
    try testing.expectEqual(@as(u31, 1 << 20), s.initial_window_size);
    try testing.expectEqual(@as(?u32, 100), s.max_concurrent_streams);
    try testing.expectError(error.FrameSizeError, s.apply(&.{ 0, 1, 0 }, false));
    try testing.expectError(error.ProtocolError, s.apply(&.{ 0, 2, 0, 0, 0, 2 }, false));
    try testing.expectError(error.FlowControlError, s.apply(&.{ 0, 4, 0x80, 0, 0, 0 }, false));
    try testing.expectError(error.ProtocolError, s.apply(&.{ 0, 5, 0, 0, 0x3f, 0xff }, false));
    try s.apply(&.{ 0xff, 0xff, 0, 0, 0, 1 }, false);
}

test "padding and priority are stripped, and bad padding refused" {
    const h: Head = .{ .len = 0, .type = .headers, .flags = Flags.padded | Flags.priority, .stream = 1 };
    const payload = [_]u8{ 2, 0x80, 0, 0, 3, 15, 'a', 'b', 0, 0 };
    const prio, const block = try headersPayload(h, &payload);
    try testing.expect(prio.?.exclusive);
    try testing.expectEqual(@as(u31, 3), prio.?.dependency);
    try testing.expectEqualStrings("ab", block);
    try testing.expectError(error.ProtocolError, unpad(.{ .len = 0, .type = .data, .flags = Flags.padded, .stream = 1 }, &.{ 3, 'a', 'b' }));
}
