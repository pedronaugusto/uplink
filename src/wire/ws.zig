//! The WebSocket protocol's wire (RFC 6455), sans I/O: frame heads read
//! and written, payloads masked, the opening handshake's keys, close codes,
//! UTF-8 checked incrementally across fragments, and the parameters of the
//! permessage-deflate extension (RFC 7692).

const std = @import("std");
const Io = std.Io;

/// What a frame carries.
pub const Opcode = enum(u4) {
    continuation = 0,
    text = 1,
    binary = 2,
    close = 8,
    ping = 9,
    pong = 10,
    _,

    /// Whether frames of this opcode are control frames.
    pub fn control(o: Opcode) bool {
        return @backingInt(o) & 0x8 != 0;
    }

    /// Whether RFC 6455 defines it.
    pub fn known(o: Opcode) bool {
        return switch (o) {
            .continuation, .text, .binary, .close, .ping, .pong => true,
            _ => false,
        };
    }
};

/// A frame's head.
pub const Header = struct {
    fin: bool = true,
    /// RSV1: the frame's message is compressed (permessage-deflate).
    rsv1: bool = false,
    rsv2: bool = false,
    rsv3: bool = false,
    opcode: Opcode,
    /// The masking key, for a frame from a client.
    mask: ?[4]u8 = null,
    /// The payload's length.
    len: u64,

    /// The most bytes a head takes.
    pub const max_len = 14;
};

/// Why a head is refused.
pub const HeadError = error{
    /// A length in 64 bits with its top bit set. A length not in its
    /// shortest form is taken: RFC 6455 asks for that of a sender only.
    InvalidLength,
};

/// A head at the start of `bytes`, and its length, or null when it has
/// not all arrived.
pub fn parseHeader(bytes: []const u8) HeadError!?struct { Header, usize } {
    if (bytes.len < 2) return null;
    const b0 = bytes[0];
    const b1 = bytes[1];
    var h: Header = .{
        .fin = b0 & 0x80 != 0,
        .rsv1 = b0 & 0x40 != 0,
        .rsv2 = b0 & 0x20 != 0,
        .rsv3 = b0 & 0x10 != 0,
        .opcode = @fromBackingInt(@intCast(b0 & 0x0f)),
        .len = b1 & 0x7f,
    };
    var at: usize = 2;
    if (h.len == 126) {
        if (bytes.len < 4) return null;
        h.len = std.mem.readInt(u16, bytes[2..4], .big);
        at = 4;
    } else if (h.len == 127) {
        if (bytes.len < 10) return null;
        h.len = std.mem.readInt(u64, bytes[2..10], .big);
        if (h.len >> 63 != 0) return error.InvalidLength;
        at = 10;
    }
    if (b1 & 0x80 != 0) {
        if (bytes.len < at + 4) return null;
        h.mask = bytes[at..][0..4].*;
        at += 4;
    }
    return .{ h, at };
}

/// Write `h` into `out`; the bytes written.
pub fn writeHeader(out: *[Header.max_len]u8, h: Header) []const u8 {
    out[0] = @as(u8, @intFromBool(h.fin)) << 7 | @as(u8, @intFromBool(h.rsv1)) << 6 |
        @as(u8, @intFromBool(h.rsv2)) << 5 | @as(u8, @intFromBool(h.rsv3)) << 4 | @backingInt(h.opcode);
    const masked: u8 = if (h.mask != null) 0x80 else 0;
    var at: usize = 2;
    if (h.len < 126) {
        out[1] = masked | @as(u8, @intCast(h.len)); // safe: under 126
    } else if (h.len <= std.math.maxInt(u16)) {
        out[1] = masked | 126;
        std.mem.writeInt(u16, out[2..4], @intCast(h.len), .big); // safe: at most 0xffff
        at = 4;
    } else {
        out[1] = masked | 127;
        std.mem.writeInt(u64, out[2..10], h.len, .big);
        at = 10;
    }
    if (h.mask) |m| {
        out[at..][0..4].* = m;
        at += 4;
    }
    return out[0..at];
}

/// XOR `data` with `key`, the payload's `offset`-th byte first: masking and
/// unmasking alike, thirty-two bytes at a time.
pub fn mask(key: [4]u8, offset: u64, data: []u8) void {
    var k: [4]u8 = undefined;
    for (&k, 0..) |*b, i| b.* = key[@intCast((offset + i) % 4)];
    const V = @Vector(32, u8);
    var lanes: [32]u8 = undefined;
    for (&lanes, 0..) |*b, i| b.* = k[i % 4];
    const pattern: V = lanes;
    var i: usize = 0;
    while (i + 32 <= data.len) : (i += 32) {
        const chunk: V = data[i..][0..32].*;
        data[i..][0..32].* = chunk ^ pattern;
    }
    while (i < data.len) : (i += 1) data[i] ^= k[i % 4];
}

/// The GUID RFC 6455 joins to a client's key.
const accept_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// The `Sec-WebSocket-Accept` value for a client's `Sec-WebSocket-Key`.
pub fn acceptKey(key: []const u8) [28]u8 {
    var sha: std.crypto.hash.Sha1 = .init(.{});
    sha.update(key);
    sha.update(accept_guid);
    var digest: [20]u8 = undefined;
    sha.final(&digest);
    var out: [28]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&out, &digest);
    return out;
}

/// A `Sec-WebSocket-Key` from 16 fresh random bytes.
pub fn keyOf(random: [16]u8) [24]u8 {
    var out: [24]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&out, &random);
    return out;
}

/// Whether `key` is a `Sec-WebSocket-Key`: 16 bytes in base64.
pub fn validKey(key: []const u8) bool {
    if (key.len != 24) return false;
    var raw: [16]u8 = undefined;
    std.base64.standard.Decoder.decode(&raw, key) catch return false;
    return true;
}

/// Close codes RFC 6455 §7.4 names.
pub const Close = struct {
    pub const normal: u16 = 1000;
    pub const going_away: u16 = 1001;
    pub const protocol_error: u16 = 1002;
    pub const unsupported: u16 = 1003;
    /// No code was given (never sent).
    pub const no_status: u16 = 1005;
    /// The connection ended without a close (never sent).
    pub const abnormal: u16 = 1006;
    pub const invalid_payload: u16 = 1007;
    pub const policy: u16 = 1008;
    pub const too_big: u16 = 1009;
    pub const extension_required: u16 = 1010;
    pub const internal: u16 = 1011;

    /// Whether a peer may send `code`: the defined ones but those never
    /// sent, and the ranges for libraries and applications.
    pub fn sendable(code: u16) bool {
        return switch (code) {
            1000...1003, 1007...1014 => true,
            3000...4999 => true,
            else => false,
        };
    }
};

/// UTF-8 checked as text arrives in pieces: a sequence cut by a piece's
/// end is held and finished by the next, and a byte that can start no
/// valid sequence fails at once, before the message ends.
pub const Utf8 = struct {
    /// Private: the bytes of a sequence not yet whole.
    held: [4]u8 = undefined,
    held_len: u8 = 0,

    /// Check `bytes`, the next piece; false at the first byte that makes
    /// the text invalid. `last` says the text ends after it.
    pub fn feed(u: *Utf8, bytes: []const u8, last: bool) bool {
        var rest = bytes;
        if (u.held_len != 0) {
            const need = sequenceLen(u.held[0]).? - u.held_len;
            const take = @min(need, rest.len);
            @memcpy(u.held[u.held_len..][0..take], rest[0..take]);
            u.held_len += @intCast(take);
            rest = rest[take..];
            if (!prefixValid(u.held[0..u.held_len])) return false;
            if (u.held_len < sequenceLen(u.held[0]).?) return !last;
            u.held_len = 0;
        }
        // Whole sequences, by std's checker; a sequence the piece cuts is
        // held for the next.
        var cut = rest.len;
        var back: usize = 0;
        while (back < 4 and back < rest.len) : (back += 1) {
            const at = rest.len - 1 - back;
            if (rest[at] & 0xc0 == 0x80) continue;
            const n = sequenceLen(rest[at]) orelse return false;
            if (n > rest.len - at) cut = at;
            break;
        }
        if (!std.unicode.utf8ValidateSlice(rest[0..cut])) return false;
        const tail = rest[cut..];
        if (tail.len == 0) return true;
        if (!prefixValid(tail)) return false;
        @memcpy(u.held[0..tail.len], tail);
        u.held_len = @intCast(tail.len);
        return !last;
    }

    /// Whether text ended where it is now: nothing held.
    pub fn complete(u: *const Utf8) bool {
        return u.held_len == 0;
    }

    fn sequenceLen(first: u8) ?u8 {
        return switch (first) {
            0x00...0x7f => 1,
            0xc2...0xdf => 2,
            0xe0...0xef => 3,
            0xf0...0xf4 => 4,
            else => null,
        };
    }

    /// Whether `bytes`, the start of one sequence, can still be valid.
    fn prefixValid(bytes: []const u8) bool {
        const n = sequenceLen(bytes[0]) orelse return false;
        if (bytes.len > 1) {
            const second = bytes[1];
            const ok = switch (bytes[0]) {
                0xe0 => second >= 0xa0 and second <= 0xbf,
                0xed => second >= 0x80 and second <= 0x9f,
                0xf0 => second >= 0x90 and second <= 0xbf,
                0xf4 => second >= 0x80 and second <= 0x8f,
                else => second & 0xc0 == 0x80,
            };
            if (!ok) return false;
        }
        for (bytes[@min(2, bytes.len)..]) |c| if (c & 0xc0 != 0x80) return false;
        return bytes.len <= n;
    }
};

/// The permessage-deflate parameters (RFC 7692 §7.1).
pub const Deflate = struct {
    server_no_context_takeover: bool = false,
    client_no_context_takeover: bool = false,
    /// 8-15; null is 15.
    server_max_window_bits: ?u4 = null,
    /// 8-15; null is 15. In an offer, `client_max_window_bits` with no
    /// value is `client_bits_offered`.
    client_max_window_bits: ?u4 = null,
    client_bits_offered: bool = false,

    /// Why an extension's parameters are refused.
    pub const Error = error{InvalidParameters};

    /// The parameters of one `permessage-deflate` element, after its name.
    pub fn parse(params: []const u8) Error!Deflate {
        var d: Deflate = .{};
        var it = std.mem.splitScalar(u8, params, ';');
        while (it.next()) |raw| {
            const p = std.mem.trim(u8, raw, " \t");
            if (p.len == 0) continue;
            const eq = std.mem.findScalar(u8, p, '=');
            const name = std.mem.trim(u8, p[0 .. eq orelse p.len], " \t");
            const value: ?[]const u8 = if (eq) |e| std.mem.trim(u8, std.mem.trim(u8, p[e + 1 ..], " \t"), "\"") else null;
            if (std.ascii.eqlIgnoreCase(name, "server_no_context_takeover")) {
                if (value != null or d.server_no_context_takeover) return error.InvalidParameters;
                d.server_no_context_takeover = true;
            } else if (std.ascii.eqlIgnoreCase(name, "client_no_context_takeover")) {
                if (value != null or d.client_no_context_takeover) return error.InvalidParameters;
                d.client_no_context_takeover = true;
            } else if (std.ascii.eqlIgnoreCase(name, "server_max_window_bits")) {
                if (d.server_max_window_bits != null) return error.InvalidParameters;
                d.server_max_window_bits = try windowBits(value orelse return error.InvalidParameters);
            } else if (std.ascii.eqlIgnoreCase(name, "client_max_window_bits")) {
                if (d.client_max_window_bits != null or d.client_bits_offered) return error.InvalidParameters;
                if (value) |v| d.client_max_window_bits = try windowBits(v) else d.client_bits_offered = true;
            } else return error.InvalidParameters;
        }
        return d;
    }

    fn windowBits(text: []const u8) Error!u4 {
        const n = std.fmt.parseUnsigned(u8, text, 10) catch return error.InvalidParameters;
        if (n < 8 or n > 15 or text.len > 2 or text[0] == '0') return error.InvalidParameters;
        return @intCast(n); // safe: 8 to 15
    }

    /// Write the parameters as an extension element, its name first.
    pub fn write(d: Deflate, w: *Io.Writer) Io.Writer.Error!void {
        try w.writeAll("permessage-deflate");
        if (d.server_no_context_takeover) try w.writeAll("; server_no_context_takeover");
        if (d.client_no_context_takeover) try w.writeAll("; client_no_context_takeover");
        if (d.server_max_window_bits) |b| try w.print("; server_max_window_bits={d}", .{b});
        if (d.client_max_window_bits) |b| try w.print("; client_max_window_bits={d}", .{b}) else if (d.client_bits_offered) try w.writeAll("; client_max_window_bits");
    }
};

const testing = std.testing;

test "heads are read and written in each length form, masked or not" {
    var buf: [Header.max_len]u8 = undefined;
    for ([_]u64{ 0, 125, 126, 65535, 65536, 1 << 40 }) |len| {
        for ([_]?[4]u8{ null, .{ 1, 2, 3, 4 } }) |m| {
            const h: Header = .{ .fin = len % 2 == 0, .rsv1 = true, .opcode = .binary, .mask = m, .len = len };
            const bytes = writeHeader(&buf, h);
            const got, const size = (try parseHeader(bytes)).?;
            try testing.expectEqual(bytes.len, size);
            try testing.expectEqual(h.len, got.len);
            try testing.expectEqual(h.fin, got.fin);
            try testing.expect(got.rsv1);
            try testing.expectEqual(h.mask, got.mask);
            try testing.expectEqual(@as(?struct { Header, usize }, null), try parseHeader(bytes[0 .. bytes.len - 1]));
        }
    }
    try testing.expectError(error.InvalidLength, parseHeader(&.{ 0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 0 }));
}

test "masking is its own inverse at any offset and length" {
    var data: [100]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @truncate(i * 7);
    const original = data;
    mask(.{ 0xaa, 0xbb, 0xcc, 0xdd }, 3, &data);
    try testing.expectEqual(original[0] ^ 0xdd, data[0]);
    try testing.expectEqual(original[1] ^ 0xaa, data[1]);
    mask(.{ 0xaa, 0xbb, 0xcc, 0xdd }, 3, data[0..40]);
    mask(.{ 0xaa, 0xbb, 0xcc, 0xdd }, 43, data[40..]);
    try testing.expectEqualSlices(u8, &original, &data);
}

test "the accept key is RFC 6455's example" {
    try testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", &acceptKey("dGhlIHNhbXBsZSBub25jZQ=="));
    try testing.expect(validKey("dGhlIHNhbXBsZSBub25jZQ=="));
    try testing.expect(!validKey("short"));
}

test "text is checked in pieces, failing at the first byte that cannot be valid" {
    const text = "κόσμε, 𝄞 and ascii";
    for (1..text.len) |cut| {
        var u: Utf8 = .{};
        try testing.expect(u.feed(text[0..cut], false));
        try testing.expect(u.feed(text[cut..], true));
    }
    var bad: Utf8 = .{};
    try testing.expect(bad.feed("ok \xce", false));
    try testing.expect(!bad.feed("\x41", false));
    var surrogate: Utf8 = .{};
    try testing.expect(!surrogate.feed("\xed\xa0", false));
    var cut_short: Utf8 = .{};
    try testing.expect(!cut_short.feed("\xe2\x82", true));
    var over: Utf8 = .{};
    try testing.expect(!over.feed("\xf4\x90\x80\x80", true));
    try testing.expect(Close.sendable(1000) and Close.sendable(4999) and !Close.sendable(1005) and !Close.sendable(1016) and !Close.sendable(999));
}

test "permessage-deflate parameters are read and refused as RFC 7692 says" {
    const d = try Deflate.parse("client_max_window_bits; server_max_window_bits=10; server_no_context_takeover");
    try testing.expect(d.client_bits_offered);
    try testing.expectEqual(@as(?u4, 10), d.server_max_window_bits);
    try testing.expect(d.server_no_context_takeover);
    try testing.expectError(error.InvalidParameters, Deflate.parse("server_max_window_bits=7"));
    try testing.expectError(error.InvalidParameters, Deflate.parse("unknown"));
    try testing.expectError(error.InvalidParameters, Deflate.parse("server_no_context_takeover; server_no_context_takeover"));
    var buf: [128]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try (Deflate{ .server_no_context_takeover = true, .client_max_window_bits = 12 }).write(&w);
    try testing.expectEqualStrings("permessage-deflate; server_no_context_takeover; client_max_window_bits=12", w.buffered());
}

test "fuzz: a head is read the same from any longer input, and from no shorter one" {
    const shakedown = @import("shakedown");
    const inputs = @import("../testing/inputs.zig");
    const seeds = [_][]const u8{ "\x81\x05hello", "\x82\xfe\x01\x00abcd", "\x02\xff\x00\x00\x00\x00\x00\x01\x00\x00", "\x88\x80\x01\x02\x03\x04" };
    try shakedown.check(testing.allocator, {}, struct {
        fn one(_: void, case: *shakedown.Case) anyerror!void {
            var buf: [64]u8 = undefined;
            const bytes = inputs.draw(case, &buf, &seeds, 16);
            const whole = parseHeader(bytes) catch return;
            const header, const size = whole orelse return;
            try testing.expect(size <= bytes.len and size <= 14);
            const again, const size2 = (try parseHeader(bytes[0..size])).?;
            try testing.expectEqual(header, again);
            try testing.expectEqual(size, size2);
            for (0..size) |k| try testing.expectEqual(null, try parseHeader(bytes[0..k]));
        }
    }.one, .{});
}
