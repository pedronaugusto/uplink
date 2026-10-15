//! Test-only: a DNS zone answered without a network, as a `Dns.Transport`:
//! each name's addresses and HTTPS records as a test sets them, every
//! answer built as a server would send it.

const std = @import("std");
const Io = std.Io;
const dns = @import("uplink.wire").dns;
const Dns = @import("../net/Dns.zig");

/// One name's records.
pub const Entry = struct {
    name: []const u8,
    a: []const [4]u8 = &.{},
    https: []const Https = &.{},
};

/// An HTTPS record: its priority, its target (empty for the record's own
/// name) and its parameters, keys ascending.
pub const Https = struct {
    priority: u16 = 1,
    target: []const u8 = "",
    params: []const Param = &.{},
};

pub const Param = struct { key: dns.Key, value: []const u8 };

pub const Zone = struct {
    entries: []const Entry,
    /// Questions asked, of every type.
    asked: std.atomic.Value(u32) = .init(0),

    pub fn transport(z: *Zone) Dns.Transport {
        return .{ .context = z, .exchangeFn = exchange };
    }

    fn exchange(_: Io, context: ?*anyopaque, query: []const u8, answer: []u8) Dns.ExchangeError![]u8 {
        const z: *Zone = @ptrCast(@alignCast(context.?)); // safe: `transport` passes a Zone
        _ = z.asked.fetchAdd(1, .monotonic);
        return z.respond(query, answer) catch error.NoAnswer;
    }

    fn respond(z: *const Zone, query: []const u8, out: []u8) ![]u8 {
        const q = try dns.Message.parse(query);
        var name_buf: [dns.max_name]u8 = undefined;
        const name = try dns.readName(query, q.question_at, &name_buf);
        const kind: dns.Type = @fromBackingInt(std.mem.readInt(u16, query[q.answers_at - 4 ..][0..2], .big));
        @memcpy(out[0..q.answers_at], query[0..q.answers_at]);
        var w: Io.Writer = .fixed(out[q.answers_at..]);
        var count: u16 = 0;
        var flags: u16 = 0x8180;
        const entry = for (z.entries) |e| {
            if (std.ascii.eqlIgnoreCase(e.name, name)) break e;
        } else null;
        if (entry) |e| switch (kind) {
            .a => for (e.a) |address| {
                try record(&w, .a, &address);
                count += 1;
            },
            .https => for (e.https) |h| {
                var data_buf: [1024]u8 = undefined;
                var d: Io.Writer = .fixed(&data_buf);
                try d.writeInt(u16, h.priority, .big);
                try writeName(&d, h.target);
                for (h.params) |p| {
                    try d.writeInt(u16, @backingInt(p.key), .big);
                    try d.writeInt(u16, @intCast(p.value.len), .big); // safe: a test's values are small
                    try d.writeAll(p.value);
                }
                try record(&w, .https, d.buffered());
                count += 1;
            },
            else => {},
        } else flags |= 3;
        std.mem.writeInt(u16, out[2..4], flags, .big);
        std.mem.writeInt(u16, out[6..8], count, .big);
        std.mem.writeInt(u16, out[8..10], 0, .big);
        std.mem.writeInt(u16, out[10..12], 0, .big);
        return out[0 .. q.answers_at + w.end];
    }

    /// A record owned by the question's name, by a pointer to it.
    fn record(w: *Io.Writer, kind: dns.Type, data: []const u8) !void {
        try w.writeAll("\xc0\x0c");
        try w.writeInt(u16, @backingInt(kind), .big);
        try w.writeInt(u16, dns.class_in, .big);
        try w.writeInt(u32, 60, .big);
        try w.writeInt(u16, @intCast(data.len), .big); // safe: a test's records are small
        try w.writeAll(data);
    }

    fn writeName(w: *Io.Writer, name: []const u8) !void {
        var it = std.mem.tokenizeScalar(u8, name, '.');
        while (it.next()) |label| {
            try w.writeByte(@intCast(label.len)); // safe: a test's labels are short
            try w.writeAll(label);
        }
        try w.writeByte(0);
    }
};

/// The value of an `alpn` parameter naming `protocols`.
pub fn alpn(comptime protocols: []const []const u8) []const u8 {
    return comptime value: {
        var out: []const u8 = "";
        for (protocols) |p| out = out ++ .{@as(u8, p.len)} ++ p;
        break :value out;
    };
}

/// The value of a `port` parameter.
pub fn port(p: u16) [2]u8 {
    var out: [2]u8 = undefined;
    std.mem.writeInt(u16, &out, p, .big);
    return out;
}
