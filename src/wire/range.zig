//! Byte ranges (RFC 9110 §14): a `Range` request field read against a
//! representation's length, and the `Content-Range` that answers one.

const std = @import("std");

/// One range of bytes, `first` to `last` inclusive, as RFC 9110 writes it.
pub const Span = struct {
    first: u64,
    last: u64,

    pub fn len(s: Span) u64 {
        return s.last - s.first + 1;
    }
};

/// What a `Range` field asks of a representation of a known length.
pub const Ranges = union(enum) {
    /// The field is not one to honour (another unit, a bad grammar, or
    /// ranges that together ask for more than the whole): answer with the
    /// whole representation, 200.
    whole,
    /// No range overlaps the representation: 416, with
    /// `Content-Range: bytes */<length>`.
    unsatisfiable,
    /// The ranges to send, in the order asked, at least one: 206.
    some: []const Span,
};

/// The most ranges honoured; a field asking more is answered whole, as is
/// one whose ranges together cover more bytes than the representation has
/// (the overlapping-range attack, CVE-2011-3192).
pub const max_ranges = 16;

/// Read `value`, a `Range` field, against a representation `length` bytes
/// long, the satisfiable ranges into `out` (at least `max_ranges` long).
pub fn parse(value: []const u8, length: u64, out: []Span) Ranges {
    std.debug.assert(out.len >= max_ranges);
    const v = std.mem.trim(u8, value, " \t");
    if (!std.ascii.startsWithIgnoreCase(v, "bytes=")) return .whole;
    var n: usize = 0;
    var total: u64 = 0;
    var any = false;
    var it = std.mem.splitScalar(u8, v["bytes=".len..], ',');
    while (it.next()) |raw| {
        const spec = std.mem.trim(u8, raw, " \t");
        if (spec.len == 0) continue;
        any = true;
        const dash = std.mem.findScalar(u8, spec, '-') orelse return .whole;
        const first_text = spec[0..dash];
        const last_text = spec[dash + 1 ..];
        var span: Span = undefined;
        if (first_text.len == 0) {
            // A suffix: the last n bytes.
            const suffix = digits(last_text) orelse return .whole;
            if (suffix == 0 or length == 0) continue;
            span = .{ .first = length - @min(suffix, length), .last = length - 1 };
        } else {
            const first = digits(first_text) orelse return .whole;
            const last: u64 = if (last_text.len == 0) std.math.maxInt(u64) else digits(last_text) orelse return .whole;
            if (last < first) return .whole;
            if (first >= length) continue;
            span = .{ .first = first, .last = @min(last, length - 1) };
        }
        if (n == max_ranges) return .whole;
        total +|= span.len();
        if (total > length) return .whole;
        out[n] = span;
        n += 1;
    }
    if (!any) return .whole;
    if (n == 0) return .unsatisfiable;
    return .{ .some = out[0..n] };
}

fn digits(text: []const u8) ?u64 {
    if (text.len == 0) return null;
    var n: u64 = 0;
    for (text) |c| {
        if (c < '0' or c > '9') return null;
        n = std.math.mul(u64, n, 10) catch return null;
        n = std.math.add(u64, n, c - '0') catch return null;
    }
    return n;
}

/// Write the `Content-Range` value of `span` in a representation `length`
/// bytes long.
pub fn writeContentRange(w: *std.Io.Writer, span: Span, length: u64) std.Io.Writer.Error!void {
    try w.print("bytes {d}-{d}/{d}", .{ span.first, span.last, length });
}

const testing = std.testing;

test "ranges are read against the length, as RFC 9110 writes them" {
    var out: [max_ranges]Span = undefined;
    const one = parse("bytes=0-499", 1000, &out).some;
    try testing.expectEqual(@as(usize, 1), one.len);
    try testing.expectEqual(Span{ .first = 0, .last = 499 }, one[0]);
    const many = parse("bytes=500-599, -100, 990-", 1000, &out).some;
    try testing.expectEqual(Span{ .first = 900, .last = 999 }, many[1]);
    try testing.expectEqual(Span{ .first = 990, .last = 999 }, many[2]);
    try testing.expectEqual(Span{ .first = 10, .last = 99 }, parse("bytes=10-5000", 100, &out).some[0]);
    try testing.expectEqual(Ranges.unsatisfiable, parse("bytes=1000-", 1000, &out));
    try testing.expectEqual(Ranges.whole, parse("items=0-1", 1000, &out));
    try testing.expectEqual(Ranges.whole, parse("bytes=5-1", 1000, &out));
    try testing.expectEqual(Ranges.whole, parse("bytes=a-1", 1000, &out));
    // Overlapping ranges asking for more than the whole are answered whole.
    try testing.expectEqual(Ranges.whole, parse("bytes=0-999,0-999", 1000, &out));
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try writeContentRange(&w, .{ .first = 0, .last = 499 }, 1000);
    try testing.expectEqualStrings("bytes 0-499/1000", w.buffered());
}
