//! `application/x-www-form-urlencoded` (the WHATWG URL standard, §5): name
//! and value pairs written as a body or query, and read back. A space is
//! `+`; `*`, `-`, `.`, `_`, digits and letters stand as themselves; every
//! other byte is `%XX`.

const std = @import("std");
const Io = std.Io;

/// One name and value.
pub const Pair = struct { name: []const u8, value: []const u8 };

/// The media type a form body is sent as.
pub const content_type = "application/x-www-form-urlencoded";

/// Write `pairs` joined by `&`.
pub fn encode(w: *Io.Writer, pairs: []const Pair) Io.Writer.Error!void {
    for (pairs, 0..) |p, i| {
        if (i != 0) try w.writeByte('&');
        try encodeText(w, p.name);
        try w.writeByte('=');
        try encodeText(w, p.value);
    }
}

/// How many bytes `encode` writes for `pairs`: the `Content-Length` of a
/// form body.
pub fn encodedLength(pairs: []const Pair) u64 {
    var n: u64 = 0;
    for (pairs, 0..) |p, i| {
        if (i != 0) n += 1;
        n += textLength(p.name) + 1 + textLength(p.value);
    }
    return n;
}

/// Write one name or value, escaped.
pub fn encodeText(w: *Io.Writer, text: []const u8) Io.Writer.Error!void {
    var start: usize = 0;
    for (text, 0..) |c, i| {
        if (plain[c]) continue;
        try w.writeAll(text[start..i]);
        if (c == ' ') {
            try w.writeByte('+');
        } else {
            const hex = "0123456789ABCDEF";
            try w.writeAll(&.{ '%', hex[c >> 4], hex[c & 15] });
        }
        start = i + 1;
    }
    try w.writeAll(text[start..]);
}

fn textLength(text: []const u8) u64 {
    var n: u64 = 0;
    for (text) |c| n += if (plain[c] or c == ' ') 1 else 3;
    return n;
}

const plain: [256]bool = blk: {
    var table: [256]bool = @splat(false);
    for ("*-._") |c| table[c] = true;
    for ('0'..'9' + 1) |c| table[c] = true;
    for ('a'..'z' + 1) |c| table[c] = true;
    for ('A'..'Z' + 1) |c| table[c] = true;
    break :blk table;
};

/// The pairs of an encoded form, as written: each name and value still
/// escaped, for `decode` to undo where the caller wants it undone. Empty
/// pieces between `&`s are skipped; a piece with no `=` is a name with an
/// empty value.
pub const Iterator = struct {
    text: []const u8,
    at: usize = 0,

    pub fn init(text: []const u8) Iterator {
        return .{ .text = text };
    }

    pub fn next(it: *Iterator) ?Pair {
        while (it.at < it.text.len) {
            const end = std.mem.findScalarPos(u8, it.text, it.at, '&') orelse it.text.len;
            const piece = it.text[it.at..end];
            it.at = end + 1;
            if (piece.len == 0) continue;
            if (std.mem.findScalar(u8, piece, '=')) |eq| return .{ .name = piece[0..eq], .value = piece[eq + 1 ..] };
            return .{ .name = piece, .value = "" };
        }
        return null;
    }
};

/// Undo the escaping of one name or value in place: `+` is a space, and
/// `%XX` its byte. A `%` not followed by two hex digits stays as it is, as
/// the standard has it. Returns the decoded bytes, a prefix of `text`.
pub fn decode(text: []u8) []u8 {
    var out: usize = 0;
    var i: usize = 0;
    while (i < text.len) : (out += 1) {
        const c = text[i];
        if (c == '+') {
            text[out] = ' ';
            i += 1;
        } else if (c == '%' and i + 2 < text.len and hexValue(text[i + 1]) != null and hexValue(text[i + 2]) != null) {
            text[out] = (hexValue(text[i + 1]).? << 4) | hexValue(text[i + 2]).?;
            i += 3;
        } else {
            text[out] = c;
            i += 1;
        }
    }
    return text[0..out];
}

fn hexValue(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

const testing = std.testing;

test "a form is written as browsers write it, and its length known first" {
    var buf: [128]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    const pairs = [_]Pair{
        .{ .name = "q", .value = "zig & http" },
        .{ .name = "name*", .value = "caf\xc3\xa9~/" },
        .{ .name = "", .value = "" },
    };
    try encode(&w, &pairs);
    try testing.expectEqualStrings("q=zig+%26+http&name*=caf%C3%A9%7E%2F&=", w.buffered());
    try testing.expectEqual(@as(u64, w.end), encodedLength(&pairs));
}

test "a form is read pair by pair and each piece decoded in place" {
    var it: Iterator = .init("a=1&&b&c=x%20y+z%2&d=%zz%41");
    const want = [_][2][]const u8{ .{ "a", "1" }, .{ "b", "" }, .{ "c", "x y z%2" }, .{ "d", "%zzA" } };
    for (want) |w| {
        const p = it.next().?;
        try testing.expectEqualStrings(w[0], p.name);
        var value_buf: [16]u8 = undefined;
        @memcpy(value_buf[0..p.value.len], p.value);
        try testing.expectEqualStrings(w[1], decode(value_buf[0..p.value.len]));
    }
    try testing.expectEqual(null, it.next());
}

test "fuzz: what is encoded decodes to itself" {
    try testing.fuzz({}, struct {
        fn one(_: void, smith: *testing.Smith) anyerror!void {
            var raw: [64]u8 = undefined;
            const text = raw[0..smith.slice(&raw)];
            var buf: [256]u8 = undefined;
            var w: Io.Writer = .fixed(&buf);
            try encodeText(&w, text);
            try testing.expectEqual(@as(u64, w.end), textLength(text));
            try testing.expectEqualSlices(u8, text, decode(w.buffered()));
        }
    }.one, .{});
}
