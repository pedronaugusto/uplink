//! Header fields (RFC 9110 §5): the grammar of names and values, the
//! read-only view a parsed head is read through, and the list syntax
//! (`1#element`) that `Connection`, `Transfer-Encoding` and their kind use.
//!
//! Nothing here allocates. A `Headers` is a view over fields that point into
//! the head's own bytes; the twenty names the framing and the client read are
//! found once, when the head is parsed, so asking for one is a table lookup.

const std = @import("std");

/// One field as it was received: slices into the head's bytes. The value
/// has its leading and trailing whitespace removed, and an obsolete line
/// fold replaced by spaces.
pub const Field = struct {
    name: []const u8,
    value: []const u8,
};

/// Whether `c` may appear in a token (RFC 9110 §5.6.2): a field name, a
/// method, a transfer coding.
pub fn isTokenChar(c: u8) bool {
    return token_chars[c];
}

/// Whether `text` is a non-empty token.
pub fn isToken(text: []const u8) bool {
    if (text.len == 0) return false;
    for (text) |c| if (!token_chars[c]) return false;
    return true;
}

/// Whether `text` may be sent as a field value (RFC 9110 §5.5): visible
/// characters, `obs-text`, spaces and tabs, with no control character, and
/// no whitespace at either end, which a recipient would strip.
pub fn isFieldValue(text: []const u8) bool {
    if (text.len == 0) return true;
    if (isWhitespace(text[0]) or isWhitespace(text[text.len - 1])) return false;
    return !hasControl(text);
}

/// Whether `text` holds a control character other than a horizontal tab:
/// NUL, CR, LF, DEL and the rest of C0. Sixteen bytes at a time.
pub fn hasControl(text: []const u8) bool {
    var i: usize = 0;
    while (i + 16 <= text.len) : (i += 16) {
        const v: @Vector(16, u8) = text[i..][0..16].*;
        const low = v < @as(@Vector(16, u8), @splat(0x20));
        const tab = v == @as(@Vector(16, u8), @splat('\t'));
        const del = v == @as(@Vector(16, u8), @splat(0x7f));
        if (@reduce(.Or, (low & ~tab) | del)) return true;
    }
    for (text[i..]) |c| if ((c < 0x20 and c != '\t') or c == 0x7f) return true;
    return false;
}

fn isWhitespace(c: u8) bool {
    return c == ' ' or c == '\t';
}

const token_chars: [256]bool = blk: {
    var table: [256]bool = @splat(false);
    for ("!#$%&'*+-.^_`|~") |c| table[c] = true;
    for ('0'..'9' + 1) |c| table[c] = true;
    for ('a'..'z' + 1) |c| table[c] = true;
    for ('A'..'Z' + 1) |c| table[c] = true;
    break :blk table;
};

/// The field names the framing and the client read, found once at parse.
pub const Known = enum(u8) {
    @"accept-encoding",
    @"alt-svc",
    connection,
    @"content-encoding",
    @"content-length",
    @"content-type",
    date,
    @"keep-alive",
    location,
    @"proxy-authenticate",
    @"proxy-connection",
    @"retry-after",
    server,
    @"set-cookie",
    te,
    trailer,
    @"transfer-encoding",
    upgrade,
    vary,
    @"www-authenticate",

    /// The known name `name` is, compared without case, or null: one
    /// switch on the length and the first letter, then one compare.
    pub fn of(name: []const u8) ?Known {
        if (name.len < 2 or name.len > longest) return null;
        const first = name[0] | 0x20;
        inline for (comptime std.enums.values(Known)) |k| {
            const text = @tagName(k);
            if (name.len == text.len and first == text[0] and eqlLower(name[1..], text[1..])) return k;
        }
        return null;
    }

    const longest = blk: {
        var n: usize = 0;
        for (std.enums.values(Known)) |k| n = @max(n, @tagName(k).len);
        break :blk n;
    };
};

/// Whether `a` equals `lower`, which is already lower case, ignoring the
/// case of `a`'s letters.
fn eqlLower(a: []const u8, lower: []const u8) bool {
    for (a, lower) |x, y| {
        if (std.ascii.toLower(x) != y) return false;
    }
    return true;
}

/// Where each known name first appears among a head's fields.
pub const Index = struct {
    /// `none` when the name is absent.
    first: [count]u16 = @splat(none),

    pub const none = std.math.maxInt(u16);
    const count = std.enums.values(Known).len;

    /// Note field `i`, named `name`.
    pub fn note(index: *Index, name: []const u8, i: usize) void {
        const k = Known.of(name) orelse return;
        const slot = &index.first[@backingInt(k)];
        if (slot.* == none) slot.* = @intCast(i);
    }
};

/// A read-only view of a head's fields, in the order they came.
pub const Headers = struct {
    fields: []const Field = &.{},
    index: Index = .{},

    /// A view over `fields`, indexing the known names.
    pub fn init(fields: []const Field) Headers {
        var h: Headers = .{ .fields = fields };
        for (fields, 0..) |f, i| h.index.note(f.name, i);
        return h;
    }

    /// The first value of the field `name`, compared without case.
    pub fn get(h: *const Headers, name: []const u8) ?[]const u8 {
        if (Known.of(name)) |k| return h.getKnown(k);
        for (h.fields) |f| if (std.ascii.eqlIgnoreCase(f.name, name)) return f.value;
        return null;
    }

    /// The first value of a known field.
    pub fn getKnown(h: *const Headers, k: Known) ?[]const u8 {
        const i = h.index.first[@backingInt(k)];
        if (i == Index.none) return null;
        return h.fields[i].value;
    }

    /// How many fields there are, repeated names counted each time.
    pub fn count(h: *const Headers) usize {
        return h.fields.len;
    }

    /// Every field, in order.
    pub fn iterator(h: *const Headers) Iterator {
        return .{ .fields = h.fields };
    }

    /// Every element of the list-valued field `name` (RFC 9110 §5.6.1),
    /// across every line it was sent on, with empty elements skipped.
    pub fn values(h: *const Headers, name: []const u8) ValueIterator {
        const start: usize = if (Known.of(name)) |k| blk: {
            const i = h.index.first[@backingInt(k)];
            break :blk if (i == Index.none) h.fields.len else i;
        } else 0;
        return .{ .fields = h.fields, .at = start, .name = name, .list = .{ .text = "" } };
    }

    /// Whether the list-valued field `name` holds the token `element`,
    /// compared without case: `Connection: close`, `Transfer-Encoding:
    /// chunked`.
    pub fn hasToken(h: *const Headers, name: []const u8, element: []const u8) bool {
        var it = h.values(name);
        while (it.next()) |e| if (std.ascii.eqlIgnoreCase(e, element)) return true;
        return false;
    }

    /// Fields in order.
    pub const Iterator = struct {
        fields: []const Field,
        at: usize = 0,

        pub fn next(it: *Iterator) ?Field {
            if (it.at == it.fields.len) return null;
            defer it.at += 1;
            return it.fields[it.at];
        }
    };

    /// List elements of one field name, across its lines.
    pub const ValueIterator = struct {
        fields: []const Field,
        at: usize,
        name: []const u8,
        list: ListIterator,

        pub fn next(it: *ValueIterator) ?[]const u8 {
            while (true) {
                if (it.list.next()) |e| return e;
                while (it.at < it.fields.len) {
                    const f = it.fields[it.at];
                    it.at += 1;
                    if (std.ascii.eqlIgnoreCase(f.name, it.name)) {
                        it.list = .{ .text = f.value };
                        break;
                    }
                } else return null;
            }
        }
    };
};

/// The elements of one `1#element` list value: split at commas outside
/// quoted strings, whitespace around each removed, empty ones skipped
/// (RFC 9110 §5.6.1). A quoted string is kept whole, quotes included.
pub const ListIterator = struct {
    text: []const u8,
    at: usize = 0,

    pub fn next(it: *ListIterator) ?[]const u8 {
        while (it.at < it.text.len) {
            const start = it.at;
            var quoted = false;
            var i = start;
            while (i < it.text.len) : (i += 1) {
                const c = it.text[i];
                if (quoted) {
                    if (c == '\\') {
                        i += 1;
                    } else if (c == '"') quoted = false;
                } else if (c == '"') {
                    quoted = true;
                } else if (c == ',') break;
            }
            const end = @min(i, it.text.len);
            it.at = end + 1;
            const element = std.mem.trim(u8, it.text[start..end], " \t");
            if (element.len != 0) return element;
        }
        return null;
    }
};

const testing = std.testing;

test "tokens, values and control characters are told apart as RFC 9110 says" {
    try testing.expect(isToken("Content-Length"));
    try testing.expect(isToken("X-!#$%&'*+.^_`|~"));
    try testing.expect(!isToken(""));
    try testing.expect(!isToken("Bad Name"));
    try testing.expect(!isToken("Bad:Name"));
    try testing.expect(!isToken("na\xffme"));
    try testing.expect(isFieldValue("text/html; charset=utf-8"));
    try testing.expect(isFieldValue("caf\xc3\xa9\twith tab"));
    try testing.expect(isFieldValue(""));
    try testing.expect(!isFieldValue(" leading"));
    try testing.expect(!isFieldValue("trailing\t"));
    for ([_]u8{ 0, '\r', '\n', 0x7f, 0x01, 0x1f }) |c| {
        var long: [40]u8 = @splat('a');
        for (0..long.len) |at| {
            long = @splat('a');
            long[at] = c;
            try testing.expect(hasControl(&long));
            try testing.expect(!isFieldValue(&long));
        }
    }
    try testing.expect(!hasControl("a\tb" ++ "a\tb" ++ "a\tb" ++ "a\tb" ++ "a\tb" ++ "a\tb" ++ "a\tb" ++ "a\tb" ++ "a\tb" ++ "a\tb"));
}

test "known names are found without case, and only whole" {
    try testing.expectEqual(Known.@"content-length", Known.of("Content-Length").?);
    try testing.expectEqual(Known.te, Known.of("TE").?);
    try testing.expectEqual(Known.@"www-authenticate", Known.of("WWW-Authenticate").?);
    try testing.expectEqual(null, Known.of("Content-Lengths"));
    try testing.expectEqual(null, Known.of("content-lengt"));
    try testing.expectEqual(null, Known.of("x"));
    try testing.expectEqual(null, Known.of(""));
}

test "a view finds the first value, every element, and keeps order" {
    const fields = [_]Field{
        .{ .name = "Connection", .value = "keep-alive, Upgrade" },
        .{ .name = "X-Thing", .value = "one" },
        .{ .name = "connection", .value = "\"quoted, comma\" ,, close" },
        .{ .name = "x-thing", .value = "two" },
    };
    const h: Headers = .init(&fields);
    try testing.expectEqualStrings("keep-alive, Upgrade", h.get("CONNECTION").?);
    try testing.expectEqualStrings("one", h.get("X-THING").?);
    try testing.expectEqual(null, h.get("Absent"));
    try testing.expectEqual(null, h.get("content-length"));
    try testing.expectEqual(@as(usize, 4), h.count());
    var it = h.values("connection");
    for ([_][]const u8{ "keep-alive", "Upgrade", "\"quoted, comma\"", "close" }) |want| {
        try testing.expectEqualStrings(want, it.next().?);
    }
    try testing.expectEqual(null, it.next());
    try testing.expect(h.hasToken("Connection", "CLOSE"));
    try testing.expect(!h.hasToken("Connection", "quoted"));
    var unknown = h.values("x-thing");
    try testing.expectEqualStrings("one", unknown.next().?);
    try testing.expectEqualStrings("two", unknown.next().?);
    try testing.expectEqual(null, unknown.next());
    var all = h.iterator();
    var n: usize = 0;
    while (all.next()) |_| n += 1;
    try testing.expectEqual(@as(usize, 4), n);
}

test "a list with an unterminated quote or a trailing escape ends at the text's end" {
    var it: ListIterator = .{ .text = "a, \"open, b\\" };
    try testing.expectEqualStrings("a", it.next().?);
    try testing.expectEqualStrings("\"open, b\\", it.next().?);
    try testing.expectEqual(null, it.next());
}
