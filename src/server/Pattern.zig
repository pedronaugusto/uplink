//! A route pattern, with Go 1.22's `ServeMux` grammar and semantics:
//! `[METHOD ][HOST]/PATH`, where a path segment is a literal, `{name}`
//! (one segment), `{name...}` (the rest of the path, last only) or `{$}`
//! (the end of a path that ends in `/`, last only), and a path ending in
//! `/` matches everything under it.
//!
//! Two patterns are compared by the requests they match: one is more
//! specific than another when it matches a strict subset of its requests;
//! two that each match some request the other does not, or that match the
//! same requests, conflict, and a router refuses the second. `GET` matches
//! `HEAD` too, and a pattern with a host is preferred to any without.
//!
//! Everything here is pure: the runtime router and the comptime one share
//! it, so a conflict is the same refusal in both, a compile error in the
//! second.

const std = @import("std");

const Pattern = @This();

/// The pattern as written.
text: []const u8,
/// The method, or null for any.
method: ?[]const u8,
/// The host, or null for any.
host: ?[]const u8,
/// The path's segments; a literal holds its text with escapes undone.
segments: []const Segment,

pub const Segment = struct {
    kind: Kind,
    /// A literal's text, or a wildcard's name ("" for the trailing `/`).
    text: []const u8,

    pub const Kind = enum {
        literal,
        /// `{name}`: one segment, not empty.
        wildcard,
        /// `{name...}` or a trailing `/`: the rest of the path, possibly
        /// nothing.
        multi,
        /// `{$}`: the end of a path whose last character is `/`.
        end,
    };
};

/// Why a pattern is refused.
pub const Error = error{
    /// Not `[METHOD ][HOST]/PATH`, a wildcard that is not a Zig-like name,
    /// `{name...}` or `{$}` not last, a wildcard inside a segment, a name
    /// used twice, or more segments than `out` holds.
    InvalidPattern,
};

/// The most wildcards a pattern may name.
pub const max_wildcards = 16;

/// How many segments `text`'s path has, for sizing `parse`'s `out`.
pub fn countSegments(text: []const u8) usize {
    const slash = std.mem.findScalar(u8, text, '/') orelse return 0;
    return std.mem.count(u8, text[slash + 1 ..], "/") + 1;
}

/// Parse `text`, its segments into `out`; literal segments with escapes
/// are unescaped into `scratch` (as long as the path will do).
pub fn parse(text: []const u8, out: []Segment, scratch: []u8) Error!Pattern {
    var rest = text;
    var method: ?[]const u8 = null;
    if (std.mem.findAny(u8, rest, " \t")) |space| {
        method = rest[0..space];
        if (method.?.len == 0) return error.InvalidPattern;
        for (method.?) |c| if (!isTokenChar(c)) return error.InvalidPattern;
        rest = std.mem.trimStart(u8, rest[space..], " \t");
    }
    const slash = std.mem.findScalar(u8, rest, '/') orelse return error.InvalidPattern;
    const host: ?[]const u8 = if (slash == 0) null else rest[0..slash];
    if (host) |h| if (std.mem.findAny(u8, h, "{}") != null) return error.InvalidPattern;
    const path = rest[slash..];
    var n: usize = 0;
    var at: usize = 1;
    var used: usize = 0;
    while (true) {
        const end = std.mem.findScalarPos(u8, path, at, '/') orelse path.len;
        const seg = path[at..end];
        const last = end == path.len;
        if (n == out.len) return error.InvalidPattern;
        if (seg.len == 0) {
            // An empty segment is only the trailing one: everything under.
            if (!last) return error.InvalidPattern;
            out[n] = .{ .kind = .multi, .text = "" };
            n += 1;
            break;
        }
        if (seg[0] == '{') {
            if (seg[seg.len - 1] != '}') return error.InvalidPattern;
            const inner = seg[1 .. seg.len - 1];
            if (std.mem.eql(u8, inner, "$")) {
                if (!last) return error.InvalidPattern;
                out[n] = .{ .kind = .end, .text = "" };
            } else if (std.mem.endsWith(u8, inner, "...")) {
                if (!last) return error.InvalidPattern;
                const name = inner[0 .. inner.len - 3];
                if (!isName(name)) return error.InvalidPattern;
                out[n] = .{ .kind = .multi, .text = name };
            } else {
                if (!isName(inner)) return error.InvalidPattern;
                out[n] = .{ .kind = .wildcard, .text = inner };
            }
        } else {
            if (std.mem.findAny(u8, seg, "{}") != null) return error.InvalidPattern;
            const unescaped = unescape(seg, scratch[used..]) orelse return error.InvalidPattern;
            used += unescaped.len;
            out[n] = .{ .kind = .literal, .text = unescaped };
        }
        n += 1;
        if (last) break;
        at = end + 1;
    }
    const segments = out[0..n];
    // Names are unique, and there are not too many of them.
    var names: usize = 0;
    for (segments, 0..) |a, i| {
        if (a.kind != .wildcard and !(a.kind == .multi and a.text.len != 0)) continue;
        names += 1;
        for (segments[i + 1 ..]) |b| if ((b.kind == .wildcard or b.kind == .multi) and std.mem.eql(u8, a.text, b.text)) return error.InvalidPattern;
    }
    if (names > max_wildcards) return error.InvalidPattern;
    return .{ .text = text, .method = method, .host = host, .segments = segments };
}

fn isTokenChar(c: u8) bool {
    return switch (c) {
        'a'...'z', 'A'...'Z', '0'...'9', '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        else => false,
    };
}

/// A wildcard's name: a letter or `_`, then letters, digits and `_`.
fn isName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name, 0..) |c, i| switch (c) {
        'a'...'z', 'A'...'Z', '_' => {},
        '0'...'9' => if (i == 0) return false,
        else => return false,
    };
    return true;
}

/// `text` with its `%XX` escapes undone into `out`; `text` itself when it
/// has none. Null for a broken escape or no room.
pub fn unescape(text: []const u8, out: []u8) ?[]const u8 {
    if (std.mem.findScalar(u8, text, '%') == null) return text;
    var n: usize = 0;
    var i: usize = 0;
    while (i < text.len) : (n += 1) {
        if (n == out.len) return null;
        if (text[i] == '%') {
            if (i + 2 >= text.len) return null;
            const hi = hexValue(text[i + 1]) orelse return null;
            const lo = hexValue(text[i + 2]) orelse return null;
            out[n] = hi << 4 | lo;
            i += 3;
        } else {
            out[n] = text[i];
            i += 1;
        }
    }
    return out[0..n];
}

fn hexValue(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}

/// Whether `escaped`, a request path's segment, is `literal` once its
/// escapes are undone, compared without a buffer.
pub fn eqlEscaped(literal: []const u8, escaped: []const u8) bool {
    var i: usize = 0;
    var j: usize = 0;
    while (j < escaped.len) : (i += 1) {
        if (i == literal.len) return false;
        var c = escaped[j];
        if (c == '%') {
            if (j + 2 >= escaped.len) return false;
            const hi = hexValue(escaped[j + 1]) orelse return false;
            const lo = hexValue(escaped[j + 2]) orelse return false;
            c = hi << 4 | lo;
            j += 3;
        } else j += 1;
        if (c != literal[i]) return false;
    }
    return i == literal.len;
}

/// Whether `path` (as sent, escapes in, starting with `/`) matches the
/// pattern's path; its wildcards' escaped values go into `values` in
/// order, and how many there are is returned.
pub fn matchPath(p: *const Pattern, path: []const u8, values: *[max_wildcards][]const u8) ?u8 {
    var rest = path[1..];
    var slash = true;
    var n: u8 = 0;
    for (p.segments) |seg| switch (seg.kind) {
        .multi => {
            if (!slash) return null;
            if (seg.text.len != 0) {
                values[n] = rest;
                n += 1;
            }
            return n;
        },
        .end => return if (slash and rest.len == 0) n else null,
        .literal, .wildcard => {
            if (!slash) return null;
            const cut = std.mem.findScalar(u8, rest, '/');
            const segment = rest[0 .. cut orelse rest.len];
            if (seg.kind == .literal) {
                if (!eqlEscaped(seg.text, segment)) return null;
            } else {
                if (segment.len == 0) return null;
                values[n] = segment;
                n += 1;
            }
            rest = if (cut) |c| rest[c + 1 ..] else "";
            slash = cut != null;
        },
    };
    return if (!slash and rest.len == 0) n else null;
}

/// Whether the pattern's method takes `method`: its own, `GET`'s for a
/// `HEAD`, or any for a pattern with none.
pub fn takesMethod(p: *const Pattern, method: []const u8) bool {
    const m = p.method orelse return true;
    return std.mem.eql(u8, m, method) or (std.mem.eql(u8, m, "GET") and std.mem.eql(u8, method, "HEAD"));
}

/// How the requests two patterns match relate.
pub const Relation = enum {
    /// The same requests.
    equivalent,
    /// The first matches all the second does, and more.
    more_general,
    /// The first matches a strict subset of the second's.
    more_specific,
    /// No request both match.
    disjoint,
    /// Some request both match, and each matches some the other does not.
    overlaps,

    fn inverse(r: Relation) Relation {
        return switch (r) {
            .more_general => .more_specific,
            .more_specific => .more_general,
            else => r,
        };
    }

    fn combine(r1: Relation, r2: Relation) Relation {
        return switch (r1) {
            .equivalent => r2,
            .disjoint => .disjoint,
            .overlaps => if (r2 == .disjoint) .disjoint else .overlaps,
            .more_general, .more_specific => if (r2 == .equivalent) r1 else if (r2 == r1.inverse()) .overlaps else r2,
        };
    }
};

fn compareSegments(s1: Segment, s2: Segment) Relation {
    if (s1.kind == .multi and s2.kind == .multi) return .equivalent;
    if (s1.kind == .multi) return .more_general;
    if (s2.kind == .multi) return .more_specific;
    if (s1.kind == .wildcard and s2.kind == .wildcard) return .equivalent;
    if (s1.kind == .wildcard) return if (s2.kind == .end) .disjoint else .more_general;
    if (s2.kind == .wildcard) return if (s1.kind == .end) .disjoint else .more_specific;
    if (s1.kind == .end and s2.kind == .end) return .equivalent;
    if (s1.kind == .end or s2.kind == .end) return .disjoint;
    return if (std.mem.eql(u8, s1.text, s2.text)) .equivalent else .disjoint;
}

fn comparePaths(p1: *const Pattern, p2: *const Pattern) Relation {
    const last1 = p1.segments[p1.segments.len - 1].kind;
    const last2 = p2.segments[p2.segments.len - 1].kind;
    if (p1.segments.len != p2.segments.len and last1 != .multi and last2 != .multi) return .disjoint;
    var rel: Relation = .equivalent;
    const common = @min(p1.segments.len, p2.segments.len);
    for (p1.segments[0..common], p2.segments[0..common]) |a, b| {
        rel = rel.combine(compareSegments(a, b));
        if (rel == .disjoint) return rel;
    }
    if (p1.segments.len == p2.segments.len) return rel;
    // The longer goes on past the shorter's multi, which matches its rest.
    if (p1.segments.len < p2.segments.len and last1 == .multi) return rel.combine(.more_general);
    if (p2.segments.len < p1.segments.len and last2 == .multi) return rel.combine(.more_specific);
    return .disjoint;
}

fn compareMethods(p1: *const Pattern, p2: *const Pattern) Relation {
    const m1 = p1.method orelse return if (p2.method == null) .equivalent else .more_general;
    const m2 = p2.method orelse return .more_specific;
    if (std.mem.eql(u8, m1, m2)) return .equivalent;
    if (std.mem.eql(u8, m1, "GET") and std.mem.eql(u8, m2, "HEAD")) return .more_general;
    if (std.mem.eql(u8, m1, "HEAD") and std.mem.eql(u8, m2, "GET")) return .more_specific;
    return .disjoint;
}

/// How the requests `p1` matches relate to those `p2` matches, hosts
/// aside.
pub fn compare(p1: *const Pattern, p2: *const Pattern) Relation {
    return compareMethods(p1, p2).combine(comparePaths(p1, p2));
}

/// Whether a router may not hold both: the same host, and the same
/// requests or overlapping ones with neither more specific.
pub fn conflicts(p1: *const Pattern, p2: *const Pattern) bool {
    if (!optionalEql(p1.host, p2.host)) return false;
    const rel = p1.compare(p2);
    return rel == .equivalent or rel == .overlaps;
}

fn optionalEql(a: ?[]const u8, b: ?[]const u8) bool {
    const x = a orelse return b == null;
    const y = b orelse return false;
    return std.ascii.eqlIgnoreCase(x, y);
}

const testing = std.testing;

fn parsed(text: []const u8, storage: []Segment, scratch: []u8) !Pattern {
    return parse(text, storage, scratch);
}

test "patterns are read as Go 1.22 writes them" {
    var seg: [8]Segment = undefined;
    var scratch: [64]u8 = undefined;
    const p = try parse("GET example.com/a/{id}/b%20c/{rest...}", &seg, &scratch);
    try testing.expectEqualStrings("GET", p.method.?);
    try testing.expectEqualStrings("example.com", p.host.?);
    try testing.expectEqual(@as(usize, 4), p.segments.len);
    try testing.expectEqualStrings("b c", p.segments[2].text);
    try testing.expectEqual(Segment.Kind.multi, p.segments[3].kind);
    const tree = try parse("/static/", &seg, &scratch);
    try testing.expectEqual(Segment.Kind.multi, tree.segments[1].kind);
    try testing.expectEqual(Segment.Kind.end, (try parse("/{$}", &seg, &scratch)).segments[0].kind);
    for ([_][]const u8{ "", "GET", "{h}/a", "/{x...}/y", "/{$}/y", "/a{x}", "/{1x}", "/{x}/{x}", "/a//b", "/%zz", " /a" }) |bad| {
        testing.expectError(error.InvalidPattern, parse(bad, &seg, &scratch)) catch |err| {
            std.debug.print("accepted {s}\n", .{bad});
            return err;
        };
    }
    try testing.expectEqual(@as(usize, 3), countSegments("GET /a/b/"));
}

test "specificity and conflicts follow Go's rules" {
    var s1: [8]Segment = undefined;
    var s2: [8]Segment = undefined;
    var x1: [32]u8 = undefined;
    var x2: [32]u8 = undefined;
    const Case = struct { []const u8, []const u8, Relation };
    const cases = [_]Case{
        .{ "/a", "/a", .equivalent },
        .{ "/a", "/b", .disjoint },
        .{ "/a/{x}", "/a/b", .more_general },
        .{ "/a/", "/a/b/c", .more_general },
        .{ "/a/{x}", "/{y}/b", .overlaps },
        .{ "/{$}", "/", .more_specific },
        .{ "/{x}", "/{$}", .disjoint },
        .{ "GET /a", "/a", .more_specific },
        .{ "GET /a", "HEAD /a", .more_general },
        .{ "GET /a", "POST /a", .disjoint },
        .{ "GET /{x}", "/a", .overlaps },
        .{ "/a/{x...}", "/a/", .equivalent },
    };
    for (cases) |case| {
        const a = try parsed(case[0], &s1, &x1);
        const b = try parsed(case[1], &s2, &x2);
        testing.expectEqual(case[2], a.compare(&b)) catch |err| {
            std.debug.print("{s} vs {s}\n", .{ case[0], case[1] });
            return err;
        };
        try testing.expectEqual(case[2].inverse(), b.compare(&a));
    }
    try testing.expect((try parsed("/a/{x}", &s1, &x1)).conflicts(&try parsed("/a/{y}", &s2, &x2)));
    try testing.expect(!(try parsed("h.com/a", &s1, &x1)).conflicts(&try parsed("/a", &s2, &x2)));
}

test "a request segment matches a literal with its escapes undone" {
    try testing.expect(eqlEscaped("b c", "b%20c"));
    try testing.expect(eqlEscaped("abc", "abc"));
    try testing.expect(!eqlEscaped("ab", "abc"));
    try testing.expect(!eqlEscaped("abc", "ab"));
    try testing.expect(eqlEscaped("a/b", "a%2Fb"));
    try testing.expect(!eqlEscaped("a", "%4"));
    var out: [8]u8 = undefined;
    try testing.expectEqualStrings("a b", unescape("a%20b", &out).?);
    try testing.expectEqual(null, unescape("a%2", &out));
}

test "a path is matched segment by segment, its captures in order" {
    var seg: [8]Segment = undefined;
    var scratch: [32]u8 = undefined;
    var values: [max_wildcards][]const u8 = undefined;
    const p = try parse("/a/{x}/c/{rest...}", &seg, &scratch);
    try testing.expectEqual(@as(?u8, 2), p.matchPath("/a/b%2F/c/d/e", &values));
    try testing.expectEqualStrings("b%2F", values[0]);
    try testing.expectEqualStrings("d/e", values[1]);
    try testing.expectEqual(@as(?u8, 2), p.matchPath("/a/b/c/", &values));
    try testing.expectEqualStrings("", values[1]);
    try testing.expectEqual(null, p.matchPath("/a/b/c", &values));
    try testing.expectEqual(null, p.matchPath("/a//c/d", &values));
    const end = try parse("/a/{$}", &seg, &scratch);
    try testing.expectEqual(@as(?u8, 0), end.matchPath("/a/", &values));
    try testing.expectEqual(null, end.matchPath("/a/b", &values));
    const exact = try parse("/a", &seg, &scratch);
    try testing.expectEqual(@as(?u8, 0), exact.matchPath("/a", &values));
    try testing.expectEqual(null, exact.matchPath("/a/", &values));
}
