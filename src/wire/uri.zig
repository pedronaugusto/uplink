//! URIs and IRIs, strictly: RFC 3986's generic syntax with every component's grammar, and RFC
//! 3987's IRIs, which allow `ucschar` in every component and `iprivate` in the query. The family's
//! one URI recognizer: JSON Schema's `uri`, `uri-reference`, `iri` and `iri-reference` formats are
//! `check`, and `$id` and `$ref` resolve through `resolve`. Sans I/O and allocation-free; it reads
//! only the text it is given.
//!
//! Every slice in a `Reference` (and its `Authority` and `Host`) points into the text it was parsed
//! from: a caller may compute a component's offset as `component.ptr - text.ptr`.
const std = @import("std");
const aegis = @import("aegis");

/// RFC 3986's characters, or RFC 3987's: UTF-8, `ucschar` in every component, `iprivate` in the
/// query.
pub const Charset = enum { uri, iri };

/// The production a text must be.
pub const Form = enum {
    /// `URI`: a scheme, a fragment allowed. JSON Schema's `uri` (`iri` in the IRI charset).
    uri,
    /// `URI-reference`: a `URI` or a `relative-ref`. JSON Schema's `uri-reference`.
    reference,
    /// `absolute-URI`: a scheme and no fragment (a base URI).
    absolute,
    /// `relative-ref`: no scheme.
    relative,
};

pub const Host = union(enum) {
    /// An RFC 3986 `IPv6address`, without its brackets.
    ipv6: []const u8,
    /// An `IPvFuture` (`v1.x`), without its brackets.
    ipv_future: []const u8,
    /// An `IPv4address`: four dec-octets, no leading zeros.
    ipv4: [4]u8,
    /// A `reg-name` (`ireg-name` in the IRI charset), possibly empty.
    name: []const u8,
};

pub const Authority = struct {
    /// The userinfo before `@`, without the `@`.
    userinfo: ?[]const u8,
    host: Host,
    /// The host as written, brackets and all.
    host_text: []const u8,
    /// The digits after `:`, possibly none (`http://a:/` has an empty port).
    port: ?[]const u8,
};

/// A reference taken apart. Every slice points into the text it was parsed from. `authority` is
/// present after `//`; `query` and `fragment` are present after `?` and `#`, possibly empty.
pub const Reference = struct {
    scheme: ?[]const u8 = null,
    authority: ?Authority = null,
    path: []const u8 = "",
    query: ?[]const u8 = null,
    fragment: ?[]const u8 = null,

    /// The narrowest production it is: `absolute`, `uri`, or `relative`.
    pub fn form(r: Reference) Form {
        if (r.scheme == null) return .relative;
        return if (r.fragment == null) .absolute else .uri;
    }

    /// RFC 3986 §5.3's recomposition: the text it was parsed from.
    pub fn format(r: Reference, w: *std.Io.Writer) std.Io.Writer.Error!void {
        if (r.scheme) |s| try w.print("{s}:", .{s});
        if (r.authority) |a| {
            try w.writeAll("//");
            if (a.userinfo) |u| try w.print("{s}@", .{u});
            try w.writeAll(a.host_text);
            if (a.port) |p| try w.print(":{s}", .{p});
        }
        try w.writeAll(r.path);
        if (r.query) |q| try w.print("?{s}", .{q});
        if (r.fragment) |f| try w.print("#{s}", .{f});
    }
};

pub const ParseError = error{Invalid};

/// Where reading stopped, and what was expected there.
pub const Diagnostic = struct {
    offset: usize = 0,
    expected: []const u8 = "",
};

// Character classes.

const Set = std.StaticBitSet(128);

fn set(comptime chars: []const u8) Set {
    var s: Set = .empty;
    for (chars) |c| s.set(c);
    return s;
}

fn merge(comptime sets: []const Set) Set {
    var s: Set = .empty;
    for (sets) |x| s.setUnion(x);
    return s;
}

const alpha = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz");
const digit = set("0123456789");
const unreserved = merge(&.{ alpha, digit, set("-._~") });
const sub_delims = set("!$&'()*+,;=");
const pchar = merge(&.{ unreserved, sub_delims, set(":@") });
const query_chars = merge(&.{ pchar, set("/?") });
const userinfo_chars = merge(&.{ unreserved, sub_delims, set(":") });
const reg_name_chars = merge(&.{ unreserved, sub_delims });
const segment_nz_nc = merge(&.{ unreserved, sub_delims, set("@") });
const scheme_chars = merge(&.{ alpha, digit, set("+-.") });

/// RFC 3987's `ucschar`: every plane's characters but its last two, from U+A0, less the
/// surrogates, the noncharacters U+FDD0-FDEF, and the private use areas (`iprivate`).
fn ucschar(c: u21) bool {
    return switch (c) {
        0xA0...0xD7FF, 0xF900...0xFDCF, 0xFDF0...0xFFEF => true,
        // Planes 1 to 13 but each plane's last two; plane 14 from U+E1000.
        0x10000...0xDFFFF => (c & 0xFFFF) <= 0xFFFD,
        0xE1000...0xEFFFD => true,
        else => false,
    };
}

/// RFC 3987's `iprivate`: the private use areas.
fn iprivate(c: u21) bool {
    return switch (c) {
        0xE000...0xF8FF, 0xF0000...0xFFFFD, 0x100000...0x10FFFD => true,
        else => false,
    };
}

/// The bidi formatting characters RFC 3987 §4.1 forbids in an IRI.
fn bidiFormatting(c: u21) bool {
    return c == 0x200E or c == 0x200F or (c >= 0x202A and c <= 0x202E);
}

const Reader = struct {
    text: []const u8,
    charset: Charset,
    diagnostic: ?*Diagnostic,

    fn fail(r: *const Reader, at: usize, expected: []const u8) ParseError {
        if (r.diagnostic) |d| d.* = .{ .offset = at, .expected = expected };
        return error.Invalid;
    }

    /// Checks `s` (at `start` in the text) holds only `allowed`, percent-encodings and, in the IRI
    /// charset, `ucschar` (and `iprivate` where `private`).
    fn chars(r: *const Reader, start: usize, s: []const u8, comptime allowed: Set, private: bool, expected: []const u8) ParseError!void {
        var i: usize = 0;
        while (i < s.len) {
            const c = s[i];
            if (c == '%') {
                if (i + 2 >= s.len or !std.ascii.isHex(s[i + 1]) or !std.ascii.isHex(s[i + 2])) return r.fail(start + i, "two hex digits after '%'");
                i += 3;
                continue;
            }
            if (c < 0x80) {
                if (!allowed.isSet(c)) return r.fail(start + i, expected);
                i += 1;
                continue;
            }
            if (r.charset == .uri) return r.fail(start + i, "ASCII: a URI has no other characters");
            const len = std.unicode.utf8ByteSequenceLength(c) catch return r.fail(start + i, "UTF-8");
            if (i + len > s.len) return r.fail(start + i, "UTF-8");
            const cp = std.unicode.utf8Decode(s[i..][0..len]) catch return r.fail(start + i, "UTF-8");
            if (bidiFormatting(cp)) return r.fail(start + i, "no bidi formatting character");
            if (!(ucschar(cp) or (private and iprivate(cp)))) return r.fail(start + i, if (private) "ucschar or iprivate" else "ucschar");
            i += len;
        }
    }

    fn authority(r: *const Reader, start: usize, s: []const u8) ParseError!Authority {
        var a: Authority = .{ .userinfo = null, .host = undefined, .host_text = undefined, .port = null };
        var rest = s;
        var at = start;
        if (std.mem.findScalarLast(u8, rest, '@')) |i| {
            try r.chars(at, rest[0..i], userinfo_chars, false, "a userinfo character");
            a.userinfo = rest[0..i];
            rest = rest[i + 1 ..];
            at += i + 1;
        }
        // The port: after the last ':' that follows the host (an IPv6 literal holds colons).
        var host_end = rest.len;
        if (rest.len > 0 and rest[0] == '[') {
            const close = std.mem.findScalar(u8, rest, ']') orelse return r.fail(at, "']' closing the IP literal");
            host_end = close + 1;
            if (host_end < rest.len and rest[host_end] != ':') return r.fail(at + host_end, "':' and a port, or the authority's end");
        } else if (std.mem.findScalarLast(u8, rest, ':')) |i| host_end = i;
        if (host_end < rest.len) {
            const port = rest[host_end + 1 ..];
            for (port, 0..) |c, i| if (!std.ascii.isDigit(c)) return r.fail(at + host_end + 1 + i, "a port digit");
            a.port = port;
        }
        const host = rest[0..host_end];
        a.host_text = host;
        a.host = try r.hostOf(at, host);
        return a;
    }

    fn hostOf(r: *const Reader, at: usize, host: []const u8) ParseError!Host {
        if (host.len > 0 and host[0] == '[') {
            const inner = host[1 .. host.len - 1];
            if (inner.len > 0 and (inner[0] == 'v' or inner[0] == 'V')) {
                const dot = std.mem.findScalar(u8, inner, '.') orelse return r.fail(at + 1, "'.' in an IPvFuture");
                if (dot < 2) return r.fail(at + 2, "a hex digit after 'v'");
                for (inner[1..dot], 0..) |c, i| if (!std.ascii.isHex(c)) return r.fail(at + 2 + i, "a hex digit");
                if (dot + 1 == inner.len) return r.fail(at + 1 + inner.len, "a character after '.'");
                for (inner[dot + 1 ..], 0..) |c, i| {
                    if (c >= 0x80 or !userinfo_chars.isSet(c)) return r.fail(at + 2 + dot + i, "an IPvFuture character");
                }
                return .{ .ipv_future = inner };
            }
            if (!ipv6(inner)) return r.fail(at + 1, "an IPv6 address (no zone identifier)");
            return .{ .ipv6 = inner };
        }
        if (ipv4(host)) |octets| return .{ .ipv4 = octets };
        try r.chars(at, host, reg_name_chars, false, "a host character");
        return .{ .name = host };
    }
};

/// RFC 3986's `dec-octet`: 0 to 255, no leading zero.
fn decOctet(s: []const u8) ?u8 {
    if (s.len == 0 or s.len > 3) return null;
    for (s) |c| if (!std.ascii.isDigit(c)) return null;
    if (s.len > 1 and s[0] == '0') return null;
    const v = std.fmt.parseInt(u16, s, 10) catch return null;
    return if (v > 255) null else @intCast(v);
}

/// RFC 3986's `IPv4address`.
fn ipv4(s: []const u8) ?[4]u8 {
    var out: [4]u8 = undefined;
    var parts = std.mem.splitScalar(u8, s, '.');
    var i: usize = 0;
    while (parts.next()) |part| : (i += 1) {
        if (i == 4) return null;
        out[i] = decOctet(part) orelse return null;
    }
    return if (i == 4) out else null;
}

fn h16(s: []const u8) bool {
    if (s.len == 0 or s.len > 4) return false;
    for (s) |c| if (!std.ascii.isHex(c)) return false;
    return true;
}

/// RFC 3986's `IPv6address`, all nine of its forms: eight groups of `h16` (the last two possibly an
/// IPv4 address), or fewer with one `::` standing for the rest.
fn ipv6(s: []const u8) bool {
    if (s.len < 2) return false;
    const gap = std.mem.find(u8, s, "::");
    if (gap) |g| if (std.mem.findPos(u8, s, g + 1, "::") != null) return false;
    // The groups before and after the gap (or all of them, where there is none).
    const head = if (gap) |g| s[0..g] else s;
    const tail = if (gap) |g| s[g + 2 ..] else "";
    var groups: usize = 0;
    for ([_][]const u8{ head, tail }, 0..) |part, which| {
        if (part.len == 0) continue;
        var it = std.mem.splitScalar(u8, part, ':');
        while (it.next()) |g| {
            const last = it.peek() == null and (which == 1 or gap == null);
            if (last and std.mem.findScalar(u8, g, '.') != null) {
                if (ipv4(g) == null) return false;
                groups += 2;
            } else {
                if (!h16(g)) return false;
                groups += 1;
            }
        }
    }
    if (gap == null) return groups == 8;
    // `::` stands for at least one group.
    return groups <= 7;
}

/// Takes `text` apart as `form` in `charset`, or refuses it with where and why in `diagnostic`.
pub fn parse(text: aegis.input.Untrusted([]const u8), form: Form, charset: Charset, diagnostic: ?*Diagnostic) ParseError!Reference {
    const s = text.readForParse();
    const r: Reader = .{ .text = s, .charset = charset, .diagnostic = diagnostic };
    var out: Reference = .{};
    // The fragment and the query, from the first '#' and the first '?' before it.
    var rest = s;
    if (std.mem.findScalar(u8, rest, '#')) |h| {
        out.fragment = rest[h + 1 ..];
        try r.chars(h + 1, out.fragment.?, query_chars, false, "a fragment character");
        rest = rest[0..h];
    }
    if (std.mem.findScalar(u8, rest, '?')) |q| {
        out.query = rest[q + 1 ..];
        try r.chars(q + 1, out.query.?, query_chars, true, "a query character");
        rest = rest[0..q];
    }
    // The scheme: letters first, up to a ':' before any '/'.
    var at: usize = 0;
    if (rest.len > 0 and rest[0] < 0x80 and alpha.isSet(rest[0])) {
        var i: usize = 1;
        while (i < rest.len and rest[i] < 0x80 and scheme_chars.isSet(rest[i])) i += 1;
        if (i < rest.len and rest[i] == ':') {
            out.scheme = rest[0..i];
            rest = rest[i + 1 ..];
            at = i + 1;
        }
    }
    switch (form) {
        .uri, .absolute => if (out.scheme == null) return r.fail(0, "a scheme and ':'"),
        .relative => if (out.scheme != null) return r.fail(0, "no scheme"),
        .reference => {},
    }
    if (form == .absolute and out.fragment != null) return r.fail(s.len - out.fragment.?.len - 1, "no fragment");
    // The authority after "//", to the path's first '/'.
    if (std.mem.startsWith(u8, rest, "//")) {
        const end = std.mem.findScalarPos(u8, rest, 2, '/') orelse rest.len;
        out.authority = try r.authority(at + 2, rest[2..end]);
        at += end;
        rest = rest[end..];
    }
    out.path = rest;
    // The path: segments of `pchar`; without a scheme or an authority the first segment has no ':'
    // (`path-noscheme`), and without an authority it does not begin with "//".
    if (out.authority == null and std.mem.startsWith(u8, rest, "//")) return r.fail(at, "a path not beginning with \"//\"");
    var segments = std.mem.splitScalar(u8, rest, '/');
    var offset = at;
    var first = true;
    while (segments.next()) |segment| {
        const relative_first = first and out.scheme == null and out.authority == null and segment.len > 0;
        if (relative_first) {
            try r.chars(offset, segment, segment_nz_nc, false, "a first segment with no ':' (a relative path)");
        } else {
            try r.chars(offset, segment, pchar, false, "a path character");
        }
        offset += segment.len + 1;
        first = false;
    }
    return out;
}

/// Whether `text` is exactly the production `form` in `charset`: JSON Schema's `uri` (`.uri`,
/// `.uri`), `uri-reference` (`.reference`, `.uri`), `iri` (`.uri`, `.iri`) and `iri-reference`
/// (`.reference`, `.iri`).
pub fn check(text: []const u8, form: Form, charset: Charset) bool {
    _ = parse(.init(text), form, charset, null) catch return false;
    return true;
}
