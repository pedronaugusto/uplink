//! The parts of an `http` or `https` URL a request is made from: where it
//! goes, and the request target (RFC 9112 §3.2) that names what it asks for.
//! Everything is checked here, so nothing in a URL can put a byte on the
//! wire that a request line or a `Host` field does not allow.
//!
//! This module reads what HTTP carries (a `Location` field, an href in a
//! server's reply), so it is lenient the way browsers and HTTP clients
//! are, on purpose. The strict recognizer is `uri`; this one is not a
//! stricter or looser version of it but a different job, and is not to be
//! made strict.

const std = @import("std");
const fields = @import("fields.zig");
const uri = @import("uri.zig");

/// A URL taken apart. Every slice points into the text it was parsed from.
pub const Url = struct {
    /// `https`: TLS is spoken to the host.
    secure: bool,
    /// The host, without IPv6 brackets.
    host: []const u8,
    port: u16,
    /// The path and query as the URL has them, percent-encoded. An empty
    /// path is sent as `/` (RFC 9112 §3.2.1): see `writeTarget`.
    target: []const u8,

    /// Whether `port` is the scheme's own, which a `Host` field leaves out.
    pub fn defaultPort(u: Url) bool {
        return u.port == @as(u16, if (u.secure) 443 else 80);
    }

    /// Whether the host is an IPv6 address, bracketed in an authority.
    pub fn ipv6(u: Url) bool {
        return std.mem.findScalar(u8, u.host, ':') != null;
    }

    /// Write the origin-form target: the path and query, `/` for an empty
    /// path, each byte past ASCII percent-encoded as browsers encode it
    /// (RFC 9112's request target is ASCII).
    pub fn writeTarget(u: Url, w: *std.Io.Writer) std.Io.Writer.Error!void {
        if (u.target.len == 0 or u.target[0] != '/') try w.writeByte('/');
        var start: usize = 0;
        for (u.target, 0..) |c, i| if (c >= 0x80) {
            try w.writeAll(u.target[start..i]);
            try w.print("%{X:0>2}", .{c});
            start = i + 1;
        };
        try w.writeAll(u.target[start..]);
    }

    /// The target `writeTarget` writes, for a field that names it (a
    /// Digest answer's `uri`): `target` itself where it is written as it
    /// is, else written into `buffer`.
    pub fn originTarget(u: Url, buffer: []u8) error{NoSpaceLeft}![]const u8 {
        const ascii = for (u.target) |c| {
            if (c >= 0x80) break false;
        } else true;
        if (ascii and u.target.len != 0 and u.target[0] == '/') return u.target;
        var w: std.Io.Writer = .fixed(buffer);
        u.writeTarget(&w) catch return error.NoSpaceLeft;
        return w.buffered();
    }

    /// Write `host[:port]` as a `Host` field or an authority has it.
    pub fn writeAuthority(u: Url, w: *std.Io.Writer, always_port: bool) std.Io.Writer.Error!void {
        if (u.ipv6()) {
            try w.print("[{s}]", .{u.host});
        } else try w.writeAll(u.host);
        if (always_port or !u.defaultPort()) try w.print(":{d}", .{u.port});
    }
};

/// Why a URL was refused.
pub const ParseError = error{
    /// Not a URL, no host, a control character, space or tab anywhere, or
    /// a user and password, which go in an `Authorization` field instead.
    InvalidUrl,
    /// A scheme other than `http` or `https`.
    UnsupportedScheme,
};

/// Take `text` apart. The fragment is dropped: it is never sent.
///
/// Lenient on purpose: it refuses what could put a byte on the wire that
/// does not belong there (a control character, a space, a tab), a user and
/// password, and a `%` or `\` in a name, and otherwise takes what RFC 3986
/// refuses: bytes past ASCII (a host in UTF-8 is IDNA's to convert, and
/// `writeTarget` percent-encodes them in the path and query),
/// `"` `<` `>` `[` `]` `^` `` ` `` `{` `|` `}` anywhere;
/// `\` and a `%` not followed by two hex digits in the path and query;
/// anything between an IPv6 literal's brackets, and anything after them
/// before the port, which is dropped; and a port written with a `+` sign
/// or `_` between digits.
pub fn parse(text: []const u8) ParseError!Url {
    if (fields.hasControl(text) or std.mem.findAny(u8, text, " \t") != null) return error.InvalidUrl;
    const p = try parts(text);
    const secure = if (std.ascii.eqlIgnoreCase(p.scheme, "https"))
        true
    else if (std.ascii.eqlIgnoreCase(p.scheme, "http"))
        false
    else
        return error.UnsupportedScheme;
    if (p.user != null or p.password != null) return error.InvalidUrl;
    const raw_host = p.host orelse return error.InvalidUrl;
    // A percent-encoded host would need decoding to be looked up; names
    // that need it are IDNA's, which callers pass as punycode.
    if (std.mem.findScalar(u8, raw_host, '%') != null and raw_host[0] != '[') return error.InvalidUrl;
    const host = if (raw_host.len >= 2 and raw_host[0] == '[' and raw_host[raw_host.len - 1] == ']') raw_host[1 .. raw_host.len - 1] else raw_host;
    if (host.len == 0 or std.mem.findAny(u8, host, "/@?#\\") != null) return error.InvalidUrl;
    return .{
        .secure = secure,
        .host = host,
        .port = p.port orelse @as(u16, if (secure) 443 else 80),
        .target = p.target,
    };
}

/// Whether `c` is one of the URL Standard's forbidden domain code points: a
/// forbidden host code point (NUL, tab, LF, CR, space, `#` `/` `:` `<` `>`
/// `?` `@` `[` `\` `]` `^` `|`), any other C0 control, `%` or DEL. The
/// URL Standard's host parser refuses a host whose domain-to-ASCII result
/// holds one; `parse` refuses some of them itself, and a client checks the
/// rest once IDNA has given the host's ASCII form.
pub fn forbiddenDomainCodePoint(c: u8) bool {
    return c < 0x20 or c == 0x7f or std.mem.findScalar(u8, " #%/:<>?@[\\]^|", c) != null;
}

/// A URL's parts as `parts` reads them. Every slice points into the text;
/// the user, password and host are as written, percent-encoded.
pub const Parts = struct {
    scheme: []const u8,
    user: ?[]const u8 = null,
    /// Null when empty.
    password: ?[]const u8 = null,
    /// With an IPv6 literal's brackets.
    host: ?[]const u8 = null,
    port: ?u16 = null,
    /// The path and query, to the fragment.
    target: []const u8,
};

/// `text` read as HTTP clients read a URL, on Appendix B's split: a scheme
/// of a letter and then letters, digits, `+`, `-` and `.`; the userinfo to
/// the authority's last `@`, the user to its first `:`; a host bracketed
/// to the last `]` or else to the last `:`, after which a decimal `u16`
/// port; no more than a host name's 254 bytes. An empty authority is taken
/// only before a path. Nothing else is checked: that is for the caller.
pub fn parts(text: []const u8) error{InvalidUrl}!Parts {
    const s = uri.split(text);
    const scheme = s.scheme orelse return error.InvalidUrl;
    if (!validScheme(scheme)) return error.InvalidUrl;
    const fragment_len = if (s.fragment) |f| f.len + 1 else 0;
    const authority_len = if (s.authority) |a| a.len + 2 else 0;
    var p: Parts = .{ .scheme = scheme, .target = text[scheme.len + 1 + authority_len .. text.len - fragment_len] };
    const authority = s.authority orelse return p;
    if (authority.len == 0) {
        if (s.path.len == 0) return error.InvalidUrl;
        return p;
    }
    var start: usize = 0;
    if (std.mem.findScalarLast(u8, authority, '@')) |at| {
        start = at + 1;
        const info = authority[0..at];
        if (std.mem.findScalar(u8, info, ':')) |colon| {
            p.user = info[0..colon];
            if (colon + 1 < info.len) p.password = info[colon + 1 ..];
        } else p.user = info;
    }
    if (start >= authority.len) return p;
    if (authority[start] == ']') return error.InvalidUrl;
    var end = authority.len;
    if (authority[start] == '[') {
        end = (std.mem.findScalarLast(u8, authority, ']') orelse return error.InvalidUrl) + 1;
        if (std.mem.findScalarLast(u8, authority, ':')) |colon| if (colon >= end) {
            p.port = std.fmt.parseInt(u16, authority[colon + 1 ..], 10) catch return error.InvalidUrl;
        };
    } else if (std.mem.findScalarLast(u8, authority, ':')) |colon| if (colon >= start) {
        end = colon;
        p.port = std.fmt.parseInt(u16, authority[colon + 1 ..], 10) catch return error.InvalidUrl;
    };
    if (start >= end) return error.InvalidUrl;
    if (end - start > std.Io.net.HostName.max_len) return error.InvalidUrl;
    p.host = authority[start..end];
    return p;
}

/// `text` with each `%` and two hex digits undone, into `out`, at least as
/// long; a `%` without them is kept. `out` may be `text`.
pub fn percentDecode(out: []u8, text: []const u8) []u8 {
    var n: usize = 0;
    var i: usize = 0;
    while (i < text.len) : (n += 1) {
        if (text[i] == '%' and text.len - i >= 3) {
            // glint-ignore: Z026 -- a `%` without two hex digits is kept as it is
            if (std.fmt.parseInt(u8, text[i + 1 ..][0..2], 16)) |byte| {
                out[n] = byte;
                i += 3;
                continue;
            } else |_| {}
        }
        out[n] = text[i];
        i += 1;
    }
    return out[0..n];
}

/// A scheme: a letter, then letters, digits, `+`, `-` and `.`.
fn validScheme(scheme: []const u8) bool {
    if (scheme.len == 0 or !std.ascii.isAlphabetic(scheme[0])) return false;
    for (scheme[1..]) |c| if (!std.ascii.isAlphanumeric(c) and c != '+' and c != '-' and c != '.') return false;
    return true;
}

/// `text`, which parsed as `u`, with `host` in place of its host, into
/// `out`: the URL with its name in another form (IDNA's ASCII one).
pub fn withHost(text: []const u8, u: Url, host: []const u8, out: []u8) error{NoSpaceLeft}![]u8 {
    const start = @intFromPtr(u.host.ptr) - @intFromPtr(text.ptr); // safe: `parse` gave `u.host` as a slice of `text`, so it starts within it
    const end = start + u.host.len;
    const len = start + host.len + (text.len - end);
    if (len > out.len) return error.NoSpaceLeft;
    @memcpy(out[0..start], text[0..start]);
    @memcpy(out[start..][0..host.len], host);
    @memcpy(out[start + host.len .. len], text[end..]);
    return out[0..len];
}

test "a URL's host is replaced, the rest kept" {
    const text = "https://B\xc3\x9cCHER.example:8443/a?b#c";
    const u = try parse(text);
    var out: [128]u8 = undefined;
    const replaced = try withHost(text, u, "xn--bcher-kva.example", &out);
    try std.testing.expectEqualStrings("https://xn--bcher-kva.example:8443/a?b#c", replaced);
    try std.testing.expectEqualStrings("xn--bcher-kva.example", (try parse(replaced)).host);
    try std.testing.expectError(error.NoSpaceLeft, withHost(text, u, "xn--bcher-kva.example", out[0..10]));
}

/// Whether two URLs have the same origin (RFC 6454): scheme, host without
/// case, and port.
pub fn sameOrigin(a: Url, b: Url) bool {
    return a.secure == b.secure and a.port == b.port and std.ascii.eqlIgnoreCase(a.host, b.host);
}

/// Why a reference cannot be resolved.
pub const ResolveError = error{
    /// `base` is not an absolute URL.
    InvalidUrl,
    /// The result does not fit `out`.
    NoSpaceLeft,
};

/// The URL `reference` names relative to `base`, an absolute URL, by RFC
/// 3986 §5.2, into `out`: what a `Location` field leads to. Dot segments
/// are removed; a space, a control character or a byte past ASCII in the
/// reference is percent-encoded, as browsers encode them; and a
/// reference with no fragment keeps the base's (RFC 9110 §10.2.2).
pub fn resolve(base: []const u8, reference: []const u8, out: []u8) ResolveError![]u8 {
    const b = split(base);
    if (b.scheme == null or b.authority == null) return error.InvalidUrl;
    const r = split(reference);
    var w: Writer = .{ .out = out };
    if (r.scheme) |scheme| {
        try w.lower(scheme);
        try w.raw(":");
        try w.authorityOf(r.authority);
        try w.path(r.path);
        try w.query(r.query);
    } else if (r.authority != null) {
        try w.lower(b.scheme.?);
        try w.raw(":");
        try w.authorityOf(r.authority);
        try w.path(r.path);
        try w.query(r.query);
    } else {
        try w.lower(b.scheme.?);
        try w.raw(":");
        try w.authorityOf(b.authority);
        if (r.path.len == 0) {
            try w.path(b.path);
            try w.query(r.query orelse b.query);
        } else {
            if (r.path[0] == '/') {
                try w.path(r.path);
            } else {
                // Merge: the base's path up to its last slash, then the
                // reference's; `/` alone when the base has an authority and
                // no path.
                const start = w.len;
                const dir_end = if (std.mem.findScalarLast(u8, b.path, '/')) |i| i + 1 else 0;
                if (b.path.len == 0) try w.raw("/") else try w.encoded(b.path[0..dir_end]);
                try w.encoded(r.path);
                w.len = start + removeDotSegments(out[start..w.len]).len;
            }
            try w.query(r.query);
        }
    }
    if (r.fragment orelse b.fragment) |f| {
        try w.raw("#");
        try w.encoded(f);
    }
    return out[0..w.len];
}

/// Appendix B's split, where a scheme that is not one is part of the path.
fn split(text: []const u8) uri.Split {
    var p = uri.split(text);
    if (p.scheme) |scheme| if (!validScheme(scheme)) {
        // The text then begins with that would-be scheme, not "//", so it
        // has no authority: everything before the query is the path.
        const tail = (if (p.query) |q| q.len + 1 else 0) + (if (p.fragment) |f| f.len + 1 else 0);
        p.scheme = null;
        p.authority = null;
        p.path = text[0 .. text.len - tail];
    };
    return p;
}

/// Bytes into a fixed buffer, with percent-encoding where a URL needs it.
const Writer = struct {
    out: []u8,
    len: usize = 0,

    fn raw(w: *Writer, bytes: []const u8) ResolveError!void {
        if (w.out.len - w.len < bytes.len) return error.NoSpaceLeft;
        @memcpy(w.out[w.len..][0..bytes.len], bytes);
        w.len += bytes.len;
    }

    fn lower(w: *Writer, bytes: []const u8) ResolveError!void {
        const start = w.len;
        try w.raw(bytes);
        for (w.out[start..w.len]) |*c| c.* = std.ascii.toLower(c.*);
    }

    fn encoded(w: *Writer, bytes: []const u8) ResolveError!void {
        for (bytes) |c| {
            if (c > 0x20 and c < 0x7f) {
                try w.raw(&.{c});
            } else {
                const hex = "0123456789ABCDEF";
                try w.raw(&.{ '%', hex[c >> 4], hex[c & 15] });
            }
        }
    }

    fn authorityOf(w: *Writer, authority: ?[]const u8) ResolveError!void {
        const a = authority orelse return;
        try w.raw("//");
        try w.encoded(a);
    }

    fn path(w: *Writer, p: []const u8) ResolveError!void {
        const start = w.len;
        try w.encoded(p);
        w.len = start + removeDotSegments(w.out[start..w.len]).len;
    }

    fn query(w: *Writer, q: ?[]const u8) ResolveError!void {
        const text = q orelse return;
        try w.raw("?");
        try w.encoded(text);
    }
};

/// RFC 3986 §5.2.4, in place: the output never outgrows the input read.
fn removeDotSegments(p: []u8) []u8 {
    var in: usize = 0;
    var out: usize = 0;
    while (in < p.len) {
        const rest = p[in..];
        if (std.mem.startsWith(u8, rest, "../")) {
            in += 3;
        } else if (std.mem.startsWith(u8, rest, "./")) {
            in += 2;
        } else if (std.mem.startsWith(u8, rest, "/./")) {
            in += 2;
        } else if (std.mem.eql(u8, rest, "/.")) {
            in += 1;
            p[in] = '/';
        } else if (std.mem.startsWith(u8, rest, "/../")) {
            in += 3;
            out = std.mem.findScalarLast(u8, p[0..out], '/') orelse 0;
        } else if (std.mem.eql(u8, rest, "/..")) {
            in += 2;
            p[in] = '/';
            out = std.mem.findScalarLast(u8, p[0..out], '/') orelse 0;
        } else if (std.mem.eql(u8, rest, ".") or std.mem.eql(u8, rest, "..")) {
            in = p.len;
        } else {
            const first_end = std.mem.findScalarPos(u8, p, in + 1, '/') orelse p.len;
            @memmove(p[out..][0 .. first_end - in], p[in..first_end]);
            out += first_end - in;
            in = first_end;
        }
    }
    return p[0..out];
}

const testing = std.testing;

test "a URL gives its host, port and origin-form target" {
    const u = try parse("https://Git.Example.com:8443/team/repo.git/info/refs?service=git-upload-pack#frag");
    try testing.expect(u.secure);
    try testing.expectEqualStrings("Git.Example.com", u.host);
    try testing.expectEqual(@as(u16, 8443), u.port);
    try testing.expectEqualStrings("/team/repo.git/info/refs?service=git-upload-pack", u.target);
    const bare = try parse("http://example.com");
    var target_buf: [64]u8 = undefined;
    var target: std.Io.Writer = .fixed(&target_buf);
    try bare.writeTarget(&target);
    try testing.expectEqualStrings("/", target.buffered());
    target = .fixed(&target_buf);
    try (try parse("http://example.com?q=1#f")).writeTarget(&target);
    try testing.expectEqualStrings("/?q=1", target.buffered());
    try testing.expectEqual(@as(u16, 80), bare.port);
    try testing.expect(bare.defaultPort());
    const v6 = try parse("http://[::1]:8080/a%20b");
    try testing.expectEqualStrings("::1", v6.host);
    try testing.expectEqualStrings("/a%20b", v6.target);
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try v6.writeAuthority(&w, false);
    try testing.expectEqualStrings("[::1]:8080", w.buffered());
}

test "a URL that could smuggle a byte onto the wire, or names another scheme, is refused" {
    // Every control character, space and tab, in the host, the path and the query.
    for ([_][]const u8{ "\t", " ", "\r", "\n", "\x00", "\x0b", "\x0c", "\x7f", "\x01", "\x1f" }) |c| {
        for ([_][]const u8{ "http://exa{s}mple.com/", "http://example.com/a{s}b", "http://example.com/?q={s}" }) |shape| {
            const text = try std.mem.replaceOwned(u8, testing.allocator, shape, "{s}", c);
            defer testing.allocator.free(text);
            testing.expectError(error.InvalidUrl, parse(text)) catch |err| {
                std.debug.print("taken: {any}\n", .{text});
                return err;
            };
        }
    }
    for ([_][]const u8{
        "http://example.com/a b",
        "http://example.com/a\r\nHost: evil",
        "http://exa\x00mple.com/",
        "http://user:pass@example.com/",
        "http:///path",
        "http://ex%41mple.com/",
        "not a url",
    }) |text| try testing.expectError(error.InvalidUrl, parse(text));
    try testing.expectError(error.UnsupportedScheme, parse("ftp://example.com/"));
    try testing.expectError(error.UnsupportedScheme, parse("ws://example.com/"));
}

test "references resolve as RFC 3986's examples resolve" {
    const base = "http://a/b/c/d;p?q";
    const cases = [_][2][]const u8{
        .{ "g:h", "g:h" },                         .{ "g", "http://a/b/c/g" },
        .{ "./g", "http://a/b/c/g" },              .{ "g/", "http://a/b/c/g/" },
        .{ "/g", "http://a/g" },                   .{ "//g", "http://g" },
        .{ "?y", "http://a/b/c/d;p?y" },           .{ "g?y", "http://a/b/c/g?y" },
        .{ "#s", "http://a/b/c/d;p?q#s" },         .{ "g#s", "http://a/b/c/g#s" },
        .{ "g?y#s", "http://a/b/c/g?y#s" },        .{ ";x", "http://a/b/c/;x" },
        .{ "g;x", "http://a/b/c/g;x" },            .{ "", "http://a/b/c/d;p?q" },
        .{ ".", "http://a/b/c/" },                 .{ "./", "http://a/b/c/" },
        .{ "..", "http://a/b/" },                  .{ "../", "http://a/b/" },
        .{ "../g", "http://a/b/g" },               .{ "../..", "http://a/" },
        .{ "../../", "http://a/" },                .{ "../../g", "http://a/g" },
        .{ "../../../g", "http://a/g" },           .{ "../../../../g", "http://a/g" },
        .{ "/./g", "http://a/g" },                 .{ "/../g", "http://a/g" },
        .{ "g.", "http://a/b/c/g." },              .{ ".g", "http://a/b/c/.g" },
        .{ "g..", "http://a/b/c/g.." },            .{ "..g", "http://a/b/c/..g" },
        .{ "./../g", "http://a/b/g" },             .{ "./g/.", "http://a/b/c/g/" },
        .{ "g/./h", "http://a/b/c/g/h" },          .{ "g/../h", "http://a/b/c/h" },
        .{ "g;x=1/./y", "http://a/b/c/g;x=1/y" },  .{ "g;x=1/../y", "http://a/b/c/y" },
        .{ "g?y/./x", "http://a/b/c/g?y/./x" },    .{ "g?y/../x", "http://a/b/c/g?y/../x" },
        .{ "g#s/./x", "http://a/b/c/g#s/./x" },    .{ "g#s/../x", "http://a/b/c/g#s/../x" },
        .{ "HTTPS://Other/x", "https://Other/x" },
    };
    var buf: [128]u8 = undefined;
    for (cases) |case| {
        const got = try resolve(base, case[0], &buf);
        testing.expectEqualStrings(case[1], got) catch |err| {
            std.debug.print("{s}\n", .{case[0]});
            return err;
        };
    }
}

test "a target's bytes past ASCII are written percent-encoded, the rest as they are" {
    const u = try parse("http://h/caf\xc3\xa9/%41?q=\xc3\xa9&r=[1]");
    try testing.expectEqualStrings("/caf\xc3\xa9/%41?q=\xc3\xa9&r=[1]", u.target);
    var buf: [64]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buf);
    try u.writeTarget(&w);
    try testing.expectEqualStrings("/caf%C3%A9/%41?q=%C3%A9&r=[1]", w.buffered());
    var named: [64]u8 = undefined;
    try testing.expectEqualStrings("/caf%C3%A9/%41?q=%C3%A9&r=[1]", try u.originTarget(&named));
    const plain = try parse("http://h/a?b");
    try testing.expectEqual(plain.target.ptr, (try plain.originTarget(&named)).ptr);
    try testing.expectEqualStrings("/?q", try (try parse("http://h?q")).originTarget(&named));
    try testing.expectError(error.NoSpaceLeft, u.originTarget(named[0..8]));
}

test "the forbidden domain code points are the URL Standard's set" {
    const set = " #%/:<>?@[\\]^|\x7f";
    for (0..0x80) |i| {
        const c: u8 = @intCast(i);
        const want = c < 0x20 or std.mem.findScalar(u8, set, c) != null;
        try testing.expectEqual(want, forbiddenDomainCodePoint(c));
    }
    for ("az09-._~!$&'()*+,;=") |c| try testing.expect(!forbiddenDomainCodePoint(c));
}

test "a redirect keeps the request's fragment and encodes what a URL cannot hold" {
    var buf: [128]u8 = undefined;
    try testing.expectEqualStrings("https://h/new#top", try resolve("https://h/old#top", "/new", &buf));
    try testing.expectEqualStrings("https://h/a%20b/caf%C3%A9", try resolve("https://h/x", "/a b/caf\xc3\xa9", &buf));
    try testing.expectEqualStrings("http://h", try resolve("http://h", "", &buf));
    try testing.expectError(error.InvalidUrl, resolve("/relative", "x", &buf));
    var tiny: [8]u8 = undefined;
    try testing.expectError(error.NoSpaceLeft, resolve("http://host/", "/long/path", &tiny));
    try testing.expect(sameOrigin(try parse("http://A.example/x"), try parse("http://a.example:80/y")));
    try testing.expect(!sameOrigin(try parse("http://a.example/"), try parse("https://a.example/")));
    try testing.expect(!sameOrigin(try parse("http://a.example/"), try parse("http://a.example:8080/")));
}

test "fuzz: any reference resolves to a URL or is refused, never past its buffer" {
    const shakedown = @import("shakedown");
    const inputs = @import("../testing/inputs.zig");
    const seeds = [_][]const u8{ "../x", "//other/y?z", "g;x=1/../y" };
    try shakedown.check(testing.allocator, {}, struct {
        fn one(_: void, case: *shakedown.Case) anyerror!void {
            var raw: [96]u8 = undefined;
            const reference = inputs.draw(case, &raw, &seeds, 32);
            var buf: [512]u8 = undefined;
            const got = resolve("https://h.example/a/b?c#d", reference, &buf) catch return;
            try testing.expect(got.len <= buf.len);
        }
    }.one, .{});
}

test "differential: parse and parts read every text as the standard library's URI reader did" {
    const shakedown = @import("shakedown");
    const gen = shakedown.gen;
    const inputs = @import("../testing/inputs.zig");
    const seeds = [_][]const u8{
        "https://Git.Example.com:8443/team/repo.git?q=1#f", "http://u:p@[::1]:8080/a%20b",
        "http:///path",                                     "socks5://a@b@c:+8_0",
        "http://[v1.x]junk:1/",                             "HTTP://ex%41mple.com?x#y",
        "http://h:/",                                       "http://]h/",
        "x1+.-://u:@h",                                     "1a://b/c",
        "http:h",                                           "http://?q",
    };
    try shakedown.check(testing.allocator, {}, struct {
        fn one(_: void, case: *shakedown.Case) anyerror!void {
            var raw: [96]u8 = undefined;
            const text = if (gen.boolean(case.source)) inputs.draw(case, &raw, &seeds, 24) else urlish(case, &raw);
            if (before(text)) |want| {
                const got = try parse(text);
                try testing.expectEqual(want.secure, got.secure);
                try testing.expectEqual(want.port, got.port);
                try testing.expectEqual(want.host.ptr, got.host.ptr);
                try testing.expectEqual(want.host.len, got.host.len);
                try testing.expectEqual(want.target.ptr, got.target.ptr);
                try testing.expectEqual(want.target.len, got.target.len);
            } else |err| try testing.expectError(err, parse(text));
            const std_uri = std.Uri.parse(text) catch {
                try testing.expectError(error.InvalidUrl, parts(text));
                return;
            };
            const got = try parts(text);
            try testing.expectEqual(std_uri.scheme.ptr, got.scheme.ptr);
            try testing.expectEqual(std_uri.scheme.len, got.scheme.len);
            try testing.expectEqual(std_uri.port, got.port);
            try same(std_uri.user, got.user);
            try same(std_uri.password, got.password);
            try same(std_uri.host, got.host);
        }

        /// Text from the bytes a URL is cut at, and a few it is not.
        fn urlish(case: *shakedown.Case, buffer: []u8) []u8 {
            const alphabet = "hH1:/?#@[]%+_.-A9 \t\x80";
            const len = gen.intRange(case.source, usize, 0, @min(buffer.len, 40));
            for (buffer[0..len]) |*c| c.* = gen.oneOf(case.source, u8, alphabet);
            return buffer[0..len];
        }

        /// The same component, as written and decoded.
        fn same(want: ?std.Uri.Component, got: ?[]const u8) !void {
            const w = want orelse return testing.expectEqual(null, got);
            const written = switch (w) {
                .raw, .percent_encoded => |s| s,
            };
            try testing.expectEqual(written.ptr, got.?.ptr);
            try testing.expectEqual(written.len, got.?.len);
            var want_buf: [96]u8 = undefined;
            var writer: std.Io.Writer = .fixed(&want_buf);
            try w.formatRaw(&writer);
            var got_buf: [96]u8 = undefined;
            try testing.expectEqualStrings(writer.buffered(), percentDecode(&got_buf, got.?));
        }

        /// `parse` as it was on the standard library's reader.
        fn before(text: []const u8) ParseError!Url {
            // url's own checks, the tab among them, before the reader's.
            if (fields.hasControl(text) or std.mem.findAny(u8, text, " \t") != null) return error.InvalidUrl;
            const u = std.Uri.parse(text) catch return error.InvalidUrl;
            const secure = if (std.ascii.eqlIgnoreCase(u.scheme, "https"))
                true
            else if (std.ascii.eqlIgnoreCase(u.scheme, "http"))
                false
            else
                return error.UnsupportedScheme;
            if (u.user != null or u.password != null) return error.InvalidUrl;
            const host_component = u.host orelse return error.InvalidUrl;
            const raw_host = switch (host_component) {
                .raw, .percent_encoded => |h| h,
            };
            if (std.mem.findScalar(u8, raw_host, '%') != null and !(raw_host.len > 0 and raw_host[0] == '[')) return error.InvalidUrl;
            const host = if (raw_host.len >= 2 and raw_host[0] == '[' and raw_host[raw_host.len - 1] == ']') raw_host[1 .. raw_host.len - 1] else raw_host;
            if (host.len == 0 or std.mem.findAny(u8, host, "/@?#\\") != null) return error.InvalidUrl;
            const after_scheme = (std.mem.find(u8, text, "://") orelse return error.InvalidUrl) + 3;
            const path_start = std.mem.findAnyPos(u8, text, after_scheme, "/?#") orelse text.len;
            const end = std.mem.findScalarPos(u8, text, path_start, '#') orelse text.len;
            return .{ .secure = secure, .host = host, .port = u.port orelse @as(u16, if (secure) 443 else 80), .target = text[path_start..end] };
        }
    }.one, .{ .cases = 50000, .seed = 0x3986 });
}

test "parts reads a URL's userinfo, bracketed host and port as written" {
    const p = try parts("socks5://us%65r:p@ss@[::1]junk:1080/x?y#z");
    try testing.expectEqualStrings("socks5", p.scheme);
    try testing.expectEqualStrings("us%65r", p.user.?);
    try testing.expectEqualStrings("p@ss", p.password.?);
    try testing.expectEqualStrings("[::1]", p.host.?);
    try testing.expectEqual(@as(?u16, 1080), p.port);
    try testing.expectEqualStrings("/x?y", p.target);
    try testing.expectEqual(@as(?[]const u8, null), (try parts("http://u:@h")).password);
    try testing.expectEqual(@as(?[]const u8, null), (try parts("http:///p")).host);
    for ([_][]const u8{ "http://", "http://?q", "1a://h", "/a:b", "http://]h", "http://[::1", "http://h:x", "http://h:65536", "http://u@:1" }) |text| {
        try testing.expectError(error.InvalidUrl, parts(text));
    }
    var buf: [16]u8 = undefined;
    try testing.expectEqualStrings("a b%2%zz%", percentDecode(&buf, "a%20b%2%zz%"));
}
