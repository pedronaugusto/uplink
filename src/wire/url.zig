//! The parts of an `http` or `https` URL a request is made from: where it
//! goes, and the request target (RFC 9112 §3.2) that names what it asks for.
//! Everything is checked here, so nothing in a URL can put a byte on the
//! wire that a request line or a `Host` field does not allow.

const std = @import("std");
const fields = @import("fields.zig");

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
    /// path.
    pub fn writeTarget(u: Url, w: *std.Io.Writer) std.Io.Writer.Error!void {
        if (u.target.len == 0 or u.target[0] != '/') try w.writeByte('/');
        try w.writeAll(u.target);
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
    /// Not a URL, no host, a control character or space anywhere, or a
    /// user and password, which go in an `Authorization` field instead.
    InvalidUrl,
    /// A scheme other than `http` or `https`.
    UnsupportedScheme,
};

/// Take `text` apart. The fragment is dropped: it is never sent.
pub fn parse(text: []const u8) ParseError!Url {
    if (fields.hasControl(text) or std.mem.findAny(u8, text, " ") != null) return error.InvalidUrl;
    const uri = std.Uri.parse(text) catch return error.InvalidUrl;
    const secure = if (std.ascii.eqlIgnoreCase(uri.scheme, "https"))
        true
    else if (std.ascii.eqlIgnoreCase(uri.scheme, "http"))
        false
    else
        return error.UnsupportedScheme;
    if (uri.user != null or uri.password != null) return error.InvalidUrl;
    const host_component = uri.host orelse return error.InvalidUrl;
    const raw_host = switch (host_component) {
        .raw, .percent_encoded => |h| h,
    };
    // A percent-encoded host would need decoding to be looked up; names
    // that need it are IDNA's, which callers pass as punycode.
    if (std.mem.findScalar(u8, raw_host, '%') != null and !(raw_host.len > 0 and raw_host[0] == '[')) return error.InvalidUrl;
    const host = if (raw_host.len >= 2 and raw_host[0] == '[' and raw_host[raw_host.len - 1] == ']') raw_host[1 .. raw_host.len - 1] else raw_host;
    if (host.len == 0 or std.mem.findAny(u8, host, "/@?#\\") != null) return error.InvalidUrl;
    // The path and query as written: from the end of the authority to the
    // fragment.
    const after_scheme = (std.mem.find(u8, text, "://") orelse return error.InvalidUrl) + 3;
    const path_start = std.mem.findAnyPos(u8, text, after_scheme, "/?#") orelse text.len;
    const end = std.mem.findScalarPos(u8, text, path_start, '#') orelse text.len;
    const target = text[path_start..end];
    return .{
        .secure = secure,
        .host = host,
        .port = uri.port orelse @as(u16, if (secure) 443 else 80),
        .target = target,
    };
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

const Parts = struct {
    scheme: ?[]const u8 = null,
    authority: ?[]const u8 = null,
    path: []const u8 = "",
    query: ?[]const u8 = null,
    fragment: ?[]const u8 = null,
};

/// RFC 3986 Appendix B's split of a reference into its parts.
fn split(text: []const u8) Parts {
    var p: Parts = .{};
    var rest = text;
    if (std.mem.findScalar(u8, rest, '#')) |i| {
        p.fragment = rest[i + 1 ..];
        rest = rest[0..i];
    }
    if (std.mem.findScalar(u8, rest, '?')) |i| {
        p.query = rest[i + 1 ..];
        rest = rest[0..i];
    }
    if (std.mem.findScalar(u8, rest, ':')) |colon| {
        const scheme = rest[0..colon];
        const slash = std.mem.findScalar(u8, rest, '/') orelse rest.len;
        if (colon < slash and colon > 0 and std.ascii.isAlphabetic(scheme[0]) and isSchemeText(scheme)) {
            p.scheme = scheme;
            rest = rest[colon + 1 ..];
        }
    }
    if (std.mem.startsWith(u8, rest, "//")) {
        const end = std.mem.findScalarPos(u8, rest, 2, '/') orelse rest.len;
        p.authority = rest[2..end];
        rest = rest[end..];
    }
    p.path = rest;
    return p;
}

fn isSchemeText(text: []const u8) bool {
    for (text) |c| if (!std.ascii.isAlphanumeric(c) and c != '+' and c != '-' and c != '.') return false;
    return true;
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
    try testing.fuzz({}, struct {
        fn one(_: void, smith: *testing.Smith) anyerror!void {
            var raw: [96]u8 = undefined;
            const reference = raw[0..smith.slice(&raw)];
            var buf: [512]u8 = undefined;
            const got = resolve("https://h.example/a/b?c#d", reference, &buf) catch return;
            try testing.expect(got.len <= buf.len);
        }
    }.one, .{ .corpus = &.{ "../x", "//other/y?z", "g;x=1/../y" } });
}
