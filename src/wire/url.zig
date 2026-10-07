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
