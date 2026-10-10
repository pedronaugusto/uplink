//! Cookies on the wire (RFC 6265bis): a `Set-Cookie` value read into its
//! name, value and attributes, the lenient date its `Expires` carries, and
//! the domain and path rules a cookie store decides with. Storage, expiry
//! and the `Cookie` field a request sends are a store's; this is the
//! grammar it is built from.
//!
//! A `Set-Cookie` is read the way RFC 6265bis §5.6 tells a user agent to
//! read it, which is more forgiving than the syntax a server must write: an
//! attribute that cannot be read is skipped, not the cookie, and a value is
//! kept as written, quotes included.

const std = @import("std");
const aegis = @import("aegis");
const date = @import("date.zig");

/// One `Set-Cookie` value, read. Every slice points into the text.
pub const SetCookie = struct {
    name: []const u8,
    value: []const u8,
    /// `Expires`, in seconds since the epoch.
    expires: ?i64 = null,
    /// `Max-Age`, in seconds from when the cookie arrived; zero or less
    /// expires it at once. It wins over `Expires`.
    max_age: ?i64 = null,
    /// `Domain`, its leading dot removed, as written: compare without case.
    domain: ?[]const u8 = null,
    /// `Path`, when it is one; null takes the request's default path.
    path: ?[]const u8 = null,
    secure: bool = false,
    http_only: bool = false,
    same_site: SameSite = .default,
    partitioned: bool = false,
};

/// The `SameSite` attribute. A client that is not a browser sends cookies
/// the same way whatever it says; it is kept so a store can write it back.
pub const SameSite = enum { default, strict, lax, none };

/// The most a name and value may hold together, and an attribute's value.
pub const max_name_value = 4096;
pub const max_attribute = 1024;

/// A `Set-Cookie` value, or null when RFC 6265bis has it ignored: a
/// control character, no name and no value, or a name and value longer
/// than `max_name_value`.
pub fn parse(text: []const u8) ?SetCookie {
    for (text) |c| if ((c < 0x20 and c != '\t') or c == 0x7f) return null;
    const end = std.mem.findScalar(u8, text, ';') orelse text.len;
    const pair = text[0..end];
    var c: SetCookie = undefined;
    if (std.mem.findScalar(u8, pair, '=')) |eq| {
        c = .{ .name = trim(pair[0..eq]), .value = trim(pair[eq + 1 ..]) };
    } else c = .{ .name = "", .value = trim(pair) };
    if (c.name.len == 0 and c.value.len == 0) return null;
    if (c.name.len + c.value.len > max_name_value) return null;
    var rest = if (end < text.len) text[end + 1 ..] else "";
    while (rest.len != 0) {
        const next = std.mem.findScalar(u8, rest, ';') orelse rest.len;
        attribute(&c, rest[0..next]);
        rest = if (next < rest.len) rest[next + 1 ..] else "";
    }
    return c;
}

fn trim(text: []const u8) []const u8 {
    return std.mem.trim(u8, text, " \t");
}

/// Apply one `name[=value]` attribute; the last of a name wins.
fn attribute(c: *SetCookie, av: []const u8) void {
    const eq = std.mem.findScalar(u8, av, '=');
    const name = trim(if (eq) |i| av[0..i] else av);
    const value = if (eq) |i| trim(av[i + 1 ..]) else "";
    if (value.len > max_attribute) return;
    if (std.ascii.eqlIgnoreCase(name, "expires")) {
        if (parseDate(value)) |t| c.expires = t;
    } else if (std.ascii.eqlIgnoreCase(name, "max-age")) {
        if (parseMaxAge(value)) |n| c.max_age = n;
    } else if (std.ascii.eqlIgnoreCase(name, "domain")) {
        // An empty domain is ignored, as RFC 6265bis advises.
        const d = if (value.len != 0 and value[0] == '.') value[1..] else value;
        if (d.len != 0) c.domain = d;
    } else if (std.ascii.eqlIgnoreCase(name, "path")) {
        c.path = if (value.len != 0 and value[0] == '/') value else null;
    } else if (std.ascii.eqlIgnoreCase(name, "secure")) {
        c.secure = true;
    } else if (std.ascii.eqlIgnoreCase(name, "httponly")) {
        c.http_only = true;
    } else if (std.ascii.eqlIgnoreCase(name, "samesite")) {
        c.same_site = if (std.ascii.eqlIgnoreCase(value, "strict"))
            .strict
        else if (std.ascii.eqlIgnoreCase(value, "lax"))
            .lax
        else if (std.ascii.eqlIgnoreCase(value, "none"))
            .none
        else
            .default;
    } else if (std.ascii.eqlIgnoreCase(name, "partitioned")) {
        c.partitioned = true;
    }
}

/// `Max-Age`: an optional `-` and digits; a huge one is clamped.
fn parseMaxAge(text: []const u8) ?i64 {
    if (text.len == 0) return null;
    const negative = text[0] == '-';
    const digits = if (negative) text[1..] else text;
    if (digits.len == 0) return null;
    var n: i64 = 0;
    for (digits) |d| {
        if (d < '0' or d > '9') return null;
        n = (aegis.int.Checked(i64).init(n).mul(10) catch return std.math.maxInt(i32)).raw();
        n = (aegis.int.Checked(i64).init(n).add(d - '0') catch return std.math.maxInt(i32)).raw();
    }
    // No cookie lives past a few hundred years; this keeps sums in range.
    n = @min(n, std.math.maxInt(i32));
    return if (negative) -n else n;
}

/// A cookie date (RFC 6265bis §5.1.1): the time, day, month and year found
/// among the tokens in whatever order, as browsers read `Expires`. Seconds
/// since the epoch, or null.
pub fn parseDate(text: []const u8) ?i64 {
    var time: ?[3]u32 = null;
    var day: ?u32 = null;
    var month: ?u32 = null;
    var year: ?u32 = null;
    var i: usize = 0;
    while (i < text.len) {
        while (i < text.len and isDelimiter(text[i])) i += 1;
        const start = i;
        while (i < text.len and !isDelimiter(text[i])) i += 1;
        const token = text[start..i];
        if (token.len == 0) continue;
        if (time == null) if (hmsTime(token)) |t| {
            time = t;
            continue;
        };
        if (day == null) if (leadingDigits(token, 1, 2)) |d| {
            day = d;
            continue;
        };
        if (month == null) if (monthOf(token)) |m| {
            month = m;
            continue;
        };
        if (year == null) if (leadingDigits(token, 2, 4)) |y| {
            year = y;
            continue;
        };
    }
    const t = time orelse return null;
    var y = year orelse return null;
    if (y >= 70 and y <= 99) y += 1900;
    if (y <= 69) y += 2000;
    if (y < 1601) return null;
    return date.civil(y, month orelse return null, day orelse return null, t[0], t[1], t[2]);
}

fn isDelimiter(c: u8) bool {
    return c == 0x09 or (c >= 0x20 and c <= 0x2f) or (c >= 0x3b and c <= 0x40) or (c >= 0x5b and c <= 0x60) or (c >= 0x7b and c <= 0x7e);
}

/// `min` to `max` digits at the token's start, and no digit after them.
fn leadingDigits(token: []const u8, min: usize, max: usize) ?u32 {
    var n: u32 = 0;
    var count: usize = 0;
    while (count < token.len and std.ascii.isDigit(token[count])) : (count += 1) {
        if (count == max) return null;
        n = n * 10 + (token[count] - '0');
    }
    if (count < min) return null;
    return n;
}

/// `h:m:s`, each one or two digits, and anything not a digit after.
fn hmsTime(token: []const u8) ?[3]u32 {
    var out: [3]u32 = undefined;
    var at: usize = 0;
    for (&out, 0..) |*part, n| {
        var count: usize = 0;
        var v: u32 = 0;
        while (at < token.len and std.ascii.isDigit(token[at]) and count < 3) : (at += 1) {
            v = v * 10 + (token[at] - '0');
            count += 1;
        }
        if (count == 0 or count > 2) return null;
        part.* = v;
        if (n < 2) {
            if (at >= token.len or token[at] != ':') return null;
            at += 1;
        }
    }
    if (at < token.len and std.ascii.isDigit(token[at])) return null;
    return out;
}

fn monthOf(token: []const u8) ?u32 {
    if (token.len < 3) return null;
    const names = [_][]const u8{ "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec" };
    for (names, 1..) |m, n| if (std.ascii.eqlIgnoreCase(token[0..3], m)) return @intCast(n);
    return null;
}

/// Whether `host` lies in `domain` (RFC 6265bis §5.1.3): the same name,
/// without case, or a name under it that is not an IP address.
pub fn domainMatch(host: []const u8, domain: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(host, domain)) return true;
    if (host.len <= domain.len or !std.ascii.endsWithIgnoreCase(host, domain)) return false;
    if (host[host.len - domain.len - 1] != '.') return false;
    return !isAddress(host);
}

/// Whether `host` is an IP address rather than a name.
pub fn isAddress(host: []const u8) bool {
    if (std.mem.findScalar(u8, host, ':') != null) return true;
    if (host.len == 0) return false;
    // An IPv4 address: its last label is a number.
    const dot = std.mem.findScalarLast(u8, host, '.') orelse return false;
    const last = host[dot + 1 ..];
    if (last.len == 0) return false;
    for (last) |c| if (!std.ascii.isDigit(c)) return false;
    return true;
}

/// Whether a request for `request_path` gets a cookie of `cookie_path`
/// (RFC 6265bis §5.1.4).
pub fn pathMatch(request_path: []const u8, cookie_path: []const u8) bool {
    if (!std.mem.startsWith(u8, request_path, cookie_path)) return false;
    if (request_path.len == cookie_path.len) return true;
    return cookie_path[cookie_path.len - 1] == '/' or request_path[cookie_path.len] == '/';
}

/// The path a cookie with no `Path` gets from the request's
/// (RFC 6265bis §5.1.4): up to its last `/`, or `/`.
pub fn defaultPath(request_path: []const u8) []const u8 {
    if (request_path.len == 0 or request_path[0] != '/') return "/";
    const last = std.mem.findScalarLast(u8, request_path, '/').?;
    if (last == 0) return "/";
    return request_path[0..last];
}

/// The path of a request target: up to its query.
pub fn pathOf(target: []const u8) []const u8 {
    const end = std.mem.findAny(u8, target, "?#") orelse target.len;
    return if (end == 0) "/" else target[0..end];
}

const testing = std.testing;

test "a Set-Cookie value is read as a browser reads it" {
    const c = parse("SID=31d4d96e407aad42; Path=/; Secure; HttpOnly; Domain=.Example.com; Max-Age=60; SameSite=Lax").?;
    try testing.expectEqualStrings("SID", c.name);
    try testing.expectEqualStrings("31d4d96e407aad42", c.value);
    try testing.expectEqualStrings("Example.com", c.domain.?);
    try testing.expectEqualStrings("/", c.path.?);
    try testing.expect(c.secure and c.http_only);
    try testing.expectEqual(@as(?i64, 60), c.max_age);
    try testing.expectEqual(SameSite.lax, c.same_site);
    const bare = parse(" lone value ; path=relative; max-age=x; domain=; expires=never").?;
    try testing.expectEqualStrings("", bare.name);
    try testing.expectEqualStrings("lone value", bare.value);
    try testing.expectEqual(null, bare.path);
    try testing.expectEqual(null, bare.max_age);
    try testing.expectEqual(null, bare.domain);
    try testing.expectEqual(null, bare.expires);
    const quoted = parse("q=\"a b\"; Max-Age=-5; Max-Age=99999999999999999999").?;
    try testing.expectEqualStrings("\"a b\"", quoted.value);
    try testing.expectEqual(@as(?i64, std.math.maxInt(i32)), quoted.max_age);
    try testing.expectEqual(@as(?i64, -5), parse("a=b; Max-Age=-5").?.max_age);
    try testing.expectEqual(null, parse(""));
    try testing.expectEqual(null, parse(" = ; Path=/"));
    try testing.expectEqual(null, parse("a=b\x00c"));
    const long: [max_name_value]u8 = @splat('v');
    try testing.expectEqual(null, parse("n=" ++ long));
}

test "cookie dates are found among their tokens in any order" {
    const want: ?i64 = 784111777;
    for ([_][]const u8{
        "Sun, 06 Nov 1994 08:49:37 GMT",
        "Sunday, 06-Nov-94 08:49:37 GMT",
        "Sun Nov  6 08:49:37 1994",
        "06 nOvember 1994 8:49:37",
        "8:49:37 1994-Nov-06",
    }) |text| {
        testing.expectEqual(want, parseDate(text)) catch |err| {
            std.debug.print("{s}\n", .{text});
            return err;
        };
    }
    for ([_][]const u8{ "", "Sun, 06 Nov 1600 08:49:37 GMT", "31 Feb 2020 00:00:00", "06 Nov 1994", "06 Nov 1994 25:00:00", "06 Xyz 1994 08:49:37" }) |bad| {
        try testing.expectEqual(@as(?i64, null), parseDate(bad));
    }
    try testing.expectEqual(@as(?i64, 1767225600), parseDate("Thu, 01 Jan 26 00:00:00 GMT"));
}

test "domains match without case and only above a label, never for an address" {
    try testing.expect(domainMatch("example.com", "Example.COM"));
    try testing.expect(domainMatch("www.example.com", "example.com"));
    try testing.expect(!domainMatch("wwwexample.com", "example.com"));
    try testing.expect(!domainMatch("example.com", "www.example.com"));
    try testing.expect(!domainMatch("1.2.3.4", "2.3.4"));
    try testing.expect(domainMatch("1.2.3.4", "1.2.3.4"));
    try testing.expect(isAddress("::1") and isAddress("10.0.0.1") and !isAddress("a.b") and !isAddress("x.1a"));
}

test "paths match on whole segments, and a default path is the request's directory" {
    try testing.expect(pathMatch("/docs/web", "/docs"));
    try testing.expect(pathMatch("/docs/", "/docs/"));
    try testing.expect(pathMatch("/docs", "/docs"));
    try testing.expect(!pathMatch("/docsets", "/docs"));
    try testing.expect(!pathMatch("/", "/docs"));
    try testing.expectEqualStrings("/", defaultPath(""));
    try testing.expectEqualStrings("/", defaultPath("/file"));
    try testing.expectEqualStrings("/a/b", defaultPath("/a/b/c"));
    try testing.expectEqualStrings("/a/b", pathOf("/a/b?c=/d"));
    try testing.expectEqualStrings("/", pathOf("?q"));
}

test "fuzz: any Set-Cookie value is read or ignored, and a read one keeps its limits" {
    try testing.fuzz({}, struct {
        fn one(_: void, smith: *testing.Smith) anyerror!void {
            var buf: [256]u8 = undefined;
            const text = buf[0..smith.slice(&buf)];
            const c = parse(text) orelse return;
            try testing.expect(c.name.len + c.value.len <= max_name_value);
            if (c.path) |p| try testing.expect(p[0] == '/');
            _ = parseDate(text);
        }
    }.one, .{ .corpus = &.{ "a=b; Path=/; Expires=Sun, 06 Nov 1994 08:49:37 GMT", "x; Max-Age=-1; Domain=.e.com" } });
}
