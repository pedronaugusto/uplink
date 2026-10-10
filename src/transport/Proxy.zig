//! A proxy every connection goes through: HTTP (an absolute URL for an
//! `http` target, a `CONNECT` tunnel for an `https` one), HTTPS (the same
//! inside TLS to the proxy), or SOCKS 4, 4a, 5 or 5h (a tunnel for both).
//!
//! Two sets of rules read proxies from the environment, because both are
//! in use: one that prefers the lower-case variable names, which git follows,
//! and one that prefers the upper-case names, which git-lfs follows. They differ in which variables count, in their
//! default port, and in what `no_proxy` can name.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const wire = @import("uplink.wire");
const auth = wire.auth;
const url_mod = wire.url;
const tls_mod = @import("../tls.zig");

const Proxy = @This();

kind: Kind,
/// The proxy's host, without IPv6 brackets.
host: []const u8,
port: u16,
/// The user and password the proxy is answered with, and which of its
/// challenges may be answered.
credential: ?Credential = null,
/// The lines of a `CONNECT` after its `Host`, in order. A line named
/// `Proxy-Authorization` with an empty value stands for the answer to the
/// proxy, written when there is one. `null` is the answer, then
/// `Proxy-Connection: Keep-Alive`.
connect_headers: ?[]const std.http.Header = null,
/// TLS to an `https` proxy.
tls: Tls = .{},

pub const Kind = enum {
    http,
    https,
    socks4,
    socks4a,
    socks5,
    socks5h,

    /// Whether the proxy speaks SOCKS.
    pub fn socks(k: Kind) bool {
        return switch (k) {
            .http, .https => false,
            .socks4, .socks4a, .socks5, .socks5h => true,
        };
    }
};

/// Which reading of the environment's proxy settings to follow. See
/// `fromEnvironment` and `bypassed` for what each does.
pub const Rules = enum {
    /// The lower-case names first, which git follows: `http_proxy` only in
    /// lower case, `no_proxy` naming hosts, domains and address ranges, and
    /// port 1080 for an `http` proxy given without one.
    lowercase,
    /// The upper-case names first, which git-lfs follows: ports in
    /// `no_proxy`, loopback never proxied, and port 80 for an `http` proxy
    /// given without one.
    uppercase,
};

/// A proxy's credential.
pub const Credential = struct {
    user: []const u8,
    password: []const u8,
    /// `any` sends nothing until the proxy asks, then answers the strongest
    /// scheme it offers; `basic` sends Basic from
    /// the first request; `digest` waits and answers Digest only.
    method: auth.Method = .any,
};

/// TLS to an `https` proxy.
pub const Tls = struct {
    /// The certificate and key a proxy that asks for one is answered with.
    client_auth: ?*const tls_mod.ClientAuth = null,
    /// How the proxy's certificate is checked.
    trust: Trust = .as_target,

    pub const Trust = union(enum) {
        /// As the target's is, with the client's `verify` and authorities,
        /// as git-lfs checks it.
        as_target,
        /// Always, whatever the client's `verify` says, against these
        /// authorities or, null, the system's, as git checks it.
        own: ?*tls_mod.Trust,
    };
};

/// Why a proxy setting was refused.
pub const ParseError = error{
    /// Not a proxy URL or `host:port`, or a scheme that is not a proxy's.
    InvalidProxy,
    OutOfMemory,
};

/// `host:port`, or a URL with scheme `http`, `https`, `socks4`, `socks4a`,
/// `socks5` or `socks5h`, with an optional percent-encoded user and
/// password. A missing port is 1080 for SOCKS, 443 for `https`, and for
/// `http` 1080 under `.lowercase` or 80 under `.uppercase`. Every string
/// belongs to `arena`.
pub fn parse(arena: Allocator, text: []const u8, rules: Rules) ParseError!Proxy {
    const url = if (std.mem.find(u8, text, "://") == null) try arena.print("http://{s}", .{text}) else try arena.dupe(u8, text);
    const uri = std.Uri.parse(url) catch return error.InvalidProxy;
    const kind = kindOf(uri.scheme) orelse return error.InvalidProxy;
    const host = if (uri.host) |h| try h.toRawMaybeAlloc(arena) else return error.InvalidProxy;
    const bare = if (host.len >= 2 and host[0] == '[' and host[host.len - 1] == ']') host[1 .. host.len - 1] else host;
    if (bare.len == 0 or std.mem.findAny(u8, bare, "\x00\r\n\t /@") != null) return error.InvalidProxy;
    var proxy: Proxy = .{
        .kind = kind,
        .host = bare,
        .port = uri.port orelse defaultPort(kind, rules),
    };
    if (uri.user != null or uri.password != null) proxy.credential = .{
        .user = if (uri.user) |u| try u.toRawMaybeAlloc(arena) else "",
        .password = if (uri.password) |p| try p.toRawMaybeAlloc(arena) else "",
    };
    return proxy;
}

fn kindOf(scheme: []const u8) ?Kind {
    inline for (comptime std.enums.values(Kind)) |k| {
        if (std.ascii.eqlIgnoreCase(scheme, @tagName(k))) return k;
    }
    return null;
}

fn defaultPort(kind: Kind, rules: Rules) u16 {
    return switch (kind) {
        .https => 443,
        .http => switch (rules) {
            .lowercase => 1080,
            .uppercase => 80,
        },
        .socks4, .socks4a, .socks5, .socks5h => 1080,
    };
}

/// Errors from `fromEnvironment`.
pub const FromEnvironmentError = error{
    /// `url` is not an `http` or `https` URL.
    InvalidUrl,
    InvalidProxy,
    OutOfMemory,
};

/// Which proxy a client's requests go through.
pub const Choice = union(enum) {
    /// None: every connection goes straight to its server.
    none,
    /// This one, for every request.
    fixed: Proxy,
    /// The one the environment names for each request's URL, by either set
    /// of rules (see `fromEnvironment`). The map must outlive the client,
    /// which reads each variable once, at the first request that needs it.
    environment: Environment,

    pub const Environment = struct {
        env: *const std.process.Environ.Map,
        rules: Rules,
    };
};

/// The proxy the environment chooses for `url`, or null: none is set, or
/// `no_proxy` names the host. uplink never reads the process environment
/// itself; the caller hands it in.
///
/// - `.lowercase`: for `https`, `https_proxy`, `HTTPS_PROXY`, `all_proxy`,
///   `ALL_PROXY`; for `http`, `http_proxy` (lower case only, because a CGI
///   program is handed a request's `Proxy` field as `HTTP_PROXY`),
///   `all_proxy`, `ALL_PROXY`. Then `no_proxy`, else `NO_PROXY`.
/// - `.uppercase`: for `https`, `HTTPS_PROXY`, `https_proxy`, then the `http`
///   list; for `http`, `HTTP_PROXY`, `http_proxy`, `all_proxy`,
///   `ALL_PROXY`. Then `NO_PROXY`, else `no_proxy`. Never for `localhost`
///   or a loopback address.
pub fn fromEnvironment(arena: Allocator, env: *const std.process.Environ.Map, url: []const u8, rules: Rules) FromEnvironmentError!?Proxy {
    const target = url_mod.parse(url) catch return error.InvalidUrl;
    const value = environmentValue(env, target.secure, rules) orelse return null;
    if (bypassed(noProxyValue(env, rules), target.host, target.port, rules)) return null;
    const proxy = try parse(arena, value, rules);
    return proxy;
}

/// The proxy setting the environment holds for `https` or `http` targets
/// under `rules`, unparsed, or null.
pub fn environmentValue(env: *const std.process.Environ.Map, https: bool, rules: Rules) ?[]const u8 {
    const names: []const []const u8 = switch (rules) {
        .lowercase => if (https) &.{ "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY" } else &.{ "http_proxy", "all_proxy", "ALL_PROXY" },
        .uppercase => if (https) &.{ "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "all_proxy", "ALL_PROXY" } else &.{ "HTTP_PROXY", "http_proxy", "all_proxy", "ALL_PROXY" },
    };
    for (names) |name| {
        const v = env.get(name) orelse continue;
        if (v.len != 0) return v;
    }
    return null;
}

/// The `no_proxy` list the environment holds under `rules`, or empty.
pub fn noProxyValue(env: *const std.process.Environ.Map, rules: Rules) []const u8 {
    const names: [2][]const u8 = switch (rules) {
        .lowercase => .{ "no_proxy", "NO_PROXY" },
        .uppercase => .{ "NO_PROXY", "no_proxy" },
    };
    for (names) |name| {
        const v = env.get(name) orelse continue;
        if (v.len != 0) return v;
    }
    return "";
}

/// Whether a request to `host` on `port` goes around the proxy, as a
/// `no_proxy` list says under `rules`.
///
/// - `.lowercase`: `*`; the host itself; a domain it lies in, with or without a
///   leading dot; an address range in CIDR notation for an address host.
/// - `.uppercase`: never through the proxy for `localhost` or a loopback address;
///   `*`; a domain and the hosts under it, `.domain` or `*.domain` for the
///   hosts under it only; an address; a range; each with a port or without.
pub fn bypassed(no_proxy: []const u8, host: []const u8, port: u16, rules: Rules) bool {
    const bare = std.mem.trim(u8, std.mem.trim(u8, host, " "), "[]");
    return switch (rules) {
        .lowercase => lowercaseBypassed(no_proxy, bare),
        .uppercase => uppercaseBypassed(no_proxy, bare, port),
    };
}

fn lowercaseBypassed(list: []const u8, host: []const u8) bool {
    const ip: ?IpAddress = IpAddress.parse(host, 0) catch null;
    var it = std.mem.tokenizeAny(u8, list, ", \t");
    while (it.next()) |entry| {
        if (std.mem.eql(u8, entry, "*")) return true;
        if (std.mem.findScalar(u8, entry, '/')) |slash| {
            if (ip) |a| if (inCidr(a, entry, slash)) return true;
            continue;
        }
        const domain = std.mem.trim(u8, std.mem.trimStart(u8, entry, "."), "[]");
        if (domain.len == 0) continue;
        if (std.ascii.eqlIgnoreCase(host, domain)) return true;
        if (ip == null and host.len > domain.len and std.ascii.endsWithIgnoreCase(host, domain) and host[host.len - domain.len - 1] == '.') return true;
    }
    return false;
}

fn uppercaseBypassed(list: []const u8, host: []const u8, port: u16) bool {
    if (std.ascii.eqlIgnoreCase(host, "localhost")) return true;
    const ip: ?IpAddress = IpAddress.parse(host, 0) catch null;
    if (ip) |a| if (isLoopback(a)) return true;
    var port_buf: [8]u8 = undefined;
    const port_text = std.mem.print(&port_buf, "{d}", .{port}) catch unreachable; // unreachable: a u16 is at most five digits
    var it = std.mem.splitScalar(u8, list, ',');
    while (it.next()) |raw| {
        const entry = std.mem.trim(u8, raw, " \t\r\n");
        if (entry.len == 0) continue;
        if (std.mem.eql(u8, entry, "*")) return true;
        if (std.mem.findScalar(u8, entry, '/')) |slash| {
            if (ip) |a| if (inCidr(a, entry, slash)) return true;
            continue;
        }
        // `host:port` or `[v6]:port`, else the entry is all host.
        var entry_host = entry;
        var entry_port: []const u8 = "";
        if (splitHostPort(entry)) |hp| {
            entry_host = hp.host;
            entry_port = hp.port;
            if (entry_host.len == 0) continue;
        }
        const port_ok = entry_port.len == 0 or std.mem.eql(u8, entry_port, port_text);
        if (IpAddress.parse(entry_host, 0)) |entry_ip| {
            if (ip) |a| if (sameAddress(a, entry_ip) and port_ok) return true;
            continue;
        } else |_| {}
        if (ip != null) continue;
        var domain = entry_host;
        if (std.mem.startsWith(u8, domain, "*.")) domain = domain[1..];
        const match_host = domain[0] != '.';
        const suffix_ok = if (match_host)
            host.len > domain.len and std.ascii.endsWithIgnoreCase(host, domain) and host[host.len - domain.len - 1] == '.'
        else
            std.ascii.endsWithIgnoreCase(host, domain);
        const exact = match_host and std.ascii.eqlIgnoreCase(host, domain);
        if ((suffix_ok or exact) and port_ok) return true;
    }
    return false;
}

fn splitHostPort(text: []const u8) ?struct { host: []const u8, port: []const u8 } {
    if (text.len != 0 and text[0] == '[') {
        const close = std.mem.findScalar(u8, text, ']') orelse return null;
        if (close + 1 >= text.len or text[close + 1] != ':') return null;
        return .{ .host = text[1..close], .port = text[close + 2 ..] };
    }
    const colon = std.mem.findScalar(u8, text, ':') orelse return null;
    // More than one colon is an IPv6 address with no port.
    if (std.mem.findScalarPos(u8, text, colon + 1, ':') != null) return null;
    return .{ .host = text[0..colon], .port = text[colon + 1 ..] };
}

/// An address's bytes, an IPv4 address written as IPv6 read as IPv4.
fn addressBytes(a: IpAddress, buf: *[16]u8) []const u8 {
    switch (a) {
        .ip4 => |v4| {
            buf[0..4].* = v4.bytes;
            return buf[0..4];
        },
        .ip6 => |v6| {
            if (std.mem.eql(u8, v6.bytes[0..12], &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff })) {
                buf[0..4].* = v6.bytes[12..16].*;
                return buf[0..4];
            }
            buf.* = v6.bytes;
            return buf[0..16];
        },
    }
}

fn isLoopback(a: IpAddress) bool {
    var buf: [16]u8 = undefined;
    const bytes = addressBytes(a, &buf);
    if (bytes.len == 4) return bytes[0] == 127;
    return std.mem.eql(u8, bytes, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 });
}

fn sameAddress(a: IpAddress, b: IpAddress) bool {
    var abuf: [16]u8 = undefined;
    var bbuf: [16]u8 = undefined;
    return std.mem.eql(u8, addressBytes(a, &abuf), addressBytes(b, &bbuf));
}

/// Whether `a` lies in the range `entry`, `base/bits` with the slash at
/// `slash`.
fn inCidr(a: IpAddress, entry: []const u8, slash: usize) bool {
    const base = IpAddress.parse(std.mem.trim(u8, entry[0..slash], "[]"), 0) catch return false;
    const bits = std.fmt.parseInt(u8, entry[slash + 1 ..], 10) catch return false;
    var abuf: [16]u8 = undefined;
    var bbuf: [16]u8 = undefined;
    const x = addressBytes(a, &abuf);
    const y = addressBytes(base, &bbuf);
    if (x.len != y.len or bits > x.len * 8) return false;
    var i: usize = 0;
    while (i < bits) : (i += 1) {
        const mask = @as(u8, 0x80) >> @intCast(i % 8);
        if ((x[i / 8] & mask) != (y[i / 8] & mask)) return false;
    }
    return true;
}

const testing = std.testing;

test "proxy URLs keep IPv6 hosts and decoded credentials, and default their ports by rules" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const p = try parse(a, "SOCKS5H://us%65r:p%40ss@[::1]", .lowercase);
    try testing.expectEqualStrings("::1", p.host);
    try testing.expectEqual(@as(u16, 1080), p.port);
    try testing.expectEqual(Kind.socks5h, p.kind);
    try testing.expectEqualStrings("user", p.credential.?.user);
    try testing.expectEqualStrings("p@ss", p.credential.?.password);
    try testing.expectEqual(@as(u16, 1080), (try parse(a, "proxy.example", .lowercase)).port);
    try testing.expectEqual(@as(u16, 80), (try parse(a, "proxy.example", .uppercase)).port);
    try testing.expectEqual(@as(u16, 443), (try parse(a, "https://proxy.example", .uppercase)).port);
    try testing.expectEqual(Kind.https, (try parse(a, "HTTPS://proxy.example:8443", .lowercase)).kind);
    for ([_][]const u8{ "unsupported://host", "socks5://", "socks5://host:bad", "socks5://h%00st", "ftp://h" }) |text| {
        try testing.expectError(error.InvalidProxy, parse(a, text, .lowercase));
    }
    const explicit = try parse(a, "socks4://user@host:7777", .lowercase);
    try testing.expectEqual(@as(u16, 7777), explicit.port);
    try testing.expectEqualStrings("", explicit.credential.?.password);
}

test "parsed proxy strings outlive the text they came from" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    for ([_][]const u8{ "http", "https", "socks4", "socks4a", "socks5", "socks5h" }) |scheme| {
        var buffer: [128]u8 = undefined;
        const raw = try std.mem.print(&buffer, "{s}://user:secret@[::1]:3128", .{scheme});
        const proxy = try parse(arena.allocator(), raw, .lowercase);
        @memset(buffer[0..raw.len], 'x');
        try testing.expectEqualStrings("::1", proxy.host);
        try testing.expectEqualStrings("user", proxy.credential.?.user);
        try testing.expectEqualStrings("secret", proxy.credential.?.password);
        try testing.expectEqual(@as(u16, 3128), proxy.port);
    }
}

test "the lower-case rules: lower-case http_proxy only, https's own list, no_proxy before NO_PROXY" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    // Windows names its variables without case: there `HTTP_PROXY` is
    // `http_proxy` under either rules, and `NO_PROXY` is `no_proxy`.
    const cased = builtin.target.os.tag != .windows;
    var env: std.process.Environ.Map = .init(testing.allocator);
    defer env.deinit();
    try env.put("HTTP_PROXY", "http://upper:1");
    if (cased) try testing.expectEqual(null, try fromEnvironment(a, &env, "http://git.example/x", .lowercase));
    try testing.expectEqualStrings("upper", (try fromEnvironment(a, &env, "http://git.example/x", .uppercase)).?.host);
    try env.put("http_proxy", "http://lower:2");
    try env.put("HTTPS_PROXY", "http://secure:3");
    try testing.expectEqualStrings("lower", (try fromEnvironment(a, &env, "http://git.example/x", .lowercase)).?.host);
    try testing.expectEqualStrings("secure", (try fromEnvironment(a, &env, "https://git.example/x", .lowercase)).?.host);
    try env.put("NO_PROXY", "other.example");
    try env.put("no_proxy", ".example");
    try testing.expectEqual(null, try fromEnvironment(a, &env, "https://git.example/x", .lowercase));
    // The upper-case rules read NO_PROXY first, which does not name git.example.
    if (cased) try testing.expect((try fromEnvironment(a, &env, "https://git.example/x", .uppercase)) != null);
    try testing.expectEqual(null, try fromEnvironment(a, &env, "http://localhost:8080/", .uppercase));
    try testing.expectError(error.InvalidUrl, fromEnvironment(a, &env, "ftp://x/", .lowercase));
}

test "no_proxy is read as each set of rules reads it" {
    try testing.expect(bypassed("*", "anything", 80, .lowercase));
    try testing.expect(bypassed("example.com", "git.example.com", 80, .lowercase));
    try testing.expect(bypassed(".example.com", "example.com", 80, .lowercase));
    try testing.expect(!bypassed("ample.com", "example.com", 80, .lowercase));
    try testing.expect(bypassed("10.0.0.0/8, 192.168.1.1", "10.1.2.3", 80, .lowercase));
    try testing.expect(bypassed("::1", "[::1]", 80, .lowercase));
    try testing.expect(!bypassed("10.0.0.0/8", "11.0.0.1", 80, .lowercase));
    try testing.expect(bypassed("", "127.0.0.2", 80, .uppercase));
    try testing.expect(bypassed("", "LOCALHOST", 80, .uppercase));
    try testing.expect(bypassed("example.com:443", "git.example.com", 443, .uppercase));
    try testing.expect(!bypassed("example.com:443", "git.example.com", 80, .uppercase));
    try testing.expect(bypassed("*.example.com", "git.example.com", 80, .uppercase));
    try testing.expect(!bypassed("*.example.com", "example.com", 80, .uppercase));
    try testing.expect(bypassed("fd00::/8", "fd12::1", 80, .uppercase));
    try testing.expect(bypassed("[::ffff:10.0.0.1]:80", "10.0.0.1", 80, .uppercase));
    try testing.expect(!bypassed("10.0.0.1", "git.example.com", 80, .uppercase));
}

test "the upper-case rules go around the proxy for loopback, and for what NO_PROXY names, with a port or without" {
    const Case = struct { host: []const u8, port: u16 = 443, list: []const u8, around: bool };
    for ([_]Case{
        .{ .host = "localhost", .list = "", .around = true },
        .{ .host = "127.0.0.1", .list = "", .around = true },
        .{ .host = "127.8.9.10", .list = "", .around = true },
        .{ .host = "::1", .list = "", .around = true },
        .{ .host = "[::1]", .list = "", .around = true },
        .{ .host = "git.example.com", .list = "", .around = false },
        .{ .host = "git.example.com", .list = "*", .around = true },
        .{ .host = "git.example.com", .list = "example.com", .around = true },
        .{ .host = "example.com", .list = "example.com", .around = true },
        .{ .host = "badexample.com", .list = "example.com", .around = false },
        .{ .host = "example.com", .list = ".example.com", .around = false },
        .{ .host = "git.example.com", .list = ".example.com", .around = true },
        .{ .host = "example.com", .list = "*.example.com", .around = false },
        .{ .host = "git.EXAMPLE.com", .list = " other.org , Example.com ", .around = true },
        .{ .host = "git.example.com", .port = 443, .list = "example.com:8443", .around = false },
        .{ .host = "git.example.com", .port = 8443, .list = "example.com:8443", .around = true },
        .{ .host = "10.1.2.3", .list = "10.0.0.0/8", .around = true },
        .{ .host = "11.1.2.3", .list = "10.0.0.0/8", .around = false },
        .{ .host = "192.168.1.5", .list = "192.168.1.5", .around = true },
        .{ .host = "192.168.1.5", .port = 80, .list = "192.168.1.5:8080", .around = false },
        .{ .host = "fd00::1", .list = "fd00::/8", .around = true },
        .{ .host = "10.1.2.3", .list = "10.1.2.3.example", .around = false },
    }) |case| {
        testing.expectEqual(case.around, bypassed(case.list, case.host, case.port, .uppercase)) catch |err| {
            std.debug.print("{s}:{d} with NO_PROXY={s}\n", .{ case.host, case.port, case.list });
            return err;
        };
    }
}
