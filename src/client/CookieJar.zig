//! A cookie store (RFC 6265bis): what servers set with `Set-Cookie`, kept
//! and sent back in a `Cookie` field to the requests it belongs to. A jar
//! is the caller's: one may serve several clients, and is safe to share
//! between tasks. It reads and writes the Netscape cookie file that curl,
//! git (`http.cookieFile`, `http.saveCookies`) and browsers' exporters use.
//!
//! Cookies are filed by domain, so a request looks at the few domains its
//! host lies in, not at every cookie. Storing allocates; sending never
//! does.
//!
//! The store follows RFC 6265bis §5.7: a `Domain` must cover the request's
//! host and not be a public suffix; a `Secure` cookie is taken only over
//! `https`, and a plain one may not shadow it; `__Secure-` and `__Host-`
//! names keep their promises; the longest path is sent first. Expired
//! cookies are dropped as they are met. There is no public suffix list in
//! uplink: `Options.public_suffix` plugs one in, and without one a domain
//! of a single label (`com`, `local`) is taken as a suffix.

const std = @import("std");
const aegis = @import("aegis");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const cookie = @import("../wire/cookie.zig");
const fields = @import("../wire/fields.zig");
const url_mod = @import("../wire/url.zig");

const CookieJar = @This();

gpa: Allocator,
options: Options,
/// Private: the cookies, reached only through the lock beside them.
state: aegis.BlockingGuarded(State),
/// Private: cookies kept in all, and readable without the lock: a request
/// with no cookie to send reads it alone, and pays for no lock.
total: std.atomic.Value(u32) = .init(0),

/// What the lock guards.
const State = struct {
    /// Lower-cased domains, owned, to their cookies.
    domains: std.StringHashMapUnmanaged(std.ArrayList(*Cookie)) = .empty,
    /// The order cookies were made in.
    next_seq: u64 = 0,
    /// The cookies one request sends, sorted; kept for the next.
    scratch: std.ArrayList(*Cookie) = .empty,
};

/// How much a jar keeps, and how it knows a public suffix.
pub const Options = struct {
    /// Cookies kept for one domain; past it, the oldest go.
    max_per_domain: u16 = 50,
    /// Cookies kept in all; past it, the oldest go.
    max_total: u32 = 3000,
    /// Whether a domain is a public suffix (`co.uk`, `github.io`), where no
    /// cookie may be set for every host under it.
    public_suffix: ?PublicSuffix = null,
};

/// A public suffix list, the caller's.
pub const PublicSuffix = struct {
    context: ?*anyopaque,
    /// Whether `domain`, lower-cased, is a public suffix.
    isFn: *const fn (context: ?*anyopaque, domain: []const u8) bool,
};

/// One kept cookie. Every slice is in `bytes`.
pub const Cookie = struct {
    name: []const u8,
    value: []const u8,
    /// Lower-cased.
    domain: []const u8,
    path: []const u8,
    /// Seconds since the epoch; null for a session cookie, which goes with
    /// the jar.
    expires: ?i64,
    /// Sent to `domain` alone, not to the hosts under it.
    host_only: bool,
    secure: bool,
    http_only: bool,
    same_site: cookie.SameSite,
    /// Private: the order it was made in.
    seq: u64,
    bytes: []u8,

    fn expired(c: *const Cookie, now: i64) bool {
        const e = c.expires orelse return false;
        return e <= now;
    }
};

pub fn init(gpa: Allocator, options: Options) CookieJar {
    return .{ .gpa = gpa, .options = options, .state = .init(.{}) };
}

/// Free every cookie. No task may be using the jar.
pub fn deinit(jar: *CookieJar, io: Io) void {
    var held = jar.state.acquireUncancelable(io);
    const s = held.value();
    var it = s.domains.iterator();
    while (it.next()) |kv| {
        for (kv.value_ptr.items) |c| jar.freeCookie(c);
        kv.value_ptr.deinit(jar.gpa);
        jar.gpa.free(kv.key_ptr.*);
    }
    s.domains.deinit(jar.gpa);
    s.scratch.deinit(jar.gpa);
    held.deinit(io);
    jar.* = undefined;
}

fn freeCookie(jar: *CookieJar, c: *Cookie) void {
    jar.gpa.free(c.bytes);
    jar.gpa.destroy(c);
}

/// How many cookies are kept, expired ones not yet met included.
pub fn count(jar: *const CookieJar) u32 {
    return jar.total.load(.monotonic);
}

/// Seconds since the epoch, now.
fn nowOf(io: Io) i64 {
    return Io.Clock.real.now(io).toSeconds();
}

/// Take one `Set-Cookie` value from a response to `url`. One the rules
/// refuse is dropped, as a browser drops it.
pub fn store(jar: *CookieJar, io: Io, url: url_mod.Url, set_cookie: []const u8) Allocator.Error!void {
    return jar.storeAt(io, url, set_cookie, nowOf(io));
}

/// Take every `Set-Cookie` of a response to `url`.
pub fn storeAll(jar: *CookieJar, io: Io, url: url_mod.Url, headers: *const fields.Headers) Allocator.Error!void {
    if (headers.getKnown(.@"set-cookie") == null) return;
    const now = nowOf(io);
    var it = headers.iterator();
    while (it.next()) |f| {
        if (std.ascii.eqlIgnoreCase(f.name, "set-cookie")) try jar.storeAt(io, url, f.value, now);
    }
}

fn storeAt(jar: *CookieJar, io: Io, url: url_mod.Url, set_cookie: []const u8, now: i64) Allocator.Error!void {
    const sc = cookie.parse(set_cookie) orelse return;
    var host_buf: [Io.net.HostName.max_len]u8 = undefined;
    if (url.host.len > host_buf.len) return;
    const host = std.ascii.lowerString(&host_buf, url.host);
    var domain_buf: [Io.net.HostName.max_len]u8 = undefined;
    var domain: []const u8 = host;
    var host_only = true;
    if (sc.domain) |d| {
        if (d.len > domain_buf.len) return;
        const lower = std.ascii.lowerString(&domain_buf, d);
        if (jar.isPublicSuffix(lower)) {
            if (!std.mem.eql(u8, lower, host)) return;
        } else {
            if (!cookie.domainMatch(host, lower)) return;
            domain = lower;
            host_only = false;
        }
    }
    const path = sc.path orelse cookie.defaultPath(cookie.pathOf(url.target));
    if (sc.secure and !url.secure) return;
    if (!prefixKept(sc, host_only, path)) return;
    var expires: ?i64 = sc.expires;
    if (sc.max_age) |age| expires = if (age <= 0) std.math.minInt(i64) else now +| age;

    var held = jar.state.acquireUncancelable(io);
    defer held.deinit(io);
    const s = held.value();
    if (!sc.secure and !url.secure and shadowsSecure(s, host, sc.name, path)) return;
    const gop = try s.domains.getOrPut(jar.gpa, domain);
    if (!gop.found_existing) {
        gop.key_ptr.* = jar.gpa.dupe(u8, domain) catch |err| {
            s.domains.removeByPtr(gop.key_ptr);
            return err;
        };
        gop.value_ptr.* = .empty;
    }
    const list = gop.value_ptr;
    // The same name, domain, host-only flag and path: replaced, keeping
    // when it was first made.
    var seq = s.next_seq;
    for (list.items, 0..) |old, i| {
        if (old.host_only != host_only or !std.mem.eql(u8, old.name, sc.name) or !std.mem.eql(u8, old.path, path)) continue;
        seq = old.seq;
        _ = list.orderedRemove(i);
        jar.freeCookie(old);
        _ = jar.total.fetchSub(1, .monotonic);
        break;
    }
    if (expires) |e| if (e <= now) return jar.dropEmpty(s, gop.key_ptr.*);
    // Room for every cookie in the list a request sends, so sending never
    // allocates or drops one.
    try s.scratch.ensureTotalCapacity(jar.gpa, jar.total.load(.monotonic) + 1);
    const c = try jar.make(sc, gop.key_ptr.*, path, expires, host_only, seq);
    errdefer jar.freeCookie(c);
    try list.append(jar.gpa, c);
    if (seq == s.next_seq) s.next_seq += 1;
    _ = jar.total.fetchAdd(1, .monotonic);
    jar.enforceLimits(s, list, now);
}

/// The rules of the `__Secure-` and `__Host-` name prefixes.
fn prefixKept(sc: cookie.SetCookie, host_only: bool, path: []const u8) bool {
    const text = if (sc.name.len != 0) sc.name else sc.value;
    if (std.ascii.startsWithIgnoreCase(text, "__Secure-")) return sc.name.len != 0 and sc.secure;
    if (std.ascii.startsWithIgnoreCase(text, "__Host-")) return sc.name.len != 0 and sc.secure and host_only and std.mem.eql(u8, path, "/");
    return true;
}

fn isPublicSuffix(jar: *const CookieJar, domain: []const u8) bool {
    if (jar.options.public_suffix) |ps| return ps.isFn(ps.context, domain);
    return std.mem.findScalar(u8, domain, '.') == null;
}

/// Whether a plain cookie `name` for `host` at `path` would shadow a
/// `Secure` one (RFC 6265bis §5.7, step 16).
fn shadowsSecure(s: *State, host: []const u8, name: []const u8, path: []const u8) bool {
    var it = s.domains.iterator();
    while (it.next()) |kv| for (kv.value_ptr.items) |c| {
        if (!c.secure or !std.mem.eql(u8, c.name, name)) continue;
        if (!cookie.domainMatch(host, c.domain) and !cookie.domainMatch(c.domain, host)) continue;
        if (cookie.pathMatch(path, c.path)) return true;
    };
    return false;
}

fn make(jar: *CookieJar, sc: cookie.SetCookie, domain: []const u8, path: []const u8, expires: ?i64, host_only: bool, seq: u64) Allocator.Error!*Cookie {
    const bytes = try jar.gpa.alloc(u8, sc.name.len + sc.value.len + path.len);
    errdefer jar.gpa.free(bytes);
    const c = try jar.gpa.create(Cookie);
    @memcpy(bytes[0..sc.name.len], sc.name);
    @memcpy(bytes[sc.name.len..][0..sc.value.len], sc.value);
    @memcpy(bytes[sc.name.len + sc.value.len ..], path);
    c.* = .{
        .name = bytes[0..sc.name.len],
        .value = bytes[sc.name.len..][0..sc.value.len],
        .domain = domain,
        .path = bytes[sc.name.len + sc.value.len ..],
        .expires = expires,
        .host_only = host_only,
        .secure = sc.secure,
        .http_only = sc.http_only,
        .same_site = sc.same_site,
        .seq = seq,
        .bytes = bytes,
    };
    return c;
}

/// Past a domain's or the jar's cap: expired cookies go, then the oldest.
fn enforceLimits(jar: *CookieJar, s: *State, list: *std.ArrayList(*Cookie), now: i64) void {
    if (list.items.len > jar.options.max_per_domain) {
        jar.purgeExpired(list, now);
        while (list.items.len > jar.options.max_per_domain) {
            var oldest: usize = 0;
            for (list.items, 0..) |c, i| if (c.seq < list.items[oldest].seq) {
                oldest = i;
            };
            jar.freeCookie(list.orderedRemove(oldest));
            _ = jar.total.fetchSub(1, .monotonic);
        }
    }
    while (jar.total.load(.monotonic) > jar.options.max_total) {
        var oldest: ?struct { list: *std.ArrayList(*Cookie), index: usize } = null;
        var it = s.domains.valueIterator();
        while (it.next()) |l| for (l.items, 0..) |c, i| {
            if (oldest == null or c.seq < oldest.?.list.items[oldest.?.index].seq) oldest = .{ .list = l, .index = i };
        };
        const o = oldest orelse break;
        jar.freeCookie(o.list.orderedRemove(o.index));
        _ = jar.total.fetchSub(1, .monotonic);
    }
}

fn purgeExpired(jar: *CookieJar, list: *std.ArrayList(*Cookie), now: i64) void {
    var i: usize = 0;
    while (i < list.items.len) {
        if (list.items[i].expired(now)) {
            jar.freeCookie(list.orderedRemove(i));
            _ = jar.total.fetchSub(1, .monotonic);
        } else i += 1;
    }
}

/// Drop a domain with no cookies left.
fn dropEmpty(jar: *CookieJar, s: *State, domain: []const u8) void {
    const list = s.domains.getPtr(domain) orelse return;
    if (list.items.len != 0) return;
    list.deinit(jar.gpa);
    const kv = s.domains.fetchRemove(domain).?;
    jar.gpa.free(kv.key);
}

/// Write `Cookie: …` and its line end for a request to `url`, with the
/// cookies that go to it, longest path first: whether any went. A
/// session-long cookie and a persistent one alike; expired ones are
/// dropped as they are met.
pub fn writeField(jar: *CookieJar, io: Io, w: *Io.Writer, url: url_mod.Url) Io.Writer.Error!bool {
    if (jar.total.load(.monotonic) == 0) return false;
    var host_buf: [Io.net.HostName.max_len]u8 = undefined;
    if (url.host.len > host_buf.len) return false;
    const host = std.ascii.lowerString(&host_buf, url.host);
    const path = cookie.pathOf(url.target);
    const now = nowOf(io);
    var held = jar.state.acquireUncancelable(io);
    defer held.deinit(io);
    const s = held.value();
    s.scratch.clearRetainingCapacity();
    // The host, then each domain above it; an address is only itself.
    var domain = host;
    const address = cookie.isAddress(host);
    while (true) {
        if (s.domains.getPtr(domain)) |list| {
            jar.purgeExpired(list, now);
            for (list.items) |c| {
                if (c.host_only and domain.len != host.len) continue;
                if (c.secure and !url.secure) continue;
                if (!cookie.pathMatch(path, c.path)) continue;
                s.scratch.appendAssumeCapacity(c);
            }
        }
        if (address) break;
        const dot = std.mem.findScalar(u8, domain, '.') orelse break;
        domain = domain[dot + 1 ..];
    }
    if (s.scratch.items.len == 0) return false;
    std.sort.insertion(*Cookie, s.scratch.items, {}, sendFirst);
    try w.writeAll("Cookie: ");
    for (s.scratch.items, 0..) |c, i| {
        if (i != 0) try w.writeAll("; ");
        if (c.name.len != 0) {
            try w.writeAll(c.name);
            try w.writeByte('=');
        }
        try w.writeAll(c.value);
    }
    try w.writeAll("\r\n");
    return true;
}

fn sendFirst(_: void, a: *Cookie, b: *Cookie) bool {
    if (a.path.len != b.path.len) return a.path.len > b.path.len;
    return a.seq < b.seq;
}

/// Forget every cookie.
pub fn clear(jar: *CookieJar, io: Io) void {
    var held = jar.state.acquireUncancelable(io);
    defer held.deinit(io);
    const s = held.value();
    var it = s.domains.iterator();
    while (it.next()) |kv| {
        for (kv.value_ptr.items) |c| jar.freeCookie(c);
        kv.value_ptr.deinit(jar.gpa);
        jar.gpa.free(kv.key_ptr.*);
    }
    s.domains.clearRetainingCapacity();
    jar.total.store(0, .monotonic);
}

/// Forget the session cookies, as a browser does when it closes.
pub fn clearSession(jar: *CookieJar, io: Io) void {
    var held = jar.state.acquireUncancelable(io);
    defer held.deinit(io);
    const s = held.value();
    var it = s.domains.valueIterator();
    while (it.next()) |list| {
        var i: usize = 0;
        while (i < list.items.len) {
            if (list.items[i].expires == null) {
                jar.freeCookie(list.orderedRemove(i));
                _ = jar.total.fetchSub(1, .monotonic);
            } else i += 1;
        }
    }
}

/// Errors from `load`.
pub const LoadError = error{
    ReadFailed,
    /// A line longer than the reader's buffer.
    StreamTooLong,
    OutOfMemory,
};

/// Read cookies from a Netscape cookie file, as curl writes one:
/// `domain`, `TRUE` when hosts under it get it, `path`, `TRUE` for secure,
/// expiry in seconds (0 for a session cookie), name and value, separated by
/// tabs; `#HttpOnly_` before an HTTP-only cookie's domain; other `#` lines
/// are comments. Lines that are not cookies, and expired cookies, are
/// skipped. A cookie read replaces one of the same name, domain and path.
pub fn load(jar: *CookieJar, io: Io, r: *Io.Reader) LoadError!void {
    const now = nowOf(io);
    while (true) {
        const taken = r.takeDelimiter('\n') catch |err| return switch (err) {
            error.ReadFailed => error.ReadFailed,
            error.StreamTooLong => error.StreamTooLong,
        };
        const raw = taken orelse return;
        const line = std.mem.trimEnd(u8, raw, "\r");
        try jar.loadLine(io, line, now);
    }
}

fn loadLine(jar: *CookieJar, io: Io, line: []const u8, now: i64) Allocator.Error!void {
    var text = line;
    var http_only = false;
    if (std.mem.startsWith(u8, text, "#HttpOnly_")) {
        http_only = true;
        text = text["#HttpOnly_".len..];
    } else if (text.len == 0 or text[0] == '#') return;
    var parts: [7][]const u8 = @splat("");
    var it = std.mem.splitScalar(u8, text, '\t');
    var n: usize = 0;
    while (it.next()) |p| : (n += 1) {
        if (n == parts.len) return;
        parts[n] = p;
    }
    if (n < 6) return;
    const domain_raw = if (parts[0].len != 0 and parts[0][0] == '.') parts[0][1..] else parts[0];
    if (domain_raw.len == 0 or domain_raw.len > Io.net.HostName.max_len) return;
    const name = parts[5];
    const value = parts[6];
    if (name.len + value.len > cookie.max_name_value) return;
    if (fields.hasControl(name) or fields.hasControl(value) or std.mem.findScalar(u8, name, ';') != null or std.mem.findScalar(u8, value, ';') != null) return;
    const path = parts[2];
    if (path.len == 0 or path[0] != '/') return;
    const expires_n = std.fmt.parseInt(i64, parts[4], 10) catch return;
    const expires: ?i64 = if (expires_n == 0) null else expires_n;
    if (expires) |e| if (e <= now) return;
    var domain_buf: [Io.net.HostName.max_len]u8 = undefined;
    const domain = std.ascii.lowerString(&domain_buf, domain_raw);
    const sc: cookie.SetCookie = .{
        .name = name,
        .value = value,
        .secure = std.ascii.eqlIgnoreCase(parts[3], "TRUE"),
        .http_only = http_only,
    };
    var held = jar.state.acquireUncancelable(io);
    defer held.deinit(io);
    const s = held.value();
    const gop = try s.domains.getOrPut(jar.gpa, domain);
    if (!gop.found_existing) {
        gop.key_ptr.* = jar.gpa.dupe(u8, domain) catch |err| {
            s.domains.removeByPtr(gop.key_ptr);
            return err;
        };
        gop.value_ptr.* = .empty;
    }
    const host_only = !std.ascii.eqlIgnoreCase(parts[1], "TRUE");
    const list = gop.value_ptr;
    for (list.items, 0..) |old, i| {
        if (old.host_only != host_only or !std.mem.eql(u8, old.name, name) or !std.mem.eql(u8, old.path, path)) continue;
        _ = list.orderedRemove(i);
        jar.freeCookie(old);
        _ = jar.total.fetchSub(1, .monotonic);
        break;
    }
    try s.scratch.ensureTotalCapacity(jar.gpa, jar.total.load(.monotonic) + 1);
    const c = try jar.make(sc, gop.key_ptr.*, path, expires, host_only, s.next_seq);
    errdefer jar.freeCookie(c);
    try list.append(jar.gpa, c);
    s.next_seq += 1;
    _ = jar.total.fetchAdd(1, .monotonic);
    jar.enforceLimits(s, list, now);
}

/// Which cookies `save` writes.
pub const SaveOptions = struct {
    /// Session cookies too, with expiry 0, as curl writes them; git's
    /// `http.saveCookies` keeps only persistent ones.
    session: bool = false,
};

/// Write the unexpired cookies as a Netscape cookie file, oldest first.
pub fn save(jar: *CookieJar, io: Io, w: *Io.Writer, options: SaveOptions) Io.Writer.Error!void {
    const now = nowOf(io);
    var held = jar.state.acquireUncancelable(io);
    defer held.deinit(io);
    const s = held.value();
    try w.writeAll("# Netscape HTTP Cookie File\n\n");
    s.scratch.clearRetainingCapacity();
    var it = s.domains.valueIterator();
    while (it.next()) |list| for (list.items) |c| {
        if (c.expired(now) or (c.expires == null and !options.session)) continue;
        s.scratch.appendAssumeCapacity(c);
    };
    std.sort.insertion(*Cookie, s.scratch.items, {}, older);
    for (s.scratch.items) |c| {
        try w.print("{s}{s}{s}\t{s}\t{s}\t{s}\t{d}\t{s}\t{s}\n", .{
            if (c.http_only) "#HttpOnly_" else "",
            if (c.host_only) "" else ".",
            c.domain,
            if (c.host_only) "FALSE" else "TRUE",
            c.path,
            if (c.secure) "TRUE" else "FALSE",
            c.expires orelse 0,
            c.name,
            c.value,
        });
    }
}

fn older(_: void, a: *Cookie, b: *Cookie) bool {
    return a.seq < b.seq;
}

const testing = std.testing;
const shakedown = @import("shakedown");

fn field(jar: *CookieJar, io: Io, url: []const u8) ![]const u8 {
    const S = struct {
        threadlocal var buf: [1024]u8 = undefined;
    };
    var w: Io.Writer = .fixed(&S.buf);
    if (!try jar.writeField(io, &w, try url_mod.parse(url))) return "";
    return w.buffered();
}

test "cookies go back to their host, domain and path, longest path first" {
    var clock: shakedown.Clock = .init(testing.io, .{});
    const io = clock.io();
    var jar: CookieJar = .init(testing.allocator, .{});
    defer jar.deinit(io);
    const from = try url_mod.parse("https://www.example.com/docs/page");
    try jar.store(io, from, "host=1");
    try jar.store(io, from, "wide=2; Domain=.Example.com; Path=/");
    try jar.store(io, from, "deep=3; Path=/docs/web");
    try jar.store(io, from, "safe=4; Secure; Path=/");
    try testing.expectEqualStrings("Cookie: deep=3; host=1; wide=2; safe=4\r\n", try field(&jar, io, "https://www.example.com/docs/web/x"));
    try testing.expectEqualStrings("Cookie: wide=2\r\n", try field(&jar, io, "http://api.example.com/docs"));
    try testing.expectEqualStrings("Cookie: host=1; wide=2\r\n", try field(&jar, io, "http://WWW.example.com/docs"));
    try testing.expectEqualStrings("", try field(&jar, io, "https://example.org/"));
    try testing.expectEqual(@as(u32, 4), jar.count());
}

test "the store's rules refuse what a browser refuses" {
    var clock: shakedown.Clock = .init(testing.io, .{});
    const io = clock.io();
    var jar: CookieJar = .init(testing.allocator, .{});
    defer jar.deinit(io);
    const plain = try url_mod.parse("http://www.example.com/");
    const secure = try url_mod.parse("https://www.example.com/");
    try jar.store(io, plain, "a=1; Domain=other.com");
    try jar.store(io, plain, "b=1; Domain=com");
    try jar.store(io, plain, "c=1; Secure");
    try jar.store(io, secure, "__Secure-d=1");
    try jar.store(io, secure, "__Host-e=1; Secure; Domain=example.com");
    try jar.store(io, secure, "__Host-f=1; Secure; Path=/sub");
    try testing.expectEqual(@as(u32, 0), jar.count());
    try jar.store(io, secure, "__Host-ok=1; Secure; Path=/");
    try jar.store(io, secure, "s=secret; Secure");
    try jar.store(io, plain, "s=shadow");
    try testing.expectEqual(@as(u32, 2), jar.count());
    // A domain of one label is a suffix, but may still be the host's own.
    const local = try url_mod.parse("http://localhost/");
    try jar.store(io, local, "l=1; Domain=localhost");
    try testing.expectEqualStrings("Cookie: l=1\r\n", try field(&jar, io, "http://localhost/"));
}

test "a cookie is replaced by name, domain and path, and expires as it says" {
    var clock: shakedown.Clock = .init(testing.io, .{});
    const io = clock.io();
    var jar: CookieJar = .init(testing.allocator, .{});
    defer jar.deinit(io);
    const url = try url_mod.parse("http://h.test/");
    try jar.store(io, url, "a=1; Max-Age=60");
    try jar.store(io, url, "b=2");
    try jar.store(io, url, "a=3; Max-Age=60");
    try testing.expectEqualStrings("Cookie: a=3; b=2\r\n", try field(&jar, io, "http://h.test/"));
    clock.advance(.fromSeconds(61));
    try testing.expectEqualStrings("Cookie: b=2\r\n", try field(&jar, io, "http://h.test/"));
    try jar.store(io, url, "b=gone; Max-Age=0");
    try testing.expectEqualStrings("", try field(&jar, io, "http://h.test/"));
    try testing.expectEqual(@as(u32, 0), jar.count());
    try jar.store(io, url, "x=1; Expires=Thu, 01 Jan 2099 00:00:00 GMT");
    try jar.store(io, url, "y=1; Expires=Thu, 01 Jan 2000 00:00:00 GMT");
    try testing.expectEqualStrings("Cookie: x=1\r\n", try field(&jar, io, "http://h.test/"));
}

test "a domain keeps its cap, and the jar its own, by dropping the oldest" {
    var clock: shakedown.Clock = .init(testing.io, .{});
    const io = clock.io();
    var jar: CookieJar = .init(testing.allocator, .{ .max_per_domain = 2, .max_total = 3 });
    defer jar.deinit(io);
    const a = try url_mod.parse("http://a.test/");
    const b = try url_mod.parse("http://b.test/");
    try jar.store(io, a, "one=1");
    try jar.store(io, a, "two=2");
    try jar.store(io, a, "three=3");
    try testing.expectEqualStrings("Cookie: two=2; three=3\r\n", try field(&jar, io, "http://a.test/"));
    try jar.store(io, b, "four=4");
    try jar.store(io, b, "five=5");
    try testing.expectEqual(@as(u32, 3), jar.count());
    try testing.expectEqualStrings("Cookie: three=3\r\n", try field(&jar, io, "http://a.test/"));
}

test "the Netscape file is read and written as curl reads and writes it" {
    var clock: shakedown.Clock = .init(testing.io, .{});
    const io = clock.io();
    var jar: CookieJar = .init(testing.allocator, .{});
    defer jar.deinit(io);
    const file =
        "# Netscape HTTP Cookie File\n" ++
        "# a comment\n\n" ++
        ".example.com\tTRUE\t/\tFALSE\t4102444800\twide\tw\r\n" ++
        "#HttpOnly_host.example.com\tFALSE\t/app\tTRUE\t4102444800\tsid\ts1\n" ++
        "old.example.com\tFALSE\t/\tFALSE\t1\tgone\tx\n" ++
        "session.example.com\tFALSE\t/\tFALSE\t0\tsess\t\n" ++
        "broken line\n";
    var in: Io.Reader = .fixed(file);
    try jar.load(io, &in);
    try testing.expectEqual(@as(u32, 3), jar.count());
    try testing.expectEqualStrings("Cookie: sid=s1; wide=w\r\n", try field(&jar, io, "https://host.example.com/app/x"));
    var buf: [512]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try jar.save(io, &w, .{});
    try testing.expectEqualStrings(
        "# Netscape HTTP Cookie File\n\n" ++
            ".example.com\tTRUE\t/\tFALSE\t4102444800\twide\tw\n" ++
            "#HttpOnly_host.example.com\tFALSE\t/app\tTRUE\t4102444800\tsid\ts1\n",
        w.buffered(),
    );
    w = .fixed(&buf);
    try jar.save(io, &w, .{ .session = true });
    try testing.expect(std.mem.find(u8, w.buffered(), "session.example.com\tFALSE\t/\tFALSE\t0\tsess\t\n") != null);
    jar.clearSession(io);
    try testing.expectEqual(@as(u32, 2), jar.count());
    jar.clear(io);
    try testing.expectEqual(@as(u32, 0), jar.count());
}

test "a store that runs out of memory keeps the jar whole" {
    const Check = struct {
        fn run(gpa: Allocator) !void {
            var jar: CookieJar = .init(gpa, .{});
            defer jar.deinit(testing.io);
            const url = try url_mod.parse("http://h.test/a/b");
            try jar.store(testing.io, url, "a=1; Path=/");
            try jar.store(testing.io, url, "b=2; Domain=h.test");
            var buf: [128]u8 = undefined;
            var w: Io.Writer = .fixed(&buf);
            _ = try jar.writeField(testing.io, &w, url);
        }
    };
    var no_resize: shakedown.alloc.NoResize = .init(testing.allocator);
    try testing.checkAllAllocationFailures(no_resize.allocator(), Check.run, .{});
}
