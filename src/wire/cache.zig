//! How long a response may be kept (RFC 9111): its `Cache-Control`
//! directives read (§5.2), a request's too, whether a response may be stored
//! at all (§3), its lifetime for a private or a shared cache (§4.2.1, the
//! heuristic of §4.2.2 included), its current age from `Age`, `Date` and the
//! times it was asked for and arrived (§4.2.3), and so whether a stored one
//! may be used as it is, after a revalidation, or not at all (§4.2, §4.2.4).
//!
//! Read as §4.2.1 and §1.2.2 ask: a delta-seconds past 2^31 is taken as
//! 2^31; a directive's value may be a token or a quoted string; a directive
//! the response sends twice, or one whose value is not a delta-seconds,
//! makes the response stale (a lifetime of 0), never fresher than either
//! value says.

const std = @import("std");
const fields = @import("fields.zig");
const date = @import("date.zig");

/// The largest delta-seconds kept (RFC 9111 §1.2.2): longer is taken as this.
pub const max_seconds: u32 = 1 << 31;

/// One directive: its name, and its value with any quotes undone in place
/// of nothing. The value of a quoted string with a `\` escape is given as
/// written between the quotes.
pub const Directive = struct {
    name: []const u8,
    value: ?[]const u8 = null,
};

/// The directives of one `Cache-Control` value, in order.
pub const Iterator = struct {
    list: fields.ListIterator,

    pub fn init(value: []const u8) Iterator {
        return .{ .list = .{ .text = value } };
    }

    pub fn next(it: *Iterator) ?Directive {
        const element = it.list.next() orelse return null;
        const eq = std.mem.findScalar(u8, element, '=') orelse return .{ .name = element };
        const name = std.mem.trimEnd(u8, element[0..eq], " \t");
        var value = std.mem.trimStart(u8, element[eq + 1 ..], " \t");
        if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') value = value[1 .. value.len - 1];
        return .{ .name = name, .value = value };
    }
};

/// What a response's directives say to a cache. Seconds are null when the
/// directive is absent.
pub const Response = struct {
    max_age: ?u32 = null,
    s_maxage: ?u32 = null,
    no_store: bool = false,
    no_cache: bool = false,
    private: bool = false,
    public: bool = false,
    must_revalidate: bool = false,
    /// A shared cache's `must-revalidate` (§5.2.2.8).
    proxy_revalidate: bool = false,
    /// Store only if the status code's caching rules are understood (§5.2.2.3).
    must_understand: bool = false,
    immutable: bool = false,
    /// The fields a qualified `no-cache` or `private` names, as written
    /// between its quotes; null when unqualified or absent.
    no_cache_fields: ?[]const u8 = null,
    private_fields: ?[]const u8 = null,
    /// RFC 5861.
    stale_while_revalidate: ?u32 = null,
    stale_if_error: ?u32 = null,
    /// A directive with seconds sent twice, or with a value that is not a
    /// delta-seconds: the response is to be taken as stale.
    conflicting: bool = false,
};

/// The directives of every `Cache-Control` line of `headers`.
pub fn readResponse(headers: *const fields.Headers) Response {
    var r: Response = .{};
    var lines = headers.iterator();
    while (lines.next()) |f| {
        if (!std.ascii.eqlIgnoreCase(f.name, "cache-control")) continue;
        var it: Iterator = .init(f.value);
        while (it.next()) |d| apply(&r, d);
    }
    return r;
}

/// The directives of one `Cache-Control` value.
pub fn parse(value: []const u8) Response {
    var r: Response = .{};
    var it: Iterator = .init(value);
    while (it.next()) |d| apply(&r, d);
    return r;
}

fn apply(r: *Response, d: Directive) void {
    const Name = enum { @"max-age", @"s-maxage", @"no-store", @"no-cache", private, public, @"must-revalidate", @"proxy-revalidate", @"must-understand", immutable, @"stale-while-revalidate", @"stale-if-error" };
    var lower: [32]u8 = undefined;
    if (d.name.len > lower.len) return;
    const which = std.meta.stringToEnum(Name, std.ascii.lowerString(&lower, d.name)) orelse return;
    switch (which) {
        .@"max-age" => seconds(r, &r.max_age, d.value),
        .@"s-maxage" => seconds(r, &r.s_maxage, d.value),
        .@"stale-while-revalidate" => seconds(r, &r.stale_while_revalidate, d.value),
        .@"stale-if-error" => seconds(r, &r.stale_if_error, d.value),
        // `no-cache` and `private` may name fields (§5.2.2.4, §5.2.2.7): for
        // a private cache either form means the same, and a shared one keeps
        // the names.
        .@"no-store" => r.no_store = true,
        .@"no-cache" => {
            r.no_cache = true;
            if (d.value) |v| r.no_cache_fields = v;
        },
        .private => {
            r.private = true;
            if (d.value) |v| r.private_fields = v;
        },
        .public => r.public = true,
        .@"must-revalidate" => r.must_revalidate = true,
        .@"proxy-revalidate" => r.proxy_revalidate = true,
        .@"must-understand" => r.must_understand = true,
        .immutable => r.immutable = true,
    }
}

fn seconds(r: *Response, slot: *?u32, value: ?[]const u8) void {
    if (slot.* != null) r.conflicting = true;
    const parsed = deltaSeconds(value orelse "") orelse {
        r.conflicting = true;
        slot.* = 0;
        return;
    };
    slot.* = if (slot.*) |earlier| @min(earlier, parsed) else parsed;
}

/// A delta-seconds (RFC 9111 §1.2.2): one or more digits, capped at
/// `max_seconds`; null for anything else.
pub fn deltaSeconds(text: []const u8) ?u32 {
    if (text.len == 0) return null;
    var n: u64 = 0;
    for (text) |c| {
        if (c < '0' or c > '9') return null;
        n = @min(n * 10 + (c - '0'), max_seconds);
    }
    return @intCast(n);
}

/// The response's `Age` (RFC 9111 §5.1), 0 when absent or not a
/// delta-seconds.
pub fn age(headers: *const fields.Headers) u32 {
    return deltaSeconds(std.mem.trim(u8, headers.get("age") orelse return 0, " \t")) orelse 0;
}

/// How long a private cache may keep the response from its arrival, in
/// seconds (RFC 9111 §4.2.1, less `Age` as §4.2.3 counts it): 0 under
/// `no-store`, `no-cache` or conflicting directives; `max-age` when given;
/// else `Expires` less `Date` (an `Expires` that is no date is in the past).
/// Null when the response says nothing, which leaves the lifetime to the
/// cache's own rule.
pub fn freshFor(headers: *const fields.Headers) ?u32 {
    const r = readResponse(headers);
    if (r.no_store or r.no_cache or r.conflicting) return 0;
    const life: u32 = r.max_age orelse blk: {
        const expires = headers.get("expires") orelse return null;
        const at = date.parse(expires) orelse break :blk 0;
        const now = date.parse(headers.get("date") orelse break :blk 0) orelse break :blk 0;
        break :blk secondsOf(now.saturatingDurationTo(at));
    };
    return life -| age(headers);
}

/// What a request's directives ask of a cache (§5.2.1). Seconds are null
/// when the directive is absent; `max-stale` with no value takes any
/// staleness, as `max_seconds`.
pub const Request = struct {
    max_age: ?u32 = null,
    max_stale: ?u32 = null,
    min_fresh: ?u32 = null,
    no_cache: bool = false,
    no_store: bool = false,
    only_if_cached: bool = false,
};

/// The directives of every `Cache-Control` line of a request's `headers`;
/// with none, `Pragma: no-cache` is `no-cache` (§5.4).
pub fn readRequest(headers: *const fields.Headers) Request {
    var r: Request = .{};
    var any = false;
    var lines = headers.iterator();
    while (lines.next()) |f| {
        if (!std.ascii.eqlIgnoreCase(f.name, "cache-control")) continue;
        any = true;
        var it: Iterator = .init(f.value);
        while (it.next()) |d| applyRequest(&r, d);
    }
    if (!any) if (headers.get("pragma")) |pragma| {
        var it: Iterator = .init(pragma);
        while (it.next()) |d| if (std.ascii.eqlIgnoreCase(d.name, "no-cache")) {
            r.no_cache = true;
        };
    };
    return r;
}

fn applyRequest(r: *Request, d: Directive) void {
    const Name = enum { @"max-age", @"max-stale", @"min-fresh", @"no-cache", @"no-store", @"only-if-cached" };
    var lower: [32]u8 = undefined;
    if (d.name.len > lower.len) return;
    const which = std.meta.stringToEnum(Name, std.ascii.lowerString(&lower, d.name)) orelse return;
    switch (which) {
        // A request's bad value is the stricter reading: no age is fresh
        // enough, no staleness allowed, freshness asked for to the limit.
        .@"max-age" => r.max_age = least(r.max_age, deltaSeconds(d.value orelse "") orelse 0),
        .@"max-stale" => r.max_stale = least(r.max_stale, if (d.value) |v| deltaSeconds(v) orelse 0 else max_seconds),
        .@"min-fresh" => r.min_fresh = @max(r.min_fresh orelse 0, deltaSeconds(d.value orelse "") orelse max_seconds),
        .@"no-cache" => r.no_cache = true,
        .@"no-store" => r.no_store = true,
        .@"only-if-cached" => r.only_if_cached = true,
    }
}

fn least(a: ?u32, b: u32) u32 {
    return if (a) |x| @min(x, b) else b;
}

/// What a cache is: a private one (a client's own) or a shared one (§1).
pub const Kind = enum { private, shared };

/// Status codes whose caching rules this cache understands (§5.2.2.3), and
/// the ones a heuristic lifetime may be given (RFC 9110 §15.1).
pub fn understood(status: u16) bool {
    return switch (status) {
        200, 203, 204, 300, 301, 302, 303, 304, 307, 308, 404, 405, 410, 414, 501 => true,
        else => false,
    };
}

pub fn heuristicallyCacheable(status: u16) bool {
    return switch (status) {
        200, 203, 204, 206, 300, 301, 308, 404, 405, 410, 414, 501 => true,
        else => false,
    };
}

/// Whether a response to a request may be stored (§3): a method this cache
/// keeps (GET), a final status it understands, no `no-store` either way, a
/// shared cache not storing `private` or an authorized request without a
/// directive allowing it (§3.5), and something to go on: an explicit
/// lifetime, a validator-free heuristic (`public` or a heuristically
/// cacheable status), or `no-cache`'s keep-and-revalidate.
pub fn storable(kind: Kind, method_is_get: bool, status: u16, request: *const fields.Headers, response: *const fields.Headers) bool {
    if (!method_is_get) return false;
    if (status < 200 or status == 206) return false;
    const req = readRequest(request);
    const res = readResponse(response);
    if (req.no_store) return false;
    // `must-understand` with a status this cache understands overrides the
    // `no-store` that accompanies it for caches that do not (§5.2.2.3).
    if (res.must_understand) {
        if (!understood(status)) return false;
    } else if (res.no_store) return false;
    if (!res.must_understand and !understood(status) and !res.public and res.max_age == null and res.s_maxage == null and response.get("expires") == null) return false;
    if (kind == .shared) {
        if (res.private and res.private_fields == null) return false;
        if (request.get("authorization") != null and !(res.public or res.must_revalidate or res.s_maxage != null)) return false;
    }
    return res.public or res.max_age != null or res.no_cache or response.get("expires") != null or
        (kind == .shared and res.s_maxage != null) or heuristicallyCacheable(status) or (kind == .private and res.private);
}

/// How long a response stays fresh from its origin's view (§4.2.1), in
/// seconds: `s-maxage` for a shared cache, `max-age`, else `Expires` less
/// `Date`, else the heuristic of §4.2.2: a tenth of the time since
/// `Last-Modified`, up to `heuristic_cap`, for a status that may have one.
/// Zero under conflicting directives. Null when nothing gives one.
pub fn lifetime(kind: Kind, status: u16, headers: *const fields.Headers, heuristic_cap: u32) ?u32 {
    const r = readResponse(headers);
    if (r.conflicting) return 0;
    if (kind == .shared) if (r.s_maxage) |s| return s;
    if (r.max_age) |m| return m;
    if (headers.get("expires")) |expires| {
        const at = date.parse(expires) orelse return 0;
        const now = date.parse(headers.get("date") orelse return 0) orelse return 0;
        return secondsOf(now.saturatingDurationTo(at));
    }
    if (!(heuristicallyCacheable(status) or r.public)) return null;
    const modified = date.parse(headers.get("last-modified") orelse return null) orelse return null;
    const dated = date.parse(headers.get("date") orelse return null) orelse return null;
    if (dated.compare(modified) != .gt) return 0;
    return @min(secondsOf(modified.saturatingDurationTo(dated)) / 10, heuristic_cap);
}

/// A span as the seconds a directive counts: none below zero, and no more
/// than `max_seconds`.
fn secondsOf(span: date.Seconds) u32 {
    return @intCast(std.math.clamp(span.raw(), 0, max_seconds)); // safe: clamped into u32 above
}

/// When a response was asked for and arrived, by the cache's own clock.
pub const Times = struct {
    requested: date.Second,
    received: date.Second,
};

/// A stored response's current age at `now` (§4.2.3), in seconds.
pub fn currentAge(headers: *const fields.Headers, times: Times, now: date.Second) u32 {
    const dated = if (headers.get("date")) |d| date.parse(d) orelse times.received else times.received;
    const apparent: u64 = secondsOf(dated.saturatingDurationTo(times.received));
    const delay: u64 = secondsOf(times.requested.saturatingDurationTo(times.received));
    const corrected: u64 = @as(u64, age(headers)) + delay;
    const initial = @max(apparent, corrected);
    const resident: u64 = secondsOf(times.received.saturatingDurationTo(now));
    return @intCast(@min(initial + resident, max_seconds)); // safe: at most max_seconds, a u32
}

/// What a stored response may be used for, now (§4.2, §4.2.4, §5.2).
pub const Use = enum {
    /// As it is.
    fresh,
    /// As it is though stale: the request's `max-stale` takes it, and no
    /// directive forbids it.
    stale,
    /// Only after the origin says it is still good (a conditional request).
    revalidate,
};

/// How a stored response, with its lifetime and current age, answers a
/// request's directives.
pub fn use(kind: Kind, stored: *const fields.Headers, life: u32, current_age: u32, request: Request) Use {
    const res = readResponse(stored);
    if (request.no_cache or res.no_cache) return .revalidate;
    if (request.max_age) |m| if (current_age > m) return .revalidate;
    const left: i64 = @as(i64, life) - current_age;
    if (left - @as(i64, request.min_fresh orelse 0) > 0) return .fresh;
    if (left > 0 and request.min_fresh != null) return .revalidate;
    // Stale.
    if (res.must_revalidate or (kind == .shared and (res.proxy_revalidate or res.s_maxage != null))) return .revalidate;
    if (request.max_stale) |allowed| if (-left <= allowed) return .stale;
    return .revalidate;
}

const testing = std.testing;

fn headersOf(list: []const fields.Field) fields.Headers {
    return .init(list);
}

test "directives are read with their values, quoted or not, names without case" {
    const r = parse("Max-Age=\"600\", no-cache=\"Set-Cookie, X\", public, stale-if-error=86400, unknown=1, immutable");
    try testing.expectEqual(@as(?u32, 600), r.max_age);
    try testing.expect(r.no_cache and r.public and r.immutable);
    try testing.expectEqual(@as(?u32, 86400), r.stale_if_error);
    try testing.expect(!r.conflicting);
    var it: Iterator = .init("a, b=\"x,y\" ,c=1");
    try testing.expectEqualStrings("a", it.next().?.name);
    try testing.expectEqualStrings("x,y", it.next().?.value.?);
    try testing.expectEqualStrings("1", it.next().?.value.?);
    try testing.expectEqual(@as(?Directive, null), it.next());
}

test "seconds past 2^31 are capped; a bad or repeated value makes the response stale" {
    try testing.expectEqual(@as(?u32, max_seconds), parse("max-age=99999999999999999999").max_age);
    try testing.expectEqual(@as(?u32, null), deltaSeconds("-1"));
    try testing.expectEqual(@as(?u32, null), deltaSeconds("1.5"));
    try testing.expect(parse("max-age=abc").conflicting);
    try testing.expect(parse("max-age").conflicting);
    const twice = parse("max-age=60, max-age=3600");
    try testing.expect(twice.conflicting);
    try testing.expectEqual(@as(?u32, 60), twice.max_age);
}

test "a private cache's freshness: max-age less Age, else Expires less Date, none under no-store" {
    const h = headersOf(&.{
        .{ .name = "Cache-Control", .value = "public" },
        .{ .name = "cache-control", .value = "max-age=3600" },
        .{ .name = "Age", .value = "100" },
    });
    try testing.expectEqual(@as(?u32, 3500), freshFor(&h));
    const expires = headersOf(&.{
        .{ .name = "Date", .value = "Sun, 06 Nov 1994 08:49:37 GMT" },
        .{ .name = "Expires", .value = "Sun, 06 Nov 1994 09:49:37 GMT" },
    });
    try testing.expectEqual(@as(?u32, 3600), freshFor(&expires));
    const past = headersOf(&.{.{ .name = "Expires", .value = "0" }});
    try testing.expectEqual(@as(?u32, 0), freshFor(&past));
    const none = headersOf(&.{.{ .name = "Content-Type", .value = "application/json" }});
    try testing.expectEqual(@as(?u32, null), freshFor(&none));
    const store = headersOf(&.{.{ .name = "Cache-Control", .value = "no-store, max-age=60" }});
    try testing.expectEqual(@as(?u32, 0), freshFor(&store));
    const old = headersOf(&.{ .{ .name = "Cache-Control", .value = "max-age=60" }, .{ .name = "Age", .value = "90" } });
    try testing.expectEqual(@as(?u32, 0), freshFor(&old));
}

test "fuzz: any Cache-Control value reads without fault, and its lifetime never exceeds max-age" {
    const shakedown = @import("shakedown");
    const inputs = @import("../testing/inputs.zig");
    const seeds = [_][]const u8{ "max-age=3600, public", "no-cache=\"a, b\", max-age=\"60\"", "s-maxage=1, max-age=99999999999", "stale-if-error=5, must-revalidate" };
    try shakedown.check(testing.allocator, {}, struct {
        fn one(_: void, case: *shakedown.Case) anyerror!void {
            var buf: [96]u8 = undefined;
            const text = inputs.draw(case, &buf, &seeds, 64);
            const r = parse(text);
            const h = headersOf(&.{.{ .name = "Cache-Control", .value = text }});
            const fresh = freshFor(&h);
            if (r.max_age) |max| try testing.expect(fresh.? <= max);
            if (r.no_store or r.conflicting) try testing.expectEqual(@as(?u32, 0), fresh);
        }
    }.one, .{});
}

test "a request's directives, Pragma's no-cache with none, a bad value read strictly" {
    const h = headersOf(&.{.{ .name = "Cache-Control", .value = "max-age=60, max-stale, min-fresh=5, only-if-cached" }});
    const r = readRequest(&h);
    try testing.expectEqual(@as(?u32, 60), r.max_age);
    try testing.expectEqual(@as(?u32, max_seconds), r.max_stale);
    try testing.expectEqual(@as(?u32, 5), r.min_fresh);
    try testing.expect(r.only_if_cached and !r.no_cache);
    const pragma = headersOf(&.{.{ .name = "Pragma", .value = "no-cache" }});
    try testing.expect(readRequest(&pragma).no_cache);
    const both = headersOf(&.{ .{ .name = "Pragma", .value = "no-cache" }, .{ .name = "Cache-Control", .value = "max-age=5" } });
    try testing.expect(!readRequest(&both).no_cache);
    const bad = headersOf(&.{.{ .name = "Cache-Control", .value = "max-age=x, max-stale=y, min-fresh=z" }});
    const strict = readRequest(&bad);
    try testing.expectEqual(@as(?u32, 0), strict.max_age);
    try testing.expectEqual(@as(?u32, 0), strict.max_stale);
    try testing.expectEqual(@as(?u32, max_seconds), strict.min_fresh);
}

test "what may be stored: GET, a final understood status, no no-store, a shared cache's private and Authorization" {
    const none = headersOf(&.{});
    const plain = headersOf(&.{.{ .name = "Cache-Control", .value = "max-age=60" }});
    try testing.expect(storable(.private, true, 200, &none, &plain));
    try testing.expect(!storable(.private, false, 200, &none, &plain));
    try testing.expect(!storable(.private, true, 206, &none, &plain));
    const no_store = headersOf(&.{.{ .name = "Cache-Control", .value = "no-store" }});
    try testing.expect(!storable(.private, true, 200, &no_store, &plain));
    try testing.expect(!storable(.private, true, 200, &none, &no_store));
    const private = headersOf(&.{.{ .name = "Cache-Control", .value = "private, max-age=60" }});
    try testing.expect(storable(.private, true, 200, &none, &private));
    try testing.expect(!storable(.shared, true, 200, &none, &private));
    const auth = headersOf(&.{.{ .name = "Authorization", .value = "Bearer x" }});
    try testing.expect(!storable(.shared, true, 200, &auth, &plain));
    const public = headersOf(&.{.{ .name = "Cache-Control", .value = "public, max-age=60" }});
    try testing.expect(storable(.shared, true, 200, &auth, &public));
    // A status with no heuristic and no explicit lifetime is not kept.
    try testing.expect(!storable(.private, true, 418, &none, &none));
    try testing.expect(storable(.private, true, 404, &none, &none));
    const understand = headersOf(&.{.{ .name = "Cache-Control", .value = "must-understand, no-store, max-age=60" }});
    try testing.expect(storable(.private, true, 200, &none, &understand));
    try testing.expect(!storable(.private, true, 418, &none, &understand));
}

test "a lifetime from s-maxage for a shared cache, max-age, Expires less Date, and the heuristic" {
    const both = headersOf(&.{.{ .name = "Cache-Control", .value = "max-age=60, s-maxage=600" }});
    try testing.expectEqual(@as(?u32, 600), lifetime(.shared, 200, &both, 86400));
    try testing.expectEqual(@as(?u32, 60), lifetime(.private, 200, &both, 86400));
    const modified = headersOf(&.{
        .{ .name = "Date", .value = "Sun, 06 Nov 1994 08:49:37 GMT" },
        .{ .name = "Last-Modified", .value = "Fri, 04 Nov 1994 08:49:37 GMT" },
    });
    // Two days since modified: a tenth is 17280 s, under the cap.
    try testing.expectEqual(@as(?u32, 17280), lifetime(.private, 200, &modified, 86400));
    try testing.expectEqual(@as(?u32, 3600), lifetime(.private, 200, &modified, 3600));
    try testing.expectEqual(@as(?u32, null), lifetime(.private, 302, &modified, 86400));
    try testing.expectEqual(@as(?u32, null), lifetime(.private, 200, &headersOf(&.{}), 86400));
}

test "the current age: the larger of the apparent and the corrected age, plus the time resident" {
    const h = headersOf(&.{
        .{ .name = "Date", .value = "Sun, 06 Nov 1994 08:49:37 GMT" },
        .{ .name = "Age", .value = "10" },
    });
    const dated = date.parse("Sun, 06 Nov 1994 08:49:37 GMT").?;
    // Arrived 30 s after its Date, asked for 2 s before: apparent 30, corrected 12.
    const times: Times = .{ .requested = dated.saturatingAdd(.fromRaw(28)), .received = dated.saturatingAdd(.fromRaw(30)) };
    try testing.expectEqual(@as(u32, 30), currentAge(&h, times, dated.saturatingAdd(.fromRaw(30))));
    try testing.expectEqual(@as(u32, 130), currentAge(&h, times, dated.saturatingAdd(.fromRaw(130))));
    // A Date in the future of arrival: the corrected age stands.
    const early: Times = .{ .requested = dated.saturatingSub(.fromRaw(5)), .received = dated.saturatingSub(.fromRaw(3)) };
    try testing.expectEqual(@as(u32, 12), currentAge(&h, early, dated.saturatingSub(.fromRaw(3))));
}

test "a stored response's use: fresh, stale under max-stale, revalidated under no-cache, max-age, min-fresh and must-revalidate" {
    const plain = headersOf(&.{.{ .name = "Cache-Control", .value = "max-age=100" }});
    try testing.expectEqual(Use.fresh, use(.private, &plain, 100, 50, .{}));
    try testing.expectEqual(Use.revalidate, use(.private, &plain, 100, 150, .{}));
    try testing.expectEqual(Use.stale, use(.private, &plain, 100, 150, .{ .max_stale = 60 }));
    try testing.expectEqual(Use.revalidate, use(.private, &plain, 100, 150, .{ .max_stale = 40 }));
    try testing.expectEqual(Use.revalidate, use(.private, &plain, 100, 50, .{ .no_cache = true }));
    try testing.expectEqual(Use.revalidate, use(.private, &plain, 100, 50, .{ .max_age = 40 }));
    try testing.expectEqual(Use.revalidate, use(.private, &plain, 100, 50, .{ .min_fresh = 60 }));
    try testing.expectEqual(Use.fresh, use(.private, &plain, 100, 50, .{ .min_fresh = 40 }));
    const must = headersOf(&.{.{ .name = "Cache-Control", .value = "max-age=100, must-revalidate" }});
    try testing.expectEqual(Use.revalidate, use(.private, &must, 100, 150, .{ .max_stale = max_seconds }));
    const proxy = headersOf(&.{.{ .name = "Cache-Control", .value = "max-age=100, proxy-revalidate" }});
    try testing.expectEqual(Use.stale, use(.private, &proxy, 100, 150, .{ .max_stale = max_seconds }));
    try testing.expectEqual(Use.revalidate, use(.shared, &proxy, 100, 150, .{ .max_stale = max_seconds }));
    const no_cache = headersOf(&.{.{ .name = "Cache-Control", .value = "no-cache, max-age=100" }});
    try testing.expectEqual(Use.revalidate, use(.private, &no_cache, 100, 1, .{}));
}

test "fuzz: any request Cache-Control reads without fault, and a stored response's use never serves past what it allows" {
    const shakedown = @import("shakedown");
    const inputs = @import("../testing/inputs.zig");
    const seeds = [_][]const u8{ "max-age=0", "max-stale", "max-stale=30, min-fresh=5", "no-cache, only-if-cached", "max-age=x" };
    try shakedown.check(testing.allocator, {}, struct {
        fn one(_: void, case: *shakedown.Case) anyerror!void {
            var buf: [96]u8 = undefined;
            const text = inputs.draw(case, &buf, &seeds, 64);
            const h = headersOf(&.{.{ .name = "Cache-Control", .value = text }});
            const r = readRequest(&h);
            const stored = headersOf(&.{.{ .name = "Cache-Control", .value = "max-age=100" }});
            for ([_]u32{ 0, 50, 99, 100, 101, 1000 }) |age_now| switch (use(.private, &stored, 100, age_now, r)) {
                .fresh => {
                    try testing.expect(age_now < 100 and !r.no_cache);
                    if (r.max_age) |m| try testing.expect(age_now <= m);
                },
                .stale => try testing.expect(age_now >= 100 and r.max_stale != null and age_now - 100 <= r.max_stale.?),
                .revalidate => {},
            };
        }
    }.one, .{});
}
