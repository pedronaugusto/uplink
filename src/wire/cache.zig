//! How long a response may be kept (RFC 9111): its `Cache-Control`
//! directives read (§5.2), and the freshness a private cache gives it from
//! them, from `Expires` and `Date`, and from `Age` (§4.2).
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
    immutable: bool = false,
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
    const Name = enum { @"max-age", @"s-maxage", @"no-store", @"no-cache", private, public, @"must-revalidate", immutable, @"stale-while-revalidate", @"stale-if-error" };
    var lower: [32]u8 = undefined;
    if (d.name.len > lower.len) return;
    const which = std.meta.stringToEnum(Name, std.ascii.lowerString(&lower, d.name)) orelse return;
    switch (which) {
        .@"max-age" => seconds(r, &r.max_age, d.value),
        .@"s-maxage" => seconds(r, &r.s_maxage, d.value),
        .@"stale-while-revalidate" => seconds(r, &r.stale_while_revalidate, d.value),
        .@"stale-if-error" => seconds(r, &r.stale_if_error, d.value),
        // `no-cache` and `private` may name fields (§5.2.2.4, §5.2.2.7): for
        // a private cache either form means the same.
        .@"no-store" => r.no_store = true,
        .@"no-cache" => r.no_cache = true,
        .private => r.private = true,
        .public => r.public = true,
        .@"must-revalidate" => r.must_revalidate = true,
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
    const lifetime: u32 = r.max_age orelse blk: {
        const expires = headers.get("expires") orelse return null;
        const at = date.parse(expires) orelse break :blk 0;
        const now = date.parse(headers.get("date") orelse break :blk 0) orelse break :blk 0;
        break :blk @intCast(std.math.clamp(at - now, 0, max_seconds));
    };
    return lifetime -| age(headers);
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
