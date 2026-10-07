//! What a client does with a response or failure that is not the end of a
//! request: which redirects it follows, and which failures and statuses it
//! tries again, how often and how long apart.

const std = @import("std");
const Io = std.Io;
const date = @import("../wire/date.zig");
const url_mod = @import("../wire/url.zig");
const Method = @import("../wire/Method.zig");

/// Which redirects are followed.
pub const Redirects = union(enum) {
    /// None: a 3xx is the caller's.
    none,
    /// Up to `max` in a row, as the policy allows.
    follow: Follow,

    pub const Follow = struct {
        /// More than this many in a row fails with `TooManyRedirects`.
        max: u8 = 10,
        /// Only to the request's own origin; a 3xx elsewhere is returned.
        same_origin_only: bool = false,
        /// Follow an `https` URL to an `http` one, which sends the request
        /// in the clear. Off by default: `InsecureRedirect`.
        allow_downgrade: bool = false,
    };

    /// The default: follow up to ten, never from `https` to `http`.
    pub const default: Redirects = .{ .follow = .{} };
};

/// Errors a redirect raises.
pub const RedirectError = error{ TooManyRedirects, InsecureRedirect };

/// Whether a redirect from `from` to `to` is followed, `hops` having been
/// followed already: an error ends the request, and false hands the 3xx to
/// the caller.
pub fn mayFollow(follow: Redirects.Follow, from: url_mod.Url, to: url_mod.Url, hops: u8) RedirectError!bool {
    if (hops >= follow.max) return error.TooManyRedirects;
    if (from.secure and !to.secure and !follow.allow_downgrade) return error.InsecureRedirect;
    if (follow.same_origin_only and !url_mod.sameOrigin(from, to)) return false;
    return true;
}

/// What follows a redirect status (RFC 9110 §15.4): the method to use
/// and whether the body goes with it. 301 and 302 turn a POST into a GET
/// without a body, as every client does; 303 turns anything but HEAD into
/// a GET; 307 and 308 keep the method and the body.
pub const Hop = struct { method: Method, keep_body: bool };

/// How a redirect of `status` changes a request of `method`, or null when
/// the status is not a redirect that is followed.
pub fn hop(status: u10, method: Method) ?Hop {
    return switch (status) {
        301, 302 => if (method.eql(.POST)) .{ .method = .GET, .keep_body = false } else .{ .method = method, .keep_body = true },
        303 => if (method.eql(.HEAD)) .{ .method = .HEAD, .keep_body = false } else .{ .method = .GET, .keep_body = false },
        307, 308 => .{ .method = method, .keep_body = true },
        else => null,
    };
}

/// Which failures and statuses are tried again, and how long apart.
pub const Retries = struct {
    /// Attempts in all, the first included: 1 tries nothing again. A kept
    /// connection found stale is sent once more besides, and not counted.
    max_attempts: u8 = 3,
    /// Try again when the connection failed before any byte of a response
    /// arrived, and the request can be sent again: nothing of it went out,
    /// or its method is idempotent and its body can be sent twice.
    connection: bool = true,
    /// Try again on these statuses, waiting what `Retry-After` asks when it
    /// asks no more than `max_wait`. Only for a request whose body can be
    /// sent again, and whose method is idempotent, or whose status says the
    /// server did not act on it (429, 503). `transient` is the usual list.
    statuses: []const std.http.Status = &.{},
    /// The first wait; each later one may be twice the last, up to `cap`.
    /// The wait is a random time up to that ("full jitter"), so many
    /// clients failing at once do not come back at once.
    base: Io.Duration = .fromMilliseconds(100),
    cap: Io.Duration = .fromSeconds(10),
    /// The longest `Retry-After` honoured; a server asking for longer gets
    /// its response handed back instead.
    max_wait: Io.Duration = .fromSeconds(60),

    /// Nothing tried again.
    pub const none: Retries = .{ .max_attempts = 1, .connection = false };
    /// 429, 502, 503 and 504.
    pub const transient: []const std.http.Status = &.{ .too_many_requests, .bad_gateway, .service_unavailable, .gateway_timeout };

    /// Whether `status` is one to try again.
    pub fn retriesStatus(r: Retries, status: std.http.Status) bool {
        for (r.statuses) |s| if (s == status) return true;
        return false;
    }

    /// The wait before attempt `next` (2 for the first retry): a random
    /// time up to `base` doubled each attempt, at most `cap`. `random` is
    /// a fresh random number.
    pub fn backoff(r: Retries, next: u8, random: u64) Io.Duration {
        std.debug.assert(next >= 2);
        const shift: u6 = @intCast(@min(next - 2, 40));
        const base: u64 = @intCast(@max(0, r.base.nanoseconds));
        const cap: u64 = @intCast(@max(0, r.cap.nanoseconds));
        const ceiling = @min(cap, base *| (@as(u64, 1) << shift));
        if (ceiling == 0) return .zero;
        return .fromNanoseconds(random % (ceiling + 1));
    }
};

/// How long a `Retry-After` value asks to wait: seconds, or an HTTP date
/// against `now` (seconds since the epoch on the real clock). Null when
/// the value is neither.
pub fn retryAfter(value: []const u8, now: i64) ?Io.Duration {
    const text = std.mem.trim(u8, value, " \t");
    if (std.fmt.parseUnsigned(u32, text, 10)) |n| return .fromSeconds(n) else |_| {}
    const at = date.parse(text) orelse return null;
    return .fromSeconds(@max(0, at - now));
}

/// Whether a status says the server did not act on the request, so even a
/// method that is not idempotent may be sent again.
pub fn notActedOn(status: std.http.Status) bool {
    return status == .too_many_requests or status == .service_unavailable;
}

const testing = std.testing;

test "redirects change the method as RFC 9110 and every browser do" {
    try testing.expect(hop(301, .POST).?.method.eql(.GET));
    try testing.expect(!hop(302, .POST).?.keep_body);
    try testing.expect(hop(302, .PUT).?.method.eql(.PUT));
    try testing.expect(hop(303, .PUT).?.method.eql(.GET));
    try testing.expect(hop(303, .HEAD).?.method.eql(.HEAD));
    try testing.expect(hop(307, .POST).?.keep_body);
    try testing.expect(hop(308, .POST).?.method.eql(.POST));
    try testing.expectEqual(null, hop(304, .GET));
    try testing.expectEqual(null, hop(300, .GET));
}

test "a redirect is refused past its count, from https to http, and off its origin when asked" {
    const a = try url_mod.parse("https://a.test/");
    const plain = try url_mod.parse("http://a.test/");
    const other = try url_mod.parse("https://b.test/");
    try testing.expect(try mayFollow(.{}, a, other, 9));
    try testing.expectError(error.TooManyRedirects, mayFollow(.{}, a, other, 10));
    try testing.expectError(error.InsecureRedirect, mayFollow(.{}, a, plain, 0));
    try testing.expect(try mayFollow(.{ .allow_downgrade = true }, a, plain, 0));
    try testing.expect(try mayFollow(.{}, plain, a, 0));
    try testing.expect(!try mayFollow(.{ .same_origin_only = true }, a, other, 0));
    try testing.expectError(error.TooManyRedirects, mayFollow(.{ .max = 0 }, a, a, 0));
}

test "backoff grows from its base to its cap, at random below each" {
    const r: Retries = .{ .base = .fromMilliseconds(100), .cap = .fromSeconds(1) };
    try testing.expectEqual(@as(i96, 100 * std.time.ns_per_ms), r.backoff(2, 100 * std.time.ns_per_ms).nanoseconds);
    try testing.expectEqual(@as(i96, 0), r.backoff(2, 100 * std.time.ns_per_ms + 1).nanoseconds);
    for (2..60) |n| {
        const d = r.backoff(@intCast(n), 0xdead_beef_cafe);
        try testing.expect(d.nanoseconds >= 0 and d.nanoseconds <= std.time.ns_per_s);
    }
    try testing.expectEqual(@as(i96, 0), (Retries{ .base = .zero }).backoff(3, 7).nanoseconds);
    try testing.expect(r.retriesStatus(.ok) == false);
    try testing.expect((Retries{ .statuses = Retries.transient }).retriesStatus(.service_unavailable));
}

test "Retry-After is read as seconds or as a date" {
    try testing.expectEqual(@as(i96, 120 * std.time.ns_per_s), retryAfter(" 120 ", 0).?.nanoseconds);
    try testing.expectEqual(@as(i96, 37 * std.time.ns_per_s), retryAfter("Sun, 06 Nov 1994 08:49:37 GMT", 784111740).?.nanoseconds);
    try testing.expectEqual(@as(i96, 0), retryAfter("Sun, 06 Nov 1994 08:49:37 GMT", 784111800).?.nanoseconds);
    try testing.expectEqual(null, retryAfter("soon", 0));
    try testing.expectEqual(null, retryAfter("-1", 0));
}
