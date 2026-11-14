//! The span every timeout, delay, keepalive and lifetime uplink is given is
//! in, and every duration it reports: aegis's duration in nanoseconds,
//! never negative, read and written in aegis's text form (`30s`, `1m30s`,
//! `250ms`) and logged with `{f}`. A default reads as one:
//! `.literal("90s")`.
//!
//! std's `Io.Duration` is what an `Io` call takes and what two timestamps
//! subtract to; `toIo` and `of` are where the two meet. The calendar clock
//! is read in one place, `calendar`, as the instant HTTP dates name.

const std = @import("std");
const aegis = @import("aegis");
const Io = std.Io;
const date = @import("uplink.wire").date;

/// A span of time, in nanoseconds: up to 584 years.
pub const Duration = aegis.units.Duration(.nanosecond, u64);

/// The calendar clock now, in the whole seconds an HTTP date names: what a
/// cache stamps a response with and a cookie's expiry is measured against.
pub fn calendar(io: Io) date.Second {
    // Only a clock 292 billion years from the epoch holds more seconds than
    // an i64: the end of the calendar.
    return date.Second.fromTimestamp(Io.Clock.real.now(io), .down) catch .fromRaw(std.math.maxInt(i64));
}

/// `d` as std's duration, for an `Io` call. Every span fits.
pub fn toIo(d: Duration) Io.Duration {
    return d.toIoDuration();
}

/// A measured span as uplink's: one negative (a clock that stepped back)
/// is zero, and one past 584 years the longest there is.
pub fn of(d: Io.Duration) Duration {
    const exact = IoSpan.fromIoDuration(d, .exact);
    if (exact.compare(.fromRaw(0)) != .gt) return .fromRaw(0);
    return exact.convert(.nanosecond, u64, .exact) catch .fromRaw(std.math.maxInt(u64));
}

/// std's span, as aegis holds it: the same nanoseconds, signed.
const IoSpan = aegis.units.Duration(.nanosecond, i96);

/// A moment as std's timestamps hold it, on the clock it was read from: what
/// two timestamps of one clock compare as.
const Moment = aegis.units.Instant(.any, .nanosecond, i96);

/// How `a` and `b`, two timestamps of one clock, are ordered.
pub fn order(a: Io.Timestamp, b: Io.Timestamp) std.math.Order {
    return Moment.fromTimestamp(a, .exact).compare(.fromTimestamp(b, .exact));
}

/// Whether `a` comes before `b`, two timestamps of one clock.
pub fn before(a: Io.Timestamp, b: Io.Timestamp) bool {
    return order(a, b) == .lt;
}

/// Whether what is left of a wait is nothing: none, or less, its deadline
/// passed.
pub fn spent(left: Io.Duration) bool {
    return IoSpan.fromIoDuration(left, .exact).compare(.fromRaw(0)) != .gt;
}

/// The shorter of two optional spans; null is no limit.
pub fn shorter(a: ?Duration, b: ?Duration) ?Duration {
    const x = a orelse return b;
    const y = b orelse return x;
    return if (x.compare(y) == .lt) x else y;
}

test "spans meet std's: negative is zero, and every span converts back" {
    try std.testing.expectEqual(@as(u64, 0), of(.fromSeconds(-1)).raw());
    try std.testing.expectEqual(@as(i96, 250 * std.time.ns_per_ms), toIo(.literal("250ms")).nanoseconds);
    try std.testing.expectEqual(@as(i96, std.math.maxInt(u64)), toIo(of(.{ .nanoseconds = std.math.maxInt(i96) })).nanoseconds);
    try std.testing.expectEqual(Duration.literal("1s"), shorter(.literal("1s"), .literal("2s")).?);
    try std.testing.expectEqual(Duration.literal("2s"), shorter(null, .literal("2s")).?);
    try std.testing.expectEqual(null, shorter(null, null));
}

test "timestamps order as their clock's moments, and a span left is spent at zero or less" {
    const one: Io.Timestamp = .fromNanoseconds(1);
    try std.testing.expect(before(.zero, one));
    try std.testing.expect(!before(one, one));
    try std.testing.expectEqual(std.math.Order.gt, order(one, .fromNanoseconds(-1)));
    try std.testing.expect(spent(.zero));
    try std.testing.expect(spent(.fromSeconds(-1)));
    try std.testing.expect(!spent(.fromNanoseconds(1)));
}
