//! The awake clock as a number: nanoseconds since its start, in an `i64`,
//! as the timer keeps them in an atomic and the pool in its idle list. An
//! `Instant` is its own type, so a time read from another clock cannot
//! meet one, and a span between two is checked.

const std = @import("std");
const aegis = @import("aegis");
const Io = std.Io;

/// A point on the awake clock.
pub const Instant = aegis.units.Instant(.awake, .nanosecond, i64);

/// The awake clock now.
pub fn now(io: Io) Instant {
    return of(Io.Clock.awake.now(io));
}

/// `t`, a timestamp read from the awake clock. One that an `i64` of
/// nanoseconds cannot hold, 292 years from the start, is the latest
/// instant, as a deadline that far off never comes.
pub fn of(t: Io.Timestamp) Instant {
    return Instant.fromIoTimestamp(t.withClock(.awake), .exact) catch |err| switch (err) {
        error.Overflow => .fromRaw(if (t.nanoseconds < 0) std.math.minInt(i64) else std.math.maxInt(i64)),
        error.Inexact => unreachable, // unreachable: nanoseconds convert to nanoseconds exactly
        error.ClockMismatch => unreachable, // unreachable: the timestamp was given the awake clock just above
    };
}

const testing = std.testing;

test "a timestamp keeps its nanoseconds, and one past an i64 is the latest instant" {
    try testing.expectEqual(@as(i64, 1500), of(.fromNanoseconds(1500)).raw());
    try testing.expectEqual(std.math.maxInt(i64), of(.fromNanoseconds(@as(i96, std.math.maxInt(i64)) + 1)).raw());
    try testing.expectEqual(std.math.minInt(i64), of(.fromNanoseconds(@as(i96, std.math.minInt(i64)) - 1)).raw());
}
