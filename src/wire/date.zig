//! HTTP dates (RFC 9110 §5.6.7): the three forms a recipient reads —
//! IMF-fixdate (`Sun, 06 Nov 1994 08:49:37 GMT`), the obsolete RFC 850 form
//! (`Sunday, 06-Nov-94 08:49:37 GMT`) and C's asctime (`Sun Nov  6 08:49:37
//! 1994`) — and IMF-fixdate written, the only form a sender writes. Times
//! are seconds since the Unix epoch, in UTC.
//!
//! A recipient may read leniently (RFC 9110 §5.6.7): the zone may be
//! written `UTC` as well as `GMT`, as Go reads it, the weekday is checked to
//! be one but not checked against the date, and an RFC 850 two-digit year
//! is taken as 19xx from 70 up and 20xx below, as curl takes it.

const std = @import("std");

/// The seconds since the epoch `text` names, or null when it is no HTTP date
/// or no real date and time.
pub fn parse(text: []const u8) ?i64 {
    const t = std.mem.trim(u8, text, " \t");
    if (t.len < 24) return null;
    if (t[3] == ',') return parseImf(t);
    if (t[3] == ' ') return parseAsctime(t);
    return parseRfc850(t);
}

/// `Sun, 06 Nov 1994 08:49:37 GMT`.
fn parseImf(t: []const u8) ?i64 {
    if (t.len != 29 or t[4] != ' ' or t[7] != ' ' or t[11] != ' ' or t[16] != ' ' or t[25] != ' ') return null;
    _ = shortDay(t[0..3]) orelse return null;
    if (!zone(t[26..29])) return null;
    const day = digits(t[5..7]) orelse return null;
    const month = monthOf(t[8..11]) orelse return null;
    const year = digits(t[12..16]) orelse return null;
    return civilAt(year, month, day, t[17..25]);
}

/// `Sunday, 06-Nov-94 08:49:37 GMT`.
fn parseRfc850(t: []const u8) ?i64 {
    const comma = std.mem.findScalar(u8, t, ',') orelse return null;
    if (!longDay(t[0..comma])) return null;
    const rest = t[comma + 1 ..];
    if (rest.len != 23 or rest[0] != ' ' or rest[3] != '-' or rest[7] != '-' or rest[10] != ' ' or rest[19] != ' ') return null;
    if (!zone(rest[20..23])) return null;
    const day = digits(rest[1..3]) orelse return null;
    const month = monthOf(rest[4..7]) orelse return null;
    const yy = digits(rest[8..10]) orelse return null;
    const year = if (yy >= 70) 1900 + yy else 2000 + yy;
    return civilAt(year, month, day, rest[11..19]);
}

/// `Sun Nov  6 08:49:37 1994`: the day of the month space-padded.
fn parseAsctime(t: []const u8) ?i64 {
    if (t.len != 24 or t[7] != ' ' or t[10] != ' ' or t[19] != ' ') return null;
    _ = shortDay(t[0..3]) orelse return null;
    const month = monthOf(t[4..7]) orelse return null;
    const day_text = if (t[8] == ' ') t[9..10] else t[8..10];
    const day = digits(day_text) orelse return null;
    const year = digits(t[20..24]) orelse return null;
    return civilAt(year, month, day, t[11..19]);
}

/// `hh:mm:ss` on a day.
fn civilAt(year: u32, month: u32, day: u32, clock: []const u8) ?i64 {
    if (clock[2] != ':' or clock[5] != ':') return null;
    const hour = digits(clock[0..2]) orelse return null;
    const minute = digits(clock[3..5]) orelse return null;
    // A leap second is read as the last second of its minute.
    const second = @min(digits(clock[6..8]) orelse return null, 59);
    return civil(year, month, day, hour, minute, second);
}

fn zone(text: []const u8) bool {
    return std.mem.eql(u8, text, "GMT") or std.mem.eql(u8, text, "UTC");
}

const short_days = [_][]const u8{ "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun" };
const long_days = [_][]const u8{ "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday" };
const months = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

fn shortDay(text: []const u8) ?usize {
    for (short_days, 0..) |d, i| if (std.mem.eql(u8, text, d)) return i;
    return null;
}

fn longDay(text: []const u8) bool {
    for (long_days) |d| if (std.mem.eql(u8, text, d)) return true;
    return false;
}

fn monthOf(text: []const u8) ?u32 {
    for (months, 1..) |m, i| if (std.mem.eql(u8, text, m)) return @intCast(i);
    return null;
}

fn digits(text: []const u8) ?u32 {
    var n: u32 = 0;
    for (text) |c| {
        if (c < '0' or c > '9') return null;
        n = n * 10 + (c - '0');
    }
    return n;
}

/// Seconds since the epoch of a UTC date and time, or null for one that
/// does not exist.
pub fn civil(year: u32, month: u32, day: u32, hour: u32, minute: u32, second: u32) ?i64 {
    if (year < 1 or month < 1 or month > 12 or day < 1 or hour > 23 or minute > 59 or second > 59) return null;
    if (day > daysIn(year, month)) return null;
    return daysFromCivil(year, month, day) * std.time.s_per_day + @as(i64, hour) * 3600 + @as(i64, minute) * 60 + second;
}

fn daysIn(year: u32, month: u32) u32 {
    const leap = (year % 4 == 0 and year % 100 != 0) or year % 400 == 0;
    const lengths = [_]u32{ 31, if (leap) 29 else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    return lengths[month - 1];
}

/// Days from 1970-01-01 to a civil date, by Howard Hinnant's algorithm.
fn daysFromCivil(year: u32, month: u32, day: u32) i64 {
    const y: i64 = @as(i64, year) - @intFromBool(month <= 2);
    const era = @divFloor(y, 400);
    const yoe = y - era * 400;
    const m: i64 = month;
    const doy = @divFloor(153 * (if (m > 2) m - 3 else m + 9) + 2, 5) + @as(i64, day) - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146097 + doe - 719468;
}

/// The longest text `format` writes.
pub const formatted_len = 29;

/// `seconds` as an IMF-fixdate, in `out`. Years before 1 or after 9999
/// are clamped to those years' ends.
pub fn format(seconds: i64, out: *[formatted_len]u8) []const u8 {
    const lowest = comptime daysFromCivil(1, 1, 1) * std.time.s_per_day;
    const highest = comptime daysFromCivil(9999, 12, 31) * std.time.s_per_day + std.time.s_per_day - 1;
    const s = std.math.clamp(seconds, lowest, highest);
    const days = @divFloor(s, std.time.s_per_day);
    const in_day: u32 = @intCast(s - days * std.time.s_per_day);
    // civil_from_days, Howard Hinnant's inverse.
    const z = days + 719468;
    const era = @divFloor(z, 146097);
    const doe = z - era * 146097;
    const yoe = @divFloor(doe - @divFloor(doe, 1460) + @divFloor(doe, 36524) - @divFloor(doe, 146096), 365);
    const doy = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100));
    const mp = @divFloor(5 * doy + 2, 153);
    const day: u32 = @intCast(doy - @divFloor(153 * mp + 2, 5) + 1);
    const month: u32 = @intCast(if (mp < 10) mp + 3 else mp - 9);
    const year: u32 = @intCast(yoe + era * 400 + @intFromBool(month <= 2));
    // 1970-01-01 was a Thursday.
    const weekday: usize = @intCast(@mod(days + 3, 7));
    return std.mem.print(out, "{s}, {d:0>2} {s} {d:0>4} {d:0>2}:{d:0>2}:{d:0>2} GMT", .{
        short_days[weekday], day, months[month - 1], year, in_day / 3600, in_day / 60 % 60, in_day % 60,
    }) catch unreachable; // unreachable: every field has its fixed width, 29 bytes in all
}

const testing = std.testing;

test "the three forms of RFC 9110's example name one instant" {
    const want: ?i64 = 784111777;
    try testing.expectEqual(want, parse("Sun, 06 Nov 1994 08:49:37 GMT"));
    try testing.expectEqual(want, parse("Sunday, 06-Nov-94 08:49:37 GMT"));
    try testing.expectEqual(want, parse("Sun Nov  6 08:49:37 1994"));
    try testing.expectEqual(want, parse("  Sun, 06 Nov 1994 08:49:37 UTC "));
    try testing.expectEqual(@as(?i64, 0), parse("Thu, 01 Jan 1970 00:00:00 GMT"));
    try testing.expectEqual(@as(?i64, 1767225600), parse("Thursday, 01-Jan-26 00:00:00 GMT"));
    try testing.expectEqual(@as(?i64, 951782400), parse("Tue Feb 29 00:00:00 2000"));
}

test "a date that is not one of the forms, or not a real date, is refused" {
    for ([_][]const u8{
        "",
        "120",
        "Sun, 06 Nov 1994 08:49:37 gmt",
        "Xyz, 06 Nov 1994 08:49:37 GMT",
        "Sun, 31 Nov 1994 08:49:37 GMT",
        "Sun, 06 Nov 1994 24:00:00 GMT",
        "Sun, 06 Nov 1994 08:49:37 CET",
        "Sun, 6 Nov 1994 08:49:37 GMT",
        "Sun, 06 Nov 1994 08-49-37 GMT",
        "Sunday, 06 Nov 94 08:49:37 GMT",
        "Sundae, 06-Nov-94 08:49:37 GMT",
        "Sun Nov 31 08:49:37 1994",
        "Mon Feb 29 00:00:00 1900",
    }) |bad| {
        testing.expectEqual(@as(?i64, null), parse(bad)) catch |err| {
            std.debug.print("{s}\n", .{bad});
            return err;
        };
    }
}

test "a written date reads back as the same second, across the calendar" {
    var buf: [formatted_len]u8 = undefined;
    try testing.expectEqualStrings("Sun, 06 Nov 1994 08:49:37 GMT", format(784111777, &buf));
    try testing.expectEqualStrings("Thu, 01 Jan 1970 00:00:00 GMT", format(0, &buf));
    try testing.expectEqualStrings("Wed, 31 Dec 1969 23:59:59 GMT", format(-1, &buf));
    try testing.expectEqualStrings("Fri, 31 Dec 9999 23:59:59 GMT", format(std.math.maxInt(i64), &buf));
    var prng: std.Random.DefaultPrng = .init(0x0da7e);
    for (0..2000) |_| {
        const s = prng.random().intRangeAtMost(i64, -2208988800, 4102444800);
        try testing.expectEqual(@as(?i64, s), parse(format(s, &buf)));
    }
}

test "fuzz: any text is a date or is not, and never a crash" {
    try testing.fuzz({}, struct {
        fn one(_: void, smith: *testing.Smith) anyerror!void {
            var buf: [48]u8 = undefined;
            const text = buf[0..smith.slice(&buf)];
            if (parse(text)) |s| {
                var out: [formatted_len]u8 = undefined;
                try testing.expectEqual(@as(?i64, s), parse(format(s, &out)));
            }
        }
    }.one, .{ .corpus = &.{ "Sun, 06 Nov 1994 08:49:37 GMT", "Sunday, 06-Nov-94 08:49:37 GMT", "Sun Nov  6 08:49:37 1994" } });
}
