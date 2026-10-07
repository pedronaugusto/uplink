//! Test-only: a response head parser written straight from RFC 9112's
//! grammar, a byte at a time, with nothing in common with `wire.h1` but the
//! rules. The fuzz test runs both on the same bytes and wants the same
//! answer.

const std = @import("std");

pub const Field = struct { name: []const u8, value: []const u8 };

pub const Head = struct {
    major_minor: [2]u8,
    status: u16,
    reason: []const u8,
    fields: []const Field,
    len: usize,
};

/// One line of the head: its text without its line end, and where the next
/// starts.
const Line = struct { text: []const u8, next: usize };

fn line(bytes: []const u8, at: usize) ?Line {
    var i = at;
    while (i < bytes.len) : (i += 1) {
        if (bytes[i] != '\n') continue;
        const end = if (i > at and bytes[i - 1] == '\r') i - 1 else i;
        return .{ .text = bytes[at..end], .next = i + 1 };
    }
    return null;
}

fn isTchar(c: u8) bool {
    return switch (c) {
        '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~' => true,
        '0'...'9', 'a'...'z', 'A'...'Z' => true,
        else => false,
    };
}

fn isWs(c: u8) bool {
    return c == ' ' or c == '\t';
}

fn controlFree(text: []const u8) bool {
    for (text) |c| if ((c < 0x20 and c != '\t') or c == 0x7f) return false;
    return true;
}

/// The head at the start of `bytes`, `error.Incomplete` without a blank
/// line, or `error.Invalid`. Values come in `arena`, folds joined by one
/// space.
pub fn parse(arena: std.mem.Allocator, bytes: []const u8, max_fields: usize) error{ Incomplete, Invalid, OutOfMemory }!Head {
    const status_line = line(bytes, 0) orelse return error.Incomplete;
    const s = status_line.text;
    // HTTP-version = "HTTP/" DIGIT "." DIGIT, then SP 3DIGIT, then SP and
    // the reason, or nothing.
    if (s.len < 12) return blankOr(bytes, error.Invalid);
    if (!std.mem.eql(u8, s[0..5], "HTTP/") or !std.ascii.isDigit(s[5]) or s[6] != '.' or !std.ascii.isDigit(s[7])) return blankOr(bytes, error.Invalid);
    if (s[5] != '1' or s[8] != ' ') return blankOr(bytes, error.Invalid);
    var status: u16 = 0;
    for (s[9..12], 0..) |c, i| {
        if (!std.ascii.isDigit(c) or (i == 0 and c == '0')) return blankOr(bytes, error.Invalid);
        status = status * 10 + (c - '0');
    }
    var reason: []const u8 = "";
    if (s.len > 12) {
        if (s[12] != ' ') return blankOr(bytes, error.Invalid);
        reason = s[13..];
        if (!controlFree(reason)) return blankOr(bytes, error.Invalid);
    }
    var fields: std.ArrayList(Field) = .empty;
    var at = status_line.next;
    while (true) {
        const l = line(bytes, at) orelse return error.Incomplete;
        at = l.next;
        if (l.text.len == 0) break;
        if (isWs(l.text[0])) {
            // obs-fold: the value goes on, joined by a space.
            if (fields.items.len == 0) return blankOr(bytes, error.Invalid);
            const last = &fields.items[fields.items.len - 1];
            const more = std.mem.trim(u8, l.text, " \t");
            if (!controlFree(more)) return blankOr(bytes, error.Invalid);
            last.value = std.mem.trim(u8, try std.mem.concat(arena, u8, &.{ last.value, " ", more }), " ");
            continue;
        }
        const colon = std.mem.findScalar(u8, l.text, ':') orelse return blankOr(bytes, error.Invalid);
        var name_end = colon;
        while (name_end > 0 and isWs(l.text[name_end - 1])) name_end -= 1;
        const name = l.text[0..name_end];
        if (name.len == 0) return blankOr(bytes, error.Invalid);
        for (name) |c| if (!isTchar(c)) return blankOr(bytes, error.Invalid);
        const value = std.mem.trim(u8, l.text[colon + 1 ..], " \t");
        if (!controlFree(value)) return blankOr(bytes, error.Invalid);
        if (fields.items.len == max_fields) return blankOr(bytes, error.Invalid);
        try fields.append(arena, .{ .name = name, .value = value });
    }
    return .{ .major_minor = .{ s[5], s[7] }, .status = status, .reason = reason, .fields = fields.items, .len = at };
}

/// A malformed head is only known to be one once it is whole: before its
/// blank line, it is still incomplete.
fn blankOr(bytes: []const u8, err: error{Invalid}) error{ Incomplete, Invalid } {
    var at: usize = 0;
    while (line(bytes, at)) |l| {
        if (l.text.len == 0 and at != 0) return err;
        at = l.next;
    }
    return error.Incomplete;
}
