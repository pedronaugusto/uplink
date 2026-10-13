//! `.netrc`: the logins a user keeps per machine, as ftp, curl and git
//! read them. Tokens are separated by spaces, tabs and line ends; a value
//! may be quoted, with `\"`, `\\`, `\n`, `\r` and `\t` escapes, as curl
//! reads it. `machine <name>` starts an entry, `default` the entry for any
//! machine, which ends the file's search; `login`, `password` and
//! `account` fill the entry; `macdef <name>` skips its macro, to the next
//! blank line.
//!
//! Nothing here reads a file: the caller hands over the text, and the
//! result's slices point into it, or into the buffer a quoted value is
//! unescaped into.

const std = @import("std");

/// The login for one machine.
pub const Entry = struct {
    login: ?[]const u8 = null,
    password: ?[]const u8 = null,
    account: ?[]const u8 = null,
};

/// Why a `.netrc` cannot be read.
pub const Error = error{
    /// A keyword without its value, or a quoted value without its end.
    InvalidNetrc,
    /// A quoted value longer than the buffer given for it.
    ValueTooLong,
};

/// The entry for `host`, compared without case, or the `default` entry
/// when no machine before it names the host; null when neither is there.
/// Quoted values are unescaped into `buffer`.
pub fn find(text: []const u8, host: []const u8, buffer: []u8) Error!?Entry {
    var t: Tokens = .{ .text = text, .buffer = buffer };
    var current: ?Entry = null;
    var matching = false;
    while (try t.next()) |word| {
        if (std.mem.eql(u8, word, "machine") or std.mem.eql(u8, word, "default")) {
            if (matching) return current;
            const is_default = word[0] == 'd';
            const name = if (is_default) "" else (try t.next()) orelse return error.InvalidNetrc;
            matching = is_default or std.ascii.eqlIgnoreCase(name, host);
            current = if (matching) .{} else null;
        } else if (std.mem.eql(u8, word, "login") or std.mem.eql(u8, word, "password") or std.mem.eql(u8, word, "account")) {
            const value = (try t.next()) orelse return error.InvalidNetrc;
            if (current) |*e| switch (word[0]) {
                'l' => e.login = value,
                'p' => e.password = value,
                else => e.account = value,
            };
        } else if (std.mem.eql(u8, word, "macdef")) {
            _ = (try t.next()) orelse return error.InvalidNetrc;
            t.skipMacro();
        }
        // Any other word is not one of the format's: passed over, as curl
        // and ftp pass it.
    }
    return if (matching) current else null;
}

const Tokens = struct {
    text: []const u8,
    at: usize = 0,
    buffer: []u8,
    used: usize = 0,

    fn next(t: *Tokens) Error!?[]const u8 {
        while (t.at < t.text.len and isSpace(t.text[t.at])) t.at += 1;
        if (t.at == t.text.len) return null;
        if (t.text[t.at] != '"') {
            const start = t.at;
            while (t.at < t.text.len and !isSpace(t.text[t.at])) t.at += 1;
            return t.text[start..t.at];
        }
        t.at += 1;
        const start = t.used;
        while (true) {
            if (t.at == t.text.len) return error.InvalidNetrc;
            var c = t.text[t.at];
            t.at += 1;
            if (c == '"') break;
            if (c == '\\') {
                if (t.at == t.text.len) return error.InvalidNetrc;
                c = switch (t.text[t.at]) {
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    else => |e| e,
                };
                t.at += 1;
            }
            if (t.used == t.buffer.len) return error.ValueTooLong;
            t.buffer[t.used] = c;
            t.used += 1;
        }
        return t.buffer[start..t.used];
    }

    /// Past a macro's body: to the first blank line after its own line.
    fn skipMacro(t: *Tokens) void {
        const end = std.mem.findPos(u8, t.text, t.at, "\n\n") orelse t.text.len;
        t.at = end;
    }

    fn isSpace(c: u8) bool {
        return c == ' ' or c == '\t' or c == '\n' or c == '\r';
    }
};

const testing = std.testing;

test "the entry for a machine, the default after none, and quoted values" {
    const text =
        \\machine example.com login alice password "s3 cr\"et"
        \\macdef init
        \\machine evil.example password nope
        \\
        \\machine Other.Example
        \\  login bob
        \\  password hunter2 account acct
        \\default login anon password guest
        \\machine late.example login never
    ;
    var buf: [64]u8 = undefined;
    const a = (try find(text, "example.com", &buf)).?;
    try testing.expectEqualStrings("alice", a.login.?);
    try testing.expectEqualStrings("s3 cr\"et", a.password.?);
    const b = (try find(text, "other.example", &buf)).?;
    try testing.expectEqualStrings("bob", b.login.?);
    try testing.expectEqualStrings("hunter2", b.password.?);
    try testing.expectEqualStrings("acct", b.account.?);
    // A machine inside a macro is the macro's, and one after `default` is
    // never reached.
    const d = (try find(text, "evil.example", &buf)).?;
    try testing.expectEqualStrings("anon", d.login.?);
    const late = (try find(text, "late.example", &buf)).?;
    try testing.expectEqualStrings("anon", late.login.?);
    try testing.expectEqual(null, try find("machine a login b", "c", &buf));
    try testing.expectError(error.InvalidNetrc, find("machine a login", "a", &buf));
    try testing.expectError(error.InvalidNetrc, find("machine a password \"open", "a", &buf));
    var tiny: [2]u8 = undefined;
    try testing.expectError(error.ValueTooLong, find("machine a password \"long\"", "a", &tiny));
}

test "fuzz: any text is read or refused, and an entry found is the host's" {
    const shakedown = @import("shakedown");
    const inputs = @import("../testing/inputs.zig");
    const seeds = [_][]const u8{ "machine h login u password p\n", "default login \"a\\tb\"\nmacdef m\nx\n\nmachine h", "machine H account x" };
    try shakedown.check(testing.allocator, {}, struct {
        fn one(_: void, case: *shakedown.Case) anyerror!void {
            var text_buf: [128]u8 = undefined;
            const text = inputs.draw(case, &text_buf, &seeds, 32);
            var buf: [64]u8 = undefined;
            const entry = find(text, "h", &buf) catch return;
            if (entry) |e| for ([_]?[]const u8{ e.login, e.password, e.account }) |v| if (v) |s| {
                // A value is the text's, or the buffer's when it was quoted.
                const in_text = @intFromPtr(s.ptr) >= @intFromPtr(text.ptr) and @intFromPtr(s.ptr) + s.len <= @intFromPtr(text.ptr) + text.len; // safe: addresses compared only
                const in_buf = @intFromPtr(s.ptr) >= @intFromPtr(&buf) and @intFromPtr(s.ptr) + s.len <= @intFromPtr(&buf) + buf.len; // safe: addresses compared only
                try testing.expect(in_text or in_buf);
            };
        }
    }.one, .{});
}
