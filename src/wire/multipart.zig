//! `multipart/form-data` bodies (RFC 7578), written: fields and files as
//! parts between boundaries, each part's data streamed by the caller, with
//! the exact length known beforehand when every part's length is.
//!
//! Names and file names are escaped as the WHATWG HTML standard escapes
//! them — `"` as `%22`, CR as `%0D`, LF as `%0A` — so no name can end its
//! line or its quoted string.

const std = @import("std");
const Io = std.Io;
const fields = @import("fields.zig");

/// One part's head.
pub const Part = struct {
    /// The form field's name.
    name: []const u8,
    /// A file's name, for a file part.
    filename: ?[]const u8 = null,
    /// The part's media type; files usually say
    /// `application/octet-stream`.
    content_type: ?[]const u8 = null,
};

/// Why a part cannot be written.
pub const Error = error{
    WriteFailed,
    /// A content type with a control character, or a boundary that is not
    /// one.
    InvalidPart,
};

/// The longest boundary RFC 2046 allows.
pub const max_boundary = 70;

/// A boundary of `uplink-` and 32 hex digits of `random`, which should be
/// fresh random bytes: no body is likely to hold it.
pub fn boundaryOf(random: [16]u8) [39]u8 {
    return ("uplink-" ++ std.fmt.bytesToHex(random, .lower)).*;
}

/// Whether `boundary` is one RFC 2046 allows: 1 to 70 of its characters,
/// not ending in a space.
pub fn isBoundary(boundary: []const u8) bool {
    if (boundary.len == 0 or boundary.len > max_boundary or boundary[boundary.len - 1] == ' ') return false;
    for (boundary) |c| {
        const ok = std.ascii.isAlphanumeric(c) or std.mem.findScalar(u8, "'()+_,-./:=? ", c) != null;
        if (!ok) return false;
    }
    return true;
}

/// `multipart/form-data; boundary=…`, in `buffer`, for the body's
/// `Content-Type`.
pub fn contentType(boundary: []const u8, buffer: []u8) error{NoSpaceLeft}![]const u8 {
    return std.mem.print(buffer, "multipart/form-data; boundary={s}", .{boundary}) catch error.NoSpaceLeft;
}

/// Parts written onto `out`: `part` writes a head, the caller then writes
/// the part's data to `out`, and `end` closes the body.
pub const Writer = struct {
    out: *Io.Writer,
    boundary: []const u8,
    started: bool = false,

    /// A body between `boundary`s, which `isBoundary` must accept.
    pub fn init(out: *Io.Writer, boundary: []const u8) Writer {
        std.debug.assert(isBoundary(boundary));
        return .{ .out = out, .boundary = boundary };
    }

    /// Start a part: its boundary and head. Its data follows on `out`.
    pub fn part(w: *Writer, head: Part) Error!void {
        if (head.content_type) |t| if (!fields.isFieldValue(t)) return error.InvalidPart;
        try w.out.writeAll(if (w.started) "\r\n--" else "--");
        w.started = true;
        try w.out.writeAll(w.boundary);
        try w.out.writeAll("\r\nContent-Disposition: form-data; name=\"");
        try writeEscaped(w.out, head.name);
        try w.out.writeByte('"');
        if (head.filename) |f| {
            try w.out.writeAll("; filename=\"");
            try writeEscaped(w.out, f);
            try w.out.writeByte('"');
        }
        try w.out.writeAll("\r\n");
        if (head.content_type) |t| try w.out.print("Content-Type: {s}\r\n", .{t});
        try w.out.writeAll("\r\n");
    }

    /// A text field: its head and value.
    pub fn field(w: *Writer, name: []const u8, value: []const u8) Error!void {
        try w.part(.{ .name = name });
        try w.out.writeAll(value);
    }

    /// End the body.
    pub fn end(w: *Writer) Error!void {
        try w.out.writeAll(if (w.started) "\r\n--" else "--");
        try w.out.writeAll(w.boundary);
        try w.out.writeAll("--\r\n");
    }
};

fn writeEscaped(w: *Io.Writer, text: []const u8) Io.Writer.Error!void {
    var start: usize = 0;
    for (text, 0..) |c, i| {
        const escape: ?[]const u8 = switch (c) {
            '"' => "%22",
            '\r' => "%0D",
            '\n' => "%0A",
            else => null,
        };
        const e = escape orelse continue;
        try w.writeAll(text[start..i]);
        try w.writeAll(e);
        start = i + 1;
    }
    try w.writeAll(text[start..]);
}

fn escapedLength(text: []const u8) u64 {
    var n: u64 = text.len;
    for (text) |c| if (c == '"' or c == '\r' or c == '\n') {
        n += 2;
    };
    return n;
}

/// A part whose data's length is known.
pub const Sized = struct { head: Part, length: u64 };

/// The exact length of a body of `parts` between `boundary`s: its
/// `Content-Length`.
pub fn length(boundary: []const u8, parts: []const Sized) u64 {
    var n: u64 = 0;
    for (parts, 0..) |p, i| {
        n += (if (i == 0) @as(u64, 2) else 4) + boundary.len;
        n += "\r\nContent-Disposition: form-data; name=\"\"".len + escapedLength(p.head.name);
        if (p.head.filename) |f| n += "; filename=\"\"".len + escapedLength(f);
        n += 2;
        if (p.head.content_type) |t| n += "Content-Type: \r\n".len + t.len;
        n += 2 + p.length;
    }
    n += (if (parts.len == 0) @as(u64, 2) else 4) + boundary.len + 4;
    return n;
}

const testing = std.testing;

test "a body of fields and a file is written as RFC 7578 lays it out, at its known length" {
    var buf: [512]u8 = undefined;
    var out: Io.Writer = .fixed(&buf);
    const boundary = "AaB03x";
    var w: Writer = .init(&out, boundary);
    try w.field("submit-name", "Larry");
    try w.part(.{ .name = "files", .filename = "file1.txt", .content_type = "text/plain" });
    try out.writeAll("... contents of file1.txt ...");
    try w.end();
    try testing.expectEqualStrings(
        "--AaB03x\r\nContent-Disposition: form-data; name=\"submit-name\"\r\n\r\nLarry" ++
            "\r\n--AaB03x\r\nContent-Disposition: form-data; name=\"files\"; filename=\"file1.txt\"\r\nContent-Type: text/plain\r\n\r\n... contents of file1.txt ..." ++
            "\r\n--AaB03x--\r\n",
        out.buffered(),
    );
    try testing.expectEqual(@as(u64, out.end), length(boundary, &.{
        .{ .head = .{ .name = "submit-name" }, .length = 5 },
        .{ .head = .{ .name = "files", .filename = "file1.txt", .content_type = "text/plain" }, .length = 29 },
    }));
}

test "names cannot end their quoted string or line, and a bad content type is refused" {
    var buf: [256]u8 = undefined;
    var out: Io.Writer = .fixed(&buf);
    var w: Writer = .init(&out, "b");
    try w.part(.{ .name = "a\"b\r\nc", .filename = "x\".txt" });
    try w.end();
    try testing.expect(std.mem.find(u8, out.buffered(), "name=\"a%22b%0D%0Ac\"; filename=\"x%22.txt\"") != null);
    try testing.expectEqual(@as(u64, out.end), length("b", &.{.{ .head = .{ .name = "a\"b\r\nc", .filename = "x\".txt" }, .length = 0 }}));
    try testing.expectError(error.InvalidPart, w.part(.{ .name = "n", .content_type = "text/plain\r\nX: y" }));
    out = .fixed(&buf);
    var empty: Writer = .init(&out, "b");
    try empty.end();
    try testing.expectEqual(@as(u64, out.end), length("b", &.{}));
}

test "boundaries are made from random bytes and checked against RFC 2046" {
    const b = boundaryOf(@splat(0xab));
    try testing.expect(isBoundary(&b));
    try testing.expect(!isBoundary(""));
    try testing.expect(!isBoundary("ends in space "));
    try testing.expect(!isBoundary("semi;colon"));
    try testing.expect(!isBoundary(&(@as([71]u8, @splat('a')))));
    var buf: [128]u8 = undefined;
    try testing.expectEqualStrings("multipart/form-data; boundary=" ++ b, try contentType(&b, &buf));
}
