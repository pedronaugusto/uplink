//! `multipart/form-data` bodies (RFC 7578), written and read: fields and
//! files as parts between boundaries. A writer streams each part's data
//! from the caller, with the exact length known beforehand when every
//! part's length is; a reader hands each part's head and then its data as
//! a reader of its own, as the body arrives, keeping only the boundary's
//! length of look-ahead.
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

/// The boundary of a `multipart/*` `Content-Type`, or null.
pub fn boundaryFrom(content_type: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, content_type, ';');
    _ = it.next();
    while (it.next()) |raw| {
        const param = std.mem.trim(u8, raw, " \t");
        if (param.len < "boundary=".len or !std.ascii.eqlIgnoreCase(param[0.."boundary=".len], "boundary=")) continue;
        var value = param["boundary=".len..];
        if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') value = value[1 .. value.len - 1];
        return if (isBoundary(value)) value else null;
    }
    return null;
}

/// A part's head, as read: what `Content-Disposition` and `Content-Type`
/// say. Every slice points into the reader's head buffer and is valid until
/// the next call to `next`.
pub const PartHead = struct {
    /// The form field's name, its WHATWG escapes undone.
    name: []const u8 = "",
    /// A file part's name, its escapes undone.
    filename: ?[]const u8 = null,
    content_type: ?[]const u8 = null,
};

/// Why a body cannot be read.
pub const ReadError = error{
    /// Not a multipart body: no boundary where one must be, a part head
    /// that is not lines of fields, or a body that ends before its last
    /// boundary.
    Malformed,
    /// A part's head longer than the head buffer.
    HeadTooLarge,
    /// The body's reader failed.
    ReadFailed,
};

/// The parts of a body read from `in` as it arrives: `next` moves to the
/// next part, skipping what was left of the last one, and returns its
/// head; the part's data is read from `body`, which ends where the next
/// boundary begins.
pub const Reader = struct {
    in: *Io.Reader,
    /// Private: `\r\n--` and the boundary.
    delimiter_buffer: [max_boundary + 4]u8,
    delimiter_len: usize,
    /// Private: where a part's head is kept.
    head_buffer: []u8,
    state: State = .preamble,
    /// The current part's data.
    interface: Io.Reader,
    /// Private: why the last read failed.
    failure: ?ReadError = null,

    const State = enum { preamble, body, between, done };

    /// A reader of the body `in` gives, between `boundary`s, keeping each
    /// part's head in `head_buffer`, and using `buffer` for the part's
    /// own reads. `in`'s buffer must hold at least a boundary and its
    /// delimiter, 74 bytes, more to read in larger steps.
    pub fn init(in: *Io.Reader, boundary: []const u8, head_buffer: []u8, buffer: []u8) Reader {
        std.debug.assert(isBoundary(boundary));
        std.debug.assert(in.buffer.len >= boundary.len + 4);
        var r: Reader = .{
            .in = in,
            .delimiter_buffer = undefined,
            .delimiter_len = boundary.len + 4,
            .head_buffer = head_buffer,
            .interface = .{ .vtable = &.{ .stream = stream }, .buffer = buffer, .seek = 0, .end = 0 },
        };
        @memcpy(r.delimiter_buffer[0..4], "\r\n--");
        @memcpy(r.delimiter_buffer[4..][0..boundary.len], boundary);
        return r;
    }

    fn delimiter(r: *const Reader) []const u8 {
        return r.delimiter_buffer[0..r.delimiter_len];
    }

    /// Move to the next part and read its head, or null after the last.
    pub fn next(r: *Reader) ReadError!?PartHead {
        switch (r.state) {
            .done => return null,
            .preamble => {
                // The first boundary may start the body, without the CRLF
                // before it; anything before it is a preamble to skip.
                try r.skipTo(r.delimiter()[2..], true);
            },
            .body => {
                // Skip what is left of the current part.
                r.interface.seek = 0;
                r.interface.end = 0;
                while (r.state == .body) _ = try r.dataSlice(std.math.maxInt(usize));
            },
            .between => {},
        }
        // After a boundary: `--` ends the body; else padding, then CRLF.
        const after = try r.peek(2);
        if (std.mem.eql(u8, after, "--")) {
            r.in.toss(2);
            r.state = .done;
            return null;
        }
        while (true) {
            const c = (try r.peek(1))[0];
            if (c != ' ' and c != '\t') break;
            r.in.toss(1);
        }
        if (!std.mem.eql(u8, try r.peek(2), "\r\n")) return error.Malformed;
        r.in.toss(2);
        const head = try r.readHead();
        r.state = .body;
        return head;
    }

    /// The current part's data.
    pub fn body(r: *Reader) *Io.Reader {
        return &r.interface;
    }

    fn peek(r: *Reader, n: usize) ReadError![]u8 {
        return r.in.peek(n) catch |err| switch (err) {
            error.EndOfStream => error.Malformed,
            error.ReadFailed => error.ReadFailed,
        };
    }

    /// Skip to just past `marker`; at the start of the body only when `at_start`.
    fn skipTo(r: *Reader, marker: []const u8, at_start: bool) ReadError!void {
        if (at_start) {
            const first = try r.peek(marker.len);
            if (std.mem.eql(u8, first, marker)) {
                r.in.toss(marker.len);
                return;
            }
        }
        // A preamble: the boundary follows a CRLF.
        r.state = .body;
        while (r.state == .body) _ = try r.dataSlice(std.math.maxInt(usize));
    }

    /// The next part head's fields, up to its blank line.
    fn readHead(r: *Reader) ReadError!PartHead {
        var len: usize = 0;
        var head: PartHead = .{};
        while (true) {
            const line_end = while (true) {
                const buffered = r.in.buffered();
                if (std.mem.findScalar(u8, buffered, '\n')) |i| break i;
                if (buffered.len >= r.in.buffer.len) return error.HeadTooLarge;
                r.in.fillMore() catch |err| return switch (err) {
                    error.EndOfStream => error.Malformed,
                    error.ReadFailed => error.ReadFailed,
                };
            };
            const raw = r.in.buffered()[0 .. line_end + 1];
            if (raw.len < 2 or raw[raw.len - 2] != '\r') return error.Malformed;
            const line = raw[0 .. raw.len - 2];
            if (line.len == 0) {
                r.in.toss(raw.len);
                return head;
            }
            if (len + line.len > r.head_buffer.len) return error.HeadTooLarge;
            const kept = r.head_buffer[len..][0..line.len];
            @memcpy(kept, line);
            len += line.len;
            r.in.toss(raw.len);
            const colon = std.mem.findScalar(u8, kept, ':') orelse return error.Malformed;
            const name = kept[0..colon];
            if (!fields.isToken(name)) return error.Malformed;
            const value = trimmed(kept[colon + 1 ..]);
            if (std.ascii.eqlIgnoreCase(name, "content-type")) {
                head.content_type = value;
            } else if (std.ascii.eqlIgnoreCase(name, "content-disposition")) {
                try disposition(value, &head);
            }
        }
    }

    /// Up to `limit` bytes of the current part's data, where they lie in
    /// `in`'s buffer, stopping before a boundary; the end of the part
    /// moves the state on.
    fn dataSlice(r: *Reader, limit: usize) ReadError![]const u8 {
        const d = r.delimiter();
        while (true) {
            const buffered = r.in.buffered();
            if (std.mem.find(u8, buffered, d)) |at| {
                if (at == 0) {
                    r.in.toss(d.len);
                    r.state = .between;
                    return &.{};
                }
                const n = @min(at, limit);
                return r.take(n);
            }
            // No whole delimiter: what cannot start one is data.
            const keep = d.len - 1;
            if (buffered.len > keep) return r.take(@min(buffered.len - keep, limit));
            r.in.fillMore() catch |err| return switch (err) {
                error.EndOfStream => error.Malformed,
                error.ReadFailed => error.ReadFailed,
            };
        }
    }

    fn take(r: *Reader, n: usize) []const u8 {
        const bytes = r.in.buffered()[0..n];
        r.in.toss(n);
        return bytes;
    }

    fn stream(io_r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const r: *Reader = @alignCast(@fieldParentPtr("interface", io_r)); // safe: this vtable is installed only on a Reader's interface
        if (r.state != .body) return error.EndOfStream;
        const bytes = r.dataSlice(limit.toInt() orelse std.math.maxInt(usize)) catch |err| {
            r.failure = err;
            return error.ReadFailed;
        };
        if (bytes.len == 0) return error.EndOfStream;
        try w.writeAll(bytes);
        return bytes.len;
    }
};

/// `form-data; name="…"; filename="…"`, its quoted values unquoted and
/// their WHATWG escapes undone in place.
fn disposition(value: []u8, head: *PartHead) ReadError!void {
    var rest: []u8 = value;
    const semi = std.mem.findScalar(u8, rest, ';') orelse return;
    rest = rest[semi + 1 ..];
    while (rest.len != 0) {
        rest = trimmed(rest);
        const eq = std.mem.findScalar(u8, rest, '=') orelse return error.Malformed;
        const key = std.mem.trim(u8, rest[0..eq], " \t");
        rest = rest[eq + 1 ..];
        var v: []u8 = undefined;
        if (rest.len != 0 and rest[0] == '"') {
            const close = std.mem.findScalarPos(u8, rest, 1, '"') orelse return error.Malformed;
            v = unescapeName(rest[1..close]);
            rest = rest[close + 1 ..];
            const next = std.mem.findScalar(u8, rest, ';') orelse rest.len;
            rest = rest[@min(next + 1, rest.len)..];
        } else {
            const next = std.mem.findScalar(u8, rest, ';') orelse rest.len;
            v = trimmed(rest[0..next]);
            rest = rest[@min(next + 1, rest.len)..];
        }
        if (std.ascii.eqlIgnoreCase(key, "name")) head.name = v;
        if (std.ascii.eqlIgnoreCase(key, "filename")) head.filename = v;
    }
}

/// `text` without the spaces and tabs at its ends, still mutable.
fn trimmed(text: []u8) []u8 {
    var start: usize = 0;
    var end: usize = text.len;
    while (start < end and (text[start] == ' ' or text[start] == '\t')) start += 1;
    while (end > start and (text[end - 1] == ' ' or text[end - 1] == '\t')) end -= 1;
    return text[start..end];
}

/// `%22`, `%0D` and `%0A` undone in place, as the WHATWG standard writes a
/// form's names.
fn unescapeName(text: []u8) []u8 {
    var n: usize = 0;
    var i: usize = 0;
    while (i < text.len) : (n += 1) {
        if (text[i] == '%' and i + 2 < text.len) {
            const code = text[i + 1 .. i + 3];
            const c: ?u8 = if (std.ascii.eqlIgnoreCase(code, "22")) '"' else if (std.ascii.eqlIgnoreCase(code, "0D")) '\r' else if (std.ascii.eqlIgnoreCase(code, "0A")) '\n' else null;
            if (c) |byte| {
                text[n] = byte;
                i += 3;
                continue;
            }
        }
        text[n] = text[i];
        i += 1;
    }
    return text[0..n];
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

test "a body is read part by part as it arrives, whatever the pieces it comes in" {
    var buf: [1024]u8 = undefined;
    var out: Io.Writer = .fixed(&buf);
    const boundary = "AaB03x";
    var w: Writer = .init(&out, boundary);
    try w.field("submit-name", "Larry");
    try w.part(.{ .name = "fi\"les", .filename = "file1.txt", .content_type = "text/plain" });
    try out.writeAll("... contents of file1.txt, with \r\n--AaB03 in it ...");
    try w.end();
    const body = out.buffered();
    for ([_]usize{ 80, 128, 1024 }) |step| {
        var source: Io.Reader = .fixed(body);
        var small: [1024]u8 = undefined;
        var limited = source.limited(.unlimited, small[0..step]);
        var head_buf: [256]u8 = undefined;
        var part_buf: [16]u8 = undefined;
        var r: Reader = .init(&limited.interface, boundary, &head_buf, &part_buf);
        const first = (try r.next()).?;
        try testing.expectEqualStrings("submit-name", first.name);
        var data: [128]u8 = undefined;
        const n = try r.body().readSliceShort(&data);
        try testing.expectEqualStrings("Larry", data[0..n]);
        const second = (try r.next()).?;
        try testing.expectEqualStrings("fi\"les", second.name);
        try testing.expectEqualStrings("file1.txt", second.filename.?);
        try testing.expectEqualStrings("text/plain", second.content_type.?);
        const m = try r.body().readSliceShort(&data);
        try testing.expectEqualStrings("... contents of file1.txt, with \r\n--AaB03 in it ...", data[0..m]);
        try testing.expectEqual(null, try r.next());
    }
    try testing.expectEqualStrings("AaB03x", boundaryFrom("multipart/form-data; boundary=\"AaB03x\"").?);
    try testing.expectEqual(null, boundaryFrom("text/plain"));
}

test "a part not read is skipped, a preamble ignored, and a body cut short refused" {
    const body = "preamble\r\n--b\r\nContent-Disposition: form-data; name=a\r\n\r\nskip me\r\n--b\r\nContent-Disposition: form-data; name=\"c\"\r\n\r\nkept\r\n--b--\r\n";
    var source: Io.Reader = .fixed(body);
    var head_buf: [128]u8 = undefined;
    var part_buf: [16]u8 = undefined;
    var r: Reader = .init(&source, "b", &head_buf, &part_buf);
    try testing.expectEqualStrings("a", (try r.next()).?.name);
    try testing.expectEqualStrings("c", (try r.next()).?.name);
    var data: [16]u8 = undefined;
    try testing.expectEqualStrings("kept", data[0..try r.body().readSliceShort(&data)]);
    try testing.expectEqual(null, try r.next());
    var cut: Io.Reader = .fixed("--b\r\nContent-Disposition: form-data; name=a\r\n\r\nno end");
    var r2: Reader = .init(&cut, "b", &head_buf, &part_buf);
    _ = try r2.next();
    try testing.expectError(error.ReadFailed, r2.body().readSliceShort(&data));
    try testing.expectEqual(ReadError.Malformed, r2.failure.?);
}
