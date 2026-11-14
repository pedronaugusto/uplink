//! Properties for what `uplink.wire`'s parsers and writers promise in their
//! documentation, each checked against a definition written here from the
//! RFC rather than against the code's own helpers: a parser that does not
//! crash and puts its input back together can still let through a byte the
//! wire does not allow, and only a property that asks finds it.

const std = @import("std");
const testing = std.testing;
const shakedown = @import("shakedown");
const url = @import("url.zig");
const h1 = @import("h1.zig");
const fields = @import("fields.zig");
const uri = @import("uri.zig");
const Method = @import("Method.zig");

/// RFC 9110 §5.6.2's `tchar`, written out.
fn tchar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or std.mem.findScalar(u8, "!#$%&'*+-.^_`|~", c) != null;
}

/// A control character as RFC 9110 §5.5 forbids one in a field value:
/// C0 but HTAB, and DEL.
fn control(c: u8) bool {
    return (c < 0x20 and c != '\t') or c == 0x7f;
}

/// A byte RFC 9112 §3.2 allows in a request target: visible ASCII, and no
/// `#`, since a target carries no fragment.
fn targetByte(c: u8) bool {
    return c > 0x20 and c < 0x7f and c != '#';
}

/// Text drawn as pieces from `pieces`, up to `buffer`'s length.
fn pieced(s: *shakedown.Source, buffer: []u8, prefix: []const []const u8, pieces: []const []const u8, more: u32) []u8 {
    var len: usize = 0;
    const first = shakedown.gen.oneOf(s, []const u8, prefix);
    @memcpy(buffer[0..first.len], first);
    len = first.len;
    while (s.more(more)) {
        const piece = shakedown.gen.oneOf(s, []const u8, pieces);
        if (len + piece.len > buffer.len) break;
        @memcpy(buffer[len..][0..piece.len], piece);
        len += piece.len;
    }
    return buffer[0..len];
}

// url.zig: "nothing in a URL can put a byte on the wire that a request line
// or a `Host` field does not allow".

const url_prefixes = [_][]const u8{ "http://", "https://", "HTTP://", "http://example.com", "https://[::1]", "http://a:8080", "ftp://", "" };
const url_pieces = [_][]const u8{
    "a",    "example.com", "[::1]", "[",   "]",      ":", "8080", "/",  "?", "#", "%", "%41", "%zz", "\t", " ", "\x00",     "\r", "\n",
    "\x7f", "\xc3\xa9",    "\xff",  "\\",  "@",      "+", "_",    "\"", "<", ">", "{", "}",   "|",   "^",  "`", "user:pw@", "..", "x=1",
    "&",    ";",           "%25",   "%0d", "%c3%a9",
};

fn anyUrl(_: void, case: *shakedown.Case) !void {
    var buffer: [96]u8 = undefined;
    const text = pieced(case.source, &buffer, &url_prefixes, &url_pieces, 10);
    const u = url.parse(text) catch return;
    // The request target: ASCII a request line takes, starting with '/'.
    var target_buffer: [512]u8 = undefined;
    var tw: std.Io.Writer = .fixed(&target_buffer);
    try u.writeTarget(&tw);
    const target = tw.buffered();
    try testing.expect(target.len > 0 and target[0] == '/');
    for (target) |c| if (!targetByte(c)) {
        std.debug.print("{any} writes the target byte 0x{x}: {any}\n", .{ text, c, target });
        return error.TestUnexpectedResult;
    };
    // The `Host` value: field characters, and nothing that ends the
    // authority or starts another part (RFC 9110 §7.2, RFC 3986 §3.2).
    for ([_]bool{ false, true }) |always_port| {
        var host_buffer: [128]u8 = undefined;
        var hw: std.Io.Writer = .fixed(&host_buffer);
        try u.writeAuthority(&hw, always_port);
        const host = hw.buffered();
        try testing.expect(host.len > 0);
        for (host) |c| if (control(c) or c == ' ' or c == '\t' or std.mem.findScalar(u8, "/?#@\\", c) != null) {
            std.debug.print("{any} writes the Host byte 0x{x}: {any}\n", .{ text, c, host });
            return error.TestUnexpectedResult;
        };
        if (!u.ipv6()) try testing.expect(std.mem.findScalar(u8, u.host, ':') == null);
        // A server reads the two back as they were written, one field.
        var head_buffer: [768]u8 = undefined;
        var w: std.Io.Writer = .fixed(&head_buffer);
        try w.print("GET {s} HTTP/1.1\r\nHost: {s}\r\n\r\n", .{ target, host });
        var field_buffer: [4]fields.Field = undefined;
        const parsed = (try h1.parseRequest(w.buffered(), &field_buffer, .{})).?;
        try testing.expectEqualStrings(target, parsed.head.target);
        try testing.expectEqual(1, parsed.head.headers.count());
        try testing.expectEqualStrings(host, parsed.head.headers.get("host").?);
    }
    // `originTarget` is the target `writeTarget` writes.
    var origin_buffer: [512]u8 = undefined;
    try testing.expectEqualStrings(target, try u.originTarget(&origin_buffer));
}

test "property: an accepted URL writes only what a request line and a Host field allow" {
    try shakedown.check(testing.allocator, {}, anyUrl, .{ .cases = 20000, .seed = 0x9112 });
}

// h1.zig: requests read strictly, every head checked.

const request_prefixes = [_][]const u8{ "GET / HTTP/1.1\r\n", "POST /a?b HTTP/1.0\r\n", "\r\nGET /x HTTP/1.1\r\n", "", "GET http://h/p HTTP/1.1\r\n" };
const head_pieces = [_][]const u8{
    "GET",      " ",     "/",      "/a#b",     "/caf\xc3\xa9", "HTTP/1.1", "HTTP/2.0", "\r\n",           "\n", "\r",      ":", "Host", "h",
    "A",        "a b",   "\t",     "\x00",     "\x7f",         "\xff",     "x-y",      "Content-Length", "5",  "chunked", ",", "\"",   "@",
    "\r\n\r\n", "\r\n ", "\r\n\t", "A: b\r\n", "Host: h\r\n",  " :",       "*",        "\x01",           "%",
};

/// A request line from a method, a target of pieces and a version, so most
/// get past the line's shape to its target's bytes.
fn requestLine(s: *shakedown.Source, buffer: []u8) []u8 {
    var w: std.Io.Writer = .fixed(buffer);
    w.writeAll(shakedown.gen.oneOf(s, []const u8, &.{ "GET", "POST", "OPTIONS", "G\x00T", "" })) catch unreachable; // the buffer holds the longest line drawn
    w.writeByte(' ') catch unreachable;
    var target_buffer: [48]u8 = undefined;
    w.writeAll(pieced(s, &target_buffer, &.{ "/", "*", "http://h", "" }, &.{ "/", "a", "#", "\xff", "\xc3\xa9", "%", "%41", "?", "\t", "\x00", "\x7f", "\"", "<", "{" }, 6)) catch unreachable;
    w.writeByte(' ') catch unreachable;
    w.writeAll(shakedown.gen.oneOf(s, []const u8, &.{ "HTTP/1.1", "HTTP/1.0", "HTTP/2.0", "HTTP/1.1 " })) catch unreachable;
    w.writeAll(shakedown.gen.oneOf(s, []const u8, &.{ "\r\n", "\n" })) catch unreachable;
    return w.buffered();
}

fn anyRequest(_: void, case: *shakedown.Case) !void {
    var buffer: [160]u8 = undefined;
    var line_buffer: [80]u8 = undefined;
    const line = requestLine(case.source, &line_buffer);
    const text = if (shakedown.gen.boolean(case.source)) blk: {
        @memcpy(buffer[0..line.len], line);
        const rest = pieced(case.source, buffer[line.len..], &.{ "\r\n", "Host: h\r\n\r\n", "" }, &head_pieces, 8);
        break :blk buffer[0 .. line.len + rest.len];
    } else pieced(case.source, &buffer, &request_prefixes, &head_pieces, 14);
    var bytes_buffer: [192]u8 = undefined;
    const bytes = bytes_buffer[0..text.len];
    @memcpy(bytes, text);
    var field_buffer: [16]fields.Field = undefined;
    const limits: h1.Limits = .{ .max_head = .literal("1KiB"), .max_fields = 16 };
    const parsed = (h1.parseRequest(bytes, &field_buffer, limits) catch return) orelse return;
    // Requests are read strictly: the bytes are untouched, every line ends
    // in CRLF, and no field is folded (RFC 9112 §2.2, §5.2).
    try testing.expectEqualStrings(text, bytes);
    const head_text = text[0..parsed.len];
    try testing.expect(std.mem.endsWith(u8, head_text, "\r\n\r\n"));
    for (head_text, 0..) |c, i| if (c == '\n') {
        try testing.expect(i > 0 and head_text[i - 1] == '\r');
        if (i + 1 < head_text.len) try testing.expect(head_text[i + 1] != ' ' and head_text[i + 1] != '\t');
    };
    const head = parsed.head;
    try testing.expect(head.method.name.len > 0);
    for (head.method.name) |c| try testing.expect(tchar(c));
    try testing.expect(head.target.len > 0);
    for (head.target) |c| if (!targetByte(c)) {
        std.debug.print("{any} accepted with the target byte 0x{x}\n", .{ text, c });
        return error.TestUnexpectedResult;
    };
    try fieldsAllowed(head.headers);
    try prefixesWait(text, parsed.len, .request);
}

/// Every field a parsed head holds: a token name and a value with no
/// control character and no whitespace at either end.
fn fieldsAllowed(headers: fields.Headers) !void {
    for (headers.fields) |f| {
        try testing.expect(f.name.len > 0);
        for (f.name) |c| try testing.expect(tchar(c));
        for (f.value) |c| if (control(c)) {
            std.debug.print("the value {any} of {s} holds 0x{x}\n", .{ f.value, f.name, c });
            return error.TestUnexpectedResult;
        };
        if (f.value.len > 0) {
            try testing.expect(f.value[0] != ' ' and f.value[0] != '\t');
            try testing.expect(f.value[f.value.len - 1] != ' ' and f.value[f.value.len - 1] != '\t');
        }
    }
}

/// A head not all there is `null`, never an error, at every length short of
/// the whole; and the bytes after a head (a body) do not change it.
fn prefixesWait(text: []const u8, len: usize, which: h1.Lenience) !void {
    var copy_buffer: [256]u8 = undefined;
    var field_buffer: [16]fields.Field = undefined;
    const limits: h1.Limits = .{ .max_head = .literal("1KiB"), .max_fields = 16 };
    for (0..len) |cut| {
        const copy = copy_buffer[0..cut];
        @memcpy(copy, text[0..cut]);
        const result = switch (which) {
            .request => if (try h1.parseRequest(copy, &field_buffer, limits)) |p| p.len else null,
            .response => if (try h1.parseResponse(copy, &field_buffer, limits)) |p| p.len else null,
        };
        try testing.expectEqual(null, result);
    }
    const longer = copy_buffer[0 .. len + 7];
    @memcpy(longer[0..len], text[0..len]);
    @memcpy(longer[len..], "\r\nX: y\n");
    const again = switch (which) {
        .request => (try h1.parseRequest(longer, &field_buffer, limits)).?.len,
        .response => (try h1.parseResponse(longer, &field_buffer, limits)).?.len,
    };
    try testing.expectEqual(len, again);
}

test "property: an accepted request head holds only what RFC 9112 allows a request" {
    try shakedown.check(testing.allocator, {}, anyRequest, .{ .cases = 20000, .seed = 0x9113 });
}

const response_prefixes = [_][]const u8{ "HTTP/1.1 200 OK\r\n", "HTTP/1.0 404\n", "HTTP/1.1 301 Moved\r\nLocation: /x\r\n", "" };

fn anyResponse(_: void, case: *shakedown.Case) !void {
    var buffer: [160]u8 = undefined;
    const text = pieced(case.source, &buffer, &response_prefixes, &head_pieces, 14);
    var bytes_buffer: [192]u8 = undefined;
    const bytes = bytes_buffer[0..text.len];
    @memcpy(bytes, text);
    var field_buffer: [16]fields.Field = undefined;
    const parsed = (h1.parseResponse(bytes, &field_buffer, .{ .max_head = .literal("1KiB"), .max_fields = 16 }) catch return) orelse return;
    // Folds are joined and bare LFs taken, but no value or reason a caller
    // reads holds a line break or another control character.
    const head = parsed.head;
    const code = @backingInt(head.status);
    try testing.expect(code >= 100 and code <= 999);
    for (head.reason) |c| try testing.expect(!control(c));
    try fieldsAllowed(head.headers);
    try prefixesWait(text, parsed.len, .response);
}

test "property: an accepted response head gives back no line break in a value" {
    try shakedown.check(testing.allocator, {}, anyResponse, .{ .cases = 20000, .seed = 0x9114 });
}

// h1.writeRequestHead: "nothing a caller passes can add a line".

const out_pieces = [_][]const u8{ "a", "b c", "\r\n", "\n", "\r", "\t", " ", ":", "X-Injected: 1", "\x00", "\x7f", "\xc3\xa9", "/", "?", "#", "%", "Host" };

fn draw(s: *shakedown.Source, buffer: []u8) []u8 {
    return pieced(s, buffer, &.{""}, &out_pieces, 4);
}

fn anyHeadOut(_: void, case: *shakedown.Case) !void {
    const s = case.source;
    var b: [8][48]u8 = undefined;
    const target = [_][]const u8{ "/", draw(s, &b[0]) };
    const own = [_]std.http.Header{.{ .name = draw(s, &b[1]), .value = draw(s, &b[2]) }};
    const headers = [_]std.http.Header{ .{ .name = draw(s, &b[3]), .value = draw(s, &b[4]) }, .{ .name = "Accept", .value = draw(s, &b[5]) } };
    const head: h1.RequestHeadOut = .{
        .method = shakedown.gen.oneOf(s, Method, &.{ .GET, .POST, .HEAD }),
        .target = &target,
        .host = draw(s, &b[6]),
        .own = &own,
        .headers = &headers,
        .framing = if (shakedown.gen.boolean(s)) .{ .length = 3 } else .none,
    };
    var out_buffer: [1024]u8 = undefined;
    var w: std.Io.Writer = .fixed(&out_buffer);
    h1.writeRequestHead(&w, head) catch |err| {
        // Refused before a byte was written.
        try testing.expect(err != error.WriteFailed);
        try testing.expectEqual(0, w.buffered().len);
        return;
    };
    // What was written is read back as exactly the fields passed, in order.
    var field_buffer: [16]fields.Field = undefined;
    const parsed = (try h1.parseRequest(w.buffered(), &field_buffer, .{})).?;
    try testing.expectEqual(w.buffered().len, parsed.len);
    const p = parsed.head;
    try testing.expectEqualStrings(head.method.name, p.method.name);
    var joined: [64]u8 = undefined;
    try testing.expectEqualStrings(try std.mem.print(&joined, "{s}{s}", .{ target[0], target[1] }), p.target);
    const extra: usize = if (head.framing == .length) 1 else 0;
    try testing.expectEqual(1 + own.len + headers.len + extra, p.headers.count());
    try testing.expectEqualStrings(head.host, p.headers.fields[0].value);
    try testing.expectEqualStrings(own[0].name, p.headers.fields[1].name);
    try testing.expectEqualStrings(own[0].value, p.headers.fields[1].value);
    for (headers, p.headers.fields[2..][0..headers.len]) |want, got| {
        try testing.expectEqualStrings(want.name, got.name);
        try testing.expectEqualStrings(want.value, got.value);
    }
}

test "property: a request head written is read back as the fields passed, no more" {
    try shakedown.check(testing.allocator, {}, anyHeadOut, .{
        .cases = 20000,
        .seed = 0x9115,
        .regressions = &.{
            // A target byte past ASCII the writer sent and the reader refused (the fuzz job).
            "30d40:e:0:30d40:0:0:0:30d40",
        },
    });
}

// h1.ChunkedDecoder and ChunkedWriter.

/// The data `in` decodes to, fed `step` bytes at a time (all at once when
/// `step` is 0), whether the body ended, and the bytes consumed; an error
/// as the decoder gives it.
fn decode(in: []const u8, step: usize, lenience: h1.Lenience, out: []u8) anyerror!struct { data: []u8, done: bool, consumed: usize } {
    var d: h1.ChunkedDecoder = .{ .lenience = lenience };
    var n: usize = 0;
    var at: usize = 0;
    while (at < in.len and !d.done()) {
        const end = if (step == 0) in.len else @min(in.len, at + step);
        const got = try d.feed(in[at..end]);
        // Each feed of bytes that are there makes progress.
        if (got.consumed + got.data == 0) return error.TestUnexpectedResult;
        @memcpy(out[n..][0..got.data], in[at + got.consumed ..][0..got.data]);
        n += got.data;
        d.take(got.data);
        at += got.consumed + got.data;
    }
    return .{ .data = out[0..n], .done = d.done(), .consumed = at };
}

fn anyChunked(_: void, case: *shakedown.Case) !void {
    const s = case.source;
    // A body ChunkedWriter writes, in writes of random sizes through a
    // small buffer.
    var data_buffer: [300]u8 = undefined;
    const data = shakedown.gen.bytesInto(s, data_buffer[0..shakedown.gen.intRange(s, usize, 0, data_buffer.len)]);
    var wire_buffer: [1024]u8 = undefined;
    var out: std.Io.Writer = .fixed(&wire_buffer);
    var chunk_buffer: [16]u8 = undefined;
    var cw: h1.ChunkedWriter = .init(&out, chunk_buffer[0..shakedown.gen.intRange(s, usize, 1, chunk_buffer.len)]);
    var at: usize = 0;
    while (at < data.len) {
        const n = @min(data.len - at, shakedown.gen.intRange(s, usize, 1, 40));
        try cw.interface.writeAll(data[at..][0..n]);
        at += n;
    }
    try cw.end();
    const encoded = out.buffered();
    // decodes to itself, strictly and leniently, fed in any steps, with
    // every byte of it consumed and none after.
    const step = shakedown.gen.intRange(s, usize, 0, 9);
    var decoded: [1024]u8 = undefined;
    for ([_]h1.Lenience{ .request, .response }) |lenience| {
        const got = try decode(encoded, step, lenience, &decoded);
        try testing.expect(got.done);
        try testing.expectEqual(encoded.len, got.consumed);
        try testing.expectEqualSlices(u8, data, got.data);
    }
}

test "property: a body ChunkedWriter writes decodes to itself, fed in any steps" {
    try shakedown.check(testing.allocator, {}, anyChunked, .{ .cases = 5000, .seed = 0x7112 });
}

const chunk_pieces = [_][]const u8{ "0", "1", "5", "a", "F", "ffffffffffffffffff", "\r\n", "\n", "\r", ";", "ext", "=", "\"q\"", "\"\\\"", " ", "\t", "abcde", "x", "\x00", "Trailer: t\r\n", ":", "0\r\n\r\n" };

fn anyChunkedBytes(_: void, case: *shakedown.Case) !void {
    var buffer: [160]u8 = undefined;
    const text = pieced(case.source, &buffer, &.{ "5\r\n", "0\r\n", "" }, &chunk_pieces, 12);
    const step = shakedown.gen.intRange(case.source, usize, 1, 7);
    for ([_]h1.Lenience{ .request, .response }) |lenience| {
        // The same bytes decode the same however they arrive, and the data
        // handed out is never more than the bytes in.
        var whole_buffer: [160]u8 = undefined;
        var split_buffer: [160]u8 = undefined;
        const whole = decode(text, 0, lenience, &whole_buffer);
        const split = decode(text, step, lenience, &split_buffer);
        if (whole) |w| {
            const p = split catch |err| {
                std.debug.print("{any}: whole {any}, in steps of {d} {t}\n", .{ text, w.data, step, err });
                return error.TestUnexpectedResult;
            };
            try testing.expectEqualSlices(u8, w.data, p.data);
            try testing.expectEqual(w.done, p.done);
            try testing.expectEqual(w.consumed, p.consumed);
            try testing.expect(w.data.len <= text.len);
        } else |err| {
            if (split) |_| {
                std.debug.print("{any}: whole {t}, in steps of {d} accepted\n", .{ text, err, step });
                return error.TestUnexpectedResult;
            } else |e| try testing.expectEqual(err, e);
        }
    }
}

test "property: a chunked body decodes the same however its bytes arrive" {
    try shakedown.check(testing.allocator, {}, anyChunkedBytes, .{ .cases = 20000, .seed = 0x7113 });
}

// fields.zig: the fast paths agree with RFC 9110's definitions.

fn anyFieldText(_: void, case: *shakedown.Case) !void {
    var buffer: [80]u8 = undefined;
    // Raw bytes, or mostly the bytes the rules turn on.
    const text = if (shakedown.gen.boolean(case.source))
        shakedown.gen.bytesInto(case.source, buffer[0..shakedown.gen.intRange(case.source, usize, 0, buffer.len)])
    else
        pieced(case.source, &buffer, &.{""}, &.{ "\n", "\r", "\t", " ", "a", "-", "\x00", "\x1f", "\x7f", "\xff", ":", "aaaaaaaaaaaaaaaa" }, 16);
    // hasControl, sixteen bytes at a time, is the byte rule.
    var any_control = false;
    for (text) |c| any_control = any_control or control(c);
    try testing.expectEqual(any_control, fields.hasControl(text));
    // isToken and isFieldValue are §5.6.2 and §5.5.
    var token = text.len > 0;
    for (text) |c| token = token and tchar(c);
    try testing.expectEqual(token, fields.isToken(text));
    const ends_bare = text.len == 0 or (text[0] != ' ' and text[0] != '\t' and text[text.len - 1] != ' ' and text[text.len - 1] != '\t');
    try testing.expectEqual(!any_control and ends_bare, fields.isFieldValue(text));
    // findHeadEnd, thirty-two bytes at a time, is the first LF followed by
    // LF or CRLF.
    var naive: ?usize = null;
    for (text, 0..) |c, i| if (c == '\n') {
        if (i + 1 < text.len and text[i + 1] == '\n') {
            naive = i + 2;
            break;
        }
        if (i + 2 < text.len and text[i + 1] == '\r' and text[i + 2] == '\n') {
            naive = i + 3;
            break;
        }
    };
    try testing.expectEqual(naive, h1.findHeadEnd(text, 0));
}

test "property: the vectored field checks are RFC 9110's byte rules" {
    try shakedown.check(testing.allocator, {}, anyFieldText, .{ .cases = 20000, .seed = 0x9110 });
}

fn anyName(_: void, case: *shakedown.Case) !void {
    var buffer: [32]u8 = undefined;
    const names = comptime blk: {
        var list: [std.enums.values(fields.Known).len][]const u8 = undefined;
        for (std.enums.values(fields.Known), 0..) |k, i| list[i] = @tagName(k);
        break :blk list;
    };
    const name = shakedown.gen.mutated(case.source, &buffer, &names);
    // Known.of, which compares from the second byte, is a case-blind
    // compare against every known name.
    var want: ?fields.Known = null;
    for (std.enums.values(fields.Known)) |k| if (std.ascii.eqlIgnoreCase(@tagName(k), name)) {
        want = k;
    };
    try testing.expectEqual(want, fields.Known.of(name));
}

test "property: a known field name is found exactly when it matches, any case" {
    try shakedown.check(testing.allocator, {}, anyName, .{ .cases = 20000, .seed = 0x9111 });
}

fn anyList(_: void, case: *shakedown.Case) !void {
    var buffer: [80]u8 = undefined;
    const text = pieced(case.source, &buffer, &.{""}, &.{ "a", "chunked", ",", " ", "\t", "\"", "\\", "\"x,y\"", "gzip", ";q=1" }, 12);
    // Each element is non-empty, trimmed, and the elements and the commas
    // between them, outside quotes, put back the text's non-blank parts.
    var it: fields.ListIterator = .{ .text = text };
    var last_end: usize = 0;
    while (it.next()) |e| {
        try testing.expect(e.len > 0);
        try testing.expect(e[0] != ' ' and e[0] != '\t' and e[e.len - 1] != ' ' and e[e.len - 1] != '\t');
        const start = @intFromPtr(e.ptr) - @intFromPtr(text.ptr);
        try testing.expect(start >= last_end and start + e.len <= text.len);
        // Between elements: only whitespace and commas.
        for (text[last_end..start]) |c| try testing.expect(c == ' ' or c == '\t' or c == ',');
        last_end = start + e.len;
    }
    for (text[last_end..]) |c| try testing.expect(c == ' ' or c == '\t' or c == ',');
}

test "property: list elements are trimmed, non-empty, and cover the list" {
    try shakedown.check(testing.allocator, {}, anyList, .{ .cases = 20000, .seed = 0x9116 });
}

// uri.zig: what `resolve` takes from where (RFC 3986 §5.2.2), and slices
// into the text.

const uri_bases = [_][]const u8{ "http://a/b/c/d;p?q", "https://x.y/z/", "urn:a:b", "file:///", "http://[::1]:80/a/../b", "http://u@h:1/p?q#f" };
const uri_refs = [_][]const u8{ "../g?y#s", "./../g", "//h/i", "g;x=1/../y", ".", "..", "/./g", "?q", "#f", "a:b", "", "g", "//u@h2:8/x?y", "http:g" };

fn within(text: []const u8, part: []const u8) bool {
    if (part.len == 0) return true;
    return @intFromPtr(part.ptr) >= @intFromPtr(text.ptr) and @intFromPtr(part.ptr) + part.len <= @intFromPtr(text.ptr) + text.len;
}

fn anyComponents(_: void, case: *shakedown.Case) !void {
    var base_buffer: [96]u8 = undefined;
    var ref_buffer: [96]u8 = undefined;
    const base_text = shakedown.gen.mutated(case.source, &base_buffer, &uri_bases);
    const ref_text = shakedown.gen.mutated(case.source, &ref_buffer, &uri_refs);
    const base = uri.parse(.init(base_text), .uri, .uri, null) catch return;
    const ref = uri.parse(.init(ref_text), .reference, .uri, null) catch return;
    // Every slice points into the text it was parsed from.
    for ([_]?[]const u8{ ref.scheme, ref.path, ref.query, ref.fragment }) |part| if (part) |p| try testing.expect(within(ref_text, p));
    if (ref.authority) |a| {
        try testing.expect(within(ref_text, a.host_text));
        if (a.userinfo) |u| try testing.expect(within(ref_text, u));
        if (a.port) |p| try testing.expect(within(ref_text, p));
    }
    var out: [256]u8 = undefined;
    const target_text = try uri.resolve(base, ref, &out);
    const t = try uri.parse(.init(target_text), .uri, .uri, null);
    // §5.2.2: the scheme is the reference's, else the base's; so is the
    // authority unless the reference has a scheme or authority; the
    // fragment is always the reference's.
    try testing.expectEqualStrings(ref.scheme orelse base.scheme.?, t.scheme.?);
    const authority_source: ?uri.Authority = if (ref.scheme != null or ref.authority != null) ref.authority else base.authority;
    try testing.expectEqual(authority_source != null, t.authority != null);
    if (authority_source) |a| try testing.expectEqualStrings(a.host_text, t.authority.?.host_text);
    try testing.expectEqualDeep(ref.fragment, t.fragment);
    // The query is the reference's, or the base's for an empty path and no query.
    const query_source = if (ref.scheme == null and ref.authority == null and ref.path.len == 0 and ref.query == null) base.query else ref.query;
    try testing.expectEqualDeep(query_source, t.query);
    // A target resolves to itself: it has a scheme and no dot segments.
    var again: [256]u8 = undefined;
    try testing.expectEqualStrings(target_text, try uri.resolve(base, t, &again));
}

test "property: resolution takes each part from where RFC 3986 §5.2.2 says, and is idempotent" {
    try shakedown.check(testing.allocator, {}, anyComponents, .{ .cases = 5000, .seed = 0x5222 });
}
