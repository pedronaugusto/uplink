//! HTTP/1.1 message syntax (RFC 9112), sans I/O: heads parsed in place,
//! the body's framing decided, chunked bodies decoded from and encoded to
//! byte slices, request heads written with everything in them checked.
//!
//! **Strict on requests, lenient on responses.** A response may end its
//! lines with a bare LF and fold a field value over lines (`obs-fold`), as
//! RFC 9112 §2.2 and §5.2 allow a recipient to accept; the fold is replaced by spaces in place. A request doing either is
//! refused, as a server must refuse it.
//!
//! Nothing here allocates. The head's lines are found sixteen and thirty-two
//! bytes at a time, and a field value's characters are checked the same way.

const std = @import("std");
const Io = std.Io;
const fields_mod = @import("fields.zig");
const Method = @import("Method.zig");
const Version = @import("version.zig").Version;

const Field = fields_mod.Field;
const Headers = fields_mod.Headers;
const Status = std.http.Status;
const Header = std.http.Header;

/// The largest head and the most fields one may have.
pub const Limits = struct {
    /// The head's bytes, its blank line included.
    max_head: u32 = 64 << 10,
    max_fields: u16 = 100,
};

/// Which of RFC 9112's allowances a parse takes.
pub const Lenience = enum {
    /// Bare LF line ends and folded values accepted.
    response,
    /// Both refused.
    request,
};

/// A response's head. Every slice points into the bytes it was parsed from.
pub const ResponseHead = struct {
    version: Version,
    status: Status,
    reason: []const u8,
    headers: Headers,
};

/// A request's head. Every slice points into the bytes it was parsed from.
pub const RequestHead = struct {
    method: Method,
    target: []const u8,
    version: Version,
    headers: Headers,
};

/// A head and how many bytes it took, its blank line included.
pub fn Parsed(comptime Head: type) type {
    return struct { head: Head, len: usize };
}

/// Why a head was refused.
pub const ParseError = error{
    /// No blank line within `Limits.max_head` bytes.
    HeadTooLarge,
    /// More fields than `Limits.max_fields`, or than the slice given.
    TooManyFields,
    /// A status or request line that is not RFC 9112's.
    InvalidStartLine,
    /// A version other than HTTP/1.x.
    UnsupportedVersion,
    /// A field name that is not a token, or a line with no colon.
    InvalidFieldName,
    /// A control character in a value.
    InvalidFieldValue,
    /// A request line ending in LF alone.
    BareLineFeed,
    /// A request field folded over lines.
    ObsoleteLineFolding,
};

/// Where a head ends: the index just past its blank line, or null when the
/// blank line has not arrived. `from` is where to resume a search over
/// bytes that have grown: anything before the last three bytes searched.
pub fn findHeadEnd(bytes: []const u8, from: usize) ?usize {
    var i = from;
    while (nextLf(bytes, i)) |lf| {
        if (lf + 1 < bytes.len and bytes[lf + 1] == '\n') return lf + 2;
        if (lf + 2 < bytes.len and bytes[lf + 1] == '\r' and bytes[lf + 2] == '\n') return lf + 3;
        i = lf + 1;
    }
    return null;
}

/// The next LF at or after `from`, thirty-two bytes at a time.
fn nextLf(bytes: []const u8, from: usize) ?usize {
    var i = from;
    while (i + 32 <= bytes.len) : (i += 32) {
        const v: @Vector(32, u8) = bytes[i..][0..32].*;
        const hits: u32 = @bitCast(v == @as(@Vector(32, u8), @splat('\n')));
        if (hits != 0) return i + @ctz(hits);
    }
    while (i < bytes.len) : (i += 1) if (bytes[i] == '\n') return i;
    return null;
}

/// A response head at the start of `bytes`, or null when it is not all
/// there yet. Fields go into `fields`. A folded value is unfolded in
/// `bytes`, which is why they are mutable.
pub fn parseResponse(bytes: []u8, fields: []Field, limits: Limits) ParseError!?Parsed(ResponseHead) {
    const end = try headEnd(bytes, limits) orelse return null;
    const line, const next = lineAt(bytes[0..end], 0, .response) catch return error.InvalidStartLine;
    var head: ResponseHead = undefined;
    try parseStatusLine(line, &head);
    const n = try parseFields(bytes[0..end], next, fields[0..@min(fields.len, limits.max_fields)], .response);
    head.headers = .init(fields[0..n]);
    return .{ .head = head, .len = end };
}

/// A request head at the start of `bytes`, or null when it is not all there
/// yet. Empty lines before the request line are skipped, as RFC 9112 §2.2
/// asks of a server.
pub fn parseRequest(bytes: []u8, fields: []Field, limits: Limits) ParseError!?Parsed(RequestHead) {
    var start: usize = 0;
    while (bytes.len - start >= 2 and bytes[start] == '\r' and bytes[start + 1] == '\n') start += 2;
    const end = try headEnd(bytes[start..], limits) orelse return null;
    const message = bytes[start..][0..end];
    const line, const next = try lineAt(message, 0, .request);
    var head: RequestHead = undefined;
    try parseRequestLine(line, &head);
    const n = try parseFields(message, next, fields[0..@min(fields.len, limits.max_fields)], .request);
    head.headers = .init(fields[0..n]);
    return .{ .head = head, .len = start + end };
}

fn headEnd(bytes: []const u8, limits: Limits) ParseError!?usize {
    const window = bytes[0..@min(bytes.len, limits.max_head)];
    if (findHeadEnd(window, 0)) |end| return end;
    if (bytes.len >= limits.max_head) return error.HeadTooLarge;
    return null;
}

/// The line at `from` in `bytes` without its line end, and where the next
/// one starts. `bytes` holds a whole head, so a line end is always there.
fn lineAt(bytes: []const u8, from: usize, lenience: Lenience) ParseError!struct { []const u8, usize } {
    const lf = nextLf(bytes, from) orelse return error.InvalidStartLine;
    if (lf > from and bytes[lf - 1] == '\r') return .{ bytes[from .. lf - 1], lf + 1 };
    if (lenience == .request) return error.BareLineFeed;
    return .{ bytes[from..lf], lf + 1 };
}

fn parseVersion(text: []const u8) ParseError!Version {
    if (text.len != 8 or !std.mem.startsWith(u8, text, "HTTP/") or text[6] != '.') return error.InvalidStartLine;
    if (!std.ascii.isDigit(text[5]) or !std.ascii.isDigit(text[7])) return error.InvalidStartLine;
    if (text[5] != '1') return error.UnsupportedVersion;
    // A later 1.x is read as the latest this speaks (RFC 9110 §2.5).
    return if (text[7] == '0') .http1_0 else .http1_1;
}

fn parseStatusLine(line: []const u8, head: *ResponseHead) ParseError!void {
    if (line.len < 12 or line[8] != ' ') return error.InvalidStartLine;
    head.version = try parseVersion(line[0..8]);
    const digits = line[9..12];
    if (digits[0] < '1' or digits[0] > '9' or !std.ascii.isDigit(digits[1]) or !std.ascii.isDigit(digits[2])) return error.InvalidStartLine;
    const code: u10 = @intCast(@as(u16, digits[0] - '0') * 100 + @as(u16, digits[1] - '0') * 10 + (digits[2] - '0'));
    head.status = @fromBackingInt(code);
    head.reason = "";
    if (line.len > 12) {
        if (line[12] != ' ') return error.InvalidStartLine;
        head.reason = line[13..];
        if (fields_mod.hasControl(head.reason)) return error.InvalidStartLine;
    }
}

fn parseRequestLine(line: []const u8, head: *RequestHead) ParseError!void {
    const sp1 = std.mem.findScalar(u8, line, ' ') orelse return error.InvalidStartLine;
    const sp2 = std.mem.findScalarPos(u8, line, sp1 + 1, ' ') orelse return error.InvalidStartLine;
    head.method = Method.parse(line[0..sp1]) catch return error.InvalidStartLine;
    head.target = line[sp1 + 1 .. sp2];
    if (!isTarget(head.target)) return error.InvalidStartLine;
    head.version = try parseVersion(line[sp2 + 1 ..]);
}

/// Whether `text` may be sent as a request target: not empty, and no
/// whitespace or control character.
pub fn isTarget(text: []const u8) bool {
    if (text.len == 0) return false;
    if (fields_mod.hasControl(text)) return false;
    return std.mem.findAny(u8, text, " \t") == null;
}

/// The fields after the start line, which ends at `from`, up to the blank
/// line. Returns how many went into `out`.
fn parseFields(bytes: []u8, from: usize, out: []Field, lenience: Lenience) ParseError!usize {
    var n: usize = 0;
    var at = from;
    while (true) {
        const line, const next = try lineAt(bytes, at, lenience);
        if (line.len == 0) return n;
        if (line[0] == ' ' or line[0] == '\t') {
            if (lenience == .request) return error.ObsoleteLineFolding;
            if (n == 0) return error.InvalidFieldName;
            try unfold(bytes, &out[n - 1], at, line);
        } else {
            if (n == out.len) return error.TooManyFields;
            out[n] = try parseField(line, lenience);
            n += 1;
        }
        at = next;
    }
}

fn parseField(line: []const u8, lenience: Lenience) ParseError!Field {
    const colon = std.mem.findScalar(u8, line, ':') orelse return error.InvalidFieldName;
    var name = line[0..colon];
    // Whitespace before the colon: refused in a request, dropped from a
    // response, as RFC 9112 §5.1 tells a proxy to drop it.
    if (lenience == .response) name = std.mem.trimEnd(u8, name, " \t");
    if (!fields_mod.isToken(name)) return error.InvalidFieldName;
    const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
    if (fields_mod.hasControl(value)) return error.InvalidFieldValue;
    return .{ .name = name, .value = value };
}

/// Join a continuation line to `field`: the line end and the whitespace
/// between become spaces, in place, and the value runs on to the line's
/// end (RFC 9112 §5.2).
fn unfold(bytes: []u8, field: *Field, line_start: usize, line: []const u8) ParseError!void {
    const value_start = @intFromPtr(field.value.ptr) - @intFromPtr(bytes.ptr); // safe: the value was sliced from `bytes`, so its address lies within them
    const value_end = value_start + field.value.len;
    const line_end = line_start + line.len;
    @memset(bytes[value_end..line_start], ' ');
    const joined = std.mem.trim(u8, bytes[value_start..line_end], " \t");
    if (fields_mod.hasControl(joined)) return error.InvalidFieldValue;
    // An empty first line leaves the value starting at the continuation.
    field.value = joined;
}

/// The fields of a chunked body's trailer section (RFC 9112 §7.1.2):
/// `bytes` is the section as the decoder consumed it, its blank line
/// included, read leniently as a response head is. Fields go into
/// `fields`; a folded value is unfolded in `bytes`.
pub fn parseTrailer(bytes: []u8, fields: []Field) ParseError!Headers {
    if (findHeadEnd(bytes, 0) == null) {
        // Only the blank line: no fields.
        if (bytes.len <= 2) return .{};
        return error.InvalidFieldName;
    }
    const n = try parseFields(bytes, 0, fields, .response);
    return .init(fields[0..n]);
}

/// How a message's body is delimited.
pub const Framing = union(enum) {
    /// No body.
    none,
    /// Exactly this many bytes.
    length: u64,
    /// Chunked transfer coding.
    chunked,
    /// Until the connection closes: responses only.
    until_close,
};

/// A response's framing, and whether its connection may carry another
/// exchange after it.
pub const ResponseFraming = struct {
    framing: Framing,
    keep_alive: bool,
};

/// Why a message's framing cannot be trusted.
pub const FramingError = error{
    /// A `Content-Length` that is not digits, or overflows.
    InvalidContentLength,
    /// `Content-Length` values that differ.
    ConflictingContentLength,
    /// `chunked` more than once, or a request whose last coding is not
    /// `chunked`, or one with both `Transfer-Encoding` and
    /// `Content-Length`.
    InvalidTransferEncoding,
};

/// RFC 9112 §6.3, in its order, for a response to `method`.
pub fn responseFraming(method: Method, head: *const ResponseHead) FramingError!ResponseFraming {
    var keep_alive = keepAlive(head.version, &head.headers);
    const code = @backingInt(head.status);
    if (method.bodiless() or code / 100 == 1 or code == 204 or code == 304) return .{ .framing = .none, .keep_alive = keep_alive };
    // A tunnel: what follows is no longer HTTP.
    if (method.eql(.CONNECT) and code / 100 == 2) return .{ .framing = .none, .keep_alive = false };
    if (head.headers.getKnown(.@"transfer-encoding") != null) {
        const chunked_last = try chunkedLast(&head.headers);
        // Both: Transfer-Encoding wins, and the connection is not trusted
        // with another exchange. HTTP/1.0 with Transfer-Encoding likewise.
        if (head.headers.getKnown(.@"content-length") != null or head.version == .http1_0) keep_alive = false;
        if (!chunked_last) return .{ .framing = .until_close, .keep_alive = false };
        return .{ .framing = .chunked, .keep_alive = keep_alive };
    }
    if (try contentLength(&head.headers)) |n| return .{ .framing = .{ .length = n }, .keep_alive = keep_alive };
    return .{ .framing = .until_close, .keep_alive = false };
}

/// RFC 9112 §6.3 for a request, with the smuggling rules: a request whose
/// last coding is not `chunked`, or that names both `Transfer-Encoding` and
/// `Content-Length`, is refused.
pub fn requestFraming(head: *const RequestHead) FramingError!Framing {
    if (head.headers.getKnown(.@"transfer-encoding") != null) {
        if (head.headers.getKnown(.@"content-length") != null) return error.InvalidTransferEncoding;
        if (head.version == .http1_0) return error.InvalidTransferEncoding;
        if (!try chunkedLast(&head.headers)) return error.InvalidTransferEncoding;
        return .chunked;
    }
    if (try contentLength(&head.headers)) |n| return if (n == 0) .none else .{ .length = n };
    return .none;
}

/// Whether `chunked` is the last transfer coding; `chunked` anywhere else,
/// or twice, is refused.
fn chunkedLast(headers: *const Headers) FramingError!bool {
    var it = headers.values("transfer-encoding");
    var seen = false;
    var last = false;
    while (it.next()) |coding| {
        const is_chunked = std.ascii.eqlIgnoreCase(codingName(coding), "chunked");
        if (is_chunked and seen) return error.InvalidTransferEncoding;
        seen = seen or is_chunked;
        last = is_chunked;
    }
    return last;
}

/// A coding's name without its parameters: `gzip` of `gzip;q=1`.
fn codingName(element: []const u8) []const u8 {
    const end = std.mem.findScalar(u8, element, ';') orelse element.len;
    return std.mem.trimEnd(u8, element[0..end], " \t");
}

/// Every `Content-Length` value, which must agree; `5, 5` is one value.
fn contentLength(headers: *const Headers) FramingError!?u64 {
    if (headers.getKnown(.@"content-length") == null) return null;
    var it = headers.values("content-length");
    var length: ?u64 = null;
    while (it.next()) |text| {
        const n = parseLength(text) orelse return error.InvalidContentLength;
        if (length) |was| if (was != n) return error.ConflictingContentLength;
        length = n;
    }
    return length orelse error.InvalidContentLength;
}

/// `1*DIGIT`, with no sign, no separator and no overflow.
pub fn parseLength(text: []const u8) ?u64 {
    if (text.len == 0) return null;
    var n: u64 = 0;
    for (text) |c| {
        if (c < '0' or c > '9') return null;
        n = std.math.mul(u64, n, 10) catch return null;
        n = std.math.add(u64, n, c - '0') catch return null;
    }
    return n;
}

/// Whether a message's connection may carry another exchange, as its
/// version and `Connection` say.
pub fn keepAlive(version: Version, headers: *const Headers) bool {
    return switch (version) {
        .http1_0 => headers.hasToken("connection", "keep-alive"),
        .http1_1 => !headers.hasToken("connection", "close"),
        .h2, .h3 => true,
    };
}

/// The chunked transfer coding, decoded from bytes as they come: framing
/// bytes are consumed here, and the data between them is handed to the
/// caller in place, never copied.
pub const ChunkedDecoder = struct {
    state: State = .size,
    lenience: Lenience = .response,
    /// Data bytes left in the current chunk, or the size being read.
    remaining: u64 = 0,
    /// Digits of the size read so far, or bytes of the current extension
    /// or trailer line.
    count: u32 = 0,
    /// Trailer bytes so far.
    trailer_len: u32 = 0,

    /// The longest chunk extension skipped, and the most trailer bytes.
    pub const max_extension = 4 << 10;
    pub const max_trailer = 64 << 10;

    /// The states `feed` stops at come last, so one compare per byte tells
    /// it to go on.
    const State = enum { size, size_space, extension, size_lf, data_cr, data_lf, trailer_line, end_lf, data, trailer_start, done };

    /// Why a chunked body is malformed.
    pub const Error = error{
        InvalidChunkSize,
        ChunkSizeOverflow,
        ChunkExtensionTooLong,
        /// A chunk's data not followed by its line end.
        InvalidChunkEnd,
        TrailerTooLarge,
        InvalidTrailer,
    };

    /// What `feed` found: `consumed` framing bytes, then, in a chunk,
    /// `data` bytes of it at `in[consumed..]`, which the caller passes on
    /// and reports with `take`.
    pub const Step = struct { consumed: usize, data: usize };

    /// Read framing bytes from `in` up to the next data, a line of the
    /// trailer section, or the end. Once `inTrailer` says so before a feed,
    /// every byte it consumes is the trailer's, its closing blank line
    /// included, for a caller that keeps trailers to gather.
    pub fn feed(d: *ChunkedDecoder, in: []const u8) Error!Step {
        var i: usize = 0;
        while (i < in.len) : (i += 1) {
            if (@backingInt(d.state) >= @backingInt(State.data)) switch (d.state) {
                .data => return .{ .consumed = i, .data = @min(d.remaining, in.len - i) },
                .done => break,
                // A line of the trailer section starts: stop before it, so
                // the caller gathers the section from the next feed on.
                .trailer_start => if (i != 0) return .{ .consumed = i, .data = 0 },
                else => unreachable, // unreachable: only the states past `data` get here
            };
            try d.byte(in[i]);
        }
        const data: usize = if (d.state == .data) @min(d.remaining, in.len - i) else 0;
        return .{ .consumed = i, .data = data };
    }

    /// The caller passed on `n` data bytes of the current chunk; none is
    /// always allowed.
    pub fn take(d: *ChunkedDecoder, n: usize) void {
        if (n == 0) return;
        std.debug.assert(d.state == .data);
        std.debug.assert(n <= d.remaining);
        d.remaining -= n;
        if (d.remaining == 0) d.state = .data_cr;
    }

    /// The bytes of the current chunk's data still to come, when the
    /// decoder is inside one; 0 while it reads framing.
    pub fn pending(d: *const ChunkedDecoder) u64 {
        return if (d.state == .data) d.remaining else 0;
    }

    /// Whether the last chunk and the trailer have been read.
    pub fn done(d: *const ChunkedDecoder) bool {
        return d.state == .done;
    }

    /// Whether the last chunk has been read and its trailer section, if
    /// any, is being read.
    pub fn inTrailer(d: *const ChunkedDecoder) bool {
        return switch (d.state) {
            .trailer_start, .trailer_line, .end_lf => true,
            else => false,
        };
    }

    fn byte(d: *ChunkedDecoder, c: u8) Error!void {
        switch (d.state) {
            .size => try d.sizeByte(c),
            .size_space => switch (c) {
                ' ', '\t' => {},
                ';' => d.enter(.extension),
                '\r' => d.state = .size_lf,
                '\n' => try d.lineFeedAfterSize(),
                else => return error.InvalidChunkSize,
            },
            .extension => switch (c) {
                '\r' => d.state = .size_lf,
                '\n' => try d.lineFeedAfterSize(),
                else => {
                    if ((c < 0x20 and c != '\t') or c == 0x7f) return error.InvalidChunkSize;
                    d.count += 1;
                    if (d.count > max_extension) return error.ChunkExtensionTooLong;
                },
            },
            .size_lf => if (c == '\n') d.sizeDone() else return error.InvalidChunkSize,
            .data => unreachable, // unreachable: `feed` returns before a data byte
            .data_cr => switch (c) {
                '\r' => d.state = .data_lf,
                '\n' => if (d.lenience == .response) d.nextChunk() else return error.InvalidChunkEnd,
                else => return error.InvalidChunkEnd,
            },
            .data_lf => if (c == '\n') d.nextChunk() else return error.InvalidChunkEnd,
            .trailer_start => switch (c) {
                '\r' => d.state = .end_lf,
                '\n' => if (d.lenience == .response) {
                    d.state = .done;
                } else return error.InvalidTrailer,
                else => {
                    d.state = .trailer_line;
                    try d.trailerByte(c);
                },
            },
            .trailer_line => {
                if (c == '\n') {
                    d.state = .trailer_start;
                } else try d.trailerByte(c);
            },
            .end_lf => if (c == '\n') {
                d.state = .done;
            } else return error.InvalidTrailer,
            .done => unreachable, // unreachable: `feed` stops at the end
        }
    }

    fn sizeByte(d: *ChunkedDecoder, c: u8) Error!void {
        const digit: ?u8 = switch (c) {
            '0'...'9' => c - '0',
            'a'...'f' => c - 'a' + 10,
            'A'...'F' => c - 'A' + 10,
            else => null,
        };
        if (digit) |v| {
            if (d.remaining >> 60 != 0) return error.ChunkSizeOverflow;
            d.remaining = d.remaining << 4 | v;
            d.count += 1;
            return;
        }
        if (d.count == 0) return error.InvalidChunkSize;
        switch (c) {
            ' ', '\t' => d.state = .size_space,
            ';' => d.enter(.extension),
            '\r' => d.state = .size_lf,
            '\n' => try d.lineFeedAfterSize(),
            else => return error.InvalidChunkSize,
        }
    }

    fn enter(d: *ChunkedDecoder, state: State) void {
        d.state = state;
        d.count = 0;
    }

    fn lineFeedAfterSize(d: *ChunkedDecoder) Error!void {
        if (d.lenience == .request) return error.InvalidChunkSize;
        d.sizeDone();
    }

    fn sizeDone(d: *ChunkedDecoder) void {
        d.count = 0;
        d.state = if (d.remaining == 0) .trailer_start else .data;
    }

    fn nextChunk(d: *ChunkedDecoder) void {
        d.state = .size;
        d.remaining = 0;
        d.count = 0;
    }

    fn trailerByte(d: *ChunkedDecoder, c: u8) Error!void {
        d.trailer_len += 1;
        if (d.trailer_len > max_trailer) return error.TrailerTooLarge;
        if (c == 0) return error.InvalidTrailer;
    }
};

/// What a request head writer is given.
pub const RequestHeadOut = struct {
    method: Method,
    /// Origin form (`/path?query`), absolute form for a proxy, or
    /// `host:port` for `CONNECT`, in pieces written one after another.
    target: []const []const u8,
    /// The `Host` field's value, written first.
    host: []const u8,
    /// Fields of the sender's own, written after `Host`.
    own: []const Header = &.{},
    /// The caller's fields, in their order and case.
    headers: []const Header = &.{},
    /// Written last: `Content-Length` or `Transfer-Encoding: chunked`.
    framing: Framing = .none,
};

/// Why a head was not written.
pub const WriteHeadError = error{
    /// The writer failed.
    WriteFailed,
    /// A method that is not a token, or a target with whitespace or a
    /// control character.
    InvalidRequestLine,
    /// A field name that is not a token, or a value with a control
    /// character or whitespace at its ends.
    InvalidHeader,
};

/// Write a request head, checking every name, value and the request line
/// before a byte is written, so nothing a caller passes can add a line.
pub fn writeRequestHead(w: *Io.Writer, head: RequestHeadOut) WriteHeadError!void {
    try checkRequestHead(head);
    try w.writeAll(head.method.name);
    try w.writeByte(' ');
    for (head.target) |piece| try w.writeAll(piece);
    try w.writeAll(" HTTP/1.1\r\nHost: ");
    try w.writeAll(head.host);
    try w.writeAll("\r\n");
    for (head.own) |h| try writeField(w, h);
    for (head.headers) |h| try writeField(w, h);
    switch (head.framing) {
        .none, .until_close => {},
        .length => |n| try w.print("Content-Length: {d}\r\n", .{n}),
        .chunked => try w.writeAll("Transfer-Encoding: chunked\r\n"),
    }
    try w.writeAll("\r\n");
}

/// Check everything `writeRequestHead` would write, writing nothing.
pub fn checkRequestHead(head: RequestHeadOut) error{ InvalidRequestLine, InvalidHeader }!void {
    if (!fields_mod.isToken(head.method.name)) return error.InvalidRequestLine;
    var target_len: usize = 0;
    for (head.target) |piece| {
        if (piece.len != 0 and !isTarget(piece)) return error.InvalidRequestLine;
        target_len += piece.len;
    }
    if (target_len == 0) return error.InvalidRequestLine;
    if (!fields_mod.isFieldValue(head.host)) return error.InvalidHeader;
    for (head.own) |h| try checkHeader(h);
    for (head.headers) |h| try checkHeader(h);
}

/// Check one field: a token name and a value with nothing that would end
/// its line.
pub fn checkHeader(h: Header) error{InvalidHeader}!void {
    if (!fields_mod.isToken(h.name) or !fields_mod.isFieldValue(h.value)) return error.InvalidHeader;
}

/// Write one checked field and its line end.
pub fn writeField(w: *Io.Writer, h: Header) Io.Writer.Error!void {
    try w.writeAll(h.name);
    try w.writeAll(": ");
    try w.writeAll(h.value);
    try w.writeAll("\r\n");
}

/// A body written in chunks onto `out`: each drain of the buffer is one
/// chunk, and `end` writes the last one.
pub const ChunkedWriter = struct {
    out: *Io.Writer,
    interface: Io.Writer,

    pub fn init(out: *Io.Writer, buffer: []u8) ChunkedWriter {
        return .{ .out = out, .interface = .{ .vtable = &.{ .drain = drain }, .buffer = buffer } };
    }

    /// Write what is buffered as a chunk, then the last chunk.
    pub fn end(cw: *ChunkedWriter) Io.Writer.Error!void {
        try cw.interface.flush();
        try cw.out.writeAll("0\r\n\r\n");
    }

    fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const cw: *ChunkedWriter = @alignCast(@fieldParentPtr("interface", w)); // safe: this vtable is installed only on a ChunkedWriter's interface
        const buffered = w.buffered();
        var total: usize = buffered.len;
        for (data[0 .. data.len - 1]) |d| total += d.len;
        total += data[data.len - 1].len * splat;
        if (total == 0) return 0;
        try cw.out.print("{x}\r\n", .{total});
        try cw.out.writeAll(buffered);
        for (data[0 .. data.len - 1]) |d| try cw.out.writeAll(d);
        try cw.out.splatBytesAll(data[data.len - 1], splat);
        try cw.out.writeAll("\r\n");
        return w.consume(total);
    }
};

/// A body of a declared length written onto `out`: writing past the length
/// fails, and `remaining` says what is still owed.
pub const LengthWriter = struct {
    out: *Io.Writer,
    remaining: u64,
    /// Set when a write would have gone past the declared length.
    overflowed: bool = false,
    interface: Io.Writer,

    pub fn init(out: *Io.Writer, length: u64, buffer: []u8) LengthWriter {
        return .{ .out = out, .remaining = length, .interface = .{ .vtable = &.{ .drain = drain }, .buffer = buffer } };
    }

    fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const lw: *LengthWriter = @alignCast(@fieldParentPtr("interface", w)); // safe: this vtable is installed only on a LengthWriter's interface
        const buffered = w.buffered();
        var total: u64 = buffered.len;
        for (data[0 .. data.len - 1]) |d| total += d.len;
        total += @as(u64, data[data.len - 1].len) * splat;
        if (total > lw.remaining) {
            lw.overflowed = true;
            return error.WriteFailed;
        }
        try lw.out.writeAll(buffered);
        for (data[0 .. data.len - 1]) |d| try lw.out.writeAll(d);
        try lw.out.splatBytesAll(data[data.len - 1], splat);
        lw.remaining -= total;
        return w.consume(@intCast(total));
    }
};

const testing = std.testing;

/// `text` `n` times over, at compile time.
fn repeat(comptime text: []const u8, comptime n: usize) *const [text.len * n]u8 {
    var out: [text.len * n]u8 = undefined;
    for (0..n) |i| @memcpy(out[i * text.len ..][0..text.len], text);
    const final = out;
    return &final;
}

test "a response head is parsed in place, its fields indexed and its framing decided" {
    var bytes = "HTTP/1.1 200 OK\r\nContent-Length: 12\r\nContent-Encoding: gzip\r\nLocation: /x\r\n\r\nbody".*;
    var fields: [8]Field = undefined;
    const parsed = (try parseResponse(&bytes, &fields, .{})).?;
    try testing.expectEqual(bytes.len - 4, parsed.len);
    const head = &parsed.head;
    try testing.expectEqual(Status.ok, head.status);
    try testing.expectEqual(Version.http1_1, head.version);
    try testing.expectEqualStrings("OK", head.reason);
    try testing.expectEqualStrings("/x", head.headers.get("location").?);
    const f = try responseFraming(.GET, head);
    try testing.expectEqual(@as(u64, 12), f.framing.length);
    try testing.expect(f.keep_alive);
    try testing.expectEqual(Framing.none, (try responseFraming(.HEAD, head)).framing);
}

test "a head not yet whole is asked for more, and one past the limit is refused" {
    var fields: [8]Field = undefined;
    var partial = "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n".*;
    try testing.expectEqual(null, try parseResponse(&partial, &fields, .{}));
    var long = ("HTTP/1.1 200 OK\r\nX: " ++ comptime repeat("a", 100)).*;
    try testing.expectError(error.HeadTooLarge, parseResponse(&long, &fields, .{ .max_head = 64 }));
    var many = ("HTTP/1.1 200 OK\r\n" ++ comptime repeat("A: b\r\n", 9) ++ "\r\n").*;
    try testing.expectError(error.TooManyFields, parseResponse(&many, &fields, .{}));
    try testing.expectError(error.TooManyFields, parseResponse(&many, &fields, .{ .max_fields = 3 }));
}

test "a response is read leniently: bare LF, a folded value, a missing reason" {
    var bytes = "HTTP/1.1 200\nX-Fold: first\r\n  second\n\tthird\nB : spaced\n\n".*;
    var fields: [8]Field = undefined;
    const parsed = (try parseResponse(&bytes, &fields, .{})).?;
    try testing.expectEqual(bytes.len, parsed.len);
    try testing.expectEqualStrings("", parsed.head.reason);
    const folded = parsed.head.headers.get("x-fold").?;
    try testing.expect(std.mem.startsWith(u8, folded, "first"));
    try testing.expect(std.mem.endsWith(u8, folded, "third"));
    try testing.expect(!fields_mod.hasControl(folded));
    try testing.expectEqualStrings("spaced", parsed.head.headers.get("B").?);
}

test "a request is read strictly: bare LF, folding and spaced names are refused" {
    var fields: [8]Field = undefined;
    var ok = "\r\nGET /a?b HTTP/1.1\r\nHost: x\r\n\r\n".*;
    const parsed = (try parseRequest(&ok, &fields, .{})).?;
    try testing.expectEqual(ok.len, parsed.len);
    try testing.expect(parsed.head.method.eql(.GET));
    try testing.expectEqualStrings("/a?b", parsed.head.target);
    var bare = "GET / HTTP/1.1\nHost: x\r\n\r\n".*;
    try testing.expectError(error.BareLineFeed, parseRequest(&bare, &fields, .{}));
    var fold = "GET / HTTP/1.1\r\nA: b\r\n c\r\n\r\n".*;
    try testing.expectError(error.ObsoleteLineFolding, parseRequest(&fold, &fields, .{}));
    var spaced = "GET / HTTP/1.1\r\nA : b\r\n\r\n".*;
    try testing.expectError(error.InvalidFieldName, parseRequest(&spaced, &fields, .{}));
    var double = "GET  / HTTP/1.1\r\n\r\n".*;
    try testing.expectError(error.InvalidStartLine, parseRequest(&double, &fields, .{}));
}

test "status lines are three digits and a space, versions HTTP/1.x only" {
    var fields: [4]Field = undefined;
    inline for (.{
        "HTTP/1.1 2000 OK\r\n\r\n",
        "HTTP/1.1 20 OK\r\n\r\n",
        "HTTP/1.1 099 OK\r\n\r\n",
        "HTTP/1.1 2x0 OK\r\n\r\n",
        "HTTP/1.1  200 OK\r\n\r\n",
        "HTTP/1.1 200OK\r\n\r\n",
        "HTTP/11 200 OK\r\n\r\n",
        "HTTX/1.1 200 OK\r\n\r\n",
        "HTTP/1.1 200 O\x00K\r\n\r\n",
    }) |text| {
        var bytes = text.*;
        try testing.expectError(error.InvalidStartLine, parseResponse(&bytes, &fields, .{}));
    }
    var two = "HTTP/2.0 200 OK\r\n\r\n".*;
    try testing.expectError(error.UnsupportedVersion, parseResponse(&two, &fields, .{}));
    var later = "HTTP/1.7 599 Odd\r\n\r\n".*;
    const parsed = (try parseResponse(&later, &fields, .{})).?;
    try testing.expectEqual(Version.http1_1, parsed.head.version);
    try testing.expectEqual(@as(u10, 599), @backingInt(parsed.head.status));
}

test "fields with no colon, a bad name or a control character are refused" {
    var fields: [4]Field = undefined;
    inline for (.{
        .{ "HTTP/1.1 200 OK\r\nNo-Colon\r\n\r\n", error.InvalidFieldName },
        .{ "HTTP/1.1 200 OK\r\n: empty\r\n\r\n", error.InvalidFieldName },
        .{ "HTTP/1.1 200 OK\r\nBad Name: v\r\n\r\n", error.InvalidFieldName },
        .{ "HTTP/1.1 200 OK\r\n folded-first: v\r\n\r\n", error.InvalidFieldName },
        .{ "HTTP/1.1 200 OK\r\nA: v\x00w\r\n\r\n", error.InvalidFieldValue },
        .{ "HTTP/1.1 200 OK\r\nA: v\rw\r\n\r\n", error.InvalidFieldValue },
        .{ "HTTP/1.1 200 OK\r\nA: v\r\r\n\r\n", error.InvalidFieldValue },
    }) |case| {
        var bytes = case[0].*;
        try testing.expectError(case[1], parseResponse(&bytes, &fields, .{}));
    }
}

test "framing follows RFC 9112 §6.3 in its order" {
    var fields: [8]Field = undefined;
    const Case = struct { []const u8, Method, Framing, bool };
    const cases = [_]Case{
        .{ "HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n", .GET, .none, true },
        .{ "HTTP/1.1 304 Not Modified\r\n\r\n", .GET, .none, true },
        .{ "HTTP/1.1 101 Switching\r\n\r\n", .GET, .none, true },
        .{ "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\nContent-Length: 5\r\n\r\n", .GET, .chunked, false },
        .{ "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n", .GET, .until_close, false },
        .{ "HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n", .GET, .chunked, false },
        .{ "HTTP/1.1 200 OK\r\nContent-Length: 5, 5\r\nContent-Length: 5\r\n\r\n", .GET, .{ .length = 5 }, true },
        .{ "HTTP/1.1 200 OK\r\n\r\n", .GET, .until_close, false },
        .{ "HTTP/1.0 200 OK\r\nContent-Length: 1\r\n\r\n", .GET, .{ .length = 1 }, false },
        .{ "HTTP/1.0 200 OK\r\nContent-Length: 1\r\nConnection: Keep-Alive\r\n\r\n", .GET, .{ .length = 1 }, true },
        .{ "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nConnection: Upgrade, Close\r\n\r\n", .GET, .{ .length = 1 }, false },
        .{ "HTTP/1.1 200 Connection established\r\n\r\n", .CONNECT, .none, false },
    };
    for (cases) |case| {
        const copy = try testing.allocator.dupe(u8, case[0]);
        defer testing.allocator.free(copy);
        const parsed = (try parseResponse(copy, &fields, .{})).?;
        const f = try responseFraming(case[1], &parsed.head);
        testing.expectEqual(case[2], f.framing) catch |err| {
            std.debug.print("{s}\n", .{case[0]});
            return err;
        };
        try testing.expectEqual(case[3], f.keep_alive);
    }
    inline for (.{
        .{ "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n", error.ConflictingContentLength },
        .{ "HTTP/1.1 200 OK\r\nContent-Length: 1_0\r\n\r\n", error.InvalidContentLength },
        .{ "HTTP/1.1 200 OK\r\nContent-Length: +1\r\n\r\n", error.InvalidContentLength },
        .{ "HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999\r\n\r\n", error.InvalidContentLength },
        .{ "HTTP/1.1 200 OK\r\nContent-Length: \r\n\r\n", error.InvalidContentLength },
        .{ "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, chunked\r\n\r\n", error.InvalidTransferEncoding },
    }) |case| {
        var bytes = case[0].*;
        const parsed = (try parseResponse(&bytes, &fields, .{})).?;
        try testing.expectError(case[1], responseFraming(.GET, &parsed.head));
    }
}

test "request framing refuses the smuggling patterns" {
    var fields: [8]Field = undefined;
    inline for (.{
        .{ "POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n", error.InvalidTransferEncoding },
        .{ "POST / HTTP/1.1\r\nTransfer-Encoding: chunked, gzip\r\n\r\n", error.InvalidTransferEncoding },
        .{ "POST / HTTP/1.0\r\nTransfer-Encoding: chunked\r\n\r\n", error.InvalidTransferEncoding },
        .{ "POST / HTTP/1.1\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\n", error.ConflictingContentLength },
    }) |case| {
        var bytes = case[0].*;
        const parsed = (try parseRequest(&bytes, &fields, .{})).?;
        try testing.expectError(case[1], requestFraming(&parsed.head));
    }
    var chunked = "POST / HTTP/1.1\r\nTransfer-Encoding: gzip, Chunked\r\n\r\n".*;
    try testing.expectEqual(Framing.chunked, try requestFraming(&(try parseRequest(&chunked, &fields, .{})).?.head));
}

/// Decode `in` whole through `d`, one byte or all at once.
fn decodeAll(d: *ChunkedDecoder, in: []const u8, out: *std.ArrayList(u8), piece: usize) !usize {
    var at: usize = 0;
    while (at < in.len and !d.done()) {
        const window = in[at..@min(in.len, at + piece)];
        const step = try d.feed(window);
        try out.appendSlice(testing.allocator, window[step.consumed..][0..step.data]);
        d.take(step.data);
        at += step.consumed + step.data;
    }
    return at;
}

test "a chunked body decodes the same whether it comes whole or a byte at a time" {
    const body = "4\r\nWiki\r\n5;ext=\"v\"\r\npedia\r\nE \t; a\r\n in\r\n\r\nchunks.\r\n0\r\nTrailer: x\r\n\r\nNEXT";
    for ([_]usize{ 1, 2, 3, 7, body.len }) |piece| {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(testing.allocator);
        var d: ChunkedDecoder = .{};
        const used = try decodeAll(&d, body, &out, piece);
        try testing.expect(d.done());
        try testing.expectEqualStrings("Wikipedia in\r\n\r\nchunks.", out.items);
        try testing.expectEqualStrings("NEXT", body[used..]);
    }
}

test "the trailer section is handed over apart from the framing, and its fields read" {
    const body = "3\r\nabc\r\n0\r\nChecksum: 1\r\nX-Fold: a\r\n b\r\n\r\nNEXT";
    for ([_]usize{ 1, 4, body.len }) |piece| {
        var d: ChunkedDecoder = .{};
        var trailer: std.ArrayList(u8) = .empty;
        defer trailer.deinit(testing.allocator);
        var at: usize = 0;
        while (!d.done()) {
            const window = body[at..@min(body.len, at + piece)];
            const was_trailer = d.inTrailer();
            const step = try d.feed(window);
            if (was_trailer) try trailer.appendSlice(testing.allocator, window[0..step.consumed]);
            d.take(step.data);
            at += step.consumed + step.data;
        }
        try testing.expectEqualStrings("NEXT", body[at..]);
        var fields: [4]Field = undefined;
        const t = try parseTrailer(trailer.items, &fields);
        try testing.expectEqualStrings("1", t.get("checksum").?);
        try testing.expectEqualStrings("a   b", t.get("x-fold").?);
    }
    var none = "\r\n".*;
    var fields: [1]Field = undefined;
    try testing.expectEqual(@as(usize, 0), (try parseTrailer(&none, &fields)).count());
}

test "chunk sizes are hex only and overflow is refused; data must end its line" {
    inline for (.{
        .{ "x\r\n", error.InvalidChunkSize },
        .{ ";\r\n", error.InvalidChunkSize },
        .{ "-1\r\n", error.InvalidChunkSize },
        .{ "0x5\r\n", error.InvalidChunkSize },
        .{ "1_0\r\n", error.InvalidChunkSize },
        .{ "10000000000000000\r\n", error.ChunkSizeOverflow },
        .{ "1\r\nab", error.InvalidChunkEnd },
        .{ "1\r\na\rb", error.InvalidChunkEnd },
        .{ "1\r\na\r\n0\r\n\rX", error.InvalidTrailer },
    }) |case| {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(testing.allocator);
        var d: ChunkedDecoder = .{};
        try testing.expectError(case[1], decodeAll(&d, case[0], &out, 1));
    }
    var long_ext: [ChunkedDecoder.max_extension + 8]u8 = @splat('a');
    long_ext[0] = '1';
    long_ext[1] = ';';
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    var d: ChunkedDecoder = .{};
    try testing.expectError(error.ChunkExtensionTooLong, decodeAll(&d, &long_ext, &out, 64));
    // Strict decoding, as a request's body is decoded, wants CRLF.
    var strict: ChunkedDecoder = .{ .lenience = .request };
    try testing.expectError(error.InvalidChunkSize, decodeAll(&strict, "1\na\r\n", &out, 4));
}

test "a request head is written with its framing, and nothing unchecked reaches the wire" {
    var buffer: [512]u8 = undefined;
    var w: Io.Writer = .fixed(&buffer);
    try writeRequestHead(&w, .{
        .method = .POST,
        .target = &.{"/upload?x=1"},
        .host = "example.com:8080",
        .own = &.{.{ .name = "User-Agent", .value = "uplink" }},
        .headers = &.{.{ .name = "X-Case", .value = "Kept As Is" }},
        .framing = .{ .length = 3 },
    });
    try testing.expectEqualStrings(
        "POST /upload?x=1 HTTP/1.1\r\nHost: example.com:8080\r\nUser-Agent: uplink\r\nX-Case: Kept As Is\r\nContent-Length: 3\r\n\r\n",
        w.buffered(),
    );
    const bad = [_]struct { RequestHeadOut, WriteHeadError }{
        .{ .{ .method = .GET, .target = &.{"/a b"}, .host = "h" }, error.InvalidRequestLine },
        .{ .{ .method = .GET, .target = &.{"/a\r\nX: y"}, .host = "h" }, error.InvalidRequestLine },
        .{ .{ .method = .GET, .target = &.{""}, .host = "h" }, error.InvalidRequestLine },
        .{ .{ .method = .{ .name = "G T" }, .target = &.{"/"}, .host = "h" }, error.InvalidRequestLine },
        .{ .{ .method = .GET, .target = &.{"/"}, .host = "h\r\nX: y" }, error.InvalidHeader },
        .{ .{ .method = .GET, .target = &.{"/"}, .host = "h", .headers = &.{.{ .name = "X", .value = "a\r\nInjected: 1" }} }, error.InvalidHeader },
        .{ .{ .method = .GET, .target = &.{"/"}, .host = "h", .headers = &.{.{ .name = "X:Y", .value = "a" }} }, error.InvalidHeader },
        .{ .{ .method = .GET, .target = &.{"/"}, .host = "h", .headers = &.{.{ .name = "X", .value = "a\x00" }} }, error.InvalidHeader },
    };
    for (bad) |case| {
        w = .fixed(&buffer);
        try testing.expectError(case[1], writeRequestHead(&w, case[0]));
        try testing.expectEqual(@as(usize, 0), w.end);
    }
}

test "a written request head parses back to what was written" {
    var buffer: [1024]u8 = undefined;
    var w: Io.Writer = .fixed(&buffer);
    const headers = [_]Header{
        .{ .name = "Accept", .value = "*/*" },
        .{ .name = "X-Empty", .value = "" },
        .{ .name = "X-Inner", .value = "a \t b" },
    };
    try writeRequestHead(&w, .{ .method = .PUT, .target = &.{ "/", "p" }, .host = "h", .headers = &headers, .framing = .chunked });
    var fields: [8]Field = undefined;
    const parsed = (try parseRequest(w.buffered(), &fields, .{})).?;
    try testing.expect(parsed.head.method.eql(.PUT));
    try testing.expectEqualStrings("h", parsed.head.headers.get("host").?);
    for (headers, 1..) |h, i| {
        try testing.expectEqualStrings(h.name, parsed.head.headers.fields[i].name);
        try testing.expectEqualStrings(h.value, parsed.head.headers.fields[i].value);
    }
    try testing.expectEqual(Framing.chunked, try requestFraming(&parsed.head));
}

test "chunked and length writers frame what passes through them" {
    var buffer: [256]u8 = undefined;
    var out: Io.Writer = .fixed(&buffer);
    var small: [4]u8 = undefined;
    var cw: ChunkedWriter = .init(&out, &small);
    try cw.interface.writeAll("hello, world");
    try cw.interface.splatBytesAll("ab", 3);
    try cw.end();
    var d: ChunkedDecoder = .{ .lenience = .request };
    var decoded: std.ArrayList(u8) = .empty;
    defer decoded.deinit(testing.allocator);
    _ = try decodeAll(&d, out.buffered(), &decoded, 5);
    try testing.expect(d.done());
    try testing.expectEqualStrings("hello, worldababab", decoded.items);

    out = .fixed(&buffer);
    var lw: LengthWriter = .init(&out, 5, &small);
    try lw.interface.writeAll("abc");
    try lw.interface.flush();
    try testing.expectEqual(@as(u64, 2), lw.remaining);
    try testing.expectError(error.WriteFailed, lw.interface.writeAll("defgh"));
    try testing.expect(lw.overflowed);
}

test "fuzz: any response head is parsed or refused by name, and a parsed one holds no control character" {
    try testing.fuzz({}, struct {
        fn one(_: void, smith: *testing.Smith) anyerror!void {
            var buf: [512]u8 = undefined;
            const bytes = buf[0..smith.slice(&buf)];
            var fields: [16]Field = undefined;
            const parsed = (parseResponse(bytes, &fields, .{ .max_head = 400, .max_fields = 16 }) catch return) orelse return;
            try testing.expect(parsed.len <= bytes.len);
            var it = parsed.head.headers.iterator();
            while (it.next()) |f| {
                try testing.expect(fields_mod.isToken(f.name));
                try testing.expect(!fields_mod.hasControl(f.value));
            }
            _ = responseFraming(.GET, &parsed.head) catch return;
        }
    }.one, .{ .corpus = &.{
        "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n",
        "HTTP/1.1 200 OK\nA: b\n c\n\n",
        "HTTP/1.0 404 Nope\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
    } });
}

test "fuzz: a chunked body fed in any pieces decodes as it does whole" {
    try testing.fuzz({}, struct {
        fn one(_: void, smith: *testing.Smith) anyerror!void {
            var buf: [256]u8 = undefined;
            const in = buf[0..smith.slice(&buf)];
            var whole: std.ArrayList(u8) = .empty;
            defer whole.deinit(testing.allocator);
            var a: ChunkedDecoder = .{};
            const whole_result = decodeAll(&a, in, &whole, in.len + 1);
            var pieces: std.ArrayList(u8) = .empty;
            defer pieces.deinit(testing.allocator);
            var b: ChunkedDecoder = .{};
            const piece_result = decodeAll(&b, in, &pieces, 3);
            if (whole_result) |n| {
                try testing.expectEqual(n, try piece_result);
                try testing.expectEqualStrings(whole.items, pieces.items);
                try testing.expectEqual(a.done(), b.done());
            } else |err| try testing.expectError(err, piece_result);
        }
    }.one, .{ .corpus = &.{ "3\r\nabc\r\n0\r\n\r\n", "1;x=y\r\na\r\n0\r\nT: v\r\n\r\n" } });
}
