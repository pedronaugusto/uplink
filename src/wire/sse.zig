//! Server-Sent Events (the `text/event-stream` format of the WHATWG HTML
//! standard, §9.2): events read from a stream as it arrives, and written.
//!
//! `Parser` takes bytes as they come and hands back each event when its
//! blank line arrives, a line split across reads or a value longer than any
//! read included: a value is copied straight into the buffer it belongs to,
//! never gathered into a line first. `Reader` runs one over an `Io.Reader`.
//! Lines end in CRLF, LF or CR; a leading byte-order mark is skipped; a
//! comment line (`:` first) is skipped; an event cut off by the stream's end
//! is dropped, as the standard says.

const std = @import("std");
const Io = std.Io;

/// One event. `data` and `type` point into the parser's buffers and are
/// valid until it is fed again; `id` is the last event ID, which carries
/// over to later events.
pub const Event = struct {
    /// `event`, or `message` when none was given.
    type: []const u8,
    /// Every `data` line, joined by LF.
    data: []const u8,
    /// The last event ID the stream set, empty when none.
    id: []const u8,
    /// The reconnection time the stream last set with `retry`, in
    /// milliseconds: how long a client waits before reconnecting. It
    /// carries over to later events, as `id` does.
    retry: ?u64 = null,
};

/// Why a stream cannot be read.
pub const Error = error{
    /// An event's data is longer than the parser's buffer.
    DataTooLong,
    /// An `event` or `id` value longer than the parser keeps.
    FieldTooLong,
};

/// The longest `event` and `id` values kept.
pub const max_type = 256;
pub const max_id = 1024;

/// Events from bytes, sans I/O.
pub const Parser = struct {
    /// Private: where `data` lines gather.
    data: []u8,
    data_len: usize = 0,
    /// Private: the event type, and the id being read, and the last id.
    type_buf: [max_type]u8 = undefined,
    type_len: u16 = 0,
    pending_id: [max_id]u8 = undefined,
    pending_id_len: u16 = 0,
    id_buf: [max_id]u8 = undefined,
    id_len: u16 = 0,
    /// Private: the line state.
    state: State = .bom,
    bom_seen: u2 = 0,
    after_cr: bool = false,
    name_buf: [8]u8 = undefined,
    name_len: u8 = 0,
    field: Field = .ignored,
    /// Private: a `retry` value being read, and whether it is all digits.
    retry_value: u64 = 0,
    retry_ok: bool = false,
    retry: ?u64 = null,
    /// Private: whether a `data` field was seen since the last dispatch.
    has_data: bool = false,

    const State = enum { bom, line_start, name, value_start, value, comment };
    const Field = enum { data, event, id, retry, ignored };

    /// A parser gathering data in `data_buffer`, which bounds an event.
    pub fn init(data_buffer: []u8) Parser {
        return .{ .data = data_buffer };
    }

    /// What `feed` found: how many bytes it took, and the event they
    /// completed, if one.
    pub const Step = struct { consumed: usize, event: ?Event = null };

    /// Take bytes up to the end of `in` or of the next event.
    pub fn feed(p: *Parser, in: []const u8) Error!Step {
        var i: usize = 0;
        while (i < in.len) : (i += 1) {
            const c = in[i];
            if (p.after_cr) {
                p.after_cr = false;
                if (c == '\n') continue;
            }
            if (p.state == .bom) {
                const bom = "\xEF\xBB\xBF";
                if (c == bom[p.bom_seen]) {
                    p.bom_seen += 1;
                    if (p.bom_seen == 3) p.state = .line_start;
                    continue;
                }
                // Not a mark after all: what was taken of it was text, which
                // a stream never starts with in practice; begin the line.
                p.state = .line_start;
            }
            if (c == '\r' or c == '\n') {
                p.after_cr = c == '\r';
                if (try p.endLine()) |event| return .{ .consumed = i + 1, .event = event };
                continue;
            }
            try p.byte(c);
        }
        return .{ .consumed = i };
    }

    fn byte(p: *Parser, c: u8) Error!void {
        switch (p.state) {
            .bom => unreachable, // unreachable: `feed` leaves the mark state before a byte reaches here
            .line_start => {
                if (c == ':') {
                    p.state = .comment;
                    return;
                }
                p.state = .name;
                p.name_len = 0;
                p.nameByte(c);
            },
            .name => if (c == ':') {
                p.startValue();
                p.state = .value_start;
            } else p.nameByte(c),
            .value_start => {
                p.state = .value;
                if (c != ' ') try p.valueByte(c);
            },
            .value => try p.valueByte(c),
            .comment => {},
        }
    }

    fn nameByte(p: *Parser, c: u8) void {
        if (p.name_len < p.name_buf.len) p.name_buf[p.name_len] = c;
        p.name_len +|= 1;
    }

    fn startValue(p: *Parser) void {
        const name = p.name_buf[0..@min(p.name_len, p.name_buf.len)];
        p.field = if (p.name_len > p.name_buf.len)
            .ignored
        else if (std.mem.eql(u8, name, "data"))
            .data
        else if (std.mem.eql(u8, name, "event"))
            .event
        else if (std.mem.eql(u8, name, "id"))
            .id
        else if (std.mem.eql(u8, name, "retry"))
            .retry
        else
            .ignored;
        switch (p.field) {
            .event => p.type_len = 0,
            .id => p.pending_id_len = 0,
            .retry => {
                p.retry_value = 0;
                p.retry_ok = false;
            },
            .data => p.has_data = true,
            .ignored => {},
        }
    }

    fn valueByte(p: *Parser, c: u8) Error!void {
        switch (p.field) {
            .data => {
                if (p.data_len == p.data.len) return error.DataTooLong;
                p.data[p.data_len] = c;
                p.data_len += 1;
            },
            .event => {
                if (p.type_len == max_type) return error.FieldTooLong;
                p.type_buf[p.type_len] = c;
                p.type_len += 1;
            },
            .id => {
                if (p.pending_id_len == max_id) return error.FieldTooLong;
                p.pending_id[p.pending_id_len] = c;
                p.pending_id_len += 1;
            },
            .retry => {
                if (c >= '0' and c <= '9') {
                    p.retry_value = p.retry_value *| 10 +| (c - '0');
                    p.retry_ok = true;
                } else {
                    p.field = .ignored;
                    p.retry_ok = false;
                }
            },
            .ignored => {},
        }
    }

    /// A line ended: finish its field, or, for an empty line, the event.
    fn endLine(p: *Parser) Error!?Event {
        switch (p.state) {
            .bom => unreachable, // unreachable: a line end leaves the mark state first
            .line_start => return p.dispatch(),
            .comment => {},
            .name => {
                // A field with no colon: the whole line is its name.
                p.startValue();
                try p.finishField();
            },
            .value_start, .value => try p.finishField(),
        }
        p.state = .line_start;
        return null;
    }

    fn finishField(p: *Parser) Error!void {
        switch (p.field) {
            .data => {
                if (p.data_len == p.data.len) return error.DataTooLong;
                p.data[p.data_len] = '\n';
                p.data_len += 1;
            },
            .id => if (std.mem.findScalar(u8, p.pending_id[0..p.pending_id_len], 0) == null) {
                @memcpy(p.id_buf[0..p.pending_id_len], p.pending_id[0..p.pending_id_len]);
                p.id_len = p.pending_id_len;
            },
            .retry => if (p.retry_ok) {
                p.retry = p.retry_value;
            },
            .event, .ignored => {},
        }
        p.field = .ignored;
    }

    fn dispatch(p: *Parser) ?Event {
        defer {
            p.data_len = 0;
            p.type_len = 0;
            p.has_data = false;
        }
        if (!p.has_data) return null;
        const data = p.data[0 .. p.data_len - @intFromBool(p.data_len != 0)];
        return .{
            .type = if (p.type_len == 0) "message" else p.type_buf[0..p.type_len],
            .data = data,
            .id = p.id_buf[0..p.id_len],
            .retry = p.retry,
        };
    }

    /// The last event ID the stream set: what a client sends as
    /// `Last-Event-ID` when it reconnects.
    pub fn lastId(p: *const Parser) []const u8 {
        return p.id_buf[0..p.id_len];
    }
};

/// Events read from a stream, such as a response body.
pub const Reader = struct {
    in: *Io.Reader,
    parser: Parser,

    /// Events from `in`, each at most `data_buffer.len` bytes of data.
    pub fn init(in: *Io.Reader, data_buffer: []u8) Reader {
        return .{ .in = in, .parser = .init(data_buffer) };
    }

    /// Errors from `next`.
    pub const NextError = Error || error{ReadFailed};

    /// The next event, or null at the stream's end.
    pub fn next(r: *Reader) NextError!?Event {
        while (true) {
            if (r.in.bufferedLen() == 0) r.in.fillMore() catch |err| switch (err) {
                error.EndOfStream => return null,
                error.ReadFailed => return error.ReadFailed,
            };
            const step = try r.parser.feed(r.in.buffered());
            r.in.toss(step.consumed);
            if (step.event) |e| return e;
        }
    }
};

/// What `writeEvent` writes; each field left null is left out.
pub const Outgoing = struct {
    type: ?[]const u8 = null,
    /// Split into one `data` line per line it holds.
    data: []const u8,
    id: ?[]const u8 = null,
    retry: ?u64 = null,
};

/// Errors from `writeEvent`.
pub const WriteError = error{
    WriteFailed,
    /// A type or id holding a line break, or an id holding NUL.
    InvalidField,
};

/// Write one event and the blank line that ends it.
pub fn writeEvent(w: *Io.Writer, event: Outgoing) WriteError!void {
    if (event.type) |t| if (std.mem.findAny(u8, t, "\r\n") != null) return error.InvalidField;
    if (event.id) |id| if (std.mem.findAny(u8, id, "\r\n\x00") != null) return error.InvalidField;
    if (event.type) |t| try w.print("event: {s}\n", .{t});
    if (event.id) |id| try w.print("id: {s}\n", .{id});
    if (event.retry) |ms| try w.print("retry: {d}\n", .{ms});
    var rest = event.data;
    while (true) {
        const end = std.mem.findAny(u8, rest, "\r\n") orelse rest.len;
        try w.print("data: {s}\n", .{rest[0..end]});
        if (end == rest.len) break;
        const skip: usize = if (rest[end] == '\r' and end + 1 < rest.len and rest[end + 1] == '\n') 2 else 1;
        rest = rest[end + skip ..];
    }
    try w.writeAll("\n");
}

const testing = std.testing;

fn collect(stream: []const u8, piece: usize, out: *std.ArrayList(u8)) !void {
    var buf: [256]u8 = undefined;
    var p: Parser = .init(&buf);
    var at: usize = 0;
    while (at < stream.len) {
        const window = stream[at..@min(stream.len, at + piece)];
        const step = try p.feed(window);
        at += step.consumed;
        if (step.event) |e| {
            try out.print(testing.allocator, "[{s}|{s}|{s}|{?d}]", .{ e.type, e.data, e.id, e.retry });
        }
    }
}

test "events are read as the standard's examples read, in any pieces" {
    const stream = "\xEF\xBB\xBF: comment\r\ndata: first\r\ndata:second\n\nevent: add\rid: 7\rdata\r\rid\nretry: 2500\ndata:  two spaces\n\ndata: cut off";
    var whole: std.ArrayList(u8) = .empty;
    defer whole.deinit(testing.allocator);
    try collect(stream, stream.len, &whole);
    try testing.expectEqualStrings("[message|first\nsecond||null][add||7|null][message| two spaces||2500]", whole.items);
    for ([_]usize{ 1, 2, 3, 5 }) |piece| {
        var pieces: std.ArrayList(u8) = .empty;
        defer pieces.deinit(testing.allocator);
        try collect(stream, piece, &pieces);
        try testing.expectEqualStrings(whole.items, pieces.items);
    }
}

test "an event with no data is not dispatched, and an id with NUL is ignored" {
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(testing.allocator);
    try collect("event: lonely\n\nid: a\x00b\ndata: x\n\nretry: 1x\ndata\n\n", 64, &out);
    try testing.expectEqualStrings("[message|x||null][message|||null]", out.items);
}

test "data past the buffer is refused by name, and the reader stops at the end" {
    var small: [4]u8 = undefined;
    var p: Parser = .init(&small);
    try testing.expectError(error.DataTooLong, p.feed("data: too long\n\n"));
    var in: Io.Reader = .fixed("id: 9\ndata: a\n\ndata: b\n\n");
    var buf: [32]u8 = undefined;
    var r: Reader = .init(&in, &buf);
    try testing.expectEqualStrings("a", (try r.next()).?.data);
    const second = (try r.next()).?;
    try testing.expectEqualStrings("b", second.data);
    try testing.expectEqualStrings("9", second.id);
    try testing.expectEqual(null, try r.next());
}

test "a written event reads back as itself" {
    var buf: [256]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try writeEvent(&w, .{ .type = "update", .id = "42", .retry = 100, .data = "line one\r\nline two\nline three" });
    try writeEvent(&w, .{ .data = "" });
    var in: Io.Reader = .fixed(w.buffered());
    var data: [64]u8 = undefined;
    var r: Reader = .init(&in, &data);
    const e = (try r.next()).?;
    try testing.expectEqualStrings("update", e.type);
    try testing.expectEqualStrings("line one\nline two\nline three", e.data);
    try testing.expectEqualStrings("42", e.id);
    try testing.expectEqual(@as(?u64, 100), e.retry);
    const empty = (try r.next()).?;
    try testing.expectEqualStrings("", empty.data);
    try testing.expectError(error.InvalidField, writeEvent(&w, .{ .type = "a\nb", .data = "" }));
}

test "fuzz: any stream is read in pieces as it is read whole" {
    try testing.fuzz({}, struct {
        fn one(_: void, smith: *testing.Smith) anyerror!void {
            var buf: [256]u8 = undefined;
            const stream = buf[0..smith.slice(&buf)];
            var whole: std.ArrayList(u8) = .empty;
            defer whole.deinit(testing.allocator);
            const a = collect(stream, stream.len + 1, &whole);
            var pieces: std.ArrayList(u8) = .empty;
            defer pieces.deinit(testing.allocator);
            const b = collect(stream, 3, &pieces);
            if (a) |_| {
                try b;
                try testing.expectEqualStrings(whole.items, pieces.items);
            } else |err| try testing.expectError(err, b);
        }
    }.one, .{ .corpus = &.{ "data: a\n\n", "event: x\rdata\r\n\r\n" } });
}
