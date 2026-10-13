//! The answer to one request: a status, fields, and a body written through
//! `writer` or given whole to `send`.
//!
//! Nothing goes out until the head must: the first time the body's buffer
//! fills, or at `end`. So a handler sets the status and fields in any
//! order before writing, and a body that fits the buffer goes out with its
//! `Content-Length`, counted for it; a longer one is chunked, or, to an
//! HTTP/1.0 client, ends with the connection. A length declared with
//! `setLength` is held to: a body that passes it fails, and one that falls
//! short closes the connection. A `HEAD` is answered with the head a `GET`
//! would have, its body not sent.
//!
//! A response must not move once `writer` has been called.

const std = @import("std");
const Io = std.Io;
const Status = std.http.Status;
const wire = @import("uplink.wire");
const h1 = wire.h1;
const fields = wire.fields;
const Header = std.http.Header;
const BufferPool = @import("../transport/BufferPool.zig");
const Connection = @import("Connection.zig");

const Response = @This();

/// The status the head will carry; 200 unless set before the head goes.
status: Status = .ok,

/// Private: the connection the response goes out on.
conn: *Connection,
/// Private: the request is a `HEAD`: the body is counted, not sent.
head_only: bool,
/// Private: the client speaks HTTP/1.0, which knows no chunks.
http1_0: bool,
/// Private: the fields as they will be written, each line whole.
fields_buffer: []u8 = &.{},
fields_len: usize = 0,
/// Private: the body's buffer, from the pool once `writer` is asked for.
body_buffer: []u8 = &.{},
/// Private: where the response stands.
state: State = .open,
/// Private: the length the handler declared.
declared: ?u64 = null,
/// Private: the framing the head chose.
framing: Framing = .none,
/// Private: body bytes still owed under a declared length.
remaining: u64 = 0,
/// Private: the connection closes after this response.
closing: bool = false,
/// Private: the handler named a `Date` field of its own.
has_date: bool = false,
/// Private: a write failed; the connection is closed after.
broken: bool = false,
/// Private: the trailer's fields, for a chunked body.
trailer_buffer: []u8 = &.{},
trailer_len: usize = 0,
/// Private: the body writer.
interface: Io.Writer,

const State = enum {
    /// Nothing sent: the status and fields may change.
    open,
    /// The head went out; the body is being written.
    streaming,
    /// Done.
    ended,
    /// The connection was handed to the handler.
    hijacked,
};

const Framing = enum { none, length, chunked, close };

/// Why a field or a write was refused.
pub const Error = error{
    /// A field name that is not a token, or a value that would end its
    /// line; or a field the server writes itself: `Content-Length` (see
    /// `setLength`) and `Transfer-Encoding`.
    InvalidHeader,
    /// The head has gone out already.
    HeadSent,
    /// The fields do not fit the largest buffer there is.
    HeadTooLarge,
    /// A body for a status that has none (1xx, 204, 304), or more than
    /// the declared length.
    BodyNotAllowed,
    /// Less body than the declared length at `end`.
    BodyIncomplete,
    /// The connection failed, or a write waited past the activity timeout.
    WriteFailed,
    OutOfMemory,
};

/// A response to a request on `conn`.
pub fn init(conn: *Connection, head_only: bool, http1_0: bool) Response {
    return .{
        .conn = conn,
        .head_only = head_only,
        .http1_0 = http1_0,
        .interface = .{ .vtable = &.{ .drain = drain }, .buffer = &.{} },
    };
}

/// Add a field to the head. A name and value are checked whole before
/// anything is kept, so nothing a caller passes can add a line. A
/// `Connection` field that names `close` closes the connection after the
/// response.
pub fn header(r: *Response, name: []const u8, value: []const u8) Error!void {
    if (r.state != .open) return error.HeadSent;
    h1.checkHeader(.{ .name = name, .value = value }) catch return error.InvalidHeader;
    if (std.ascii.eqlIgnoreCase(name, "content-length") or std.ascii.eqlIgnoreCase(name, "transfer-encoding")) return error.InvalidHeader;
    if (std.ascii.eqlIgnoreCase(name, "date")) r.has_date = true;
    if (std.ascii.eqlIgnoreCase(name, "connection") and fields.ListIterator.contains(value, "close")) r.closing = true;
    const need = name.len + 2 + value.len + 2;
    try r.reserve(&r.fields_buffer, r.fields_len, need);
    var w: Io.Writer = .fixed(r.fields_buffer[r.fields_len..]);
    h1.writeField(&w, .{ .name = name, .value = value }) catch unreachable; // unreachable: room was reserved for the line
    r.fields_len += need;
}

/// Room for `need` more bytes after `len` in `buffer`, taken from the pool
/// or moved to a larger buffer.
fn reserve(r: *Response, buffer: *[]u8, len: usize, need: usize) Error!void {
    const pool = &r.conn.server.buffers;
    const io = r.conn.io;
    if (buffer.len - len >= need) return;
    const class = BufferPool.Class.fitting(len + need) orelse return error.HeadTooLarge;
    const larger = try pool.acquire(io, class);
    @memcpy(larger[0..len], buffer.*[0..len]);
    if (buffer.len != 0) pool.release(io, buffer.*);
    buffer.* = larger;
}

/// Declare the body's length, sent as `Content-Length`: the body written
/// must be exactly this long.
pub fn setLength(r: *Response, length: u64) Error!void {
    if (r.state != .open) return error.HeadSent;
    r.declared = length;
}

/// Close the connection after this response, saying so in its head.
pub fn closeAfter(r: *Response) void {
    r.closing = true;
}

/// The body's writer. Its buffer is the server's, a few KiB: a body that
/// fits goes out with its length counted.
pub fn writer(r: *Response, io: Io) Error!*Io.Writer {
    r.conn.io = io;
    if (r.state == .hijacked or r.state == .ended) return error.HeadSent;
    if (r.body_buffer.len == 0) {
        r.body_buffer = try r.conn.server.buffers.acquire(io, .small);
        r.interface.buffer = r.body_buffer;
    }
    return &r.interface;
}

/// Send `body` whole with its length, and end the response.
pub fn send(r: *Response, io: Io, body: []const u8) Error!void {
    r.conn.io = io;
    if (r.state != .open) return error.HeadSent;
    if (r.declared) |n| if (n != body.len) return error.BodyNotAllowed;
    r.declared = body.len;
    try r.sendHead(.length);
    if (!r.head_only and r.framing == .length) r.out().writeAll(body) catch return r.fail();
    r.remaining = 0;
    return r.end(io);
}

/// Add a field to the trailer of a chunked body, sent at `end`.
pub fn trailer(r: *Response, name: []const u8, value: []const u8) Error!void {
    if (r.state == .ended or r.state == .hijacked) return error.HeadSent;
    h1.checkHeader(.{ .name = name, .value = value }) catch return error.InvalidHeader;
    const need = name.len + 2 + value.len + 2;
    try r.reserve(&r.trailer_buffer, r.trailer_len, need);
    var w: Io.Writer = .fixed(r.trailer_buffer[r.trailer_len..]);
    h1.writeField(&w, .{ .name = name, .value = value }) catch unreachable; // unreachable: room was reserved for the line
    r.trailer_len += need;
}

/// Finish the response: the head if it has not gone, what the body's
/// buffer holds, a chunked body's last chunk and trailer, and everything
/// pushed to the client.
pub fn end(r: *Response, io: Io) Error!void {
    r.conn.io = io;
    switch (r.state) {
        .ended, .hijacked => return,
        .open => {
            const buffered = r.interface.buffered();
            if (r.declared == null) r.declared = buffered.len;
            try r.sendHead(.length);
            try r.bodyBytes(&.{buffered}, 1);
            r.interface.end = 0;
        },
        .streaming => {
            r.interface.flush() catch return r.fail();
        },
    }
    switch (r.framing) {
        .chunked => {
            const w = r.out();
            w.writeAll("0\r\n") catch return r.fail();
            w.writeAll(r.trailer_buffer[0..r.trailer_len]) catch return r.fail();
            w.writeAll("\r\n") catch return r.fail();
        },
        .length => if (r.remaining != 0) {
            // The client counts on a body this long: the connection ends
            // short instead, so it sees a truncation.
            r.broken = true;
            r.state = .ended;
            return error.BodyIncomplete;
        },
        .none, .close => {},
    }
    r.state = .ended;
    r.conn.flush() catch return r.fail();
}

/// A connection taken over by the handler, after a `101` or a `2xx` to a
/// `CONNECT`: the head goes out as set, and the handler speaks the new
/// protocol on the reader and writer until it returns, when the server
/// closes the connection.
pub const Hijacked = struct {
    reader: *Io.Reader,
    writer: *Io.Writer,
    conn: *Connection,

    /// Push what was written to the peer.
    pub fn flush(h: Hijacked) Io.Writer.Error!void {
        return h.conn.flush();
    }
};

/// Send the head as it stands, with no body framing, and hand the
/// connection to the caller.
pub fn hijack(r: *Response, io: Io) Error!Hijacked {
    r.conn.io = io;
    if (r.state != .open) return error.HeadSent;
    try r.sendHead(.none);
    r.conn.flush() catch return r.fail();
    r.state = .hijacked;
    r.conn.hijacked = true;
    return .{ .reader = r.conn.reader(), .writer = r.conn.writer(), .conn = r.conn };
}

/// Whether the head has gone out.
pub fn headSent(r: *const Response) bool {
    return r.state != .open;
}

/// Whether the connection can carry another exchange after this response.
pub fn keepsConnection(r: *const Response) bool {
    return r.state == .ended and !r.closing and !r.broken and r.framing != .close;
}

/// Give back the response's buffers.
pub fn release(r: *Response, io: Io) void {
    const pool = &r.conn.server.buffers;
    for ([_][]u8{ r.fields_buffer, r.body_buffer, r.trailer_buffer }) |b| if (b.len != 0) pool.release(io, b);
    r.fields_buffer = &.{};
    r.body_buffer = &.{};
    r.trailer_buffer = &.{};
}

/// Forget everything set, for an answer the server writes in its place
/// (a 500 after a handler failed before its head went out).
pub fn reset(r: *Response, io: Io) void {
    std.debug.assert(r.state == .open);
    r.release(io);
    const kept = r.*;
    r.* = .init(kept.conn, kept.head_only, kept.http1_0);
    r.closing = kept.closing;
}

fn out(r: *Response) *Io.Writer {
    return r.conn.writer();
}

fn fail(r: *Response) Error {
    r.broken = true;
    return error.WriteFailed;
}

/// Whether the status carries a body at all.
fn bodiless(status: Status) bool {
    const code = @backingInt(status);
    return code / 100 == 1 or code == 204 or code == 304;
}

/// Write the head. `want` is the framing the caller has: `length` when
/// the length is known (`declared`), `chunked` while streaming, `none` for
/// a head alone.
fn sendHead(r: *Response, want: Framing) Error!void {
    std.debug.assert(r.state == .open);
    const code = @backingInt(r.status);
    r.framing = if (bodiless(r.status) or want == .none)
        .none
    else switch (want) {
        .length => .length,
        else => if (r.declared != null) .length else if (r.http1_0) .close else .chunked,
    };
    if (r.framing == .close) r.closing = true;
    if (r.conn.server.isStopping()) r.closing = true;
    const w = r.out();
    h1.writeStatusLine(w, r.status) catch return r.fail();
    if (!r.has_date) {
        var date_buf: [wire.date.formatted_len]u8 = undefined;
        const now = Io.Clock.real.now(r.conn.io).toSeconds();
        w.print("Date: {s}\r\n", .{wire.date.format(now, &date_buf)}) catch return r.fail();
    }
    switch (r.framing) {
        .length => {
            const n = r.declared.?;
            // A 304 or a HEAD keeps the length a GET would have.
            w.print("Content-Length: {d}\r\n", .{n}) catch return r.fail();
            r.remaining = n;
        },
        .chunked => w.writeAll("Transfer-Encoding: chunked\r\n") catch return r.fail(),
        .none => if (code == 204 or code / 100 == 1) {} else if (want != .none) w.writeAll("Content-Length: 0\r\n") catch return r.fail(),
        .close => {},
    }
    if (r.closing and code != 101) w.writeAll("Connection: close\r\n") catch return r.fail();
    w.writeAll(r.fields_buffer[0..r.fields_len]) catch return r.fail();
    w.writeAll("\r\n") catch return r.fail();
    r.state = .streaming;
}

/// Write body bytes as the framing says; a `HEAD`'s are counted, not sent.
fn bodyBytes(r: *Response, data: []const []const u8, splat: usize) Error!void {
    var total: u64 = 0;
    for (data[0 .. data.len - 1]) |d| total += d.len;
    total += @as(u64, data[data.len - 1].len) * splat;
    if (total == 0) return;
    switch (r.framing) {
        .none => return error.BodyNotAllowed,
        .length => {
            if (total > r.remaining) {
                r.broken = true;
                return error.BodyNotAllowed;
            }
            r.remaining -= total;
        },
        .chunked, .close => {},
    }
    if (r.head_only) return;
    const w = r.out();
    if (r.framing == .chunked) w.print("{x}\r\n", .{total}) catch return r.fail();
    for (data[0 .. data.len - 1]) |d| w.writeAll(d) catch return r.fail();
    w.splatBytesAll(data[data.len - 1], splat) catch return r.fail();
    if (r.framing == .chunked) w.writeAll("\r\n") catch return r.fail();
}

fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
    const r: *Response = @alignCast(@fieldParentPtr("interface", w)); // safe: this vtable is installed only on a Response's interface
    switch (r.state) {
        .open => r.sendHead(.chunked) catch return error.WriteFailed,
        .streaming => {},
        .ended, .hijacked => return error.WriteFailed,
    }
    const buffered = w.buffered();
    r.bodyBytes(&.{buffered}, 1) catch return error.WriteFailed;
    var n: usize = buffered.len;
    for (data[0 .. data.len - 1]) |d| n += d.len;
    n += data[data.len - 1].len * splat;
    r.bodyBytes(data, splat) catch return error.WriteFailed;
    return w.consume(n);
}
