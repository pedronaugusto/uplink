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
//! With compression on, a body of a type worth compressing, long enough,
//! to a client that accepts a coding the server offers, goes out under that
//! coding, through warp: whole with its compressed length when it fits the
//! buffer (and only if compressing made it smaller), chunked as it is
//! written otherwise, with `Vary: Accept-Encoding` either way.
//!
//! A response must not move once `writer` has been called.

const std = @import("std");
const aegis = @import("aegis");
const Io = std.Io;
const Status = std.http.Status;
const wire = @import("uplink.wire");
const h1 = wire.h1;
const fields = wire.fields;
const BufferPool = @import("../transport/BufferPool.zig");
const Encoder = @import("../coding/Encoder.zig");
const Timed = @import("../net/Timed.zig");
const Socket = @import("Socket.zig");
const Session = @import("h2/Session.zig");
const hpack = wire.hpack;

const Response = @This();

/// The status the head will carry; 200 unless set before the head goes.
status: Status = .ok,

/// Private: the connection the response goes out on.
socket: *Socket,
/// Private: the request is a `HEAD`: the body is counted, not sent.
head_only: bool,
/// Private: the client speaks HTTP/1.0, which knows no chunks.
http1_0: bool,
/// Private: the request's `Accept-Encoding`.
accept_encoding: ?[]const u8,
/// Private: the fields as they will be written, each line whole.
fields_buffer: []u8 = &.{},
fields_len: usize = 0,
/// Private: the body's buffer, from the pool once `writer` is asked for.
body_buffer: []u8 = &.{},
/// Private: where the response stands.
state: State = .open,
/// Private: the length the handler declared, of the body as written.
declared: ?u64 = null,
/// Private: the framing the head chose.
framing: Framing = .none,
/// Private: body bytes still owed under a declared length.
remaining: u64 = 0,
/// Private: the connection closes after this response.
closing: bool = false,
/// Private: what the handler set that the server reads.
has_date: bool = false,
has_content_encoding: bool = false,
/// Private: the `Content-Type` is one compression covers.
compressible: bool = false,
/// Private: a write failed; the connection is closed after.
broken: bool = false,
/// Private: a write failed for the writing task's cancelation.
canceled: bool = false,
/// Private: the trailer's fields, for a chunked body.
trailer_buffer: []u8 = &.{},
trailer_len: usize = 0,
/// Private: the encoder of a body sent under a coding, and the writer
/// that frames what it writes.
encoder: ?*Encoder = null,
framed: Io.Writer = .{ .vtable = &.{ .drain = drainFramed }, .buffer = &.{} },
framed_buffer: []u8 = &.{},
/// Private: a taken-over HTTP/2 stream's writer: its bytes as DATA.
tunnel: Io.Writer = .{ .vtable = &.{ .drain = drainTunnel }, .buffer = &.{} },
/// Private: the buffer a taken-over HTTP/2 stream is read through.
tunnel_in: []u8 = &.{},
/// Private: the HTTP/2 stream the response goes on, if it does.
stream: ?*Session.Stream = null,
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

const Framing = enum {
    none,
    length,
    chunked,
    close,
    /// HTTP/2's DATA frames, the length not said.
    frames,
};

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
    /// The task writing was canceled, or the connection's: nothing more
    /// goes out.
    Canceled,
    OutOfMemory,
};

/// A response to a request on `socket`.
pub fn init(socket: *Socket, head_only: bool, http1_0: bool, accept_encoding: ?[]const u8) Response {
    return .{
        .socket = socket,
        .head_only = head_only,
        .http1_0 = http1_0,
        .accept_encoding = accept_encoding,
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
    if (std.ascii.eqlIgnoreCase(name, "content-encoding")) r.has_content_encoding = true;
    if (std.ascii.eqlIgnoreCase(name, "content-type")) r.compressible = if (r.socket.context.options.compression) |c| c.covers(value) else false;
    if (std.ascii.eqlIgnoreCase(name, "connection") and fields.ListIterator.contains(value, "close")) r.closing = true;
    try r.appendField(&r.fields_buffer, &r.fields_len, name, value);
}

fn appendField(r: *Response, buffer: *[]u8, len: *usize, name: []const u8, value: []const u8) Error!void {
    const need = name.len + 2 + value.len + 2;
    try r.reserve(buffer, len.*, need);
    var w: Io.Writer = .fixed(buffer.*[len.*..]);
    h1.writeField(&w, .{ .name = name, .value = value }) catch unreachable; // unreachable: room was reserved for the line
    len.* += need;
}

/// Room for `need` more bytes after `len` in `buffer`, taken from the pool
/// or moved to a larger buffer.
fn reserve(r: *Response, buffer: *[]u8, len: usize, need: usize) Error!void {
    const pool = &r.socket.context.buffers;
    const io = r.socket.io;
    if (buffer.len - len >= need) return;
    const class = BufferPool.Class.fitting(len + need) orelse return error.HeadTooLarge;
    const larger = try pool.acquire(io, class);
    @memcpy(larger[0..len], buffer.*[0..len]);
    if (buffer.len != 0) pool.release(io, buffer.*);
    buffer.* = larger;
}

/// Declare the body's length, sent as `Content-Length`: the body written
/// must be exactly this long. A body sent compressed is chunked instead,
/// and still held to the length declared.
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
    r.socket.adopt(io);
    if (r.state == .hijacked or r.state == .ended) return error.HeadSent;
    if (r.body_buffer.len == 0) {
        r.body_buffer = try r.socket.context.buffers.acquire(io, .small);
        r.interface.buffer = r.body_buffer;
    }
    return &r.interface;
}

/// Send `body` whole, and end the response.
pub fn send(r: *Response, io: Io, body: []const u8) Error!void {
    r.socket.adopt(io);
    if (r.state != .open) return error.HeadSent;
    if (r.declared) |n| if (n != body.len) return error.BodyNotAllowed;
    return r.sendWhole(body);
}

/// Add a field to the trailer of a chunked body, sent at `end`.
pub fn trailer(r: *Response, name: []const u8, value: []const u8) Error!void {
    if (r.state == .ended or r.state == .hijacked) return error.HeadSent;
    h1.checkHeader(.{ .name = name, .value = value }) catch return error.InvalidHeader;
    try r.appendField(&r.trailer_buffer, &r.trailer_len, name, value);
}

/// Finish the response: the head if it has not gone, what the body's
/// buffer holds, a chunked body's last chunk and trailer, and everything
/// pushed to the client.
pub fn end(r: *Response, io: Io) Error!void {
    r.socket.adopt(io);
    switch (r.state) {
        .ended => return,
        .hijacked => {
            // A taken-over stream ends with the handler, as a connection
            // taken over closes.
            if (r.stream) |st| if (!st.ended) {
                r.tunnel.flush() catch return r.fail();
                st.writeData(io, "", true) catch |err| return r.failStream(err);
            };
            return;
        },
        .open => {
            const buffered = r.interface.buffered();
            r.interface.end = 0;
            if (r.declared) |n| if (n != buffered.len) {
                // Declared and short: the head promised more than came.
                try r.sendHead(.length, null);
                try r.bodyBytes(&.{buffered}, 1);
                return r.finishShort();
            };
            return r.sendWhole(buffered);
        },
        .streaming => {
            r.interface.flush() catch return r.fail();
        },
    }
    if (r.encoder) |e| {
        e.finish() catch return r.fail();
        r.framed.flush() catch return r.fail();
    }
    if (r.declared != null and r.remaining != 0) return r.finishShort();
    if (r.stream) |st| {
        if (!st.ended) try r.endH2(st);
        r.state = .ended;
        return;
    }
    if (r.framing == .chunked) {
        const w = r.out();
        w.writeAll("0\r\n") catch return r.fail();
        w.writeAll(r.trailer_buffer[0..r.trailer_len]) catch return r.fail();
        w.writeAll("\r\n") catch return r.fail();
    }
    r.state = .ended;
    r.flushOut() catch return r.fail();
}

/// End an HTTP/2 response: its trailers, or an empty DATA, with
/// END_STREAM.
fn endH2(r: *Response, st: *Session.Stream) Error!void {
    if (r.trailer_len != 0) {
        var list: [max_h2_fields]hpack.Field = undefined;
        const n = wire.h2.message.appendLines(&list, 0, r.trailer_buffer[0..r.trailer_len]) catch return error.HeadTooLarge;
        st.writeHeaders(r.socket.io, list[0..n], true) catch |err| return r.failStream(err);
        return;
    }
    st.writeData(r.socket.io, "", true) catch |err| return r.failStream(err);
}

/// The client counts on a longer body: the connection ends short instead,
/// so it sees a truncation, never a short success.
fn finishShort(r: *Response) Error {
    r.broken = true;
    r.state = .ended;
    if (r.stream) |st| {
        st.reset(r.socket.io, .internal_error);
        return error.BodyIncomplete;
    }
    // glint-ignore: Z026 -- the connection closes next; what went out goes out cut
    r.socket.flush() catch {};
    return error.BodyIncomplete;
}

/// A body known whole: its own length, or compressed and the length of
/// that, when compressing makes it smaller.
fn sendWhole(r: *Response, body: []const u8) Error!void {
    if (r.coding(body.len)) |c| compressed: {
        const pool = &r.socket.context.buffers;
        const io = r.socket.io;
        const out_buffer = pool.acquire(io, .large) catch break :compressed;
        defer pool.release(io, out_buffer);
        var sink: Io.Writer = .fixed(out_buffer);
        const encoders = &r.socket.context.encoders.?;
        const e = encoders.acquire(io, c, &sink) catch break :compressed;
        defer encoders.release(io, e);
        e.writer().writeAll(body) catch break :compressed;
        e.finish() catch break :compressed;
        const coded = sink.buffered();
        if (coded.len >= body.len) break :compressed;
        r.declared = coded.len;
        try r.sendHead(.length, c);
        r.remaining = 0;
        if (r.stream) |st| {
            if (!st.ended) st.writeData(r.socket.io, coded, true) catch |err| return r.failStream(err);
            r.state = .ended;
            return;
        }
        if (!r.head_only) r.out().writeAll(coded) catch return r.fail();
        r.state = .ended;
        r.flushOut() catch return r.fail();
        return;
    }
    if (bodiless(r.status)) {
        if (body.len != 0) return error.BodyNotAllowed;
    } else r.declared = body.len;
    try r.sendHead(.length, null);
    if (r.stream) |st| {
        if (!st.ended and !r.head_only and body.len != 0) {
            r.remaining = 0;
            st.writeData(r.socket.io, body, true) catch |err| return r.failStream(err);
        } else if (!st.ended) try r.endH2(st);
        r.state = .ended;
        return;
    }
    try r.bodyBytes(&.{body}, 1);
    r.state = .ended;
    r.flushOut() catch return r.fail();
}

/// A connection taken over by the handler, after a `101` or a `2xx` to a
/// `CONNECT`: the head goes out as set, and the handler speaks the new
/// protocol on the reader and writer until it returns, when the server
/// closes the connection. No server timeout bounds it any more: the
/// protocol keeps its own.
pub const Hijacked = struct {
    reader: *Io.Reader,
    writer: *Io.Writer,
    socket: *Socket,
    /// The HTTP/2 stream taken over, when it is one.
    stream: ?*Session.Stream = null,
    /// Private: the response taken over, whose writes the stream's are.
    response: *const Response,

    /// Push what was written to the peer.
    pub fn flush(h: Hijacked) Io.Writer.Error!void {
        if (h.stream != null) return h.writer.flush();
        return h.socket.flush();
    }

    /// Wait up to `timeout` for the peer to send something; the wait ends
    /// nothing when nothing comes.
    pub fn awaitReadable(h: Hijacked, io: Io, timeout: Io.Duration) Io.Cancelable!Timed.Readiness {
        if (h.stream) |st| return st.awaitReadable(io, timeout);
        return h.socket.awaitReadable(io, timeout);
    }

    /// Whether a read or write failed for a cancelation: the handler's
    /// task's, or the connection's.
    pub fn canceled(h: Hijacked) bool {
        if (h.response.failure() == error.Canceled) return true;
        const st = h.stream orelse return false;
        const failed = st.read_failure orelse return false;
        return failed == error.Canceled;
    }
};

/// Send the head as it stands, with no body framing, and hand the
/// connection to the caller. On HTTP/2, after a 2xx to an extended
/// `CONNECT` (RFC 8441), the stream is what is taken over: its data both
/// ways, until either end ends it.
pub fn hijack(r: *Response, io: Io) Error!Hijacked {
    r.socket.adopt(io);
    if (r.state != .open) return error.HeadSent;
    if (r.stream) |st| {
        if (@backingInt(r.status) / 100 != 2) return error.HeadSent;
        // The stream carries another protocol's bytes: never coded.
        r.compressible = false;
        try r.sendHeadH2(st, .chunked, null);
        r.body_buffer = try r.socket.context.buffers.acquire(io, .small);
        r.tunnel.buffer = r.body_buffer;
        // What the stream carries is read as a connection would be,
        // through a buffer of its own.
        r.tunnel_in = try r.socket.context.buffers.acquire(io, .record);
        const in = st.reader(io);
        in.buffer = r.tunnel_in;
        r.state = .hijacked;
        return .{ .reader = in, .writer = &r.tunnel, .socket = r.socket, .stream = st, .response = r };
    }
    try r.sendHead(.none, null);
    r.flushOut() catch return r.fail();
    r.state = .hijacked;
    r.socket.hijacked = true;
    r.socket.phase = .hijacked;
    return .{ .reader = r.socket.reader(), .writer = r.socket.writer(), .socket = r.socket, .response = r };
}

/// Whether the head has gone out.
pub fn headSent(r: *const Response) bool {
    return r.state != .open;
}

/// Whether the connection can carry another exchange after this response.
pub fn keepsConnection(r: *const Response) bool {
    if (r.stream != null) return r.state == .ended and !r.broken;
    return r.state == .ended and !r.closing and !r.broken and r.framing != .close;
}

/// Give back the response's buffers and its encoder.
pub fn release(r: *Response, io: Io) void {
    const pool = &r.socket.context.buffers;
    for ([_][]u8{ r.fields_buffer, r.body_buffer, r.trailer_buffer, r.framed_buffer, r.tunnel_in }) |b| if (b.len != 0) pool.release(io, b);
    r.tunnel_in = &.{};
    r.fields_buffer = &.{};
    r.body_buffer = &.{};
    r.trailer_buffer = &.{};
    r.framed_buffer = &.{};
    if (r.encoder) |e| r.socket.context.encoders.?.release(io, e);
    r.encoder = null;
}

/// Forget everything set, for an answer the server writes in its place
/// (a 500 after a handler failed before its head went out).
pub fn reset(r: *Response, io: Io) void {
    std.debug.assert(r.state == .open);
    r.release(io);
    const kept = r.*;
    r.* = .init(kept.socket, kept.head_only, kept.http1_0, kept.accept_encoding);
    r.closing = kept.closing;
}

fn out(r: *Response) *Io.Writer {
    return r.socket.writer();
}

/// Push what was written: the socket's buffer on HTTP/1.1; HTTP/2's
/// frames go as they are written.
fn flushOut(r: *Response) Io.Writer.Error!void {
    if (r.stream != null) return;
    return r.socket.flush();
}

fn fail(r: *Response) Error {
    r.broken = true;
    return r.failure();
}

/// An HTTP/2 stream's write failed.
fn failStream(r: *Response, err: Session.WriteError) Error {
    r.noteStream(err);
    return r.failure();
}

/// A taken-over stream's write failed, for its writer.
fn tunnelFailed(r: *Response, err: Session.WriteError) error{WriteFailed} {
    r.noteStream(err);
    return error.WriteFailed;
}

fn noteStream(r: *Response, err: Session.WriteError) void {
    r.broken = true;
    if (err == error.Canceled) r.canceled = true;
}

/// Why the last write failed, the body writer's included (it says
/// `error.WriteFailed` alone): `error.Canceled` when the writing task was
/// canceled, or the connection's task.
pub fn failure(r: *const Response) error{ WriteFailed, Canceled } {
    return if (r.canceled or r.socket.failed() == .canceled) error.Canceled else error.WriteFailed;
}

/// Whether the status carries a body at all.
fn bodiless(status: Status) bool {
    const code = @backingInt(status);
    return code / 100 == 1 or code == 204 or code == 304;
}

/// The coding to send the body under, for a body `length` long when that
/// is known: none unless compression is on, the body is one it covers and
/// long enough, nothing else coded it, and the client accepts one offered.
fn coding(r: *const Response, length: ?u64) ?Encoder.Coding {
    const c = r.socket.context.options.compression orelse return null;
    if (r.head_only or bodiless(r.status) or r.status == .partial_content) return null;
    if (r.has_content_encoding or !r.compressible) return null;
    if (length) |n| if (aegis.units.Bytes(u64).fromRaw(n).compare(c.min_size.convert(u64)) == .lt) return null;
    var offered: [3]wire.coding.ContentCoding = undefined;
    for (c.codings, 0..) |each, i| offered[i] = each.content();
    const chosen = wire.coding.negotiate(r.accept_encoding, offered[0..c.codings.len]) orelse return null;
    for (c.codings) |each| if (each.content() == chosen) return each;
    return null;
}

/// Write the head. `want` is the framing the caller has: `length` when the
/// length is known (`declared`), `chunked` while streaming, `none` for a
/// head alone. `coded` is the coding a whole body was put under.
fn sendHead(r: *Response, want: Framing, coded: ?Encoder.Coding) Error!void {
    std.debug.assert(r.state == .open);
    if (r.stream) |st| return r.sendHeadH2(st, want, coded);
    const code = @backingInt(r.status);
    // A body streamed under a coding is chunked, whatever its length.
    const streamed = if (want == .chunked) r.coding(r.declared) else null;
    r.framing = if (bodiless(r.status) or want == .none)
        .none
    else switch (want) {
        .length => .length,
        else => if (r.declared != null and streamed == null) .length else if (r.http1_0) .close else .chunked,
    };
    if (r.framing == .close) r.closing = true;
    if (r.socket.context.isStopping()) r.closing = true;
    if (streamed) |c| try r.startEncoder(c);
    const w = r.out();
    h1.writeStatusLine(w, r.status) catch return r.fail();
    if (!r.has_date) {
        var date_buf: [wire.date.formatted_len]u8 = undefined;
        const now = Io.Clock.real.now(r.socket.io).toSeconds();
        w.print("Date: {s}\r\n", .{wire.date.format(now, &date_buf)}) catch return r.fail();
    }
    switch (r.framing) {
        .length => w.print("Content-Length: {d}\r\n", .{r.declared.?}) catch return r.fail(),
        .chunked => w.writeAll("Transfer-Encoding: chunked\r\n") catch return r.fail(),
        // A 304 may name the length a 200 would have; nothing else here
        // has one.
        .none => if (code == 304 and want != .none) if (r.declared) |n| w.print("Content-Length: {d}\r\n", .{n}) catch return r.fail(),
        .close => {},
        .frames => unreachable, // unreachable: HTTP/1.1's head never frames its body as HTTP/2 does
    }
    if (r.declared) |n| r.remaining = n;
    if (coded orelse streamed) |c| w.print("Content-Encoding: {s}\r\n", .{c.name()}) catch return r.fail();
    if (r.compressible and !r.has_content_encoding) w.writeAll("Vary: Accept-Encoding\r\n") catch return r.fail();
    if (r.closing and code != 101) w.writeAll("Connection: close\r\n") catch return r.fail();
    w.writeAll(r.fields_buffer[0..r.fields_len]) catch return r.fail();
    w.writeAll("\r\n") catch return r.fail();
    r.state = .streaming;
}

/// The head as HTTP/2 HEADERS: the status and the fields with lower-case
/// names, those of a connection's own left out; the stream ends with them
/// when no body follows.
fn sendHeadH2(r: *Response, st: *Session.Stream, want: Framing, coded: ?Encoder.Coding) Error!void {
    const code = @backingInt(r.status);
    const streamed = if (want == .chunked) r.coding(r.declared) else null;
    r.framing = if (bodiless(r.status) or want == .none)
        .none
    else switch (want) {
        .length => .length,
        else => if (r.declared != null and streamed == null) .length else .frames,
    };
    if (streamed) |c| try r.startEncoder(c);
    var list: [max_h2_fields]hpack.Field = undefined;
    var n: usize = 0;
    var status_buf: [3]u8 = undefined;
    list[n] = .{ .name = ":status", .value = std.mem.print(&status_buf, "{d}", .{code}) catch unreachable }; // unreachable: a status is three digits
    n += 1;
    var date_buf: [wire.date.formatted_len]u8 = undefined;
    if (!r.has_date) {
        list[n] = .{ .name = "date", .value = wire.date.format(Io.Clock.real.now(r.socket.io).toSeconds(), &date_buf) };
        n += 1;
    }
    var length_buf: [20]u8 = undefined;
    const say_length = r.framing == .length or (code == 304 and r.declared != null);
    if (say_length) {
        list[n] = .{ .name = "content-length", .value = std.mem.print(&length_buf, "{d}", .{r.declared.?}) catch unreachable }; // unreachable: a u64 is at most 20 digits
        n += 1;
    }
    if (r.declared) |d| r.remaining = d;
    if (coded orelse streamed) |c| {
        list[n] = .{ .name = "content-encoding", .value = c.name() };
        n += 1;
    }
    if (r.compressible and !r.has_content_encoding) {
        list[n] = .{ .name = "vary", .value = "accept-encoding" };
        n += 1;
    }
    n = wire.h2.message.appendLines(&list, n, r.fields_buffer[0..r.fields_len]) catch return error.HeadTooLarge;
    const end_stream = r.framing == .none or r.head_only or (r.framing == .length and r.declared.? == 0);
    st.writeHeaders(r.socket.io, list[0..n], end_stream) catch |err| return r.failStream(err);
    r.state = .streaming;
}

/// The most fields an HTTP/2 head carries.
const max_h2_fields = 128;

fn startEncoder(r: *Response, c: Encoder.Coding) Error!void {
    const io = r.socket.io;
    r.framed_buffer = try r.socket.context.buffers.acquire(io, .small);
    r.framed.buffer = r.framed_buffer;
    r.encoder = try r.socket.context.encoders.?.acquire(io, c, &r.framed);
}

/// Write body bytes as written by the handler: held to a declared length,
/// counted and not sent for a `HEAD`, encoded when the body has a coding.
fn bodyBytes(r: *Response, data: []const []const u8, splat: usize) Error!void {
    var total: u64 = 0;
    for (data[0 .. data.len - 1]) |d| total += d.len;
    total += @as(u64, data[data.len - 1].len) * splat;
    if (total == 0) return;
    if (r.framing == .none) return error.BodyNotAllowed;
    if (r.declared != null) {
        if (total > r.remaining) {
            r.broken = true;
            return error.BodyNotAllowed;
        }
        r.remaining -= total;
    }
    if (r.head_only) return;
    if (r.encoder) |e| {
        const w = e.writer();
        for (data[0 .. data.len - 1]) |d| w.writeAll(d) catch return r.fail();
        w.splatBytesAll(data[data.len - 1], splat) catch return r.fail();
        return;
    }
    return r.frame(data, splat, total);
}

/// Bytes onto the connection as the framing says.
fn frame(r: *Response, data: []const []const u8, splat: usize, total: u64) Error!void {
    if (r.stream) |st| {
        const io = r.socket.io;
        for (data[0 .. data.len - 1]) |d| st.writeData(io, d, false) catch |err| return r.failStream(err);
        for (0..splat) |_| st.writeData(io, data[data.len - 1], false) catch |err| return r.failStream(err);
        return;
    }
    const w = r.out();
    if (r.framing == .chunked) w.print("{x}\r\n", .{total}) catch return r.fail();
    for (data[0 .. data.len - 1]) |d| w.writeAll(d) catch return r.fail();
    w.splatBytesAll(data[data.len - 1], splat) catch return r.fail();
    if (r.framing == .chunked) w.writeAll("\r\n") catch return r.fail();
}

fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
    const r: *Response = @alignCast(@fieldParentPtr("interface", w)); // safe: this vtable is installed only on a Response's interface
    switch (r.state) {
        .open => r.sendHead(.chunked, null) catch return error.WriteFailed,
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

/// A taken-over stream's bytes, as DATA.
fn drainTunnel(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
    const r: *Response = @alignCast(@fieldParentPtr("tunnel", w)); // safe: this vtable is installed only on a Response's `tunnel`
    const st = r.stream.?;
    const io = r.socket.io;
    st.writeData(io, w.buffered(), false) catch |err| return r.tunnelFailed(err);
    var n: usize = 0;
    for (data[0 .. data.len - 1]) |d| {
        st.writeData(io, d, false) catch |err| return r.tunnelFailed(err);
        n += d.len;
    }
    for (0..splat) |_| {
        st.writeData(io, data[data.len - 1], false) catch |err| return r.tunnelFailed(err);
        n += data[data.len - 1].len;
    }
    w.end = 0;
    return n;
}

/// What the encoder writes, framed onto the connection.
fn drainFramed(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
    const r: *Response = @alignCast(@fieldParentPtr("framed", w)); // safe: this vtable is installed only on a Response's `framed`
    const buffered = w.buffered();
    var n: usize = 0;
    for (data[0 .. data.len - 1]) |d| n += d.len;
    n += data[data.len - 1].len * splat;
    if (buffered.len != 0) r.frame(&.{buffered}, 1, buffered.len) catch return error.WriteFailed;
    if (n != 0) r.frame(data, splat, n) catch return error.WriteFailed;
    return w.consume(buffered.len + n);
}
