//! A message's body as its framing delimits it: a length, chunks, or the
//! connection's end. The body's bytes pass from the connection's reader to
//! the caller's writer without a copy of the body reader's own; chunk
//! framing is consumed where it lies in the connection's buffer. A chunked
//! body's trailer section, when it has fields, is gathered into a buffer
//! from the pool for the message's `trailers`. A body may be capped, as a
//! server caps a request's: past the cap it reads no more.

const std = @import("std");
const aegis = @import("aegis");
const Io = std.Io;
const wire = @import("uplink.wire");
const h1 = wire.h1;
const Field = wire.fields.Field;
const BufferPool = @import("BufferPool.zig");
const Duration = @import("../span.zig").Duration;

const Body = @This();

interface: Io.Reader,
/// Private: the connection's reader.
in: *Io.Reader,
/// Private: how the body is delimited.
framing: h1.Framing,
/// Private: bytes left of a body of known length.
remaining: u64,
/// Private: the chunk framing's state.
chunked: h1.ChunkedDecoder = .{},
/// Private: the bytes a body without a known length may still have before
/// it is too large; null is no cap.
allowed: ?u64 = null,
/// Where reading stands: `state.current()`.
state: Reading.Runtime(void) = .init({}),
/// Private: where trailer bytes go, and the `Io` to borrow it with;
/// null keeps none.
trailer_pool: ?*BufferPool = null,
trailer_io: Io = undefined,
/// Private: the trailer section as read, its blank line included.
trailer: BufferPool.Buffer = &.{},
trailer_len: usize = 0,

pub const State = enum {
    reading,
    /// The body was read to its end.
    done,
    /// The connection failed under the body; it says why.
    read_failed,
    /// The connection ended before the body did.
    incomplete,
    /// The chunk framing was malformed.
    malformed,
    /// The body passed its cap.
    too_large,
};

/// How a body ends: read to its end, or one way of failing, each once.
const Ending = enum { done, read_failed, incomplete, malformed, too_large };
const Reading = aegis.state.Machine(State, Ending, .{ .initial = .reading, .terminal = &.{ .done, .read_failed, .incomplete, .malformed, .too_large }, .edges = &.{
    .{ .from = .reading, .on = .done, .to = .done },
    .{ .from = .reading, .on = .read_failed, .to = .read_failed },
    .{ .from = .reading, .on = .incomplete, .to = .incomplete },
    .{ .from = .reading, .on = .malformed, .to = .malformed },
    .{ .from = .reading, .on = .too_large, .to = .too_large },
} });

/// A body read from `in` as `framing` says, with `buffer` for the reader's
/// own buffering.
pub fn init(in: *Io.Reader, framing: h1.Framing, buffer: []u8) Body {
    var b: Body = .{
        .interface = .{ .vtable = &.{ .stream = stream }, .buffer = buffer, .seek = 0, .end = 0 },
        .in = in,
        .framing = framing,
        .remaining = switch (framing) {
            .length => |n| n,
            else => 0,
        },
    };
    const empty = switch (framing) {
        .none => true,
        .length => |n| n == 0,
        .chunked, .until_close => false,
    };
    if (empty) b.end(.done);
    return b;
}

/// End the body as `how` says. It ends once.
fn end(b: *Body, how: Ending) void {
    _ = b.state.step(how) catch unreachable; // unreachable: every ending is taken from reading, and reading stops at it
}

/// A request's body, read as a server reads one: its chunk framing
/// strictly, CRLF line ends and extensions as RFC 9112 writes them.
pub fn initStrict(in: *Io.Reader, framing: h1.Framing, buffer: []u8) Body {
    var b: Body = .init(in, framing, buffer);
    b.chunked.lenience = .request;
    return b;
}

/// Whether the whole body has been read, its own buffer included: what the
/// connection needs to carry another exchange.
pub fn complete(b: *const Body) bool {
    return b.state.current() == .done and b.interface.seek == b.interface.end;
}

fn stream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
    const b: *Body = @alignCast(@fieldParentPtr("interface", r)); // safe: this vtable is installed only on a Body's interface
    switch (b.state.current()) {
        .reading => {},
        .done => return error.EndOfStream,
        .read_failed, .incomplete, .malformed, .too_large => return error.ReadFailed,
    }
    if (limit == .nothing) return 0;
    return switch (b.framing) {
        .none => unreachable, // unreachable: a body with no framing starts done
        .length => b.streamLength(w, limit),
        .until_close => {
            const n = b.in.stream(w, try b.capped(limit, std.math.maxInt(u64))) catch |err| return switch (err) {
                error.EndOfStream => {
                    b.end(.done);
                    return error.EndOfStream;
                },
                error.ReadFailed => b.failed(.read_failed),
                error.WriteFailed => error.WriteFailed,
            };
            b.count(n);
            return n;
        },
        .chunked => b.streamChunked(w, limit),
    };
}

fn streamLength(b: *Body, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
    const n = b.in.stream(w, limit.min(.limited64(b.remaining))) catch |err| return switch (err) {
        error.EndOfStream => b.failed(.incomplete),
        error.ReadFailed => b.failed(.read_failed),
        error.WriteFailed => error.WriteFailed,
    };
    b.remaining -= n;
    if (b.remaining == 0) b.end(.done);
    return n;
}

fn streamChunked(b: *Body, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
    const d = &b.chunked;
    while (true) {
        const pending = d.pending();
        if (pending != 0) {
            const n = b.in.stream(w, try b.capped(limit, pending)) catch |err| return switch (err) {
                error.EndOfStream => b.failed(.incomplete),
                error.ReadFailed => b.failed(.read_failed),
                error.WriteFailed => error.WriteFailed,
            };
            d.take(n);
            b.count(n);
            return n;
        }
        if (d.done()) {
            b.end(.done);
            return error.EndOfStream;
        }
        if (b.in.bufferedLen() == 0) b.in.fillMore() catch |err| return switch (err) {
            error.EndOfStream => b.failed(.incomplete),
            error.ReadFailed => b.failed(.read_failed),
        };
        const in_trailer = d.inTrailer();
        const step = d.feed(b.in.buffered()) catch return b.failed(.malformed);
        if (in_trailer) b.keepTrailer(b.in.buffered()[0..step.consumed]) catch return b.failed(.read_failed);
        b.in.toss(step.consumed);
    }
}

/// Room left for trailer bytes, the rest of the buffer going to the
/// fields they are parsed into.
pub const trailer_fields = 64;

/// Gather trailer bytes. An empty section, its blank line alone, needs no
/// buffer.
fn keepTrailer(b: *Body, bytes: []const u8) error{OutOfMemory}!void {
    const pool = b.trailer_pool orelse return;
    if (b.trailer.len == 0) {
        // A field line never starts with a line end: these end the section.
        if (std.mem.trimStart(u8, bytes, "\r\n").len == 0) return;
        b.trailer = try pool.acquire(b.trailer_io, .large);
    }
    const room = b.trailer.len - trailer_fields * @sizeOf(Field) - @alignOf(Field);
    // The decoder refuses a section past its cap before this could be.
    const n = @min(bytes.len, room - b.trailer_len);
    @memcpy(b.trailer[b.trailer_len..][0..n], bytes[0..n]);
    b.trailer_len += n;
}

/// The trailer section's bytes, once the body is read, when it had fields.
pub fn trailerBytes(b: *Body) ?[]u8 {
    if (b.state.current() != .done or b.trailer.len == 0) return null;
    return b.trailer[0..b.trailer_len];
}

/// Cap the body at `max` bytes: a longer one reads to the cap, then fails
/// with its state `too_large`. For a body of known length the caller
/// compares the length itself, before reading.
pub fn cap(b: *Body, max: u64) void {
    b.allowed = max;
}

/// What one end reads of a body left unread, after its exchange, so the
/// connection can carry the next: at most `bytes`, all of it by `time` from
/// the drain's start. A body that does not end within both is not read on:
/// its connection is closed instead, whatever kept it from ending (more
/// than `bytes` left, a peer that trickles, an event stream that never
/// ends).
pub const Drain = struct {
    bytes: aegis.units.Bytes(u32) = .literal("64KiB"),
    time: Duration = .literal("100ms"),
};

/// Reads the rest of the body for a drain of `bytes`, and says whether the
/// body ended within it. The caller bounds the reads by the drain's time;
/// one that ran past it fails, and the body has not ended.
pub fn drain(b: *Body, bytes: aegis.units.Bytes(u32)) bool {
    if (b.complete()) return true;
    var left: usize = bytes.raw();
    switch (b.framing) {
        // A known length past the budget is not worth reading.
        .length => if (b.remaining > left) return false,
        .chunked => {},
        .none, .until_close => return false,
    }
    while (left > 0) {
        const n = b.interface.discard(.limited(left)) catch return b.complete();
        if (n == 0) break;
        left -= n;
    }
    return b.complete();
}

/// `limit`, no more than `available` and no more than the cap leaves; a
/// body with nothing left under its cap and more to come is too large.
fn capped(b: *Body, limit: Io.Limit, available: u64) error{ReadFailed}!Io.Limit {
    const allowed = b.allowed orelse return limit.min(.limited64(available));
    if (allowed == 0) return b.failed(.too_large);
    return limit.min(.limited64(@min(available, allowed)));
}

fn count(b: *Body, n: usize) void {
    if (b.allowed) |*a| a.* -= n;
}

fn failed(b: *Body, how: Ending) error{ReadFailed} {
    b.end(how);
    return error.ReadFailed;
}

const testing = std.testing;
const test_io = @import("../testing/io.zig");

fn readAll(b: *Body) ![]u8 {
    return b.interface.allocRemaining(testing.allocator, .unlimited);
}

test "a body of known length stops at its length, and one cut short says so" {
    var in: Io.Reader = .fixed("helloNEXT");
    var buf: [4]u8 = undefined;
    var b: Body = .init(&in, .{ .length = 5 }, &buf);
    const got = try readAll(&b);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("hello", got);
    try testing.expect(b.complete());
    try testing.expectEqualStrings("NEXT", in.buffered());
    var short: Io.Reader = .fixed("hel");
    var cut: Body = .init(&short, .{ .length = 5 }, &buf);
    try testing.expectError(error.ReadFailed, readAll(&cut));
    try testing.expectEqual(State.incomplete, cut.state.current());
    try testing.expect(!cut.complete());
}

test "a chunked body is decoded where it lies, and what follows it is left" {
    var in: Io.Reader = .fixed("4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\nNEXT");
    var buf: [3]u8 = undefined;
    var b: Body = .init(&in, .chunked, &buf);
    const got = try readAll(&b);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("Wikipedia", got);
    try testing.expect(b.complete());
    try testing.expectEqualStrings("NEXT", in.buffered());
    var bad: Io.Reader = .fixed("4\r\nWikiXX");
    var malformed: Body = .init(&bad, .chunked, &buf);
    try testing.expectError(error.ReadFailed, readAll(&malformed));
    try testing.expectEqual(State.malformed, malformed.state.current());
}

test "a chunked body's trailer fields are gathered, and an empty section takes nothing" {
    var pool: BufferPool = .init(testing.allocator, 1);
    defer pool.deinit(test_io.io());
    var in: Io.Reader = .fixed("3\r\nabc\r\n0\r\nChecksum: 9\r\n\r\nNEXT");
    var buf: [2]u8 = undefined;
    var b: Body = .init(&in, .chunked, &buf);
    b.trailer_pool = &pool;
    b.trailer_io = test_io.io();
    const got = try readAll(&b);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("abc", got);
    try testing.expectEqualStrings("Checksum: 9\r\n\r\n", b.trailerBytes().?);
    pool.release(test_io.io(), b.trailer);
    var plain: Io.Reader = .fixed("3\r\nabc\r\n0\r\n\r\n");
    var none: Body = .init(&plain, .chunked, &buf);
    none.trailer_pool = &pool;
    none.trailer_io = test_io.io();
    const body = try readAll(&none);
    defer testing.allocator.free(body);
    try testing.expectEqual(null, none.trailerBytes());
}

test "a body to the connection's end, and one with none, end as framed" {
    var in: Io.Reader = .fixed("all of it");
    var buf: [2]u8 = undefined;
    var b: Body = .init(&in, .until_close, &buf);
    const got = try readAll(&b);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("all of it", got);
    var empty: Io.Reader = .fixed("NEXT");
    var none: Body = .init(&empty, .none, &buf);
    try testing.expect(none.complete());
    const nothing = try readAll(&none);
    defer testing.allocator.free(nothing);
    try testing.expectEqual(@as(usize, 0), nothing.len);
}

test "a capped body reads to its cap and then is too large" {
    var in: Io.Reader = .fixed("4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n");
    var buf: [16]u8 = undefined;
    var b: Body = .init(&in, .chunked, &buf);
    b.cap(6);
    try testing.expectError(error.ReadFailed, readAll(&b));
    try testing.expectEqual(State.too_large, b.state.current());
    var fits: Io.Reader = .fixed("4\r\nWiki\r\n0\r\n\r\n");
    var ok: Body = .init(&fits, .chunked, &buf);
    ok.cap(4);
    const got = try readAll(&ok);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("Wiki", got);
}
