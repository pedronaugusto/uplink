//! A message head, gathered from a connection into a buffer of the pool
//! with room beside it for its fields and for its body reader's buffer, so
//! that what the head's fields point at stays put while the body is read
//! from the same connection, whose buffer moves its bytes as it refills.
//!
//! The common head is found in the connection's buffer and copied once; one
//! longer than that buffer is gathered piece by piece, taking from the
//! connection only the head's bytes, never what follows it. The client
//! parses a response in it, and the server a request.

const std = @import("std");
const layout = @import("../place.zig");
const Io = std.Io;
const wire = @import("uplink.wire");
const h1 = wire.h1;
const Field = wire.fields.Field;
const BufferPool = @import("BufferPool.zig");

const Head = @This();

/// The pooled buffer: the head's bytes first.
buffer: []u8,
/// The head's length, its blank line included.
len: usize,
/// The most fields the buffer has room for.
max_fields: u16,

/// The smallest body reader buffer a head buffer leaves.
pub const min_body_buffer = 1024;

/// Why no head was gathered.
pub const Error = error{
    /// No blank line within `Limits.max_head`, the start line ended.
    HeadTooLarge,
    /// The start line alone is past `Limits.max_head`: a target too long,
    /// after its method.
    StartLineTooLong,
    /// Past `Limits.max_head` with no space in it: no start line at all.
    NoStartLine,
    /// The connection ended before the head did; `progress` says whether
    /// any of it came.
    EndOfStream,
    /// The connection failed: its owner says why.
    ReadFailed,
    OutOfMemory,
};

fn fieldsBytes(max_fields: u16) usize {
    return @as(usize, max_fields) * @sizeOf(Field);
}

/// Gather one head from `r`, taking exactly its bytes. `progress` is set
/// once a byte of it has arrived.
pub fn gather(io: Io, pool: *BufferPool, r: *Io.Reader, limits: h1.Limits, progress: *bool) Error!Head {
    var scan: usize = 0;
    while (true) {
        const buffered = r.buffered();
        if (buffered.len != 0) progress.* = true;
        const window = buffered[0..@min(buffered.len, limits.max_head.raw())];
        if (h1.findHeadEnd(window, scan)) |end| {
            const head = try place(io, pool, buffered[0..end], limits);
            r.toss(end);
            return head;
        }
        if (limits.headFull(buffered.len)) return oversize(window);
        if (buffered.len == r.buffer.len) return gatherLong(io, pool, r, limits);
        scan = buffered.len -| 3;
        r.fillMore() catch |err| return switch (err) {
            error.EndOfStream => error.EndOfStream,
            error.ReadFailed => error.ReadFailed,
        };
    }
}

/// Which part of a head that passed its limit, `start` its start, was too
/// long.
fn oversize(start: []const u8) Error {
    if (std.mem.findScalar(u8, start, '\n') != null) return error.HeadTooLarge;
    if (std.mem.findScalar(u8, start, ' ') != null) return error.StartLineTooLong;
    return error.NoStartLine;
}

/// A head longer than the connection's buffer: gathered piece by piece into
/// a large pooled buffer.
fn gatherLong(io: Io, pool: *BufferPool, r: *Io.Reader, limits: h1.Limits) Error!Head {
    const buffer = try pool.acquire(io, .large);
    errdefer pool.release(io, buffer);
    const cap = @min(limits.max_head.raw(), buffer.len - fieldsBytes(limits.max_fields) - min_body_buffer - @alignOf(Field));
    var len: usize = 0;
    while (true) {
        const chunk = r.buffered();
        const take = @min(chunk.len, cap - len);
        @memcpy(buffer[len..][0..take], chunk[0..take]);
        if (h1.findHeadEnd(buffer[0 .. len + take], len -| 3)) |end| {
            r.toss(end - len);
            return .{ .buffer = buffer, .len = end, .max_fields = limits.max_fields };
        }
        r.toss(take);
        len += take;
        if (len == cap) return oversize(buffer[0..len]);
        r.fillMore() catch |err| return switch (err) {
            error.EndOfStream => error.EndOfStream,
            error.ReadFailed => error.ReadFailed,
        };
    }
}

/// Copy `whole`, a whole head, into a pooled buffer that fits it, its
/// fields and a body reader buffer.
fn place(io: Io, pool: *BufferPool, whole: []const u8, limits: h1.Limits) Error!Head {
    const need = std.mem.alignForward(usize, whole.len, @alignOf(Field)) + fieldsBytes(limits.max_fields) + min_body_buffer;
    const class = BufferPool.Class.fitting(@max(need, BufferPool.Class.record.len())) orelse return error.HeadTooLarge;
    const buffer = try pool.acquire(io, class);
    @memcpy(buffer[0..whole.len], whole);
    return .{ .buffer = buffer, .len = whole.len, .max_fields = limits.max_fields };
}

/// The head's bytes, to parse in place.
pub fn bytes(h: *const Head) []u8 {
    return h.buffer[0..h.len];
}

/// Where the head's fields go.
pub fn fields(h: *const Head) []Field {
    const at = std.mem.alignForward(usize, h.len, @alignOf(Field));
    const ptr = layout.many(Field, h.buffer.ptr, at); // pool buffers are 64-aligned, `at` is aligned for a Field, and the buffer has room for `max_fields` of them
    return ptr[0..h.max_fields];
}

/// What the buffer leaves for the body reader.
pub fn bodyBuffer(h: *const Head) []u8 {
    const at = std.mem.alignForward(usize, h.len, @alignOf(Field)) + fieldsBytes(h.max_fields);
    return h.buffer[at..];
}

/// Give the buffer back.
pub fn release(h: *Head, io: Io, pool: *BufferPool) void {
    pool.release(io, h.buffer);
    h.* = undefined;
}

const testing = std.testing;
const test_io = @import("../testing/io.zig");
const repeat = @import("shakedown").corpus.repeat;

test "a head is taken exactly from what follows it, short or longer than the reader's buffer" {
    const io = test_io.io();
    var pool: BufferPool = .init(testing.allocator, 2);
    defer pool.deinit(io);
    var progress = false;
    var short: Io.Reader = .fixed("GET / HTTP/1.1\r\nHost: a\r\n\r\nNEXT");
    var head = try gather(io, &pool, &short, .{}, &progress);
    try testing.expect(progress);
    try testing.expectEqualStrings("GET / HTTP/1.1\r\nHost: a\r\n\r\n", head.bytes());
    try testing.expectEqualStrings("NEXT", short.buffered());
    try testing.expect(head.bodyBuffer().len >= min_body_buffer);
    try testing.expectEqual(@as(usize, 100), head.fields().len);
    head.release(io, &pool);

    // Through a reader whose buffer holds 8 bytes at a time.
    const text = "GET /long HTTP/1.1\r\nX-Pad: " ++ repeat("p", 40) ++ "\r\n\r\nNEXT";
    var source: Io.Reader = .fixed(text);
    var small: [8]u8 = undefined;
    var limited = source.limited(.unlimited, &small);
    var long = try gather(io, &pool, &limited.interface, .{}, &progress);
    try testing.expectEqualStrings(text[0 .. text.len - 4], long.bytes());
    long.release(io, &pool);

    var cut: Io.Reader = .fixed("GET / HTTP/1.1\r\nHo");
    try testing.expectError(error.EndOfStream, gather(io, &pool, &cut, .{}, &progress));
    var huge: Io.Reader = .fixed("GET / HTTP/1.1\r\nX: " ++ repeat("a", 100));
    try testing.expectError(error.HeadTooLarge, gather(io, &pool, &huge, .{ .max_head = .fromRaw(64) }, &progress));
}
