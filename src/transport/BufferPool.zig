//! The I/O buffers a client's connections and exchanges borrow, in three
//! sizes, kept for reuse once given back: a connection that sits idle holds
//! none of its own, and an exchange on a warm client allocates nothing.
//!
//! Free buffers are kept in a list threaded through their own first bytes,
//! so keeping one costs nothing beside it. Each size keeps at most `max_free`
//! buffers; one given back beyond that is freed.

const std = @import("std");
const place = @import("../place.zig");
const aegis = @import("aegis");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const tls = @import("../tls.zig");

const BufferPool = @This();

/// Private: where buffers come from and go back to.
gpa: Allocator,
/// Private: the free lists, reached only through the lock beside them.
lists: aegis.BlockingGuarded(Lists),
/// The most free buffers kept of each size.
max_free: u32,

/// The free buffers of each class and how many each list holds.
const Lists = struct {
    free: [classes.len]?*Node = @splat(null),
    counts: [classes.len]u32 = @splat(0),
};

/// The sizes buffers come in.
pub const Class = enum(u2) {
    /// A response head and its fields.
    small,
    /// One whole TLS record: a socket or TLS layer's buffer.
    record,
    /// A decompression window (64 KiB), or a head too long for `record`
    /// with its fields beside it.
    large,

    /// The bytes a buffer of this class holds.
    pub fn len(c: Class) usize {
        return classes[@backingInt(c)];
    }

    /// The smallest class holding `n` bytes, or null past the largest.
    pub fn fitting(n: usize) ?Class {
        inline for (comptime std.enums.values(Class)) |c| if (n <= c.len()) return c;
        return null;
    }
};

const classes = [_]usize{ 4 << 10, std.mem.alignForward(usize, tls.record_buffer_len, 64), 72 << 10 };

/// Buffers are aligned so a free one can hold the list's link, and so
/// what is placed past a head or a window is aligned.
pub const alignment: std.mem.Alignment = .@"64";

/// A buffer the pool hands out, with the alignment it was allocated with.
pub const Buffer = []align(alignment.toByteUnits()) u8;

/// A free buffer's first bytes: the next free one, and the buffer itself.
const Node = struct { next: ?*Node, bytes: Buffer };

/// An empty pool keeping up to `max_free` free buffers of each size.
pub fn init(gpa: Allocator, max_free: u32) BufferPool {
    return .{ .gpa = gpa, .lists = .init(.{}), .max_free = max_free };
}

/// Free every kept buffer. Buffers still borrowed must not be given back.
pub fn deinit(p: *BufferPool, io: Io) void {
    var held = p.lists.acquireUncancelable(io);
    const lists = held.value();
    for (&lists.free, classes) |*head, len| {
        while (head.*) |node| {
            head.* = node.next;
            std.debug.assert(node.bytes.len == len);
            p.gpa.free(node.bytes);
        }
    }
    held.deinit(io);
    p.* = undefined;
}

/// A buffer of `class`, a kept one when there is one.
pub fn acquire(p: *BufferPool, io: Io, class: Class) Allocator.Error!Buffer {
    const i = @backingInt(class);
    {
        var held = p.lists.acquireUncancelable(io);
        defer held.deinit(io);
        const lists = held.value();
        if (lists.free[i]) |node| {
            lists.free[i] = node.next;
            lists.counts[i] -= 1;
            return node.bytes;
        }
    }
    return p.gpa.alignedAlloc(u8, alignment, classes[i]);
}

/// Give back a buffer `acquire` returned.
pub fn release(p: *BufferPool, io: Io, buffer: Buffer) void {
    const class = Class.fitting(buffer.len).?;
    std.debug.assert(buffer.len == class.len());
    const i = @backingInt(class);
    const node = place.one(Node, buffer, 0);
    {
        var held = p.lists.acquireUncancelable(io);
        defer held.deinit(io);
        const lists = held.value();
        if (lists.counts[i] < p.max_free) {
            node.* = .{ .next = lists.free[i], .bytes = buffer };
            lists.free[i] = node;
            lists.counts[i] += 1;
            return;
        }
    }
    p.gpa.free(buffer);
}

/// How many buffers of `class` are kept free.
pub fn kept(p: *BufferPool, io: Io, class: Class) u32 {
    var held = p.lists.acquireUncancelable(io);
    defer held.deinit(io);
    return held.value().counts[@backingInt(class)];
}

const testing = std.testing;
const test_io = @import("../testing/io.zig");

test "a given-back buffer is handed out again, and past the cap it is freed" {
    const io = test_io.io();
    var pool: BufferPool = .init(testing.allocator, 1);
    defer pool.deinit(io);
    const a = try pool.acquire(io, .small);
    const b = try pool.acquire(io, .small);
    try testing.expectEqual(@as(usize, 4096), a.len);
    pool.release(io, a);
    pool.release(io, b);
    try testing.expectEqual(@as(u32, 1), pool.kept(io, .small));
    const c = try pool.acquire(io, .small);
    try testing.expectEqual(a.ptr, c.ptr);
    pool.release(io, c);
    const r = try pool.acquire(io, .record);
    try testing.expect(r.len >= tls.record_buffer_len);
    pool.release(io, r);
    try testing.expectEqual(BufferPool.Class.large, BufferPool.Class.fitting(20 << 10).?);
    try testing.expectEqual(null, BufferPool.Class.fitting((72 << 10) + 1));
}
