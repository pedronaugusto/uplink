//! The I/O buffers a client's connections and exchanges borrow, in three
//! sizes, kept for reuse once given back: a connection that sits idle holds
//! none of its own, and an exchange on a warm client allocates nothing.
//!
//! Free buffers are kept in a list threaded through their own first bytes,
//! so keeping one costs nothing beside it. Each size keeps at most `max_free`
//! buffers; one given back beyond that is freed.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const tls = @import("../tls.zig");

const BufferPool = @This();

/// Private: where buffers come from and go back to.
gpa: Allocator,
/// Private: held for the free lists.
mutex: Io.Mutex = .init,
/// Private: free buffers of each class.
free: [classes.len]?*Node = @splat(null),
/// Private: how many each list holds.
counts: [classes.len]u32 = @splat(0),
/// The most free buffers kept of each size.
max_free: u32,

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

const classes = [_]usize{ 4 << 10, std.mem.alignForward(usize, tls.Session.min_buffer_len, 64), 72 << 10 };

/// Buffers are aligned so a free one can hold the list's link.
pub const alignment: std.mem.Alignment = .@"64";

const Node = struct { next: ?*Node };

/// An empty pool keeping up to `max_free` free buffers of each size.
pub fn init(gpa: Allocator, max_free: u32) BufferPool {
    return .{ .gpa = gpa, .max_free = max_free };
}

/// Free every kept buffer. Buffers still borrowed must not be given back.
pub fn deinit(p: *BufferPool) void {
    for (&p.free, classes) |*head, len| {
        while (head.*) |node| {
            head.* = node.next;
            p.gpa.free(bytesOf(node, len));
        }
    }
    p.* = undefined;
}

/// A buffer of `class`, a kept one when there is one.
pub fn acquire(p: *BufferPool, io: Io, class: Class) Allocator.Error![]u8 {
    const i = @backingInt(class);
    {
        p.mutex.lockUncancelable(io);
        defer p.mutex.unlock(io);
        if (p.free[i]) |node| {
            p.free[i] = node.next;
            p.counts[i] -= 1;
            return bytesOf(node, classes[i]);
        }
    }
    const bytes = try p.gpa.alignedAlloc(u8, alignment, classes[i]);
    return bytes;
}

/// Give back a buffer `acquire` returned.
pub fn release(p: *BufferPool, io: Io, buffer: []u8) void {
    const class = Class.fitting(buffer.len).?;
    std.debug.assert(buffer.len == class.len());
    const i = @backingInt(class);
    const node: *Node = @ptrCast(@alignCast(buffer.ptr)); // safe: every buffer the pool hands out is aligned for a Node and longer than one
    {
        p.mutex.lockUncancelable(io);
        defer p.mutex.unlock(io);
        if (p.counts[i] < p.max_free) {
            node.* = .{ .next = p.free[i] };
            p.free[i] = node;
            p.counts[i] += 1;
            return;
        }
    }
    p.gpa.free(bytesOf(node, classes[i]));
}

/// How many buffers of `class` are kept free.
pub fn kept(p: *BufferPool, io: Io, class: Class) u32 {
    p.mutex.lockUncancelable(io);
    defer p.mutex.unlock(io);
    return p.counts[@backingInt(class)];
}

fn bytesOf(node: *Node, len: usize) []align(alignment.toByteUnits()) u8 {
    const ptr: [*]align(alignment.toByteUnits()) u8 = @ptrCast(@alignCast(node)); // safe: a node is the first bytes of a buffer the pool allocated with this alignment
    return ptr[0..len];
}

const testing = std.testing;

test "a given-back buffer is handed out again, and past the cap it is freed" {
    const io = testing.io;
    var pool: BufferPool = .init(testing.allocator, 1);
    defer pool.deinit();
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
    try testing.expect(r.len >= tls.Session.min_buffer_len);
    pool.release(io, r);
    try testing.expectEqual(BufferPool.Class.large, BufferPool.Class.fitting(20 << 10).?);
    try testing.expectEqual(null, BufferPool.Class.fitting((72 << 10) + 1));
}
