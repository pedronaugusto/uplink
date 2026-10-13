//! The memory a zstd body is decoded in, and the cap on a frame's window.
//!
//! A zstd frame names its window, up to gigabytes, and a decoder must keep
//! that much history; so the window a body may ask for is capped, and the
//! buffer it is decoded in is sized for the cap: the reader's own 4 KiB,
//! the window, one block, then the decoder's state. A frame whose window
//! passes the cap is refused as it is read. One buffer is kept for the
//! next zstd body, taken and given back with one atomic swap, whose winner
//! owns it; there is no state beside it for a lock to guard.

const std = @import("std");
const aegis = @import("aegis");
const warp = @import("warp");
const Allocator = std.mem.Allocator;

const ZstdBuffer = @This();

/// Private: the buffer kept for the next body.
kept: std.atomic.Value(?[*]u8) = .init(null),
/// The largest frame window a body may ask for.
max_window: aegis.units.Bytes(u32),
/// Private: the length of every buffer, the decoder's state included.
len: usize,

/// The decoder a buffer holds, after its reading room.
pub const State = warp.zstd.Decompress.Reader;

/// The room a decoder reads into before its window: `State.init` keeps it
/// for the reader's own buffering.
const reader_room = 4096;

/// The most a zstd block decodes to (RFC 8878 §3.1.1.2.4), which a decoder
/// keeps room for beside the window.
const block_max = 128 << 10;

/// Buffers for frames whose window is at most `max_window`.
pub fn init(max_window: aegis.units.Bytes(u32)) ZstdBuffer {
    return .{ .max_window = max_window, .len = bufferLen(max_window) };
}

/// The length of a buffer for `max_window`: the reading room, the window
/// and a block, aligned, then the state. A length no address space holds is
/// the largest there is, which no allocation gives.
fn bufferLen(max_window: aegis.units.Bytes(u32)) usize {
    const read = readLen(max_window);
    const at = std.mem.alignForward(usize, read, @alignOf(State));
    const whole = aegis.int.Checked(usize).init(at).add(@sizeOf(State)) catch return std.math.maxInt(usize);
    return whole.raw();
}

/// The part of a buffer the decoder reads and decodes into.
fn readLen(max_window: aegis.units.Bytes(u32)) usize {
    const room = aegis.int.Checked(usize).init(max_window.raw()).add(reader_room + block_max) catch return std.math.maxInt(usize);
    return room.raw();
}

/// The reading part of `buffer`, and its state after it.
pub fn split(z: *const ZstdBuffer, buffer: []u8) struct { []u8, *State } {
    std.debug.assert(buffer.len == z.len);
    const read = readLen(z.max_window);
    const at = std.mem.alignForward(usize, read, @alignOf(State));
    return .{ buffer[0..read], @ptrCast(@alignCast(buffer.ptr + at)) }; // safe: buffers are 64-aligned, `at` is aligned for State, and `len` holds a State past it
}

/// A buffer: the one kept, or a new one.
pub fn acquire(z: *ZstdBuffer, gpa: Allocator) Allocator.Error![]u8 {
    if (z.kept.swap(null, .acq_rel)) |b| return b[0..z.len];
    return gpa.alignedAlloc(u8, .@"64", z.len);
}

/// Give a buffer back: kept when none is, freed otherwise.
pub fn release(z: *ZstdBuffer, gpa: Allocator, buffer: []u8) void {
    std.debug.assert(buffer.len == z.len);
    if (z.kept.cmpxchgStrong(null, buffer.ptr, .acq_rel, .acquire) == null) return;
    gpa.free(aligned(buffer));
}

/// Free the kept buffer.
pub fn deinit(z: *ZstdBuffer, gpa: Allocator) void {
    if (z.kept.load(.acquire)) |b| gpa.free(aligned(b[0..z.len]));
    z.* = undefined;
}

fn aligned(buffer: []u8) []align(64) u8 {
    return @alignCast(buffer); // safe: every zstd buffer is allocated 64-aligned
}

test "a buffer given back is the next one taken, and a second given back is freed" {
    const gpa = std.testing.allocator;
    var z: ZstdBuffer = .init(.fromRaw(64 << 10));
    defer z.deinit(gpa);
    const a = try z.acquire(gpa);
    const b = try z.acquire(gpa);
    z.release(gpa, a);
    z.release(gpa, b);
    const c = try z.acquire(gpa);
    try std.testing.expectEqual(a.ptr, c.ptr);
    const read, const state = z.split(c);
    try std.testing.expect(@intFromPtr(state) >= @intFromPtr(read.ptr) + read.len);
    try std.testing.expect(@intFromPtr(state) + @sizeOf(State) <= @intFromPtr(c.ptr) + c.len);
    z.release(gpa, c);
}
