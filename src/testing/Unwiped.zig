//! Test-only: an allocator that notes when memory still holding some bytes
//! is freed, which is a secret left behind for the next allocation to find.
//! It refuses every resize, so a block is freed with the contents it had.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Alignment = std.mem.Alignment;

const Unwiped = @This();

inner: Allocator,
/// The bytes that must not be found in freed memory.
needle: []const u8,
/// Set when a block holding `needle` is freed.
found: bool = false,

pub fn init(inner: Allocator, needle: []const u8) Unwiped {
    return .{ .inner = inner, .needle = needle };
}

pub fn allocator(u: *Unwiped) Allocator {
    return .{ .ptr = u, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
}

fn alloc(context: *anyopaque, len: usize, alignment: Alignment, ret_addr: usize) ?[*]u8 {
    const u: *Unwiped = @ptrCast(@alignCast(context)); // safe: `allocator` passes an Unwiped
    return u.inner.rawAlloc(len, alignment, ret_addr);
}

fn resize(_: *anyopaque, _: []u8, _: Alignment, _: usize, _: usize) bool {
    return false;
}

fn remap(_: *anyopaque, _: []u8, _: Alignment, _: usize, _: usize) ?[*]u8 {
    return null;
}

fn free(context: *anyopaque, memory: []u8, alignment: Alignment, ret_addr: usize) void {
    const u: *Unwiped = @ptrCast(@alignCast(context)); // safe: `allocator` passes an Unwiped
    if (std.mem.find(u8, memory, u.needle) != null) u.found = true;
    u.inner.rawFree(memory, alignment, ret_addr);
}

test "memory freed with the needle in it is noticed, and wiped memory is not" {
    var unwiped: Unwiped = .init(std.testing.allocator, "secret");
    const a = unwiped.allocator();
    // `Allocator.free` poisons memory in Debug before the hook sees it.
    const kept = try a.dupe(u8, "a secret");
    std.crypto.secureZero(u8, kept);
    a.rawFree(kept, .of(u8), @returnAddress());
    try std.testing.expect(!unwiped.found);
    const left = try a.dupe(u8, "a secret");
    a.rawFree(left, .of(u8), @returnAddress());
    try std.testing.expect(unwiped.found);
}
