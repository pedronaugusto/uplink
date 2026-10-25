//! The one place uplink reads its own buffers as typed records: a pool
//! buffer's trailing fields, a decoder's state past its window, an encoder
//! at the end of its block, a free list's node at the front of a buffer. A
//! buffer given here was allocated by uplink, aligned for what its caller
//! places in it; the alignment is checked in every safe build.

const std = @import("std");

/// The `T`s that start `offset` bytes into `bytes`.
pub fn many(comptime T: type, bytes: [*]u8, offset: usize) [*]T {
    return @ptrCast(@alignCast(bytes + offset)); // aegis: internal: uplink allocated `bytes` aligned for the `T`s each caller lays out at `offset`
}

/// The `T` that starts `offset` bytes into `bytes`.
pub fn one(comptime T: type, bytes: [*]u8, offset: usize) *T {
    return &many(T, bytes, offset)[0];
}

/// The front of the buffer `record` was placed at the start of, as it was
/// allocated.
pub fn front(comptime alignment: std.mem.Alignment, record: anytype) [*]align(alignment.toByteUnits()) u8 {
    return @ptrCast(@alignCast(record)); // aegis: internal: a record placed at the front of a buffer uplink allocated with this alignment
}

/// `bytes` with the alignment uplink allocated them with, for the free that
/// must name it.
pub fn aligned(comptime alignment: std.mem.Alignment, bytes: []u8) []align(alignment.toByteUnits()) u8 {
    return @alignCast(bytes); // aegis: internal: uplink allocated these bytes with this alignment
}
