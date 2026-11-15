//! The one place uplink reads its own buffers as typed records: a pool
//! buffer's trailing fields, a decoder's state past its window, an encoder
//! at the end of its block, a free list's node at the front of a buffer.
//! Each takes the buffer as its type declares it and checks what it places:
//! at compile time that the buffer is declared aligned for a `T`, and in
//! every safe build that the offset keeps that alignment and the buffer
//! holds every `T` placed.

const std = @import("std");
const aegis = @import("aegis");
const wire = @import("uplink.wire");
const message = wire.h2.message;
const Field = wire.fields.Field;

/// The `count` `T`s that start `offset` bytes into `bytes`, a slice of
/// bytes declared aligned for a `T`.
pub fn many(comptime T: type, bytes: anytype, offset: usize, count: usize) []T {
    comptime aegis.assert.invariant(declared(@TypeOf(bytes)) >= @alignOf(T), "declared(@TypeOf(bytes)) >= @alignOf(T)");
    aegis.assert.invariant(std.mem.isAligned(offset, @alignOf(T)), "std.mem.isAligned(offset, @alignOf(T))");
    const part = bytes[offset..][0 .. count * @sizeOf(T)];
    const typed: []align(@alignOf(T)) u8 = @alignCast(part); // `bytes` is declared aligned for a `T` and `offset` is checked to keep that
    return std.mem.bytesAsSlice(T, typed);
}

/// The `T` that starts `offset` bytes into `bytes`, a slice of bytes
/// declared aligned for a `T`.
pub fn one(comptime T: type, bytes: anytype, offset: usize) *T {
    return &many(T, bytes, offset, 1)[0];
}

/// HTTP/2's decoded `fields` kept in `buffer`, a pooled buffer declared
/// aligned for a field: their strings first, then the fields, as
/// `message.Layout` lays them out; null when the buffer is too small.
pub fn fields(buffer: []align(@alignOf(Field)) u8, decoded: []const wire.hpack.Field) ?[]Field {
    const layout: message.Layout = .of(decoded);
    if (layout.len(decoded.len) > buffer.len) return null;
    const out = many(Field, buffer, layout.fields_at, decoded.len);
    return message.copy(buffer[0..layout.strings], out, decoded) catch aegis.assert.never("the layout gives each its room");
}

/// The alignment a slice of bytes is declared with.
fn declared(comptime Bytes: type) usize {
    const slice = switch (@typeInfo(Bytes)) {
        .pointer => |p| p,
        else => @compileError("place takes a slice of bytes, not " ++ @typeName(Bytes)),
    };
    if (slice.size != .slice or slice.child != u8) @compileError("place takes a slice of bytes, not " ++ @typeName(Bytes));
    return std.meta.alignment(Bytes);
}

test "records are placed inside the buffer, at the offset asked" {
    var buffer: [64]u8 align(8) = undefined;
    const bytes: []align(8) u8 = &buffer;
    const words = many(u64, bytes, 16, 3);
    try std.testing.expectEqual(@as(usize, 3), words.len);
    try std.testing.expectEqual(@as(*u8, &buffer[16]), @as(*u8, @ptrCast(&words[0])));
    one(u32, bytes, 60).* = 7;
    try std.testing.expectEqual(@as(u32, 7), std.mem.readInt(u32, buffer[60..64], @import("builtin").cpu.arch.endian()));
}
