//! A body's codings undone, through warp's streaming decoders: a chain of
//! readers, the first over the body as its framing delimits it, each
//! undoing one coding, the last applied first.
//!
//! What a coding promises is checked: gzip's CRC-32 and length and zlib's
//! Adler-32 at the end of each stream, zstd's content checksum where a
//! frame carries one, a gzip body of several members read whole, and a
//! stream cut short refused rather than ended. HTTP's `deflate` is zlib,
//! and a raw DEFLATE stream, which some servers send under that name, is
//! read too.
//!
//! A gzip or deflate layer lives in one large buffer of the pool, its
//! history and then its decoder's state; a zstd layer in a `ZstdBuffer`.
//! The decoder itself is the list of those buffers, so whoever holds a
//! body holds a few words more. Once started it must not move: each
//! layer reads from the one before it.

const std = @import("std");
const place = @import("../place.zig");
const warp = @import("warp");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const wire = @import("uplink.wire");
const ContentCoding = wire.coding.ContentCoding;
const Codings = wire.coding.Codings;
const BufferPool = @import("../transport/BufferPool.zig");
const ZstdBuffer = @import("ZstdBuffer.zig");

const Decoder = @This();

/// Private: one per coding, in the order the codings were applied.
layers: [Codings.max]Layer = undefined,
len: u8 = 0,

const Layer = struct {
    coding: ContentCoding,
    /// A pool buffer, or a zstd one: both 64-aligned.
    buffer: []align(64) u8,
};

const Flate = warp.Inflate.Reader;

/// Why a coded body does not decode.
pub const Error = error{
    /// Not a stream of its coding, or one that breaks the coding's rules.
    InvalidStream,
    /// A checksum or length in the stream is not the data's.
    ChecksumMismatch,
    /// A stream that names a dictionary.
    DictionaryMismatch,
    /// A zstd frame whose window passes the cap.
    WindowTooLarge,
    /// The body ended inside a stream.
    Truncated,
};

/// A flate layer's buffer: the history, then the state.
const FlateSplit = struct { history: usize, state_at: usize };

fn flateSplit(len: usize) FlateSplit {
    const at = std.mem.alignBackward(usize, len - @sizeOf(Flate), @alignOf(Flate));
    return .{ .history = at, .state_at = at };
}

comptime {
    // A flate layer's history, a whole 32 KiB window and the room the
    // reader decodes ahead into, fits beside its state in a large buffer.
    std.debug.assert(flateSplit(BufferPool.Class.large.len()).history >= (32 << 10) + 4096);
}

/// Whether every one of `codings` is one warp decodes: gzip, deflate or
/// zstd. Any other is handed over as it came.
pub fn decodes(codings: []const ContentCoding) bool {
    for (codings) |c| switch (c) {
        .gzip, .deflate, .zstd => {},
        .identity, .br => return false,
    };
    return true;
}

/// A decoder for `codings`, each of which `decodes`, with its buffers
/// taken: from `buffers` for gzip and deflate, from `zstd` for zstd.
pub fn init(io: Io, gpa: Allocator, buffers: *BufferPool, zstd: *ZstdBuffer, codings: []const ContentCoding) Allocator.Error!Decoder {
    std.debug.assert(decodes(codings));
    std.debug.assert(codings.len <= Codings.max);
    var d: Decoder = .{};
    errdefer d.deinit(io, gpa, buffers, zstd);
    for (codings) |c| {
        const buffer = if (c == .zstd) try zstd.acquire(gpa) else try buffers.acquire(io, .large);
        d.layers[d.len] = .{ .coding = c, .buffer = buffer };
        d.len += 1;
    }
    return d;
}

/// Start reading: the last-applied coding's layer over `source`, each
/// layer before it over the one after, and the decoded body from the
/// returned reader. `zstd` is the one the decoder's buffers came from.
pub fn start(d: *Decoder, source: *Io.Reader, zstd: *const ZstdBuffer) *Io.Reader {
    var in = source;
    var i = d.len;
    while (i > 0) {
        i -= 1;
        const l = &d.layers[i];
        in = switch (l.coding) {
            .zstd => zstd: {
                const room, const state = zstd.split(l.buffer);
                state.* = .init(in, room, .{});
                break :zstd &state.interface;
            },
            else => flate: {
                const state = flateOf(l);
                state.* = .init(in, l.buffer[0..flateSplit(l.buffer.len).history], .{ .accept = accept(l.coding) });
                break :flate &state.interface;
            },
        };
    }
    return in;
}

fn flateOf(l: *const Layer) *Flate {
    return place.one(Flate, l.buffer, flateSplit(l.buffer.len).state_at);
}

/// What a flate layer for `coding` accepts: gzip's members, every one; for
/// `deflate`, zlib or, failing its header, raw DEFLATE.
fn accept(coding: ContentCoding) warp.Accept {
    return switch (coding) {
        .gzip => .gzip,
        else => .zlib_or_raw,
    };
}

/// Why the last read failed, when a layer refused its stream rather than
/// the body under it failing: the layer nearest the body first.
pub fn failure(d: *const Decoder, zstd: *const ZstdBuffer) ?Error {
    var i = d.len;
    while (i > 0) {
        i -= 1;
        const l = &d.layers[i];
        const err: ?Error = switch (l.coding) {
            .zstd => if (zstd.split(l.buffer)[1].err()) |e| zstdError(e) else null,
            else => if (flateOf(l).err()) |e| flateError(e) else null,
        };
        if (err) |e| return e;
    }
    return null;
}

fn zstdError(e: warp.zstd.Decompress.Error) Error {
    return switch (e) {
        error.InvalidStream => error.InvalidStream,
        error.ChecksumMismatch => error.ChecksumMismatch,
        error.DictionaryMismatch => error.DictionaryMismatch,
        error.WindowTooLarge => error.WindowTooLarge,
        error.Truncated => error.Truncated,
        // A reader's decoder has no output of its own to fill.
        error.OutputTooSmall => error.InvalidStream,
    };
}

fn flateError(e: Flate.ReadError) Error {
    return switch (e) {
        error.InvalidStream => error.InvalidStream,
        error.ChecksumMismatch => error.ChecksumMismatch,
        error.DictionaryMismatch => error.DictionaryMismatch,
        error.Truncated => error.Truncated,
    };
}

/// Give the buffers back to where `init` took them from.
pub fn deinit(d: *Decoder, io: Io, gpa: Allocator, buffers: *BufferPool, zstd: *ZstdBuffer) void {
    for (d.layers[0..d.len]) |l| switch (l.coding) {
        .zstd => zstd.release(gpa, l.buffer),
        else => buffers.release(io, l.buffer),
    };
    d.len = 0;
}

const testing = std.testing;
const test_io = @import("../testing/io.zig");

/// `text` compressed under `container`, by warp.
fn compressed(gpa: Allocator, container: warp.Container, text: []const u8) ![]u8 {
    var compressor: warp.Compressor = try .init(gpa, .{ .level = 6 });
    defer compressor.deinit();
    const frame: warp.Compressor.Frame = .{ .container = container };
    const out = try gpa.alloc(u8, warp.Compressor.bound(text.len, frame));
    errdefer gpa.free(out);
    const n = try compressor.compress(text, out, frame);
    return gpa.realloc(out, n);
}

/// `text` as one zstd frame with its checksum.
fn zstdFrame(gpa: Allocator, text: []const u8) ![]u8 {
    var compressor: warp.zstd.Compressor = try .init(gpa, .{});
    defer compressor.deinit();
    const out = try gpa.alloc(u8, warp.zstd.Compressor.bound(text.len));
    errdefer gpa.free(out);
    const n = try compressor.compress(text, out, .{ .checksum = true });
    return gpa.realloc(out, n);
}

/// What decoding `coded` under `codings` gives, read whole.
fn decoded(gpa: Allocator, codings: []const ContentCoding, coded: []const u8) (Error || error{ OutOfMemory, StreamTooLong })![]u8 {
    const io = test_io.io();
    var buffers: BufferPool = .init(gpa, 2);
    defer buffers.deinit(io);
    var zstd: ZstdBuffer = .init(.fromRaw(1 << 20));
    defer zstd.deinit(gpa);
    var d = try init(io, gpa, &buffers, &zstd, codings);
    defer d.deinit(io, gpa, &buffers, &zstd);
    var source: Io.Reader = .fixed(coded);
    const r = d.start(&source, &zstd);
    return r.allocRemaining(gpa, .limited(1 << 20)) catch |err| switch (err) {
        error.ReadFailed => d.failure(&zstd).?,
        error.OutOfMemory => error.OutOfMemory,
        error.StreamTooLong => error.StreamTooLong,
    };
}

test "gzip, deflate as zlib and raw, and zstd are decoded, and a chain of them undone last first" {
    const gpa = testing.allocator;
    const text = "a body worth compressing: repeated repeated repeated repeated";
    for ([_]struct { warp.Container, ContentCoding }{ .{ .gzip, .gzip }, .{ .zlib, .deflate }, .{ .raw, .deflate } }) |case| {
        const coded = try compressed(gpa, case[0], text);
        defer gpa.free(coded);
        const body = try decoded(gpa, &.{case[1]}, coded);
        defer gpa.free(body);
        try testing.expectEqualStrings(text, body);
    }
    const z = try zstdFrame(gpa, text);
    defer gpa.free(z);
    const body = try decoded(gpa, &.{.zstd}, z);
    defer gpa.free(body);
    try testing.expectEqualStrings(text, body);
    // gzip applied first, then zstd: zstd comes off first.
    const inner = try compressed(gpa, .gzip, text);
    defer gpa.free(inner);
    const outer = try zstdFrame(gpa, inner);
    defer gpa.free(outer);
    const chained = try decoded(gpa, &.{ .gzip, .zstd }, outer);
    defer gpa.free(chained);
    try testing.expectEqualStrings(text, chained);
}

test "a gzip body of two members is read whole" {
    const gpa = testing.allocator;
    const a = try compressed(gpa, .gzip, "first member, ");
    defer gpa.free(a);
    const b = try compressed(gpa, .gzip, "second member");
    defer gpa.free(b);
    const both = try std.mem.concat(gpa, u8, &.{ a, b });
    defer gpa.free(both);
    const body = try decoded(gpa, &.{.gzip}, both);
    defer gpa.free(body);
    try testing.expectEqualStrings("first member, second member", body);
}

test "a checksum that is not the data's, a stream cut short and a window past the cap are refused" {
    const gpa = testing.allocator;
    const text = "a body worth compressing: repeated repeated repeated repeated";
    for ([_]struct { warp.Container, ContentCoding }{ .{ .gzip, .gzip }, .{ .zlib, .deflate } }) |case| {
        const coded = try compressed(gpa, case[0], text);
        defer gpa.free(coded);
        // The trailer's checksum is in its last four bytes (gzip's length
        // after it): flip a bit of the CRC or the Adler-32.
        const at = if (case[0] == .gzip) coded.len - 8 else coded.len - 1;
        coded[at] ^= 1;
        try testing.expectError(error.ChecksumMismatch, decoded(gpa, &.{case[1]}, coded));
        coded[at] ^= 1;
        try testing.expectError(error.Truncated, decoded(gpa, &.{case[1]}, coded[0 .. coded.len - 2]));
    }
    const z = try zstdFrame(gpa, text);
    defer gpa.free(z);
    z[z.len - 1] ^= 1;
    try testing.expectError(error.ChecksumMismatch, decoded(gpa, &.{.zstd}, z));
    z[z.len - 1] ^= 1;
    try testing.expectError(error.Truncated, decoded(gpa, &.{.zstd}, z[0 .. z.len - 3]));
    // `hello` in one raw block, in a frame declaring a window of 2^24, past
    // the test's cap of 1 MiB.
    const wide = "\x28\xb5\x2f\xfd\x00" ++ .{@as(u8, 24 - 10) << 3} ++ "\x29\x00\x00hello";
    try testing.expectError(error.WindowTooLarge, decoded(gpa, &.{.zstd}, wide));
}

test "only gzip, deflate and zstd are decoded" {
    try testing.expect(decodes(&.{ .gzip, .deflate, .zstd }));
    try testing.expect(!decodes(&.{ .gzip, .br }));
    try testing.expect(decodes(&.{}));
}
