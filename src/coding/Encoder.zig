//! A body put under one coding as it is written, through warp's streaming
//! encoders: gzip and deflate (zlib) by warp's DEFLATE, zstd by warp's
//! Zstandard with a checksum in every frame, Brotli by warp's Brotli.
//!
//! An encoder and everything it writes through lives in one block of
//! memory, taken from a `Pool` that keeps blocks for the next body: the
//! codec's tables and window, the input it stages, and the output it
//! hands on in pieces. Brotli's encoder grows its own buffers, which its
//! block keeps and its next body reuses. So a server compressing its
//! responses allocates nothing once it is warm.

const std = @import("std");
const place = @import("../place.zig");
const aegis = @import("aegis");
const warp = @import("warp");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const ContentCoding = @import("uplink.wire").coding.ContentCoding;

const Encoder = @This();

coding: Coding,
/// Private: the codec's state, in the block before this value.
state: State,
/// Private: the codec's writer, staging input.
writer_: Writer,
/// Private: the block this encoder lives in.
block: []align(64) u8,

/// The codings an encoder writes.
pub const Coding = enum {
    gzip,
    deflate,
    zstd,
    br,

    /// The coding's name in `Content-Encoding`.
    pub fn name(c: Coding) []const u8 {
        return @tagName(c);
    }

    /// The content coding it is.
    pub fn content(c: Coding) ContentCoding {
        return switch (c) {
            .gzip => .gzip,
            .deflate => .deflate,
            .zstd => .zstd,
            .br => .br,
        };
    }
};

const State = union { flate: warp.Deflate, zstd: warp.zstd.Compress, brotli: warp.brotli.Compress };
const Writer = union { flate: warp.Deflate.Writer, zstd: warp.zstd.Compress.Writer, brotli: warp.brotli.Compress.Writer };

/// How hard each coding works.
pub const Settings = struct {
    /// 1-9, zlib's scale.
    deflate_level: u4 = 5,
    zstd_level: i32 = 3,
    /// The window a zstd frame names, 2^this: a decoder keeps that much,
    /// and browsers take at most 8 MiB (RFC 9659).
    zstd_window_log: u5 = 20,
    /// 0-11, Brotli's scale: 11, its default, is for bodies compressed once
    /// and kept, far too slow for a response written as it is asked for.
    brotli_quality: u4 = 5,
    /// The window a Brotli stream names, 2^this: a decoder keeps that much.
    brotli_window_bits: u5 = 20,
};

/// The input staged before it is encoded.
const stage_len = 4096;

fn deflateOptions(s: Settings, container: warp.Container) warp.Deflate.Options {
    return .{ .level = s.deflate_level, .max_level = s.deflate_level, .container = container };
}

fn zstdOptions(s: Settings) warp.zstd.Compress.Options {
    return .{ .level = s.zstd_level, .tuning = .{ .window_log = s.zstd_window_log }, .frame = .{ .checksum = true, .content_size = false } };
}

fn brotliOptions(s: Settings) warp.brotli.Compress.Options {
    return .{ .quality = s.brotli_quality, .window_bits = s.brotli_window_bits };
}

/// The codec's part of a block for `coding`: none for Brotli, whose encoder
/// holds its own.
fn codecLen(s: Settings, coding: Coding) usize {
    const n = switch (coding) {
        .gzip => warp.Deflate.memory(deflateOptions(s, .gzip)),
        .deflate => warp.Deflate.memory(deflateOptions(s, .zlib)),
        .zstd => warp.zstd.Compress.memory(zstdOptions(s)),
        .br => 0,
    };
    return std.mem.alignForward(usize, n, 64);
}

fn blockLen(s: Settings, coding: Coding) usize {
    return std.mem.alignForward(usize, codecLen(s, coding) + stage_len, @alignOf(Encoder)) + @sizeOf(Encoder);
}

/// The encoder's writer: what is written to it is encoded onto the
/// output it was started with.
pub fn writer(e: *Encoder) *Io.Writer {
    return switch (e.coding) {
        .gzip, .deflate => &e.writer_.flate.interface,
        .zstd => &e.writer_.zstd.interface,
        .br => &e.writer_.brotli.interface,
    };
}

/// Encode everything written and end the stream, its trailer and
/// checksum written to the output.
pub fn finish(e: *Encoder) Io.Writer.Error!void {
    return switch (e.coding) {
        .gzip, .deflate => e.writer_.flate.finish(),
        .zstd => e.writer_.zstd.finish(),
        .br => e.writer_.brotli.finish(),
    };
}

/// Blocks kept for the next body, per coding.
pub const Pool = struct {
    gpa: Allocator,
    settings: Settings,
    /// Private: the free blocks, reached only through the lock beside them.
    lists: aegis.BlockingGuarded(Lists),
    /// The most free blocks kept of each coding.
    max_free: u32,

    const Lists = struct {
        free: [codings]?*Node = @splat(null),
        counts: [codings]u32 = @splat(0),
    };
    const codings = std.enums.values(Coding).len;
    /// A free block's first bytes: the next free one, and the block itself.
    const Node = struct { next: ?*Node, block: []align(64) u8 };

    pub fn init(gpa: Allocator, settings: Settings, max_free: u32) Pool {
        return .{ .gpa = gpa, .settings = settings, .lists = .init(.{}), .max_free = max_free };
    }

    /// Free every kept block. Encoders still out must not be given back.
    pub fn deinit(p: *Pool, io: Io) void {
        var held = p.lists.acquireUncancelable(io);
        const lists = held.value();
        for (&lists.free, 0..) |*head, i| {
            const len = blockLen(p.settings, @fromBackingInt(@intCast(i)));
            while (head.*) |node| {
                head.* = node.next;
                std.debug.assert(node.block.len == len);
                p.free(node.block, @fromBackingInt(@intCast(i)));
            }
        }
        held.deinit(io);
        p.* = undefined;
    }

    /// Free a block that is kept or given back, what its encoder holds with it.
    fn free(p: *Pool, block: []align(64) u8, coding: Coding) void {
        if (coding == .br) place.one(Encoder, block, block.len - @sizeOf(Encoder)).state.brotli.deinit();
        p.gpa.free(block);
    }

    /// An encoder for `coding` writing onto `output`, in a kept block when
    /// there is one.
    pub fn acquire(p: *Pool, io: Io, coding: Coding, output: *Io.Writer) Allocator.Error!*Encoder {
        const len = blockLen(p.settings, coding);
        const kept: ?[]align(64) u8 = taken: {
            var held = p.lists.acquireUncancelable(io);
            defer held.deinit(io);
            const lists = held.value();
            const i = @backingInt(coding);
            if (lists.free[i]) |node| {
                lists.free[i] = node.next;
                lists.counts[i] -= 1;
                std.debug.assert(node.block.len == len);
                break :taken node.block;
            }
            break :taken null;
        };
        const block: []align(64) u8 = kept orelse try p.gpa.alignedAlloc(u8, .@"64", len);
        const codec = codecLen(p.settings, coding);
        const e = place.one(Encoder, block, len - @sizeOf(Encoder));
        const stage = block[codec..][0..stage_len];
        const memory: []align(64) u8 = block[0..codec];
        e.coding = coding;
        e.block = block;
        switch (coding) {
            .gzip, .deflate => {
                e.state = .{ .flate = warp.Deflate.initBuffer(memory, deflateOptions(p.settings, if (coding == .gzip) .gzip else .zlib)) catch aegis.assert.never("the codec memory is what Deflate.memory asks for these options") };
                e.writer_ = .{ .flate = warp.Deflate.Writer.init(&e.state.flate, output, stage) catch aegis.assert.never("the stage is stage_len, the 4 KiB a Deflate writer needs") };
            },
            .zstd => {
                e.state = .{ .zstd = warp.zstd.Compress.initBuffer(memory, zstdOptions(p.settings)) catch aegis.assert.never("the codec memory is what zstd.Compress.memory asks for these options") };
                e.writer_ = .{ .zstd = .init(&e.state.zstd, output, stage) };
            },
            .br => {
                // A kept block's encoder starts over on the buffers it grew.
                if (kept != null) {
                    e.state.brotli.reset(brotliOptions(p.settings)) catch |err| {
                        p.free(block, coding);
                        return err;
                    };
                } else {
                    e.state = .{ .brotli = warp.brotli.Compress.init(p.gpa, brotliOptions(p.settings)) catch |err| {
                        p.gpa.free(block);
                        return err;
                    } };
                }
                e.writer_ = .{ .brotli = .init(&e.state.brotli, output, stage) };
            },
        }
        return e;
    }

    /// Give `e`'s block back: kept when there is room, freed otherwise.
    pub fn release(p: *Pool, io: Io, e: *Encoder) void {
        const block = e.block;
        const i = @backingInt(e.coding);
        {
            var held = p.lists.acquireUncancelable(io);
            defer held.deinit(io);
            const lists = held.value();
            if (lists.counts[i] < p.max_free) {
                const node = place.one(Node, block, 0);
                node.* = .{ .next = lists.free[i], .block = block };
                lists.free[i] = node;
                lists.counts[i] += 1;
                return;
            }
        }
        p.free(block, e.coding);
    }
};

const testing = std.testing;
const test_io = @import("../testing/io.zig");

test "Brotli encoders past what the pool keeps are freed with what they grew" {
    const gpa = testing.allocator;
    const io = test_io.io();
    var pool: Pool = .init(gpa, .{}, 1);
    defer pool.deinit(io);
    var out: Io.Writer.Allocating = .init(gpa);
    defer out.deinit();
    const a = try pool.acquire(io, .br, &out.writer);
    const b = try pool.acquire(io, .br, &out.writer);
    try a.writer().writeAll("first");
    try b.writer().writeAll("second");
    pool.release(io, a);
    pool.release(io, b);
}

test "each coding encodes a body that its decoder reads back, checksums included" {
    const gpa = testing.allocator;
    const io = test_io.io();
    var pool: Pool = .init(gpa, .{}, 1);
    defer pool.deinit(io);
    const text = "a response body worth compressing, repeated, repeated, repeated, repeated";
    for ([_]Coding{ .gzip, .deflate, .zstd, .br }) |coding| {
        for (0..2) |_| {
            var out: Io.Writer.Allocating = .init(gpa);
            defer out.deinit();
            const e = try pool.acquire(io, coding, &out.writer);
            try e.writer().writeAll(text);
            try e.writer().writeAll(text);
            try e.finish();
            pool.release(io, e);
            const coded = out.written();
            var plain: [256]u8 = undefined;
            const n = switch (coding) {
                .zstd => blk: {
                    var d: warp.zstd.Decompressor = .init;
                    break :blk (try d.decompress(coded, &plain, .{})).out_len;
                },
                .br => blk: {
                    const d = try gpa.create(warp.brotli.Decompressor);
                    defer gpa.destroy(d);
                    d.* = .init;
                    break :blk (try d.decompress(coded, &plain, .{})).out_len;
                },
                else => blk: {
                    var d: warp.Decompressor = .init;
                    break :blk (try d.inflate(coded, &plain, .{ .accept = if (coding == .gzip) .gzip else .zlib })).out_len;
                },
            };
            try testing.expectEqualStrings(text ++ text, plain[0..n]);
        }
    }
}
