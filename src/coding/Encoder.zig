//! A body put under one coding as it is written, through warp's streaming
//! encoders: gzip and deflate (zlib) by warp's DEFLATE, zstd by warp's
//! Zstandard with a checksum in every frame.
//!
//! An encoder and everything it writes through lives in one block of
//! memory, taken from a `Pool` that keeps blocks for the next body: the
//! codec's tables and window, the input it stages, and the output it
//! hands on in pieces. So a server compressing its responses allocates
//! nothing once it is warm.

const std = @import("std");
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
        };
    }
};

const State = union { flate: warp.Deflate, zstd: warp.zstd.Compress };
const Writer = union { flate: warp.Deflate.Writer, zstd: warp.zstd.Compress.Writer };

/// How hard each coding works.
pub const Settings = struct {
    /// 1-9, zlib's scale.
    deflate_level: u4 = 5,
    zstd_level: i32 = 3,
    /// The window a zstd frame names, 2^this: a decoder keeps that much,
    /// and browsers take at most 8 MiB (RFC 9659).
    zstd_window_log: u5 = 20,
};

/// The input staged before it is encoded.
const stage_len = 4096;

fn deflateOptions(s: Settings, container: warp.Container) warp.Deflate.Options {
    return .{ .level = s.deflate_level, .max_level = s.deflate_level, .container = container };
}

fn zstdOptions(s: Settings) warp.zstd.Compress.Options {
    return .{ .level = s.zstd_level, .tuning = .{ .window_log = s.zstd_window_log }, .frame = .{ .checksum = true, .content_size = false } };
}

/// The codec's part of a block for `coding`.
fn codecLen(s: Settings, coding: Coding) usize {
    const n = switch (coding) {
        .gzip => warp.Deflate.memory(deflateOptions(s, .gzip)),
        .deflate => warp.Deflate.memory(deflateOptions(s, .zlib)),
        .zstd => warp.zstd.Compress.memory(zstdOptions(s)),
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
    };
}

/// Encode everything written and end the stream, its trailer and
/// checksum written to the output.
pub fn finish(e: *Encoder) Io.Writer.Error!void {
    return switch (e.coding) {
        .gzip, .deflate => e.writer_.flate.finish(),
        .zstd => e.writer_.zstd.finish(),
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
    const Node = struct { next: ?*Node };

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
                p.gpa.free(blockOf(node, len));
            }
        }
        held.deinit(io);
        p.* = undefined;
    }

    /// An encoder for `coding` writing onto `output`, in a kept block when
    /// there is one.
    pub fn acquire(p: *Pool, io: Io, coding: Coding, output: *Io.Writer) Allocator.Error!*Encoder {
        const len = blockLen(p.settings, coding);
        const block: []align(64) u8 = taken: {
            var held = p.lists.acquireUncancelable(io);
            defer held.deinit(io);
            const lists = held.value();
            const i = @backingInt(coding);
            if (lists.free[i]) |node| {
                lists.free[i] = node.next;
                lists.counts[i] -= 1;
                break :taken blockOf(node, len);
            }
            break :taken null;
        } orelse try p.gpa.alignedAlloc(u8, .@"64", len);
        const codec = codecLen(p.settings, coding);
        const e: *Encoder = @ptrCast(@alignCast(block.ptr + (len - @sizeOf(Encoder)))); // safe: the block ends with room for an Encoder, aligned for it
        const stage = block[codec..][0..stage_len];
        const memory: []align(64) u8 = block[0..codec];
        e.* = .{ .coding = coding, .block = block, .state = undefined, .writer_ = undefined };
        switch (coding) {
            .gzip, .deflate => {
                e.state = .{ .flate = .initBuffer(memory, deflateOptions(p.settings, if (coding == .gzip) .gzip else .zlib)) };
                e.writer_ = .{ .flate = .init(&e.state.flate, output, stage) };
            },
            .zstd => {
                e.state = .{ .zstd = .initBuffer(memory, zstdOptions(p.settings)) };
                e.writer_ = .{ .zstd = .init(&e.state.zstd, output, stage) };
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
                const node: *Node = @ptrCast(block.ptr); // safe: a block is 64-aligned and far longer than a Node
                node.* = .{ .next = lists.free[i] };
                lists.free[i] = node;
                lists.counts[i] += 1;
                return;
            }
        }
        p.gpa.free(block);
    }

    fn blockOf(node: *Node, len: usize) []align(64) u8 {
        const ptr: [*]align(64) u8 = @ptrCast(@alignCast(node)); // safe: a node is the first bytes of a block allocated 64-aligned
        return ptr[0..len];
    }
};

const testing = std.testing;
const test_io = @import("../testing/io.zig");

test "each coding encodes a body that its decoder reads back, checksums included" {
    const gpa = testing.allocator;
    const io = test_io.io();
    var pool: Pool = .init(gpa, .{}, 1);
    defer pool.deinit(io);
    const text = "a response body worth compressing, repeated, repeated, repeated, repeated";
    for ([_]Coding{ .gzip, .deflate, .zstd }) |coding| {
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
                else => blk: {
                    var d: warp.Decompressor = .init;
                    break :blk (try d.inflate(coded, &plain, .{ .accept = if (coding == .gzip) .gzip else .zlib })).out_len;
                },
            };
            try testing.expectEqualStrings(text ++ text, plain[0..n]);
        }
    }
}
