//! `Cache.Disk` on its own: what a directory keeps across `open`, its
//! bound, the variants of one key, and the files it will not serve. The
//! exchanges through a client run over it in `cache_test.zig`.

const std = @import("std");
const Io = std.Io;
const testing = std.testing;
const test_io = @import("../testing/io.zig");
const Cache = @import("Cache.zig");

const head = "HTTP/1.1 200 OK\r\nCache-Control: max-age=60\r\n";

fn meta(vary: []const u8) Cache.Meta {
    return .{ .requested = .fromRaw(1_700_000_000), .received = .fromRaw(1_700_000_001), .vary = vary };
}

/// Stores `body` under `key` with the `Vary` values `vary`.
fn put(store: *Cache.Store, io: Io, key: []const u8, vary: []const u8, body: []const u8) !void {
    const w = (try store.begin(io, key, meta(vary), head)).?;
    if (!try store.append(io, w, body)) {
        store.abort(io, w);
        return error.Declined;
    }
    try store.commit(io, w);
}

/// The body of a held variant, read as a response reads it.
fn bodyOf(io: Io, entry: Cache.Entry) ![]u8 {
    const f = entry.body.file;
    var reader = f.file.reader(io, &.{});
    try reader.seekTo(f.offset);
    return reader.interface.readAllocAll(testing.allocator, @intCast(f.length));
}

fn files(io: Io, dir: Io.Dir) !usize {
    var n: usize = 0;
    var it = dir.iterate();
    while (try it.next(io)) |_| n += 1;
    return n;
}

test "a variant outlives its store: a second open finds it, its head, times and body" {
    const io = test_io.io();
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    {
        var disk: Cache.Disk = try .open(testing.allocator, io, tmp.dir, .{ .max_bytes = .literal("1MiB") });
        defer disk.deinit(io);
        try put(disk.store(), io, "GET https://a.test/x", "accept-language:fr\n", "bonjour");
    }
    var disk: Cache.Disk = try .open(testing.allocator, io, tmp.dir, .{ .max_bytes = .literal("1MiB") });
    defer disk.deinit(io);
    try testing.expect(disk.bytes(io).compare(.fromRaw("bonjour".len + head.len)) == .gt);
    var out: [Cache.max_variants]Cache.Entry = undefined;
    try testing.expectEqual(@as(usize, 1), try disk.store().lookup(io, "GET https://a.test/x", &out));
    defer disk.store().release(io, &out[0]);
    try testing.expectEqualStrings(head, out[0].head);
    try testing.expectEqualStrings("accept-language:fr\n", out[0].meta.vary);
    try testing.expectEqual(@as(i64, 1_700_000_001), out[0].meta.received.raw());
    const body = try bodyOf(io, out[0]);
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("bonjour", body);
    try testing.expectEqual(@as(usize, 0), try disk.store().lookup(io, "GET https://a.test/y", &out));
}

test "a key's variants are told apart by their Vary values, and one with the same values replaced" {
    const io = test_io.io();
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var disk: Cache.Disk = try .open(testing.allocator, io, tmp.dir, .{ .max_bytes = .literal("1MiB") });
    defer disk.deinit(io);
    const store = disk.store();
    try put(store, io, "k", "lang:fr\n", "bonjour");
    try put(store, io, "k", "lang:en\n", "hello");
    try put(store, io, "k", "lang:fr\n", "salut");
    var out: [Cache.max_variants]Cache.Entry = undefined;
    const n = try store.lookup(io, "k", &out);
    defer for (out[0..n]) |*e| store.release(io, e);
    try testing.expectEqual(@as(usize, 2), n);
    // Newest first.
    try testing.expectEqualStrings("lang:fr\n", out[0].meta.vary);
    const body = try bodyOf(io, out[0]);
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("salut", body);
    try testing.expectEqual(@as(usize, 2), try files(io, tmp.dir));
}

test "a store keeps no more than its bound, the least recently used evicted and its file gone" {
    const io = test_io.io();
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    const body: [200]u8 = @splat('x');
    // Measure one variant's file, then bound the store at two and a half.
    const one = blk: {
        var probe = try tmp.dir.createDirPathOpen(io, "probe", .{ .open_options = .{ .iterate = true } });
        defer probe.close(io);
        var disk: Cache.Disk = try .open(testing.allocator, io, probe, .{ .max_bytes = .literal("1MiB") });
        defer disk.deinit(io);
        try put(disk.store(), io, "a", "", &body);
        break :blk disk.bytes(io).raw();
    };
    var dir = try tmp.dir.createDirPathOpen(io, "store", .{ .open_options = .{ .iterate = true } });
    defer dir.close(io);
    var disk: Cache.Disk = try .open(testing.allocator, io, dir, .{ .max_bytes = .fromRaw(2 * one + one / 2) });
    defer disk.deinit(io);
    const store = disk.store();
    try put(store, io, "a", "", &body);
    try put(store, io, "b", "", &body);
    var out: [Cache.max_variants]Cache.Entry = undefined;
    // "a" used last: "b" is the one to go.
    store.release(io, &out[0..try store.lookup(io, "a", &out)][0]);
    try put(store, io, "c", "", &body);
    try testing.expectEqual(@as(usize, 0), try store.lookup(io, "b", &out));
    try testing.expectEqual(@as(usize, 2), try files(io, dir));
    try testing.expectEqual(2 * one, disk.bytes(io).raw());
    // A variant larger than the store is declined as it grows.
    const big: [4096]u8 = @splat('y');
    const w = (try store.begin(io, "big", meta(""), head)).?;
    try testing.expect(!try store.append(io, w, &big));
    store.abort(io, w);
    try testing.expectEqual(@as(usize, 2), try files(io, dir));
}

test "a variant held while it is removed stays readable until released" {
    const io = test_io.io();
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var disk: Cache.Disk = try .open(testing.allocator, io, tmp.dir, .{ .max_bytes = .literal("1MiB") });
    defer disk.deinit(io);
    const store = disk.store();
    try put(store, io, "k", "", "kept");
    var out: [Cache.max_variants]Cache.Entry = undefined;
    try testing.expectEqual(@as(usize, 1), try store.lookup(io, "k", &out));
    try store.remove(io, "k");
    try testing.expectEqual(@as(usize, 0), try files(io, tmp.dir));
    const body = try bodyOf(io, out[0]);
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("kept", body);
    store.release(io, &out[0]);
    try testing.expectEqual(@as(u64, 0), disk.bytes(io).raw());
}

test "a 304's head replaces a held variant's, its body kept" {
    const io = test_io.io();
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    var disk: Cache.Disk = try .open(testing.allocator, io, tmp.dir, .{ .max_bytes = .literal("1MiB") });
    defer disk.deinit(io);
    const store = disk.store();
    try put(store, io, "k", "", "body");
    var out: [Cache.max_variants]Cache.Entry = undefined;
    try testing.expectEqual(@as(usize, 1), try store.lookup(io, "k", &out));
    const newer = "HTTP/1.1 200 OK\r\nCache-Control: max-age=600\r\nX-Checked: yes\r\n";
    try store.update(io, &out[0], .{ .requested = .fromRaw(1_800_000_000), .received = .fromRaw(1_800_000_001), .vary = "" }, newer);
    store.release(io, &out[0]);
    try testing.expectEqual(@as(usize, 1), try store.lookup(io, "k", &out));
    defer store.release(io, &out[0]);
    try testing.expectEqualStrings(newer, out[0].head);
    try testing.expectEqual(@as(i64, 1_800_000_001), out[0].meta.received.raw());
    const body = try bodyOf(io, out[0]);
    defer testing.allocator.free(body);
    try testing.expectEqualStrings("body", body);
    try testing.expectEqual(@as(usize, 1), try files(io, tmp.dir));
}

test "a file that is not a variant is never served: the lookup fails by name and the file goes" {
    const io = test_io.io();
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    {
        var disk: Cache.Disk = try .open(testing.allocator, io, tmp.dir, .{ .max_bytes = .literal("1MiB") });
        defer disk.deinit(io);
        try put(disk.store(), io, "k", "", "body");
    }
    // The variant's file cut short, as no write of the store's leaves it.
    var it = tmp.dir.iterate();
    const name = (try it.next(io)).?.name;
    const file = try tmp.dir.openFile(io, name, .{ .mode = .read_write });
    try file.setLength(io, 20);
    file.close(io);
    var disk: Cache.Disk = try .open(testing.allocator, io, tmp.dir, .{ .max_bytes = .literal("1MiB") });
    defer disk.deinit(io);
    var out: [Cache.max_variants]Cache.Entry = undefined;
    try testing.expectError(error.StoreFailed, disk.store().lookup(io, "k", &out));
    try testing.expectEqual(@as(usize, 0), try disk.store().lookup(io, "k", &out));
    try testing.expectEqual(@as(usize, 0), try files(io, tmp.dir));
    try testing.expectEqual(@as(u64, 0), disk.bytes(io).raw());
}

test "open removes a write a crash left and passes over names that are not a variant's" {
    const io = test_io.io();
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    // A temp as a write draws one: the prefix and 26 base32 characters.
    try tmp.dir.writeFile(io, .{ .sub_path = ".uplink-cache-abcdefghijklmnopqrstuvwxyz", .data = "half" });
    try tmp.dir.writeFile(io, .{ .sub_path = "notes.txt", .data = "the caller's" });
    var disk: Cache.Disk = try .open(testing.allocator, io, tmp.dir, .{ .max_bytes = .literal("1MiB") });
    defer disk.deinit(io);
    try testing.expectEqual(@as(u64, 0), disk.bytes(io).raw());
    try testing.expectError(error.FileNotFound, tmp.dir.statFile(io, ".uplink-cache-abcdefghijklmnopqrstuvwxyz", .{}));
    _ = try tmp.dir.statFile(io, "notes.txt", .{});
}
