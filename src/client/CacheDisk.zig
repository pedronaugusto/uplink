//! `Cache.Disk`: a cache's store in a directory, bounded by bytes, the
//! least recently used variant evicted first.
//!
//! A variant is one file, named by its key's hash and its `Vary` values'
//! hash, holding a header (the times and the lengths), the key, the
//! values, the head, the body as it came, and a trailer with the body's
//! length. It is written through airlock: under a temp name, then synced
//! and renamed over the variant it replaces, the directory synced after,
//! so a crash leaves the old variant or the whole new one, never a torn
//! one. The index is held in memory and rebuilt from the directory's names
//! at `open`, newest first by the time each file was written; temps a
//! crash left go then.
//!
//! The directory is the store's alone. What a file says is read once, by
//! `Framing.parse`; a file that does not read as a variant of the key
//! asked for (another key whose hash collides, or bytes not written here)
//! is never served: the lookup fails by name (`StoreFailed`) and the file
//! goes, so the next asks the network.

const std = @import("std");
const aegis = @import("aegis");
const airlock = @import("airlock");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Cache = @import("CacheStore.zig");
const Store = Cache.Store;
const Entry = Cache.Entry;
const Handle = Cache.Handle;
const Writing = Cache.Writing;
const Meta = Cache.Meta;
const Error = Cache.Error;

const Disk = @This();

gpa: Allocator,
dir: Io.Dir,
options: Options,
state: aegis.BlockingGuarded(State),
/// Private: the store's functions.
storing: Store = .{ .vtable = &vtable },

/// A count of bytes: a file's, the store's.
pub const Size = aegis.units.Bytes(u64);

pub const Options = struct {
    /// The most bytes the variants' files take together; past it the
    /// least recently used go.
    max_bytes: Size,
    /// How durable a variant is once stored. `.data` survives a power cut;
    /// `.ordered` gives the old variant or the new after one, sooner.
    level: airlock.Level = .data,
    /// Where the syncs run: on a `reactor.Runtime`, `reactor.syncLane`, so
    /// that a sync holds no worker. Null syncs on the calling task.
    blocking: ?*airlock.Blocking = null,
};

/// What `open` fails with: the directory's listing or a temp's removal,
/// or files that together count past what a `u64` holds.
pub const OpenError = airlock.PruneError || Io.Dir.StatFileError || Allocator.Error || error{Overflow};

/// The store kept in `dir`, its index read from the variants there and
/// the temps a crash left removed. `dir` is borrowed until `deinit`.
pub fn open(gpa: Allocator, io: Io, dir: Io.Dir, options: Options) OpenError!Disk {
    // Any temp is a crash's: the directory is this store's alone, and no
    // write of it is in progress before it opens.
    _ = try airlock.pruneTemps(io, dir, temp_prefix, .{ .older_than = .zero });
    var index: State = .{};
    errdefer freeIndex(gpa, &index);
    const Found = struct { name: Name, size: Size, written: Io.Timestamp };
    var found: std.ArrayList(Found) = .empty;
    defer found.deinit(gpa);
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind != .file) continue;
        const name = Name.parse(entry.name) orelse continue;
        const stat = dir.statFile(io, entry.name, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => |e| return e,
        };
        try found.append(gpa, .{ .name = name, .size = .fromRaw(stat.size), .written = stat.mtime });
    }
    // Oldest first: each goes in front of its key's variants, and at the
    // used end of the order, so the newest ends first and last to go.
    std.mem.sort(Found, found.items, {}, struct {
        fn older(_: void, a: Found, b: Found) bool {
            return a.written.nanoseconds < b.written.nanoseconds;
        }
    }.older);
    for (found.items) |f| _ = try insert(gpa, &index, f.name, f.size);
    return .{ .gpa = gpa, .dir = dir, .options = options, .state = .init(index) };
}

/// Frees the index. The files stay for the next `open`. No variant may be
/// held or being written.
pub fn deinit(d: *Disk, io: Io) void {
    var held = d.state.acquireUncancelable(io);
    freeIndex(d.gpa, held.value());
    held.deinit(io);
    d.* = undefined;
}

pub fn store(d: *Disk) *Store {
    return &d.storing;
}

/// What the variants take now.
pub fn bytes(d: *Disk, io: Io) Size {
    var held = d.state.acquireUncancelable(io);
    defer held.deinit(io);
    return held.value().bytes;
}

/// The temps' prefix: never a variant's name, which is hex.
const temp_prefix = ".uplink-cache-";

/// A variant's file name: its key's hash and its `Vary` values' hash.
const Name = struct {
    key: Hash,
    vary: Hash,

    const Hash = [16]u8;
    const text_len = 2 * @sizeOf(Hash) + 1 + 2 * @sizeOf(Hash);

    fn hash(text_in: []const u8) Hash {
        var full: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(text_in, &full, .{});
        return full[0..@sizeOf(Hash)].*;
    }

    fn text(n: Name) [text_len]u8 {
        const digits = "0123456789abcdef";
        var out: [text_len]u8 = undefined;
        for (n.key, 0..) |b, i| out[2 * i ..][0..2].* = .{ digits[b >> 4], digits[b & 15] };
        out[2 * @sizeOf(Hash)] = '-';
        for (n.vary, 0..) |b, i| out[2 * @sizeOf(Hash) + 1 + 2 * i ..][0..2].* = .{ digits[b >> 4], digits[b & 15] };
        return out;
    }

    fn parse(s: []const u8) ?Name {
        if (s.len != text_len or s[2 * @sizeOf(Hash)] != '-') return null;
        var n: Name = undefined;
        _ = std.fmt.hexToBytes(&n.key, s[0 .. 2 * @sizeOf(Hash)]) catch return null;
        _ = std.fmt.hexToBytes(&n.vary, s[2 * @sizeOf(Hash) + 1 ..]) catch return null;
        // Lower case only, as `text` writes it: one name per variant.
        if (!std.mem.eql(u8, &n.text(), s)) return null;
        return n;
    }
};

const State = struct {
    /// Each key's newest variant; the others follow it on `next`.
    keys: std.AutoHashMapUnmanaged(Name.Hash, *Record) = .empty,
    /// Least recently used first.
    order: std.DoublyLinkedList = .{},
    bytes: Size = .fromRaw(0),
};

/// The index's record of a variant's file.
const Record = struct {
    name: Name,
    size: Size,
    next: ?*Record = null,
    node: std.DoublyLinkedList.Node = .{},
};

/// A variant a lookup gives out, until its release: its file open and its
/// key, values and head read.
const Held = struct {
    handle: Handle,
    file: aegis.own.OwnedIo(Io.File, closeFile),
    framing: Framing,
    /// The key, the values and the head, one allocation.
    text: []u8,
};

fn closeFile(file: *Io.File, io: Io) void {
    file.close(io);
}

/// A variant being written, until its commit or abort.
const Written = struct {
    handle: Handle,
    pending: airlock.Pending,
    name: Name,
    /// The destination's name, which the pending borrows until it ends.
    text_name: [Name.text_len]u8,
    buffer: []u8,
    writer: *Io.Writer,
    /// The file's size without the body: header, text and trailer.
    framing: Size,
    body: Size = .fromRaw(0),
};

const vtable: Store.VTable = .{
    .lookup = lookup,
    .release = release,
    .begin = begin,
    .append = append,
    .commit = commit,
    .abort = abort,
    .update = update,
    .remove = remove,
};

fn of(iface: *Store) *Disk {
    return @alignCast(@fieldParentPtr("storing", iface));
}

fn heldOf(d: *const Disk, handle: *Handle) *Held {
    aegis.assert.pre(handle.store == &d.storing, "a handle this store gave");
    // aegis: design(A019): a handle this store gave (asserted above) to an Entry is a Held's `handle`; only `lookup` makes an Entry
    return @alignCast(@fieldParentPtr("handle", handle));
}

fn writtenOf(d: *const Disk, handle: *Handle) *Written {
    aegis.assert.pre(handle.store == &d.storing, "a handle this store gave");
    // aegis: design(A019): a handle this store gave (asserted above) to a Writing is a Written's `handle`; only `begin` makes a Writing
    return @alignCast(@fieldParentPtr("handle", handle));
}

/// The file's layout. Integers little-endian.
const layout = struct {
    const magic = "uplinkc1";
    const trailer_magic = "uplinkc.";
    /// magic, requested, received, key length, values length, head length.
    const header_len = magic.len + 8 + 8 + 4 + 4 + 4;
    /// The body's length, then the trailer's magic.
    const trailer_len = 8 + trailer_magic.len;
    /// The longest key, values and head together a store keeps: longer
    /// than any request's head, so a larger count is not a variant's.
    const max_text = 1 << 20;

    fn header(out: *[header_len]u8, meta: Meta, key_len: u32, vary_len: u32, head_len: u32) void {
        out[0..magic.len].* = magic.*;
        std.mem.writeInt(i64, out[magic.len..][0..8], meta.requested.raw(), .little);
        std.mem.writeInt(i64, out[magic.len + 8 ..][0..8], meta.received.raw(), .little);
        std.mem.writeInt(u32, out[magic.len + 16 ..][0..4], key_len, .little);
        std.mem.writeInt(u32, out[magic.len + 20 ..][0..4], vary_len, .little);
        std.mem.writeInt(u32, out[magic.len + 24 ..][0..4], head_len, .little);
    }

    fn trailer(out: *[trailer_len]u8, body: Size) void {
        out[0..8].* = body.encode(.little);
        out[8..].* = trailer_magic.*;
    }
};

/// What a variant's file holds where, read from its header, its trailer
/// and its length, each part checked against the others.
const Framing = struct {
    requested: i64,
    received: i64,
    key_len: usize,
    vary_len: usize,
    head_len: usize,
    body: Size,

    /// A file's first and last bytes and its length, as nothing has read
    /// them yet.
    const Unread = aegis.input.Untrusted(struct {
        header: [layout.header_len]u8,
        trailer: [layout.trailer_len]u8,
        size: u64,
    });

    const NotAVariant = error{NotAVariant};

    fn parse(key_len: usize, raw: @FieldType(Unread, "value")) NotAVariant!Framing {
        const h = &raw.header;
        if (!std.mem.eql(u8, h[0..layout.magic.len], layout.magic)) return error.NotAVariant;
        if (!std.mem.eql(u8, raw.trailer[8..], layout.trailer_magic)) return error.NotAVariant;
        const at = layout.magic.len;
        const lengths = [3]u32{
            std.mem.readInt(u32, h[at + 16 ..][0..4], .little),
            std.mem.readInt(u32, h[at + 20 ..][0..4], .little),
            std.mem.readInt(u32, h[at + 24 ..][0..4], .little),
        };
        // Together no longer than a store keeps.
        var text: aegis.int.Ranged(u64, 0, layout.max_text) = .literal(0);
        for (lengths) |l| text = text.add(l) catch return error.NotAVariant;
        if (lengths[0] != key_len) return error.NotAVariant;
        const framing = aegis.int.Checked(u64).init(text.raw()).add(layout.header_len + layout.trailer_len) catch return error.NotAVariant;
        const rest = aegis.int.Checked(u64).init(raw.size).sub(framing.raw()) catch return error.NotAVariant;
        const body: Size = .decode(raw.trailer[0..8].*, .little);
        if (!body.eql(.fromRaw(rest.raw()))) return error.NotAVariant;
        return .{
            .requested = std.mem.readInt(i64, h[at..][0..8], .little),
            .received = std.mem.readInt(i64, h[at + 8 ..][0..8], .little),
            .key_len = lengths[0],
            .vary_len = lengths[1],
            .head_len = lengths[2],
            .body = body,
        };
    }

    fn textLen(f: Framing) usize {
        return f.key_len + f.vary_len + f.head_len;
    }

    fn bodyOffset(f: Framing) u64 {
        return layout.header_len + f.textLen();
    }
};

/// The bytes a variant of `key`, `vary` and `head` takes besides its body,
/// or null when they are longer than a store keeps.
fn framingOf(key: []const u8, vary: []const u8, head: []const u8) ?Size {
    var text: Size = .fromRaw(0);
    for ([_][]const u8{ key, vary, head }) |part| text = text.add(.fromRaw(part.len)) catch return null;
    if (text.compare(.fromRaw(layout.max_text)) == .gt) return null;
    return text.add(.fromRaw(layout.header_len + layout.trailer_len)) catch null;
}

/// Whether `more` bytes past `so_far` stay within `limit`.
fn fits(so_far: Size, more: Size, limit: Size) bool {
    const total = so_far.add(more) catch return false;
    return total.compare(limit) != .gt;
}

fn insert(gpa: Allocator, s: *State, name: Name, size: Size) (Allocator.Error || error{Overflow})!*Record {
    const total = s.bytes.add(size) catch return error.Overflow;
    const r = try gpa.create(Record);
    errdefer gpa.destroy(r);
    const slot = try s.keys.getOrPut(gpa, name.key);
    r.* = .{ .name = name, .size = size, .next = if (slot.found_existing) slot.value_ptr.* else null };
    slot.value_ptr.* = r;
    s.order.append(&r.node);
    s.bytes = total;
    return r;
}

/// Takes `r` off its key's variants, the order and the count, and frees
/// it; its file is the caller's to remove.
fn drop(d: *Disk, s: *State, r: *Record) void {
    if (s.keys.getPtr(r.name.key)) |first| {
        if (first.* == r) {
            if (r.next) |n| first.* = n else _ = s.keys.remove(r.name.key);
        } else {
            var at = first.*;
            while (at.next) |n| : (at = n) if (n == r) {
                at.next = r.next;
                break;
            };
        }
    }
    s.order.remove(&r.node);
    // The count holds every record's size, this one's among them.
    s.bytes = s.bytes.sub(r.size) catch .fromRaw(0);
    d.gpa.destroy(r);
}

fn find(s: *State, name: Name) ?*Record {
    var r = s.keys.get(name.key);
    while (r) |at| : (r = at.next) if (std.mem.eql(u8, &at.name.vary, &name.vary)) return at;
    return null;
}

fn freeIndex(gpa: Allocator, s: *State) void {
    var it = s.keys.valueIterator();
    while (it.next()) |first| {
        var r: ?*Record = first.*;
        while (r) |at| {
            r = at.next;
            gpa.destroy(at);
        }
    }
    s.keys.deinit(gpa);
}

/// Removes a variant's file. Already gone is what was asked.
fn unlinkFile(d: *Disk, io: Io, name: Name) Error!void {
    const text = name.text();
    _ = airlock.remove(io, d.dir, &text, .{ .sync = .{ .level = d.options.level, .blocking = d.options.blocking } }) catch |err| return switch (err) {
        error.FileNotFound => {},
        error.Canceled => error.Canceled,
        else => error.StoreFailed,
    };
}

fn lookup(iface: *Store, io: Io, key: []const u8, out: []Entry) Error!usize {
    const d = of(iface);
    var names: [Cache.max_variants]Name = undefined;
    var count: usize = 0;
    {
        var held = d.state.acquireUncancelable(io);
        defer held.deinit(io);
        const s = held.value();
        var r = s.keys.get(Name.hash(key));
        while (r) |at| : (r = at.next) {
            if (count == @min(out.len, names.len)) break;
            s.order.remove(&at.node);
            s.order.append(&at.node);
            names[count] = at.name;
            count += 1;
        }
    }
    var n: usize = 0;
    errdefer for (out[0..n]) |*e| release(iface, io, e);
    for (names[0..count]) |name| {
        // Evicted since the index was read: no longer stored.
        out[n] = (try d.read(io, key, name)) orelse continue;
        n += 1;
    }
    return n;
}

/// The variant `name` of `key`, open; null when its file is gone. A file
/// that is not one fails the lookup by name and is removed.
fn read(d: *Disk, io: Io, key: []const u8, name: Name) Error!?Entry {
    const text_name = name.text();
    var file: aegis.own.OwnedIo(Io.File, closeFile) = .init(d.dir.openFile(io, &text_name, .{}) catch |err| return switch (err) {
        error.FileNotFound => null,
        error.Canceled => error.Canceled,
        else => error.StoreFailed,
    });
    errdefer file.deinit(io);
    const framing = d.frame(io, file.borrow().*, key) catch |err| switch (err) {
        error.Canceled, error.OutOfMemory, error.StoreFailed => |e| return e,
        error.NotAVariant => {
            d.forget(io, name);
            return error.StoreFailed;
        },
    };
    const held = try d.gpa.create(Held);
    errdefer d.gpa.destroy(held);
    const text = try d.gpa.alloc(u8, framing.textLen());
    errdefer d.gpa.free(text);
    try readAt(io, file.borrow().*, text, layout.header_len);
    // Another key whose hash is this one's.
    if (!std.mem.eql(u8, text[0..framing.key_len], key)) {
        d.forget(io, name);
        return error.StoreFailed;
    }
    held.* = .{ .handle = .{ .store = &d.storing }, .file = undefined, .framing = framing, .text = text };
    file.moveInto(&held.file);
    const open_file = held.file.borrow().*;
    return .{
        .handle = &held.handle,
        .meta = .{ .requested = .fromRaw(framing.requested), .received = .fromRaw(framing.received), .vary = text[framing.key_len..][0..framing.vary_len] },
        .head = text[framing.key_len + framing.vary_len ..],
        .body = .{ .file = .{ .file = open_file, .offset = framing.bodyOffset(), .length = framing.body.raw() } },
    };
}

/// What `file` holds where, for `key`.
fn frame(d: *Disk, io: Io, file: Io.File, key: []const u8) (Error || Framing.NotAVariant)!Framing {
    _ = d;
    const size = file.length(io) catch |err| return ioError(err);
    if (size < layout.header_len + layout.trailer_len) return error.NotAVariant;
    var ends: @FieldType(Framing.Unread, "value") = .{ .header = undefined, .trailer = undefined, .size = size };
    try readAt(io, file, &ends.header, 0);
    try readAt(io, file, &ends.trailer, size - layout.trailer_len);
    return Framing.Unread.init(ends).parse(key.len, Framing.parse);
}

/// Takes `name` out of the index and its file away, after a read found it
/// was not a variant of the key it was asked for.
fn forget(d: *Disk, io: Io, name: Name) void {
    {
        var held = d.state.acquireUncancelable(io);
        defer held.deinit(io);
        if (find(held.value(), name)) |r| d.drop(held.value(), r);
    }
    // glint-ignore: Z026 -- the lookup fails by name already; a file left here is counted again at the next open and found again
    d.unlinkFile(io, name) catch {};
}

fn readAt(io: Io, file: Io.File, buffer: []u8, offset: u64) Error!void {
    const n = file.readPositionalAll(io, buffer, offset) catch |err| return ioError(err);
    // The file was shorter than its length said: written over since.
    if (n != buffer.len) return error.StoreFailed;
}

fn ioError(err: anyerror) Error {
    return if (err == error.Canceled) error.Canceled else error.StoreFailed;
}

fn release(iface: *Store, io: Io, entry: *const Entry) void {
    const d = of(iface);
    const held = d.heldOf(entry.handle);
    held.file.deinit(io);
    d.gpa.free(held.text);
    d.gpa.destroy(held);
}

fn begin(iface: *Store, io: Io, key: []const u8, meta: Meta, head: []const u8) Error!?Writing {
    const d = of(iface);
    const framing = framingOf(key, meta.vary, head) orelse return null;
    if (framing.compare(d.options.max_bytes) == .gt) return null;
    const w = try d.gpa.create(Written);
    errdefer d.gpa.destroy(w);
    const buffer = try d.gpa.alloc(u8, 16 << 10);
    errdefer d.gpa.free(buffer);
    const name: Name = .{ .key = Name.hash(key), .vary = Name.hash(meta.vary) };
    w.* = .{ .handle = .{ .store = &d.storing }, .pending = undefined, .name = name, .text_name = name.text(), .buffer = buffer, .writer = undefined, .framing = framing };
    // The temp's name is drawn from `temp_prefix`, beside the variant.
    w.pending = airlock.create(io, d.dir, &w.text_name, .{ .temp = .{ .random = temp_prefix } }) catch |err| return ioError(err);
    errdefer w.pending.discard(io);
    w.writer = w.pending.writer(io, buffer);
    var header: [layout.header_len]u8 = undefined;
    // Each within `max_text`, as `framingOf` checked.
    layout.header(&header, meta, @intCast(key.len), @intCast(meta.vary.len), @intCast(head.len));
    for ([_][]const u8{ &header, key, meta.vary, head }) |part| w.writer.writeAll(part) catch return writeFailed(w);
    return .{ .handle = &w.handle };
}

/// Why a write to the temp failed: airlock keeps the cause.
fn writeFailed(w: *const Written) Error {
    return ioError(w.pending.cause() orelse error.WriteFailed);
}

fn append(iface: *Store, io: Io, writing: Writing, more: []const u8) Error!bool {
    _ = io;
    const d = of(iface);
    const w = d.writtenOf(writing.handle);
    const body = w.body.add(.fromRaw(more.len)) catch return false;
    if (!fits(w.framing, body, d.options.max_bytes)) return false;
    w.writer.writeAll(more) catch return writeFailed(w);
    w.body = body;
    return true;
}

fn commit(iface: *Store, io: Io, writing: Writing) Error!void {
    const d = of(iface);
    const w = d.writtenOf(writing.handle);
    defer d.finish(io, w);
    var trailer: [layout.trailer_len]u8 = undefined;
    layout.trailer(&trailer, w.body);
    w.writer.writeAll(&trailer) catch return writeFailed(w);
    _ = w.pending.commit(io, .{ .level = d.options.level, .blocking = d.options.blocking }) catch |err| switch (err) {
        // In place, its directory's sync not done: stored, kept as stored.
        error.PublishedNotDurable => {},
        error.Canceled => return error.Canceled,
        else => return error.StoreFailed,
    };
    // `append` kept the sum within `max_bytes`.
    try d.account(io, w.name, w.framing.add(w.body) catch return error.StoreFailed);
}

/// Puts the variant `name`, of `size` bytes and just written, in the index
/// in place of the one with its name, then evicts until the store fits.
fn account(d: *Disk, io: Io, name: Name, size: Size) Error!void {
    var evicted: std.ArrayList(Name) = .empty;
    defer evicted.deinit(d.gpa);
    {
        var held = d.state.acquireUncancelable(io);
        defer held.deinit(io);
        const s = held.value();
        if (find(s, name)) |old| d.drop(s, old);
        _ = insert(d.gpa, s, name, size) catch |err| {
            // Stored but not indexed: it would never be counted, so it goes.
            // glint-ignore: Z026 -- the commit fails by name already; a file left here is counted at the next open
            d.unlinkFile(io, name) catch {};
            return switch (err) {
                error.OutOfMemory => error.OutOfMemory,
                error.Overflow => error.StoreFailed,
            };
        };
        while (s.bytes.compare(d.options.max_bytes) == .gt) {
            const node = s.order.first orelse break;
            const r: *Record = @fieldParentPtr("node", node);
            try evicted.append(d.gpa, r.name);
            d.drop(s, r);
        }
    }
    // Out of the index already: a failed removal leaves a file the next
    // `open` counts again.
    for (evicted.items) |e| try d.unlinkFile(io, e);
}

fn finish(d: *Disk, io: Io, w: *Written) void {
    w.pending.discard(io);
    d.gpa.free(w.buffer);
    d.gpa.destroy(w);
}

fn abort(iface: *Store, io: Io, writing: Writing) void {
    const d = of(iface);
    d.finish(io, d.writtenOf(writing.handle));
}

fn update(iface: *Store, io: Io, entry: *const Entry, meta: Meta, head: []const u8) Error!void {
    const d = of(iface);
    const held = d.heldOf(entry.handle);
    const key = held.text[0..held.framing.key_len];
    // The variant written again with its new head, its body copied from
    // the file this holder has open.
    const writing = (try begin(iface, io, key, meta, head)) orelse return error.StoreFailed;
    const w = d.writtenOf(writing.handle);
    // The new head made it larger than the whole store: it cannot stay.
    if (!fits(w.framing, held.framing.body, d.options.max_bytes)) {
        abort(iface, io, writing);
        return error.StoreFailed;
    }
    copyBody(io, held, w) catch |err| {
        abort(iface, io, writing);
        return err;
    };
    w.body = held.framing.body;
    return commit(iface, io, writing);
}

/// The held variant's body into the variant being written, a piece at a
/// time, each a point a cancel ends it at.
fn copyBody(io: Io, held: *Held, w: *Written) Error!void {
    var reader = held.file.borrow().reader(io, &.{});
    reader.seekTo(held.framing.bodyOffset()) catch |err| return ioError(err);
    var left = held.framing.body;
    const piece: Size = .fromRaw(64 << 10);
    while (left.compare(.fromRaw(0)) == .gt) {
        try io.checkCancel();
        const step = if (left.compare(piece) == .lt) left else piece;
        reader.interface.streamExact64(w.writer, step.raw()) catch
            return if (reader.err) |e| ioError(e) else writeFailed(w);
        left = left.sub(step) catch return error.StoreFailed;
    }
}

fn remove(iface: *Store, io: Io, key: []const u8) Error!void {
    const d = of(iface);
    var names: std.ArrayList(Name) = .empty;
    defer names.deinit(d.gpa);
    {
        var held = d.state.acquireUncancelable(io);
        defer held.deinit(io);
        const s = held.value();
        while (s.keys.get(Name.hash(key))) |r| {
            try names.append(d.gpa, r.name);
            d.drop(s, r);
        }
    }
    for (names.items) |n| try d.unlinkFile(io, n);
}
