//! An HTTP cache (RFC 9111) a client consults before it goes to the
//! network: `Client.Options.cache`. A private cache by default, as a
//! client's own is; a shared one obeys `s-maxage`, `private` and
//! `Authorization` as §3.5 says.
//!
//! What it keeps lives in a `Store`: `Memory`, bounded by bytes and
//! evicting the least recently used, or one of the caller's. A response is
//! stored as it came, its content codings and all, while the caller reads
//! it, and only once its body ended whole; one read in part is never kept.
//! What may be stored, how long it is fresh, how old it is and whether a
//! stored one may answer a request are `uplink.wire.cache`'s rules; this
//! keeps the entries and their variants (`Vary`).
//!
//! A store that fails costs the cache, never the request: the request goes
//! to the network, and the client's observer hears of it by name
//! (`cache_failed`).

const std = @import("std");
const aegis = @import("aegis");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const wire = @import("uplink.wire");
const rules = wire.cache;

const Cache = @This();

store: Store,
options: Options,

pub const Options = struct {
    /// A private cache (a client's own) or a shared one (§1).
    kind: rules.Kind = .private,
    /// The longest lifetime the heuristic of §4.2.2 gives a response with
    /// none of its own.
    heuristic_cap: aegis.units.Duration(.second, u32) = .literal("1d"),
    /// A response whose body is larger is not stored.
    max_entry: aegis.units.Bytes(u64) = .literal("8MiB"),
};

pub fn init(store: Store, options: Options) Cache {
    return .{ .store = store, .options = options };
}

/// What a store refuses with.
pub const Error = error{ OutOfMemory, StoreFailed, Canceled };

/// When a stored response was asked for and arrived, by the cache's
/// clock, in seconds since the epoch, and the request's values of the
/// fields its `Vary` names (`varyOf`).
pub const Meta = struct {
    requested: i64,
    received: i64,
    vary: []const u8,
};

/// A stored body: bytes the store holds, or a file it keeps.
pub const Body = union(enum) {
    bytes: []const u8,
    file: struct { file: Io.File, length: u64 },

    pub fn len(b: Body) u64 {
        return switch (b) {
            .bytes => |bytes| bytes.len,
            .file => |f| f.length,
        };
    }
};

/// A stored response, held from `lookup` until `release`: its head (the
/// status line and fields, as HTTP/1.1 writes them, framing fields and
/// `Age` left out), and its body.
pub const Entry = struct {
    handle: *anyopaque,
    meta: Meta,
    head: []const u8,
    body: Body,
};

/// A response being stored, between `begin` and `commit` or `abort`.
pub const Writing = struct { handle: *anyopaque };

/// Where a cache keeps what it stores. Every call may be made by several
/// tasks at once.
pub const Store = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// The variants stored under `key`, newest first, into `out`, each
        /// held until `release`.
        lookup: *const fn (context: *anyopaque, io: Io, key: []const u8, out: []Entry) Error!usize,
        release: *const fn (context: *anyopaque, io: Io, entry: *const Entry) void,
        /// A new variant for `key`; null when the store declines it.
        begin: *const fn (context: *anyopaque, io: Io, key: []const u8, meta: Meta, head: []const u8) Error!?Writing,
        /// More of its body; false when it grew past what the store takes,
        /// after which only `abort` is called.
        append: *const fn (context: *anyopaque, io: Io, writing: Writing, bytes: []const u8) Error!bool,
        /// The body is whole: the variant replaces the one with the same
        /// `Vary` values under its key.
        commit: *const fn (context: *anyopaque, io: Io, writing: Writing) Error!void,
        abort: *const fn (context: *anyopaque, io: Io, writing: Writing) void,
        /// A held variant's head and times after a 304 (§3.2, §4.3.4).
        update: *const fn (context: *anyopaque, io: Io, entry: *const Entry, meta: Meta, head: []const u8) Error!void,
        /// Every variant under `key` (§4.4).
        remove: *const fn (context: *anyopaque, io: Io, key: []const u8) Error!void,
    };

    pub fn lookup(s: Store, io: Io, key: []const u8, out: []Entry) Error!usize {
        return s.vtable.lookup(s.context, io, key, out);
    }
    pub fn release(s: Store, io: Io, entry: *const Entry) void {
        s.vtable.release(s.context, io, entry);
    }
    pub fn begin(s: Store, io: Io, key: []const u8, meta: Meta, head: []const u8) Error!?Writing {
        return s.vtable.begin(s.context, io, key, meta, head);
    }
    pub fn append(s: Store, io: Io, writing: Writing, bytes: []const u8) Error!bool {
        return s.vtable.append(s.context, io, writing, bytes);
    }
    pub fn commit(s: Store, io: Io, writing: Writing) Error!void {
        return s.vtable.commit(s.context, io, writing);
    }
    pub fn abort(s: Store, io: Io, writing: Writing) void {
        s.vtable.abort(s.context, io, writing);
    }
    pub fn update(s: Store, io: Io, entry: *const Entry, meta: Meta, head: []const u8) Error!void {
        return s.vtable.update(s.context, io, entry, meta, head);
    }
    pub fn remove(s: Store, io: Io, key: []const u8) Error!void {
        return s.vtable.remove(s.context, io, key);
    }
};

/// How many variants of one URL a lookup considers.
pub const max_variants = 8;

/// The request's values of the fields `vary` names, as a store keeps them
/// to tell variants apart: a line `name:value` per field, the name in
/// lower case, `name!` for one the request does not send. Null for
/// `Vary: *`, which no stored response answers (§4.1). `value` gives the
/// request's value of a field.
pub fn varyOf(gpa: Allocator, vary_field: ?[]const u8, context: anytype, comptime value: fn (@TypeOf(context), []const u8) ?[]const u8) Allocator.Error!?[]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    const list = vary_field orelse return try out.toOwnedSlice(gpa);
    var it: wire.fields.ListIterator = .{ .text = list };
    while (it.next()) |name| {
        if (std.mem.eql(u8, name, "*")) {
            out.deinit(gpa);
            return null;
        }
        for (name) |c| try out.append(gpa, std.ascii.toLower(c));
        if (value(context, name)) |v| {
            try out.append(gpa, ':');
            try out.appendSlice(gpa, std.mem.trim(u8, v, " \t"));
        } else try out.append(gpa, '!');
        try out.append(gpa, '\n');
    }
    return try out.toOwnedSlice(gpa);
}

/// Whether a stored variant's `Vary` values are the request's (§4.1).
pub fn varyMatches(stored: []const u8, context: anytype, comptime value: fn (@TypeOf(context), []const u8) ?[]const u8) bool {
    var lines = std.mem.splitScalar(u8, stored, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (line[line.len - 1] == '!') {
            if (value(context, line[0 .. line.len - 1]) != null) return false;
            continue;
        }
        const colon = std.mem.findScalar(u8, line, ':') orelse return false;
        const now = value(context, line[0..colon]) orelse return false;
        if (!std.mem.eql(u8, std.mem.trim(u8, now, " \t"), line[colon + 1 ..])) return false;
    }
    return true;
}

/// A store in memory: every variant a buffer of the allocator's, bounded
/// in all by `max_bytes`, the least recently used evicted first. A variant
/// in use when it is evicted or replaced is freed when its last holder
/// releases it.
pub const Memory = struct {
    gpa: Allocator,
    max_bytes: u64,
    state: aegis.BlockingGuarded(State),

    const State = struct {
        /// Each key's newest variant; the others follow it on `next`.
        keys: std.StringHashMapUnmanaged(*Item) = .empty,
        /// Least recently used first.
        order: std.DoublyLinkedList = .{},
        bytes: u64 = 0,
    };

    const Item = struct {
        key: []u8,
        vary: []u8,
        head: []u8,
        body: std.ArrayList(u8),
        /// Heads a 304 replaced, still readable by those who held the
        /// variant then: freed with it.
        retired: std.ArrayList([]u8) = .empty,
        requested: i64,
        received: i64,
        /// The next older variant of the same key.
        next: ?*Item = null,
        node: std.DoublyLinkedList.Node = .{},
        holders: u32 = 0,
        /// Out of the store: freed at its last release.
        gone: bool = false,
        /// Being written: not yet in the store.
        writing: bool = true,

        fn size(i: *const Item) u64 {
            return i.key.len + i.vary.len + i.head.len + i.body.items.len + overhead;
        }
    };

    /// What each variant costs against `max_bytes` beyond its key, its
    /// `Vary` values, its head and its body: the store's record of it,
    /// whose size the build decides, a safe build's being larger.
    pub const overhead: u64 = @sizeOf(Item);

    pub fn init(gpa: Allocator, max_bytes: aegis.units.Bytes(u64)) Memory {
        return .{ .gpa = gpa, .max_bytes = max_bytes.raw(), .state = .init(.{}) };
    }

    pub fn deinit(m: *Memory, io: Io) void {
        var held = m.state.acquireUncancelable(io);
        const s = held.value();
        var it = s.keys.valueIterator();
        while (it.next()) |first| {
            var item: ?*Item = first.*;
            while (item) |i| {
                item = i.next;
                std.debug.assert(i.holders == 0);
                m.free(i);
            }
        }
        s.keys.deinit(m.gpa);
        held.deinit(io);
        m.* = undefined;
    }

    pub fn store(m: *Memory) Store {
        return .{ .context = m, .vtable = &vtable };
    }

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

    fn of(context: *anyopaque) *Memory {
        return @ptrCast(@alignCast(context)); // safe: `store` gives its own
    }

    fn itemOf(handle: *anyopaque) *Item {
        return @ptrCast(@alignCast(handle)); // safe: every handle is one of this store's items
    }

    fn entryOf(i: *Item) Entry {
        return .{ .handle = i, .meta = .{ .requested = i.requested, .received = i.received, .vary = i.vary }, .head = i.head, .body = .{ .bytes = i.body.items } };
    }

    fn free(m: *Memory, i: *Item) void {
        m.gpa.free(i.key);
        m.gpa.free(i.vary);
        m.gpa.free(i.head);
        i.body.deinit(m.gpa);
        for (i.retired.items) |h| m.gpa.free(h);
        i.retired.deinit(m.gpa);
        m.gpa.destroy(i);
    }

    fn lookup(context: *anyopaque, io: Io, key: []const u8, out: []Entry) Error!usize {
        const m = of(context);
        var held = m.state.acquireUncancelable(io);
        defer held.deinit(io);
        const s = held.value();
        var item = s.keys.get(key);
        var n: usize = 0;
        while (item) |i| : (item = i.next) {
            if (n == out.len) break;
            i.holders += 1;
            s.order.remove(&i.node);
            s.order.append(&i.node);
            out[n] = entryOf(i);
            n += 1;
        }
        return n;
    }

    fn release(context: *anyopaque, io: Io, entry: *const Entry) void {
        const m = of(context);
        const i = itemOf(entry.handle);
        var held = m.state.acquireUncancelable(io);
        defer held.deinit(io);
        i.holders -= 1;
        if (i.holders == 0 and i.gone) m.free(i);
    }

    fn begin(context: *anyopaque, io: Io, key: []const u8, meta: Meta, head: []const u8) Error!?Writing {
        _ = io;
        const m = of(context);
        if (key.len + meta.vary.len + head.len > m.max_bytes) return null;
        const i = try m.gpa.create(Item);
        errdefer m.gpa.destroy(i);
        const owned_key = try m.gpa.dupe(u8, key);
        errdefer m.gpa.free(owned_key);
        const vary = try m.gpa.dupe(u8, meta.vary);
        errdefer m.gpa.free(vary);
        i.* = .{ .key = owned_key, .vary = vary, .head = try m.gpa.dupe(u8, head), .body = .empty, .requested = meta.requested, .received = meta.received };
        return .{ .handle = i };
    }

    fn append(context: *anyopaque, io: Io, writing: Writing, bytes: []const u8) Error!bool {
        _ = io;
        const m = of(context);
        const i = itemOf(writing.handle);
        if (i.size() + bytes.len > m.max_bytes) return false;
        try i.body.appendSlice(m.gpa, bytes);
        return true;
    }

    fn commit(context: *anyopaque, io: Io, writing: Writing) Error!void {
        const m = of(context);
        const i = itemOf(writing.handle);
        var held = m.state.acquireUncancelable(io);
        defer held.deinit(io);
        const s = held.value();
        const slot = s.keys.getOrPut(m.gpa, i.key) catch |err| {
            m.free(i);
            return err;
        };
        i.writing = false;
        // The variant with the same `Vary` values goes; the rest stay behind
        // the new one.
        var older: ?*Item = if (slot.found_existing) slot.value_ptr.* else null;
        var kept: ?*Item = null;
        var last: ?*Item = null;
        while (older) |o| {
            older = o.next;
            o.next = null;
            if (std.mem.eql(u8, o.vary, i.vary)) {
                m.drop(s, o);
                continue;
            }
            if (last) |l| l.next = o else kept = o;
            last = o;
        }
        i.next = kept;
        // The map's key is the newest variant's own.
        slot.key_ptr.* = i.key;
        slot.value_ptr.* = i;
        s.order.append(&i.node);
        s.bytes += i.size();
        m.evict(s);
    }

    /// Takes `i` out of the order and the count; frees it unless held.
    fn drop(m: *Memory, s: *State, i: *Item) void {
        s.order.remove(&i.node);
        s.bytes -= i.size();
        i.gone = true;
        if (i.holders == 0) m.free(i);
    }

    /// The least recently used variants, out, until the store fits.
    fn evict(m: *Memory, s: *State) void {
        while (s.bytes > m.max_bytes) {
            const node = s.order.first orelse return;
            const i: *Item = @fieldParentPtr("node", node);
            m.unlink(s, i);
            m.drop(s, i);
        }
    }

    /// Takes `i` off its key's list of variants, the key with it when it
    /// was the only one.
    fn unlink(m: *Memory, s: *State, i: *Item) void {
        _ = m;
        const first = s.keys.getPtr(i.key) orelse return;
        if (first.* == i) {
            if (i.next) |n| {
                const entry = s.keys.getEntry(i.key).?;
                entry.key_ptr.* = n.key;
                entry.value_ptr.* = n;
            } else _ = s.keys.remove(i.key);
            i.next = null;
            return;
        }
        var at = first.*;
        while (at.next) |n| : (at = n) if (n == i) {
            at.next = i.next;
            i.next = null;
            return;
        };
    }

    fn abort(context: *anyopaque, io: Io, writing: Writing) void {
        _ = io;
        of(context).free(itemOf(writing.handle));
    }

    fn update(context: *anyopaque, io: Io, entry: *const Entry, meta: Meta, head: []const u8) Error!void {
        const m = of(context);
        const i = itemOf(entry.handle);
        const fresh = try m.gpa.dupe(u8, head);
        errdefer m.gpa.free(fresh);
        var held = m.state.acquireUncancelable(io);
        defer held.deinit(io);
        const s = held.value();
        if (i.gone) {
            m.gpa.free(fresh);
            return;
        }
        // The old head stays readable by its holders until the variant is
        // freed.
        try i.retired.append(m.gpa, i.head);
        s.bytes -= i.size();
        i.head = fresh;
        i.requested = meta.requested;
        i.received = meta.received;
        s.bytes += i.size();
        m.evict(s);
    }

    fn remove(context: *anyopaque, io: Io, key: []const u8) Error!void {
        const m = of(context);
        var held = m.state.acquireUncancelable(io);
        defer held.deinit(io);
        const s = held.value();
        const removed = s.keys.fetchRemove(key) orelse return;
        var item: ?*Item = removed.value;
        while (item) |i| {
            item = i.next;
            i.next = null;
            m.drop(s, i);
        }
    }
};
