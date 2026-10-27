//! What a cache's store is: the interface `Cache.Memory`, `Cache.Disk`
//! and a caller's own implement, and the values it hands over. Apart from
//! `Cache.zig` so that a store in a file of its own imports it alone.

const std = @import("std");
const Io = std.Io;
const wire = @import("uplink.wire");

/// What a store refuses with.
pub const Error = error{ OutOfMemory, StoreFailed, Canceled };

/// When a stored response was asked for and arrived, on the calendar
/// clock, and the request's values of the fields its `Vary` names
/// (`varyOf`).
pub const Meta = struct {
    requested: wire.date.Second,
    received: wire.date.Second,
    vary: []const u8,
};

/// A stored body: bytes the store holds, or the `length` bytes at
/// `offset` in a file it keeps open for the holder.
pub const Body = union(enum) {
    bytes: []const u8,
    file: struct { file: Io.File, offset: u64, length: u64 },

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
    handle: *Handle,
    meta: Meta,
    head: []const u8,
    body: Body,
};

/// A response being stored, between `begin` and `commit` or `abort`.
pub const Writing = struct { handle: *Handle };

/// What a store gives back as a variant it holds or writes: a field of the
/// store's own record of it, which the store finds by `@fieldParentPtr`.
/// It names the store, so a store can tell a handle of its own.
pub const Handle = struct { store: *const Store };

/// Where a cache keeps what it stores. Every call may be made by several
/// tasks at once.
///
/// A field of the type that stores, which its functions find by
/// `@fieldParentPtr`; a cache holds a pointer to it.
pub const Store = struct {
    vtable: *const VTable,

    pub const VTable = struct {
        /// The variants stored under `key`, newest first, into `out`, each
        /// held until `release`.
        lookup: *const fn (s: *Store, io: Io, key: []const u8, out: []Entry) Error!usize,
        release: *const fn (s: *Store, io: Io, entry: *const Entry) void,
        /// A new variant for `key`; null when the store declines it.
        begin: *const fn (s: *Store, io: Io, key: []const u8, meta: Meta, head: []const u8) Error!?Writing,
        /// More of its body; false when it grew past what the store takes,
        /// after which only `abort` is called.
        append: *const fn (s: *Store, io: Io, writing: Writing, bytes: []const u8) Error!bool,
        /// The body is whole: the variant replaces the one with the same
        /// `Vary` values under its key.
        commit: *const fn (s: *Store, io: Io, writing: Writing) Error!void,
        abort: *const fn (s: *Store, io: Io, writing: Writing) void,
        /// A held variant's head and times after a 304 (§3.2, §4.3.4).
        update: *const fn (s: *Store, io: Io, entry: *const Entry, meta: Meta, head: []const u8) Error!void,
        /// Every variant under `key` (§4.4).
        remove: *const fn (s: *Store, io: Io, key: []const u8) Error!void,
    };

    pub fn lookup(s: *Store, io: Io, key: []const u8, out: []Entry) Error!usize {
        return s.vtable.lookup(s, io, key, out);
    }
    pub fn release(s: *Store, io: Io, entry: *const Entry) void {
        s.vtable.release(s, io, entry);
    }
    pub fn begin(s: *Store, io: Io, key: []const u8, meta: Meta, head: []const u8) Error!?Writing {
        return s.vtable.begin(s, io, key, meta, head);
    }
    pub fn append(s: *Store, io: Io, writing: Writing, bytes: []const u8) Error!bool {
        return s.vtable.append(s, io, writing, bytes);
    }
    pub fn commit(s: *Store, io: Io, writing: Writing) Error!void {
        return s.vtable.commit(s, io, writing);
    }
    pub fn abort(s: *Store, io: Io, writing: Writing) void {
        s.vtable.abort(s, io, writing);
    }
    pub fn update(s: *Store, io: Io, entry: *const Entry, meta: Meta, head: []const u8) Error!void {
        return s.vtable.update(s, io, entry, meta, head);
    }
    pub fn remove(s: *Store, io: Io, key: []const u8) Error!void {
        return s.vtable.remove(s, io, key);
    }
};

/// How many variants of one URL a lookup considers.
pub const max_variants = 8;
