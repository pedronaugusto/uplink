//! How a host name becomes addresses: the system's lookup by default, or a
//! caller's own. `Static` answers chosen names with chosen addresses, as
//! curl's `--resolve` does, and passes the rest on; `Cache` keeps answers
//! for a while. Each wraps another resolver, so they stack.
//!
//! An address literal never reaches a resolver: `lookup` answers it itself.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const IpAddress = Io.net.IpAddress;
const resolve = @import("resolve.zig");

const Resolver = @This();

context: ?*anyopaque,
/// Answer `host`, a name, with up to `out.len` addresses on `port`, of
/// `family` when one is given.
lookupFn: *const fn (io: Io, context: ?*anyopaque, host: []const u8, port: u16, family: ?IpAddress.Family, out: []IpAddress) LookupError![]IpAddress,

pub const LookupError = resolve.LookupError;

/// `host`'s addresses on `port`: the address itself when `host` is one,
/// else the resolver's answer.
pub fn lookup(r: Resolver, io: Io, host: []const u8, port: u16, family: ?IpAddress.Family, out: []IpAddress) LookupError![]IpAddress {
    std.debug.assert(out.len != 0);
    if (resolve.literal(host, port)) |address| {
        if (family) |f| if (address != f) return error.NameNotResolved;
        out[0] = address;
        return out[0..1];
    }
    return r.lookupFn(io, r.context, host, port, family, out);
}

/// Errors from `lookupWithin`.
pub const LookupWithinError = error{
    InvalidHostName,
    NameNotResolved,
    ConcurrencyUnavailable,
    Canceled,
    /// `timeout` ran out first.
    TimedOut,
};

/// `lookup`, abandoned once `timeout` runs out. Keeping the bound needs a
/// task to race the lookup against; with none to spare the lookup runs
/// unbounded, and `bounded` is set false.
pub fn lookupWithin(r: Resolver, io: Io, host: []const u8, port: u16, family: ?IpAddress.Family, out: []IpAddress, timeout: ?Io.Duration, bounded: *bool) LookupWithinError![]IpAddress {
    bounded.* = true;
    const limit = timeout orelse return r.lookupMapped(io, host, port, family, out);
    if (resolve.literal(host, port) != null) return r.lookupMapped(io, host, port, family, out);
    const Race = union(enum) {
        found: LookupError![]IpAddress,
        expired: Io.Cancelable!void,
    };
    var buffer: [2]Race = undefined;
    var race: Io.Select(Race) = .init(io, &buffer);
    defer while (race.cancel()) |_| {};
    race.concurrent(.found, lookup, .{ r, io, host, port, family, out }) catch {
        bounded.* = false;
        return r.lookupMapped(io, host, port, family, out);
    };
    race.concurrent(.expired, Io.sleep, .{ io, limit, .awake }) catch {
        bounded.* = false;
        while (race.cancel()) |late| switch (late) {
            .found => |result| return result,
            .expired => {},
        };
        unreachable; // unreachable: the lookup task was started above
    };
    return switch (try race.await()) {
        .found => |result| result,
        .expired => |result| if (result) |_| error.TimedOut else |err| err,
    };
}

fn lookupMapped(r: Resolver, io: Io, host: []const u8, port: u16, family: ?IpAddress.Family, out: []IpAddress) LookupWithinError![]IpAddress {
    return r.lookup(io, host, port, family, out);
}

/// The system's lookup, with no task waiting on `io.async` work (see
/// `resolve`).
pub const system: Resolver = .{ .context = null, .lookupFn = systemLookup };

fn systemLookup(io: Io, _: ?*anyopaque, host: []const u8, port: u16, family: ?IpAddress.Family, out: []IpAddress) LookupError![]IpAddress {
    return resolve.lookup(io, host, port, family, out);
}

/// Chosen names answered with chosen addresses; any other passed on.
pub const Static = struct {
    entries: []const Entry,
    /// What answers the names not listed.
    fallback: Resolver = .system,

    /// One name's answer.
    pub const Entry = struct {
        /// Compared without case.
        host: []const u8,
        /// Only for this port; null for any.
        port: ?u16 = null,
        /// Their ports are replaced by the request's.
        addresses: []const IpAddress,
    };

    pub fn resolver(s: *const Static) Resolver {
        return .{ .context = @constCast(s), .lookupFn = staticLookup }; // safe: the lookup only reads through the pointer
    }

    fn staticLookup(io: Io, context: ?*anyopaque, host: []const u8, port: u16, family: ?IpAddress.Family, out: []IpAddress) LookupError![]IpAddress {
        const s: *const Static = @ptrCast(@alignCast(context.?)); // safe: `resolver` passes a Static
        for (s.entries) |e| {
            if (!std.ascii.eqlIgnoreCase(e.host, host)) continue;
            if (e.port) |p| if (p != port) continue;
            var n: usize = 0;
            for (e.addresses) |a| {
                if (n == out.len) break;
                if (family) |f| if (a != f) continue;
                out[n] = a;
                out[n].setPort(port);
                n += 1;
            }
            if (n == 0) return error.NameNotResolved;
            return out[0..n];
        }
        return s.fallback.lookup(io, host, port, family, out);
    }

    /// Why an entry cannot be read.
    pub const ParseError = error{ InvalidEntry, OutOfMemory };

    /// An entry in curl's `--resolve` form, `host:port:address[,address]`,
    /// IPv6 addresses bracketed or not, `*` for any port; the addresses
    /// belong to `arena`. git's `http.curloptResolve` is this form.
    pub fn parseEntry(arena: Allocator, text: []const u8) ParseError!Entry {
        const t = if (text.len != 0 and text[0] == '+') text[1..] else text;
        const host_end = std.mem.findScalar(u8, t, ':') orelse return error.InvalidEntry;
        const port_end = std.mem.findScalarPos(u8, t, host_end + 1, ':') orelse return error.InvalidEntry;
        const host = t[0..host_end];
        if (host.len == 0) return error.InvalidEntry;
        const port_text = t[host_end + 1 .. port_end];
        const port: ?u16 = if (std.mem.eql(u8, port_text, "*")) null else std.fmt.parseUnsigned(u16, port_text, 10) catch return error.InvalidEntry;
        var list: std.ArrayList(IpAddress) = .empty;
        var it = std.mem.splitScalar(u8, t[port_end + 1 ..], ',');
        while (it.next()) |raw| {
            const a = std.mem.trim(u8, raw, " ");
            if (a.len == 0) continue;
            const address = resolve.literal(a, 0) orelse return error.InvalidEntry;
            try list.append(arena, address);
        }
        if (list.items.len == 0) return error.InvalidEntry;
        return .{ .host = host, .port = port, .addresses = list.items };
    }
};

/// Answers kept for `ttl`, per name, the system's lookup having no time to
/// live to give. Shared by every task of a client; a name is looked up by
/// whichever task first misses it.
pub const Cache = struct {
    gpa: Allocator,
    inner: Resolver,
    options: Options,
    /// Private: held for `entries`.
    mutex: Io.Mutex = .init,
    /// Private: names, lower-cased and owned, to their answers.
    entries: std.StringHashMapUnmanaged(Entry) = .empty,

    pub const Options = struct {
        /// How long an answer is kept: curl's default.
        ttl: Io.Duration = .fromSeconds(60),
        /// The most names kept; past it, expired answers go, then the one
        /// closest to expiring.
        max_entries: u32 = 256,
    };

    /// The most addresses kept for one name.
    pub const max_kept = 16;

    const Entry = struct {
        addresses: [max_kept]IpAddress,
        len: u8,
        /// On the awake clock.
        expires: Io.Timestamp,
    };

    pub fn init(gpa: Allocator, inner: Resolver, options: Options) Cache {
        return .{ .gpa = gpa, .inner = inner, .options = options };
    }

    pub fn deinit(c: *Cache) void {
        var it = c.entries.keyIterator();
        while (it.next()) |k| c.gpa.free(k.*);
        c.entries.deinit(c.gpa);
        c.* = undefined;
    }

    pub fn resolver(c: *Cache) Resolver {
        return .{ .context = c, .lookupFn = cacheLookup };
    }

    /// Forget every answer.
    pub fn clear(c: *Cache, io: Io) void {
        c.mutex.lockUncancelable(io);
        defer c.mutex.unlock(io);
        var it = c.entries.keyIterator();
        while (it.next()) |k| c.gpa.free(k.*);
        c.entries.clearRetainingCapacity();
    }

    fn cacheLookup(io: Io, context: ?*anyopaque, host: []const u8, port: u16, family: ?IpAddress.Family, out: []IpAddress) LookupError![]IpAddress {
        const c: *Cache = @ptrCast(@alignCast(context.?)); // safe: `resolver` passes a Cache
        var key_buf: [Io.net.HostName.max_len]u8 = undefined;
        if (host.len > key_buf.len) return error.InvalidHostName;
        const key = std.ascii.lowerString(&key_buf, host);
        const now = Io.Clock.awake.now(io);
        if (c.cached(io, key, now, port, family, out)) |found| return found;
        // Every family is asked for, so a later lookup of either finds it.
        var fresh: [max_kept]IpAddress = undefined;
        const got = try c.inner.lookup(io, host, port, null, &fresh);
        c.keep(io, key, now, got);
        return pick(got, port, family, out) orelse error.NameNotResolved;
    }

    fn cached(c: *Cache, io: Io, key: []const u8, now: Io.Timestamp, port: u16, family: ?IpAddress.Family, out: []IpAddress) ?[]IpAddress {
        c.mutex.lockUncancelable(io);
        defer c.mutex.unlock(io);
        const e = c.entries.getPtr(key) orelse return null;
        if (now.nanoseconds >= e.expires.nanoseconds) return null;
        return pick(e.addresses[0..e.len], port, family, out);
    }

    fn pick(from: []const IpAddress, port: u16, family: ?IpAddress.Family, out: []IpAddress) ?[]IpAddress {
        var n: usize = 0;
        for (from) |a| {
            if (n == out.len) break;
            if (family) |f| if (a != f) continue;
            out[n] = a;
            out[n].setPort(port);
            n += 1;
        }
        return if (n == 0) null else out[0..n];
    }

    /// Keep `addresses` for `key`. An answer that cannot be kept for want
    /// of memory is simply not kept.
    fn keep(c: *Cache, io: Io, key: []const u8, now: Io.Timestamp, addresses: []const IpAddress) void {
        var entry: Entry = .{ .addresses = undefined, .len = @intCast(@min(addresses.len, max_kept)), .expires = now.addDuration(c.options.ttl) };
        @memcpy(entry.addresses[0..entry.len], addresses[0..entry.len]);
        c.mutex.lockUncancelable(io);
        defer c.mutex.unlock(io);
        if (c.entries.getPtr(key)) |e| {
            e.* = entry;
            return;
        }
        if (c.entries.count() >= c.options.max_entries) c.evict(now);
        if (c.entries.count() >= c.options.max_entries) return;
        const owned = c.gpa.dupe(u8, key) catch return;
        c.entries.put(c.gpa, owned, entry) catch c.gpa.free(owned);
    }

    /// Drop every expired answer, or else the one expiring first.
    fn evict(c: *Cache, now: Io.Timestamp) void {
        var soonest: ?[]const u8 = null;
        var soonest_at: i96 = std.math.maxInt(i96);
        var it = c.entries.iterator();
        while (it.next()) |kv| {
            const at = kv.value_ptr.expires.nanoseconds;
            if (at <= now.nanoseconds) {
                c.dropAt(kv.key_ptr.*);
                // The iterator is invalid after a removal: start over.
                it = c.entries.iterator();
                continue;
            }
            if (at < soonest_at) {
                soonest_at = at;
                soonest = kv.key_ptr.*;
            }
        }
        if (c.entries.count() < c.options.max_entries) return;
        if (soonest) |k| c.dropAt(k);
    }

    fn dropAt(c: *Cache, key: []const u8) void {
        const kv = c.entries.fetchRemove(key) orelse return;
        c.gpa.free(kv.key);
    }
};

const testing = std.testing;
const shakedown = @import("shakedown");

/// A resolver that answers every name with 10.0.0.1 and ::2, counting.
const Counting = struct {
    calls: u32 = 0,

    fn resolver(self: *Counting) Resolver {
        return .{ .context = self, .lookupFn = answer };
    }

    fn answer(_: Io, context: ?*anyopaque, _: []const u8, port: u16, family: ?IpAddress.Family, out: []IpAddress) LookupError![]IpAddress {
        const self: *Counting = @ptrCast(@alignCast(context.?)); // safe: the test passes a Counting
        self.calls += 1;
        const all = [_]IpAddress{ .{ .ip4 = .{ .bytes = .{ 10, 0, 0, 1 }, .port = port } }, .{ .ip6 = .loopback(port) } };
        return pick(&all, family, out);
    }

    fn pick(all: []const IpAddress, family: ?IpAddress.Family, out: []IpAddress) LookupError![]IpAddress {
        var n: usize = 0;
        for (all) |a| if (family == null or a == family.?) {
            out[n] = a;
            n += 1;
        };
        return out[0..n];
    }
};

test "static entries answer their names on their ports, and pass the rest on" {
    const io = testing.io;
    var counting: Counting = .{};
    const entries = [_]Static.Entry{
        .{ .host = "git.example", .port = 443, .addresses = &.{.{ .ip4 = .loopback(0) }} },
        .{ .host = "any.example", .addresses = &.{ .{ .ip6 = .loopback(0) }, .{ .ip4 = .loopback(0) } } },
    };
    const s: Static = .{ .entries = &entries, .fallback = counting.resolver() };
    var out: [4]IpAddress = undefined;
    const r = s.resolver();
    const git = try r.lookup(io, "GIT.example", 443, null, &out);
    try testing.expectEqual(@as(usize, 1), git.len);
    try testing.expectEqual(@as(u16, 443), git[0].getPort());
    try testing.expectEqual(@as(u32, 0), counting.calls);
    _ = try r.lookup(io, "git.example", 80, null, &out);
    try testing.expectEqual(@as(u32, 1), counting.calls);
    const four = try r.lookup(io, "any.example", 1, .ip4, &out);
    try testing.expectEqual(@as(usize, 1), four.len);
    try testing.expectEqual(@as(u16, 1), four[0].getPort());
    try testing.expectEqual(@as(u16, 9), (try r.lookup(io, "[::1]", 9, null, &out))[0].getPort());
}

test "curl's --resolve entries are read, with bracketed IPv6 and any port" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const e = try Static.parseEntry(arena.allocator(), "+example.com:443:127.0.0.1,[::1]");
    try testing.expectEqualStrings("example.com", e.host);
    try testing.expectEqual(@as(?u16, 443), e.port);
    try testing.expectEqual(@as(usize, 2), e.addresses.len);
    try testing.expectEqual(@as(?u16, null), (try Static.parseEntry(arena.allocator(), "h:*:10.0.0.1")).port);
    for ([_][]const u8{ "", "h:1", ":1:10.0.0.1", "h:x:10.0.0.1", "h:1:", "h:1:not-an-address" }) |bad| {
        try testing.expectError(error.InvalidEntry, Static.parseEntry(arena.allocator(), bad));
    }
}

test "a cached answer is kept for its time, for either family and any port" {
    var clock: shakedown.Clock = .init(testing.io, .{});
    const io = clock.io();
    var counting: Counting = .{};
    var cache: Cache = .init(testing.allocator, counting.resolver(), .{ .ttl = .fromSeconds(60), .max_entries = 2 });
    defer cache.deinit();
    const r = cache.resolver();
    var out: [4]IpAddress = undefined;
    try testing.expectEqual(@as(usize, 2), (try r.lookup(io, "a.example", 80, null, &out)).len);
    const v6 = try r.lookup(io, "A.EXAMPLE", 443, .ip6, &out);
    try testing.expectEqual(@as(usize, 1), v6.len);
    try testing.expectEqual(@as(u16, 443), v6[0].getPort());
    try testing.expectEqual(@as(u32, 1), counting.calls);
    // Full: an expired answer goes first, else the one expiring soonest.
    clock.advance(.fromSeconds(10));
    _ = try r.lookup(io, "b.example", 80, null, &out);
    clock.advance(.fromSeconds(1));
    _ = try r.lookup(io, "c.example", 80, null, &out);
    try testing.expectEqual(@as(u32, 3), counting.calls);
    try testing.expectEqual(@as(u32, 2), cache.entries.count());
    try testing.expect(cache.entries.get("a.example") == null);
    // Past its time an answer is asked for again.
    clock.advance(.fromSeconds(61));
    _ = try r.lookup(io, "b.example", 80, null, &out);
    try testing.expectEqual(@as(u32, 4), counting.calls);
    cache.clear(io);
    try testing.expectEqual(@as(u32, 0), cache.entries.count());
}

test "a cache that cannot allocate still answers" {
    var counting: Counting = .{};
    var cache: Cache = .init(testing.failing_allocator, counting.resolver(), .{});
    defer cache.deinit();
    var out: [4]IpAddress = undefined;
    try testing.expectEqual(@as(usize, 2), (try cache.resolver().lookup(testing.io, "a.example", 80, null, &out)).len);
    try testing.expectEqual(@as(usize, 2), (try cache.resolver().lookup(testing.io, "a.example", 80, null, &out)).len);
    try testing.expectEqual(@as(u32, 2), counting.calls);
}
