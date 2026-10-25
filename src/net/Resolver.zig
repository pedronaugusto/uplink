//! How a host name becomes addresses: the system's lookup by default, or a
//! caller's own. `Static` answers chosen names with chosen addresses and
//! passes the rest on; `Cache` keeps answers for a while. Each wraps another
//! resolver, so they stack.
//!
//! A resolver that reads DNS itself (`Dns`) also answers a name's HTTPS
//! service binding (RFC 9460), which says where and how an `https` origin
//! is reached: `service`. The system's lookup reads none.
//!
//! An address literal never reaches a resolver: `lookup` answers it itself.

const std = @import("std");
const aegis = @import("aegis");
const reactor = @import("reactor");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const dns = @import("uplink.wire").dns;
const span = @import("../span.zig");
const Duration = span.Duration;
const IpAddress = Io.net.IpAddress;

const Resolver = @This();

context: ?*anyopaque,
/// Answer `host`, a name, with up to `out.len` addresses on `port`, of
/// `family` when one is given.
lookupFn: *const fn (io: Io, context: ?*anyopaque, host: []const u8, port: u16, family: ?IpAddress.Family, out: []IpAddress) LookupError![]IpAddress,
/// Answer the HTTPS records of `name`, the DNS name asked (a port's prefix
/// included), owned by `gpa`; null when it has none or they could not be
/// had. Null for a resolver that reads none.
serviceFn: ?*const fn (io: Io, context: ?*anyopaque, gpa: Allocator, name: []const u8) ServiceError!?Binding = null,

pub const LookupError = reactor.net.ResolveError;

/// Why `service` could not answer. A name whose records could not be had
/// (no answer, a server failure) has none: a client then connects as it
/// would without them (RFC 9460 §3).
pub const ServiceError = error{ OutOfMemory, Canceled };

/// An origin's HTTPS service binding: the ServiceMode records a client can
/// use (every key they make mandatory known), the most preferred first,
/// held past the answer they came in.
pub const Binding = struct {
    records: []Record,
    /// Private: the records' targets and parameters.
    bytes: []u8,

    /// One endpoint of the binding.
    pub const Record = struct {
        /// The name to connect to: the record's target, or the name its
        /// owner when it names none.
        target: []const u8,
        /// Its priority and parameters; its target is `target`.
        service: dns.Service,
    };

    /// A binding of copies of `records`, each with its effective target.
    pub fn init(gpa: Allocator, records: []const Record) Allocator.Error!Binding {
        var len: usize = 0;
        for (records) |r| len += r.target.len + r.service.params.len;
        const bytes = try gpa.alloc(u8, len);
        errdefer gpa.free(bytes);
        const copies = try gpa.alloc(Record, records.len);
        var at: usize = 0;
        for (records, copies) |r, *c| {
            const target = bytes[at..][0..r.target.len];
            @memcpy(target, r.target);
            at += target.len;
            const params = bytes[at..][0..r.service.params.len];
            @memcpy(params, r.service.params);
            at += params.len;
            c.* = .{ .target = target, .service = .{ .priority = r.service.priority, .target = target, .params = params } };
        }
        return .{ .records = copies, .bytes = bytes };
    }

    /// A copy owned by `gpa`.
    pub fn clone(b: Binding, gpa: Allocator) Allocator.Error!Binding {
        return init(gpa, b.records);
    }

    pub fn deinit(b: *Binding, gpa: Allocator) void {
        gpa.free(b.records);
        gpa.free(b.bytes);
        b.* = undefined;
    }
};

/// The DNS name an `https` origin's records are under: the host itself on
/// port 443, else under its port's prefix, `_8443._https.host` (RFC 9460
/// §9.1).
pub fn serviceName(host: []const u8, port: u16, out: *[dns.max_name]u8) error{InvalidHostName}![]const u8 {
    const trimmed = if (host.len != 0 and host[host.len - 1] == '.') host[0 .. host.len - 1] else host;
    if (port == 443) {
        if (trimmed.len > out.len) return error.InvalidHostName;
        @memcpy(out[0..trimmed.len], trimmed);
        return out[0..trimmed.len];
    }
    return std.mem.print(out, "_{d}._https.{s}", .{ port, trimmed }) catch error.InvalidHostName;
}

/// The HTTPS service binding of the `https` origin `host` on `port`, owned
/// by `gpa`; null when it has none, when `host` is an address, or when the
/// resolver reads no such records.
pub fn service(r: Resolver, io: Io, gpa: Allocator, host: []const u8, port: u16) ServiceError!?Binding {
    const answer = r.serviceFn orelse return null;
    if (reactor.net.literal(host, port) != null) return null;
    var name_buf: [dns.max_name]u8 = undefined;
    const name = serviceName(host, port, &name_buf) catch return null;
    return answer(io, r.context, gpa, name);
}

/// `host`'s addresses on `port`: the address itself when `host` is one,
/// else the resolver's answer.
pub fn lookup(r: Resolver, io: Io, host: []const u8, port: u16, family: ?IpAddress.Family, out: []IpAddress) LookupError![]IpAddress {
    std.debug.assert(out.len != 0);
    if (reactor.net.literal(host, port)) |address| {
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
pub fn lookupWithin(r: Resolver, io: Io, host: []const u8, port: u16, family: ?IpAddress.Family, out: []IpAddress, timeout: ?Duration, bounded: *bool) LookupWithinError![]IpAddress {
    bounded.* = true;
    const limit = timeout orelse return r.lookupMapped(io, host, port, family, out);
    if (reactor.net.literal(host, port) != null) return r.lookupMapped(io, host, port, family, out);
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
    race.concurrent(.expired, Io.sleep, .{ io, span.toIo(limit), .awake }) catch {
        // The lookup runs already; wait for it, unbounded.
        bounded.* = false;
        return switch (try race.await()) {
            .found => |result| result,
            .expired => unreachable, // unreachable: no delay was started
        };
    };
    return switch (try race.await()) {
        .found => |result| result,
        .expired => |result| if (result) |_| error.TimedOut else |err| err,
    };
}

fn lookupMapped(r: Resolver, io: Io, host: []const u8, port: u16, family: ?IpAddress.Family, out: []IpAddress) LookupWithinError![]IpAddress {
    return r.lookup(io, host, port, family, out);
}

/// The system's lookup, by reactor's `net.resolve`: bounded, and waiting on
/// no work started with `io.async`.
pub const system: Resolver = .{ .context = null, .lookupFn = systemLookup };

fn systemLookup(io: Io, _: ?*anyopaque, host: []const u8, port: u16, family: ?IpAddress.Family, out: []IpAddress) LookupError![]IpAddress {
    return reactor.net.resolve(io, host, port, .{ .family = family }, out);
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
        return .{ .context = @constCast(s), .lookupFn = staticLookup, .serviceFn = if (s.fallback.serviceFn != null) staticService else null }; // safe: the lookups only read through the pointer
    }

    /// A name listed is reached at the addresses given, so it has no
    /// binding to send it elsewhere; the rest are the fallback's.
    fn staticService(io: Io, context: ?*anyopaque, gpa: Allocator, name: []const u8) ServiceError!?Binding {
        const s: *const Static = @ptrCast(@alignCast(context.?)); // safe: `resolver` passes a Static
        for (s.entries) |e| if (std.ascii.eqlIgnoreCase(e.host, originOf(name))) return null;
        return s.fallback.serviceFn.?(io, s.fallback.context, gpa, name);
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

    /// An entry in the form `host:port:address[,address]`, IPv6 addresses
    /// bracketed or not, `*` for any port, a leading `+` allowed; the
    /// addresses belong to `arena`.
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
            const address = reactor.net.literal(a, 0) orelse return error.InvalidEntry;
            try list.append(arena, address);
        }
        if (list.items.len == 0) return error.InvalidEntry;
        return .{ .host = host, .port = port, .addresses = list.items };
    }
};

/// The host a service name is for: past a port's prefix.
fn originOf(name: []const u8) []const u8 {
    if (name.len == 0 or name[0] != '_') return name;
    const https = std.mem.find(u8, name, "._https.") orelse return name;
    return name[https + "._https.".len ..];
}

/// Answers kept for `ttl`, per name, the system's lookup having no time to
/// live to give. Shared by every task of a client; a name is looked up by
/// whichever task first misses it.
pub const Cache = struct {
    gpa: Allocator,
    inner: Resolver,
    options: Options,
    /// Private: names, lower-cased and owned, to their answers, reached
    /// only through the lock beside them.
    entries: aegis.BlockingGuarded(std.StringHashMapUnmanaged(Entry)),
    /// Private: service names, lower-cased and owned, to their bindings,
    /// none included, reached only through the lock beside them.
    services: aegis.BlockingGuarded(std.StringHashMapUnmanaged(ServiceEntry)),

    pub const Options = struct {
        /// How long an answer is kept.
        ttl: Duration = .literal("60s"),
        /// The most names kept, and apart from them the most service
        /// names; past it, expired answers go, then the one closest to
        /// expiring.
        max_entries: u32 = 256,
    };

    const ServiceEntry = struct {
        /// Null: the name has none.
        binding: ?Binding,
        /// On the awake clock.
        expires: Io.Timestamp,
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
        return .{ .gpa = gpa, .inner = inner, .options = options, .entries = .init(.empty), .services = .init(.empty) };
    }

    /// Free every answer. No task may be looking a name up.
    pub fn deinit(c: *Cache, io: Io) void {
        var held = c.entries.acquireUncancelable(io);
        const entries = held.value();
        var it = entries.keyIterator();
        while (it.next()) |k| c.gpa.free(k.*);
        entries.deinit(c.gpa);
        held.deinit(io);
        c.clearServices(io);
        var services = c.services.acquireUncancelable(io);
        services.value().deinit(c.gpa);
        services.deinit(io);
        c.* = undefined;
    }

    pub fn resolver(c: *Cache) Resolver {
        return .{ .context = c, .lookupFn = cacheLookup, .serviceFn = if (c.inner.serviceFn != null) cacheService else null };
    }

    /// Forget every answer.
    pub fn clear(c: *Cache, io: Io) void {
        {
            var held = c.entries.acquireUncancelable(io);
            defer held.deinit(io);
            const entries = held.value();
            var it = entries.keyIterator();
            while (it.next()) |k| c.gpa.free(k.*);
            entries.clearRetainingCapacity();
        }
        c.clearServices(io);
    }

    fn clearServices(c: *Cache, io: Io) void {
        var held = c.services.acquireUncancelable(io);
        defer held.deinit(io);
        const services = held.value();
        var it = services.iterator();
        while (it.next()) |kv| c.freeService(kv.key_ptr.*, kv.value_ptr);
        services.clearRetainingCapacity();
    }

    fn freeService(c: *Cache, key: []const u8, e: *ServiceEntry) void {
        c.gpa.free(key);
        if (e.binding) |*b| b.deinit(c.gpa);
    }

    fn cacheService(io: Io, context: ?*anyopaque, gpa: Allocator, name: []const u8) ServiceError!?Binding {
        const c: *Cache = @ptrCast(@alignCast(context.?)); // safe: `resolver` passes a Cache
        var key_buf: [dns.max_name]u8 = undefined;
        if (name.len > key_buf.len) return null;
        const key = std.ascii.lowerString(&key_buf, name);
        const now = Io.Clock.awake.now(io);
        {
            var held = c.services.acquireUncancelable(io);
            defer held.deinit(io);
            if (held.value().getPtr(key)) |e| if (now.nanoseconds < e.expires.nanoseconds) {
                const b = e.binding orelse return null;
                return try b.clone(gpa);
            };
        }
        const fresh = try c.inner.serviceFn.?(io, c.inner.context, gpa, name);
        c.keepService(io, key, now, fresh);
        return fresh;
    }

    /// Keep `binding`, or that there is none, for `key`. One that cannot be
    /// kept for want of memory is simply not kept.
    fn keepService(c: *Cache, io: Io, key: []const u8, now: Io.Timestamp, binding: ?Binding) void {
        var entry: ServiceEntry = .{ .binding = null, .expires = now.addDuration(span.toIo(c.options.ttl)) };
        if (binding) |b| entry.binding = b.clone(c.gpa) catch return;
        var held = c.services.acquireUncancelable(io);
        defer held.deinit(io);
        const services = held.value();
        if (services.getPtr(key)) |e| {
            if (e.binding) |*old| old.deinit(c.gpa);
            e.* = entry;
            return;
        }
        if (services.count() >= c.options.max_entries) c.evictService(services, now);
        if (services.count() >= c.options.max_entries or !c.putService(services, key, entry)) if (entry.binding) |*b| b.deinit(c.gpa);
    }

    fn putService(c: *Cache, services: *std.StringHashMapUnmanaged(ServiceEntry), key: []const u8, entry: ServiceEntry) bool {
        const owned = c.gpa.dupe(u8, key) catch return false;
        services.put(c.gpa, owned, entry) catch {
            c.gpa.free(owned);
            return false;
        };
        return true;
    }

    /// Drop every expired service answer, or else the one expiring first.
    fn evictService(c: *Cache, services: *std.StringHashMapUnmanaged(ServiceEntry), now: Io.Timestamp) void {
        var soonest: ?[]const u8 = null;
        var soonest_at: ?Io.Timestamp = null;
        var it = services.iterator();
        while (it.next()) |kv| {
            const at = kv.value_ptr.expires;
            if (at.compare(.lte, now)) {
                c.dropService(services, kv.key_ptr.*);
                it = services.iterator();
                continue;
            }
            if (soonest_at == null or at.compare(.lt, soonest_at.?)) {
                soonest_at = at;
                soonest = kv.key_ptr.*;
            }
        }
        if (services.count() < c.options.max_entries) return;
        if (soonest) |k| c.dropService(services, k);
    }

    fn dropService(c: *Cache, services: *std.StringHashMapUnmanaged(ServiceEntry), key: []const u8) void {
        var kv = services.fetchRemove(key) orelse return;
        c.freeService(kv.key, &kv.value);
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
        var held = c.entries.acquireUncancelable(io);
        defer held.deinit(io);
        const e = held.value().getPtr(key) orelse return null;
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
        var entry: Entry = .{ .addresses = undefined, .len = @intCast(@min(addresses.len, max_kept)), .expires = now.addDuration(span.toIo(c.options.ttl)) };
        @memcpy(entry.addresses[0..entry.len], addresses[0..entry.len]);
        var held = c.entries.acquireUncancelable(io);
        defer held.deinit(io);
        const entries = held.value();
        if (entries.getPtr(key)) |e| {
            e.* = entry;
            return;
        }
        if (entries.count() >= c.options.max_entries) c.evict(entries, now);
        if (entries.count() >= c.options.max_entries) return;
        const owned = c.gpa.dupe(u8, key) catch return;
        entries.put(c.gpa, owned, entry) catch c.gpa.free(owned);
    }

    /// Drop every expired answer, or else the one expiring first.
    fn evict(c: *Cache, entries: *std.StringHashMapUnmanaged(Entry), now: Io.Timestamp) void {
        var soonest: ?[]const u8 = null;
        var soonest_at: ?Io.Timestamp = null;
        var it = entries.iterator();
        while (it.next()) |kv| {
            const at = kv.value_ptr.expires;
            if (at.compare(.lte, now)) {
                c.dropAt(entries, kv.key_ptr.*);
                // The iterator is invalid after a removal: start over.
                it = entries.iterator();
                continue;
            }
            if (soonest_at == null or at.compare(.lt, soonest_at.?)) {
                soonest_at = at;
                soonest = kv.key_ptr.*;
            }
        }
        if (entries.count() < c.options.max_entries) return;
        if (soonest) |k| c.dropAt(entries, k);
    }

    fn dropAt(c: *Cache, entries: *std.StringHashMapUnmanaged(Entry), key: []const u8) void {
        const kv = entries.fetchRemove(key) orelse return;
        c.gpa.free(kv.key);
    }
};

const testing = std.testing;
const test_io = @import("../testing/io.zig");
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

/// A resolver that waits a moment, a point a cancelation would end it at,
/// and answers 10.0.0.1.
const Slow = struct {
    fn resolver() Resolver {
        return .{ .context = null, .lookupFn = answer };
    }

    fn answer(io: Io, _: ?*anyopaque, _: []const u8, port: u16, _: ?IpAddress.Family, out: []IpAddress) LookupError![]IpAddress {
        try io.sleep(.fromMilliseconds(20), .awake);
        out[0] = .{ .ip4 = .{ .bytes = .{ 10, 0, 0, 1 }, .port = port } };
        return out[0..1];
    }
};

test "a lookup with no task for its limit is waited for, never canceled" {
    // The lookup's task starts; the limit's does not.
    const plan = [_]shakedown.IoPlan.Entry{.{ .at = .{ .nth = .{ .call = .groupConcurrent, .n = 2 } }, .fault = .{ .fail = error.ConcurrencyUnavailable } }};
    const fio = try shakedown.FaultIo.init(testing.allocator, test_io.io(), .{ .plan = &plan });
    defer fio.deinit();
    var out: [4]IpAddress = undefined;
    var bounded = true;
    const found = try Slow.resolver().lookupWithin(fio.io(), "slow.example", 80, null, &out, .literal("5s"), &bounded);
    try testing.expectEqual(@as(usize, 1), found.len);
    try testing.expect(!bounded);
}

test "static entries answer their names on their ports, and pass the rest on" {
    const io = test_io.io();
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

test "entries in host:port:address form are read, with bracketed IPv6 and any port" {
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

/// How many names the cache keeps answers for.
fn keptNames(c: *Cache, io: Io) u32 {
    var held = c.entries.acquireUncancelable(io);
    defer held.deinit(io);
    return held.value().count();
}

/// Whether the cache keeps an answer for `name`.
fn kept(c: *Cache, io: Io, name: []const u8) bool {
    var held = c.entries.acquireUncancelable(io);
    defer held.deinit(io);
    return held.value().contains(name);
}

test "a cached answer is kept for its time, for either family and any port" {
    var clock: shakedown.Clock = .init(test_io.io(), .{});
    const io = clock.io();
    var counting: Counting = .{};
    var cache: Cache = .init(testing.allocator, counting.resolver(), .{ .ttl = .literal("60s"), .max_entries = 2 });
    defer cache.deinit(io);
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
    try testing.expectEqual(@as(u32, 2), keptNames(&cache, io));
    try testing.expect(!kept(&cache, io, "a.example"));
    // Past its time an answer is asked for again.
    clock.advance(.fromSeconds(61));
    _ = try r.lookup(io, "b.example", 80, null, &out);
    try testing.expectEqual(@as(u32, 4), counting.calls);
    cache.clear(io);
    try testing.expectEqual(@as(u32, 0), keptNames(&cache, io));
}

test "a cache that cannot allocate still answers" {
    const io = test_io.io();
    var counting: Counting = .{};
    var cache: Cache = .init(testing.failing_allocator, counting.resolver(), .{});
    defer cache.deinit(io);
    var out: [4]IpAddress = undefined;
    try testing.expectEqual(@as(usize, 2), (try cache.resolver().lookup(test_io.io(), "a.example", 80, null, &out)).len);
    try testing.expectEqual(@as(usize, 2), (try cache.resolver().lookup(test_io.io(), "a.example", 80, null, &out)).len);
    try testing.expectEqual(@as(u32, 2), counting.calls);
}

test "fuzz: any entry is read or refused, and one read has its host and addresses" {
    const seeds = [_][]const u8{ "example.com:443:127.0.0.1", "+a:*:[::1],10.0.0.1", "h:80: 1.2.3.4 ,", "x:99999:1.1.1.1" };
    try shakedown.check(std.testing.allocator, {}, struct {
        fn one(_: void, case: *shakedown.Case) anyerror!void {
            const gen = shakedown.gen;
            const s = case.source;
            // A known entry with a few bytes changed, or bytes from the
            // entry's own alphabet.
            var buf: [96]u8 = undefined;
            var len: usize = 0;
            if (gen.boolean(s)) {
                const seed = gen.oneOf(s, []const u8, &seeds);
                @memcpy(buf[0..seed.len], seed);
                len = seed.len;
                for (0..gen.intRange(s, u8, 0, 4)) |_| buf[gen.intRange(s, usize, 0, len - 1)] = gen.oneOf(s, u8, "a:.,[]*+ 19f");
            } else {
                while (len < buf.len and s.more(24)) : (len += 1) buf[len] = gen.oneOf(s, u8, "a:.,[]*+ 019f");
            }
            const text = buf[0..len];
            var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
            defer arena.deinit();
            const entry = Static.parseEntry(arena.allocator(), text) catch return;
            try std.testing.expect(entry.host.len != 0);
            try std.testing.expect(std.mem.findScalar(u8, entry.host, ':') == null);
        }
    }.one, .{});
}

test "an origin's records are under its name on 443, and under its port's prefix elsewhere" {
    var buf: [dns.max_name]u8 = undefined;
    try testing.expectEqualStrings("example.com", try serviceName("example.com.", 443, &buf));
    try testing.expectEqualStrings("_8443._https.example.com", try serviceName("example.com", 8443, &buf));
    try testing.expectEqualStrings("example.com", originOf("_8443._https.example.com"));
    try testing.expectEqualStrings("example.com", originOf("example.com"));
}
