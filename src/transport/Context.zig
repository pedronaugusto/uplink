//! What every connection a client makes shares: its settings, its buffers,
//! its deadlines, its proxies and their answers, its resolver and the
//! authorities it trusts. A client holds one, and each connection it opens
//! points at it, so the client must not move once it has opened one.

const std = @import("std");
const sync = @import("../sync.zig");
const aegis = @import("aegis");
const reactor = @import("reactor");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const cloak = @import("cloak");
const tls_mod = @import("../tls.zig");
const Resolver = @import("../net/Resolver.zig");
const wire = @import("uplink.wire");
const url_mod = wire.url;
const BufferPool = @import("BufferPool.zig");
const span = @import("../span.zig");
const Duration = span.Duration;
const ZstdBuffer = @import("../coding/ZstdBuffer.zig");
const Timed = @import("../net/Timed.zig");
const Observer = @import("Observer.zig");
const Proxy = @import("Proxy.zig");
const ProxyAuth = @import("ProxyAuth.zig");

const Context = @This();

gpa: Allocator,
buffers: BufferPool,
/// Keeps the deadlines of operations: in the kernel on a reactor runtime,
/// by one task on any other `Io`, started at the first one.
deadlines: reactor.net.Deadlines,
proxies: Proxies,
tls: tls_mod.ClientOptions,
system_trust: SystemTrust = .init,
/// The tickets of sessions to resume, made at the first handshake that
/// can use them.
sessions: Sessions = .init,
timeouts: Timeouts,
dial: Dial,
/// What looks names up: the cache when there is one, around the caller's
/// resolver or the system's.
resolver: Resolver,
/// Private: the cache `resolver` goes through, when it does.
dns_cache: ?Resolver.Cache,
observer: ?*Observer,
/// The buffer zstd bodies are decoded in, and the cap on their window.
zstd: ZstdBuffer,
counters: Counters = .{},

/// What a context is made from.
pub const Options = struct {
    proxy: Proxy.Choice = .none,
    tls: tls_mod.ClientOptions = .{},
    timeouts: Timeouts = .{},
    dial: Dial = .{},
    resolver: ?Resolver = null,
    dns_cache: ?Resolver.Cache.Options = .{},
    observer: ?*Observer = null,
    /// The largest window a zstd body may ask for.
    max_zstd_window: aegis.units.Bytes(u32) = .literal("8MiB"),
    /// The most free buffers of each size kept.
    max_free_buffers: u32,
};

/// A context; it must not move once `resolve` has been called, since the
/// resolver points at its cache.
pub fn init(gpa: Allocator, options: Options) Context {
    if (options.tls.resumption) |r| {
        aegis.assert.pre(r.max_tickets >= 1 and r.max_tickets <= 1 << 20, "a ticket cache keeps 1 to 2^20 tickets");
        aegis.assert.pre(r.per_server >= 1 and r.per_server <= 16, "a server keeps 1 to 16 tickets");
        aegis.assert.pre(r.max_bytes.compare(.literal("4KiB")) != .lt, "a ticket cache holds at least 4 KiB");
    }
    return .{
        .gpa = gpa,
        .buffers = .init(gpa, options.max_free_buffers),
        .deadlines = .init(span.toIo(options.timeouts.shortestPerOperation() orelse .literal("10s"))),
        .proxies = .init(gpa, options.proxy),
        .tls = options.tls,
        .timeouts = options.timeouts,
        .dial = options.dial,
        .resolver = options.resolver orelse .system,
        .dns_cache = if (options.dns_cache) |o| .init(gpa, options.resolver orelse .system, o) else null,
        .observer = options.observer,
        .zstd = .init(options.max_zstd_window),
    };
}

/// GREASE for a handshake with no ECH config, when the options ask for it.
pub fn greaseOr(ctx: *const Context) cloak.tls.ech.Mode {
    return if (ctx.tls.ech == .grease) .grease else .off;
}

/// What keeps the deadlines of the context's connections.
pub fn keeper(ctx: *Context) Timed.Keeper {
    return .{ .deadlines = &ctx.deadlines, .unenforced = &ctx.counters.timeouts_unenforced };
}

/// The resolver connections use. Pointing at the context's cache, it is
/// taken where the context stays.
pub fn resolve(ctx: *Context) Resolver {
    return if (ctx.dns_cache) |*cache| cache.resolver() else ctx.resolver;
}

/// Release what the connections shared. Every connection must be closed.
pub fn deinit(ctx: *Context, io: Io) void {
    ctx.deadlines.deinit(io);
    ctx.proxies.deinit(io);
    ctx.system_trust.deinit(io);
    ctx.sessions.deinit(ctx.gpa, io);
    if (ctx.dns_cache) |*c| c.deinit(io);
    ctx.zstd.deinit(ctx.gpa);
    ctx.buffers.deinit(io);
    ctx.* = undefined;
}

/// How long each step may take; null is no limit.
pub const Timeouts = struct {
    /// The name's lookup and the TCP connection, every address included;
    /// with a SOCKS proxy, its negotiation and local lookup too.
    connect: ?Duration = null,
    /// Each TLS handshake, SOCKS negotiation and `CONNECT` exchange.
    handshake: ?Duration = null,
    /// Any single read or write that moves no byte: an answer that stops
    /// coming, a server that stops taking a body.
    activity: ?Duration = null,
    /// A connection moving fewer than `bytes_per_second` on average over
    /// `window`, while a request waits on it, is given up on: git's
    /// `http.lowSpeedLimit` and `http.lowSpeedTime`.
    low_speed: ?LowSpeed = null,

    pub const LowSpeed = struct {
        bytes_per_second: u32,
        window: Duration,
    };

    /// The bytes a low-speed window must move.
    pub fn lowSpeedNeed(l: LowSpeed) aegis.units.Bytes(u64) {
        const window = aegis.int.Checked(u128).init(l.window.raw());
        const moved = window.mul(l.bytes_per_second) catch unreachable; // unreachable: a u64 times a u32 fits a u128
        const need = moved.div(std.time.ns_per_s) catch unreachable; // unreachable: the divisor is a nonzero constant
        return .fromRaw(aegis.int.cast(u64, need.raw()) catch std.math.maxInt(u64));
    }

    /// The shortest of the timeouts kept per operation, or null.
    pub fn shortestPerOperation(t: Timeouts) ?Duration {
        var shortest: ?Duration = null;
        for ([_]?Duration{ t.handshake, t.activity, if (t.low_speed) |l| l.window else null }) |maybe| shortest = span.shorter(shortest, maybe);
        return shortest;
    }
};

/// How connections are made.
pub const Dial = struct {
    /// Every socket's options, set before it connects (reactor's): Nagle's
    /// algorithm off unless asked otherwise.
    socket: reactor.net.SocketOptions = .{ .nodelay = true },
    /// Connect from this address (its port 0 for any), and so only to
    /// addresses of its family.
    local_address: ?Io.net.IpAddress = null,
    /// Send through this interface only.
    interface: Io.net.Interface = .none,
    /// How long one address is tried alone before the next joins it
    /// (Happy Eyeballs, RFC 8305).
    attempt_delay: Duration = .literal("250ms"),
    /// Connect to this Unix socket instead, whatever the URL's host, for
    /// local daemons. The URL still names the `Host`.
    unix_socket: ?[]const u8 = null,
    /// Connect to this Windows named pipe instead, whatever the URL's host,
    /// for a local daemon that serves on one (Docker's
    /// `\\.\pipe\docker_engine`); not with `unix_socket`. The URL
    /// still names the `Host`. Elsewhere `NamedPipeUnsupported`.
    named_pipe: ?[]const u8 = null,
};

/// Where a connection goes. Connections with equal routes are
/// interchangeable: TLS settings are the client's, the same for every
/// route, and a proxy is one of the client's own.
///
/// A route owns its host by value, so a copy of one is whole on its own:
/// it cannot outlive bytes it points at, as a slice into a connection
/// freed under it could.
pub const Route = struct {
    /// TLS to the target.
    secure: bool,
    /// Private: the host's bytes; `host` reads them.
    host_name: Host,
    port: u16,
    /// The proxy between, and the answer it is given.
    proxy: ?*Proxies.Slot = null,
    /// Which HTTP the connection may speak.
    protocol: Protocol = .http1,

    /// Which HTTP a route's connections speak.
    pub const Protocol = enum {
        /// HTTP/1.1 alone.
        http1,
        /// HTTP/2 when TLS agrees it by ALPN, else HTTP/1.1.
        negotiate,
        /// HTTP/2 over plain TCP, by prior knowledge.
        h2_prior_knowledge,
        /// HTTP/1.1 over plain TCP, each request asking the server to
        /// switch to HTTP/2 (`Upgrade: h2c`).
        h2c_upgrade,
    };

    /// A host name's bytes, held by value.
    pub const Host = aegis.bounded.Array(u8, Io.net.HostName.max_len);

    /// A route to the host `name`, which is copied; `InvalidHostName` when it is longer than a host name can be.
    pub fn init(secure: bool, name: []const u8, port: u16, proxy: ?*Proxies.Slot) error{InvalidHostName}!Route {
        const bytes = Host.fromSlice(name) catch return error.InvalidHostName;
        return .{ .secure = secure, .host_name = bytes, .port = port, .proxy = proxy };
    }

    /// The host, as the route holds it.
    pub fn host(r: *const Route) []const u8 {
        return r.host_name.constItems();
    }

    pub fn eql(a: *const Route, b: *const Route) bool {
        return a.secure == b.secure and a.port == b.port and a.proxy == b.proxy and a.protocol == b.protocol and std.ascii.eqlIgnoreCase(a.host(), b.host());
    }
};

/// The proxies a client's requests go through: one fixed, or each scheme's
/// read from the environment the first time it is needed, and each with
/// its own answer to its challenges.
pub const Proxies = struct {
    choice: Proxy.Choice,
    gpa: Allocator,
    /// Private: what the environment's proxies were parsed into, reached
    /// only through the lock held while the environment is read.
    arena: aegis.BlockingGuarded(std.heap.ArenaAllocator),
    /// Private: the fixed proxy.
    fixed: Slot = undefined,
    // Each environment proxy is read once, under the lock, and published
    // with an atomic store of its `state`, written last; after that it is
    // read without the lock. `aegis.Once` would hand out the proxy as const,
    // and a slot's answer to its challenges changes through its own lock.
    /// Private: from the environment, for `http` (0) and `https` (1).
    from_env: [2]EnvSlot = .{ .{}, .{} },
    /// Private: the environment's `no_proxy`, once read (published with the
    /// first `state`).
    no_proxy: ?[]const u8 = null,

    /// One proxy and the answer it is given.
    pub const Slot = struct {
        proxy: Proxy,
        auth: ProxyAuth = .init,
    };

    const EnvSlot = struct {
        /// Read once, under the arena's lock, and published here.
        state: aegis.Atomic(enum(u8) { unread, none, some, invalid }) = .init(.unread),
        slot: Slot = undefined,
        /// The user and password of `slot`, wiped before they are freed.
        credential: ?aegis.SecretBytes = null,
    };

    pub fn init(gpa: Allocator, choice: Proxy.Choice) Proxies {
        var p: Proxies = .{ .choice = choice, .gpa = gpa, .arena = .init(.init(gpa)) };
        if (choice == .fixed) p.fixed = .{ .proxy = choice.fixed };
        return p;
    }

    pub fn deinit(p: *Proxies, io: Io) void {
        if (p.choice == .fixed) p.fixed.auth.deinit(io);
        for (&p.from_env) |*e| {
            if (e.state.load(.acquire) == .some) e.slot.auth.deinit(io);
            if (e.credential) |*c| c.deinit(p.gpa);
        }
        var held = p.arena.acquireUncancelable(io);
        held.value().deinit();
        held.deinit(io);
        p.* = undefined;
    }

    /// Errors from `forUrl`.
    pub const Error = error{
        /// The environment names a proxy that cannot be read.
        InvalidProxy,
        OutOfMemory,
    };

    /// The proxy a request to `url` goes through, or null.
    pub fn forUrl(p: *Proxies, io: Io, url: url_mod.Url) Error!?*Slot {
        switch (p.choice) {
            .none => return null,
            .fixed => return &p.fixed,
            .environment => |e| {
                const slot = &p.from_env[@intFromBool(url.secure)];
                if (slot.state.load(.acquire) == .unread) try p.read(io, e, url.secure);
                switch (slot.state.load(.acquire)) {
                    .unread => unreachable, // unreachable: `read` leaves it read
                    .none => return null,
                    .invalid => return error.InvalidProxy,
                    .some => {},
                }
                if (Proxy.bypassed(p.no_proxy.?, url.host, url.port, e.rules)) return null;
                return &slot.slot;
            },
        }
    }

    fn read(p: *Proxies, io: Io, e: Proxy.Choice.Environment, secure: bool) Error!void {
        var held = p.arena.acquireUncancelable(io);
        defer held.deinit(io);
        const slot = &p.from_env[@intFromBool(secure)];
        if (slot.state.load(.acquire) != .unread) return;
        const a = held.value().allocator();
        if (p.no_proxy == null) p.no_proxy = try a.dupe(u8, Proxy.noProxyValue(e.env, e.rules));
        const value = Proxy.environmentValue(e.env, secure, e.rules) orelse {
            slot.state.store(.none, .release);
            return;
        };
        const proxy = Proxy.parseKept(p.gpa, a, &slot.credential, value, e.rules) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidProxy => {
                slot.state.store(.invalid, .release);
                return;
            },
        };
        slot.slot = .{ .proxy = proxy };
        slot.state.store(.some, .release);
    }
};

/// What a client counts, without a lock: independent statistics that no
/// decision reads together, each one atomic.
pub const Counters = struct {
    /// Connections made.
    opened: sync.Counter = .init(.fromRaw(0)),
    /// Exchanges that went over a kept connection.
    reused: sync.Counter = .init(.fromRaw(0)),
    /// Connections an exchange holds now.
    in_use: sync.Gauge = .init(.fromRaw(0)),
    /// Timeouts asked for that could not be kept, for want of a task to
    /// keep them or an `Io` that bounds the operation.
    timeouts_unenforced: sync.Counter = .init(.fromRaw(0)),
};

/// The system's authorities, read once, at the first verifying handshake
/// that needs them.
/// The client's ticket cache, made at the first handshake that can use
/// it, so a client allocates nothing until its first request.
pub const Sessions = struct {
    cache: aegis.BlockingGuarded(?*cloak.tls.SessionCache),

    pub const init: Sessions = .{ .cache = .init(null) };

    pub fn deinit(s: *Sessions, gpa: Allocator, io: Io) void {
        var held = s.cache.acquireUncancelable(io);
        if (held.value().*) |cache| {
            cache.deinit();
            gpa.destroy(cache);
        }
        held.deinit(io);
        s.* = undefined;
    }

    /// The cache, made now if it was not yet, bounded by `options`.
    pub fn get(s: *Sessions, gpa: Allocator, io: Io, options: tls_mod.ClientOptions.Resumption) Allocator.Error!*cloak.tls.SessionCache {
        var held = s.cache.acquireUncancelable(io);
        defer held.deinit(io);
        const slot = held.value();
        if (slot.*) |cache| return cache;
        const cache = try gpa.create(cloak.tls.SessionCache);
        errdefer gpa.destroy(cache);
        cache.* = cloak.tls.SessionCache.init(gpa, .{
            .max_entries = options.max_tickets,
            .max_bytes = options.max_bytes.raw(),
            .per_key = options.per_server,
        }) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.InvalidOptions => unreachable, // unreachable: `Context.init` checked the bounds
        };
        slot.* = cache;
        return cache;
    }
};

pub const SystemTrust = struct {
    trust: aegis.BlockingGuarded(?cloak.Trust.Snapshot),

    pub const init: SystemTrust = .{ .trust = .init(null) };

    pub fn deinit(s: *SystemTrust, io: Io) void {
        var held = s.trust.acquireUncancelable(io);
        if (held.value().*) |snapshot| snapshot.deinit();
        held.deinit(io);
        s.* = undefined;
    }

    pub const Error = Allocator.Error || error{ Canceled, Unreadable };

    /// The system's authorities, read now if they were not yet. The snapshot
    /// is made once and kept until `deinit`; every handshake borrows it.
    pub fn get(s: *SystemTrust, gpa: Allocator, io: Io) Error!cloak.Trust.Snapshot {
        var held = s.trust.acquireUncancelable(io);
        defer held.deinit(io);
        const slot = held.value();
        if (slot.*) |snapshot| return snapshot;
        var builder: cloak.Trust = .init(gpa);
        defer builder.deinit();
        builder.addSystem(io, .{}) catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.Canceled => error.Canceled,
            else => error.Unreadable,
        };
        const snapshot = builder.freeze() catch |err| return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.Unreadable,
        };
        slot.* = snapshot;
        return snapshot;
    }
};

const testing = std.testing;
const test_io = @import("../testing/io.zig");
const Unwiped = @import("../testing/Unwiped.zig");

test "routes are equal without case in the host, and the shortest per-operation timeout is found" {
    const a: Route = try .init(true, "Example.com", 443, null);
    try testing.expect(a.eql(&try .init(true, "example.COM", 443, null)));
    try testing.expect(!a.eql(&try .init(false, "example.com", 443, null)));
    try testing.expect(!a.eql(&try .init(true, "example.com", 8443, null)));
    const long: [Io.net.HostName.max_len + 1]u8 = @splat('a');
    try testing.expectError(error.InvalidHostName, Route.init(true, &long, 443, null));
    const t: Timeouts = .{ .connect = .literal("1s"), .handshake = .literal("10s"), .activity = .literal("5s") };
    try testing.expectEqual(Duration.literal("5s"), t.shortestPerOperation().?);
    try testing.expectEqual(null, (Timeouts{ .connect = .literal("1s") }).shortestPerOperation());
    const slow: Timeouts = .{ .low_speed = .{ .bytes_per_second = 1000, .window = .literal("2s") } };
    try testing.expectEqual(Duration.literal("2s"), slow.shortestPerOperation().?);
    try testing.expectEqual(@as(u64, 2000), Timeouts.lowSpeedNeed(slow.low_speed.?).raw());
}

test "the environment's proxies are read once per scheme, and no_proxy applies per request" {
    const io = test_io.io();
    var env: std.process.Environ.Map = .init(testing.allocator);
    defer env.deinit();
    try env.put("http_proxy", "http://user:pw@proxy.test:3128");
    try env.put("no_proxy", "internal.test");
    var p: Proxies = .init(testing.allocator, .{ .environment = .{ .env = &env, .rules = .lowercase } });
    defer p.deinit(io);
    const slot = (try p.forUrl(io, try url_mod.parse("http://git.test/x"))).?;
    try testing.expectEqualStrings("proxy.test", slot.proxy.host);
    try testing.expectEqualStrings("pw", slot.proxy.credential.?.password);
    try testing.expectEqual(slot, (try p.forUrl(io, try url_mod.parse("http://other.test/"))).?);
    try testing.expectEqual(null, try p.forUrl(io, try url_mod.parse("http://a.internal.test/")));
    try testing.expectEqual(null, try p.forUrl(io, try url_mod.parse("https://git.test/")));
    try env.put("https_proxy", "unsupported://x");
    var bad: Proxies = .init(testing.allocator, .{ .environment = .{ .env = &env, .rules = .lowercase } });
    defer bad.deinit(io);
    try testing.expectError(error.InvalidProxy, bad.forUrl(io, try url_mod.parse("https://git.test/")));
}

test "an environment proxy's password is in no freed memory unwiped" {
    const io = test_io.io();
    var env: std.process.Environ.Map = .init(testing.allocator);
    defer env.deinit();
    try env.put("http_proxy", "http://user:pwtoken%21@proxy.test:3128");
    var unwiped: Unwiped = .init(testing.allocator, "pwtoken");
    var p: Proxies = .init(unwiped.allocator(), .{ .environment = .{ .env = &env, .rules = .lowercase } });
    const slot = (try p.forUrl(io, try url_mod.parse("http://git.test/x"))).?;
    try testing.expectEqualStrings("proxy.test", slot.proxy.host);
    try testing.expectEqualStrings("user", slot.proxy.credential.?.user);
    try testing.expectEqualStrings("pwtoken!", slot.proxy.credential.?.password);
    p.deinit(io);
    try testing.expect(!unwiped.found);
}
