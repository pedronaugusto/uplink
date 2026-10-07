//! What every connection a client makes shares: its settings, its buffers,
//! its timer, its proxies and their answers, its resolver and the
//! authorities it trusts. A client holds one, and each connection it opens
//! points at it, so the client must not move once it has opened one.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const tls_mod = @import("../tls.zig");
const Resolver = @import("../net/Resolver.zig");
const url_mod = @import("../wire/url.zig");
const BufferPool = @import("BufferPool.zig");
const Observer = @import("Observer.zig");
const Proxy = @import("Proxy.zig");
const ProxyAuth = @import("ProxyAuth.zig");
const Timer = @import("Timer.zig");

const Context = @This();

gpa: Allocator,
buffers: BufferPool,
/// Keeps the deadlines of operations; its task starts at the first one.
timer: Timer,
proxies: Proxies,
tls: tls_mod.ClientOptions,
system_trust: SystemTrust = .init,
timeouts: Timeouts,
dial: Dial,
/// What looks names up: the cache when there is one, around the caller's
/// resolver or the system's.
resolver: Resolver,
/// Private: the cache `resolver` goes through, when it does.
dns_cache: ?Resolver.Cache,
observer: ?Observer,
/// Private: one zstd window kept for the next zstd body.
zstd_window: std.atomic.Value(?[*]u8) = .init(null),
/// The length of a zstd window: the largest frame window decoded plus a
/// block.
zstd_window_len: usize,
counters: Counters = .{},

/// What a context is made from.
pub const Options = struct {
    proxy: Proxy.Choice = .none,
    tls: tls_mod.ClientOptions = .{},
    timeouts: Timeouts = .{},
    dial: Dial = .{},
    resolver: ?Resolver = null,
    dns_cache: ?Resolver.Cache.Options = .{},
    observer: ?Observer = null,
    max_zstd_window: u32 = 8 << 20,
    /// The most free buffers of each size kept.
    max_free_buffers: u32,
};

/// A context; it must not move once `resolve` has been called, since the
/// resolver points at its cache.
pub fn init(gpa: Allocator, options: Options) Context {
    return .{
        .gpa = gpa,
        .buffers = .init(gpa, options.max_free_buffers),
        .timer = .init(options.timeouts.shortestPerOperation()),
        .proxies = .init(gpa, options.proxy),
        .tls = options.tls,
        .timeouts = options.timeouts,
        .dial = options.dial,
        .resolver = options.resolver orelse .system,
        .dns_cache = if (options.dns_cache) |o| .init(gpa, options.resolver orelse .system, o) else null,
        .observer = options.observer,
        .zstd_window_len = @as(usize, options.max_zstd_window) + std.compress.zstd.block_size_max,
    };
}

/// The resolver connections use. Pointing at the context's cache, it is
/// taken where the context stays.
pub fn resolve(ctx: *Context) Resolver {
    return if (ctx.dns_cache) |*cache| cache.resolver() else ctx.resolver;
}

/// Release what the connections shared. Every connection must be closed.
pub fn deinit(ctx: *Context, io: Io) void {
    ctx.timer.deinit(io);
    ctx.proxies.deinit();
    ctx.system_trust.deinit();
    if (ctx.dns_cache) |*c| c.deinit();
    if (ctx.zstd_window.load(.acquire)) |w| ctx.gpa.free(w[0..ctx.zstd_window_len]);
    ctx.buffers.deinit();
    ctx.* = undefined;
}

/// A zstd window: the one kept, or a new one.
pub fn acquireZstdWindow(ctx: *Context) Allocator.Error![]u8 {
    if (ctx.zstd_window.swap(null, .acq_rel)) |w| return w[0..ctx.zstd_window_len];
    return ctx.gpa.alloc(u8, ctx.zstd_window_len);
}

/// Give a zstd window back: kept when none is, freed otherwise.
pub fn releaseZstdWindow(ctx: *Context, window: []u8) void {
    std.debug.assert(window.len == ctx.zstd_window_len);
    if (ctx.zstd_window.cmpxchgStrong(null, window.ptr, .acq_rel, .acquire) == null) return;
    ctx.gpa.free(window);
}

/// How long each step may take; null is no limit.
pub const Timeouts = struct {
    /// The name's lookup and the TCP connection, every address included;
    /// with a SOCKS proxy, its negotiation and local lookup too.
    connect: ?Io.Duration = null,
    /// Each TLS handshake, SOCKS negotiation and `CONNECT` exchange.
    handshake: ?Io.Duration = null,
    /// Any single read or write that moves no byte: an answer that stops
    /// coming, a server that stops taking a body.
    activity: ?Io.Duration = null,
    /// A connection moving fewer than `bytes_per_second` on average over
    /// `window`, while a request waits on it, is given up on: curl's
    /// `LOW_SPEED_LIMIT` and `LOW_SPEED_TIME`, git's
    /// `http.lowSpeedLimit` and `http.lowSpeedTime`.
    low_speed: ?LowSpeed = null,

    pub const LowSpeed = struct {
        bytes_per_second: u32,
        window: Io.Duration,
    };

    /// The bytes a low-speed window must move.
    pub fn lowSpeedNeed(l: LowSpeed) u64 {
        const ns: u128 = @intCast(@max(0, l.window.nanoseconds));
        return @intCast(@min(std.math.maxInt(u64), @as(u128, l.bytes_per_second) * ns / std.time.ns_per_s));
    }

    /// The shortest of the timeouts kept per operation, or null.
    pub fn shortestPerOperation(t: Timeouts) ?Io.Duration {
        var shortest: ?Io.Duration = null;
        for ([_]?Io.Duration{ t.handshake, t.activity, if (t.low_speed) |l| l.window else null }) |maybe| {
            const d = maybe orelse continue;
            if (shortest == null or d.nanoseconds < shortest.?.nanoseconds) shortest = d;
        }
        return shortest;
    }
};

/// How connections are made.
pub const Dial = struct {
    /// Turn Nagle's algorithm off on every socket.
    nodelay: bool = true,
    /// Turn TCP keepalive on, probing a connection idle this long.
    keepalive: ?Io.Duration = null,
    /// How long one address is tried alone before the next joins it
    /// (Happy Eyeballs, RFC 8305).
    attempt_delay: Io.Duration = .fromMilliseconds(250),
    /// Connect to this Unix socket instead, whatever the URL's host: curl's
    /// `--unix-socket`, for local daemons. The URL still names the `Host`.
    unix_socket: ?[]const u8 = null,
};

/// Where a connection goes. Connections with equal routes are
/// interchangeable: TLS settings are the client's, the same for every
/// route, and a proxy is one of the client's own.
pub const Route = struct {
    /// TLS to the target.
    secure: bool,
    host: []const u8,
    port: u16,
    /// The proxy between, and the answer it is given.
    proxy: ?*Proxies.Slot = null,

    pub fn eql(a: Route, b: Route) bool {
        return a.secure == b.secure and a.port == b.port and a.proxy == b.proxy and std.ascii.eqlIgnoreCase(a.host, b.host);
    }
};

/// The proxies a client's requests go through: one fixed, or each scheme's
/// read from the environment the first time it is needed, and each with
/// its own answer to its challenges.
pub const Proxies = struct {
    choice: Proxy.Choice,
    gpa: Allocator,
    /// Private: held while the environment is read.
    mutex: Io.Mutex = .init,
    /// Private: the fixed proxy.
    fixed: Slot = undefined,
    /// Private: from the environment, for `http` (0) and `https` (1).
    from_env: [2]EnvSlot = .{ .{}, .{} },
    /// Private: the environment's `no_proxy`, once read.
    no_proxy: ?[]const u8 = null,
    /// Private: what the environment's proxies were parsed into.
    arena: std.heap.ArenaAllocator,

    /// One proxy and the answer it is given.
    pub const Slot = struct {
        proxy: Proxy,
        auth: ProxyAuth = .init,
    };

    const EnvSlot = struct {
        state: enum(u8) { unread, none, some, invalid } = .unread,
        slot: Slot = undefined,
    };

    pub fn init(gpa: Allocator, choice: Proxy.Choice) Proxies {
        var p: Proxies = .{ .choice = choice, .gpa = gpa, .arena = .init(gpa) };
        if (choice == .fixed) p.fixed = .{ .proxy = choice.fixed };
        return p;
    }

    pub fn deinit(p: *Proxies) void {
        if (p.choice == .fixed) p.fixed.auth.deinit();
        for (&p.from_env) |*e| if (e.state == .some) e.slot.auth.deinit();
        p.arena.deinit();
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
                // Read once, under the lock; after that, read without it:
                // `state` is written last, and only once.
                if (@atomicLoad(@TypeOf(slot.state), &slot.state, .acquire) == .unread) try p.read(io, e, url.secure);
                switch (slot.state) {
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
        p.mutex.lockUncancelable(io);
        defer p.mutex.unlock(io);
        const slot = &p.from_env[@intFromBool(secure)];
        if (slot.state != .unread) return;
        const a = p.arena.allocator();
        if (p.no_proxy == null) p.no_proxy = try a.dupe(u8, Proxy.noProxyValue(e.env, e.rules));
        const value = Proxy.environmentValue(e.env, secure, e.rules) orelse {
            @atomicStore(@TypeOf(slot.state), &slot.state, .none, .release);
            return;
        };
        const proxy = Proxy.parse(a, value, e.rules) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidProxy => {
                @atomicStore(@TypeOf(slot.state), &slot.state, .invalid, .release);
                return;
            },
        };
        slot.slot = .{ .proxy = proxy };
        @atomicStore(@TypeOf(slot.state), &slot.state, .some, .release);
    }
};

/// What a client counts, without a lock.
pub const Counters = struct {
    /// Connections made.
    opened: std.atomic.Value(u64) = .init(0),
    /// Exchanges that went over a kept connection.
    reused: std.atomic.Value(u64) = .init(0),
    /// Connections an exchange holds now.
    in_use: std.atomic.Value(u32) = .init(0),
    /// Timeouts asked for that could not be kept, for want of a task to
    /// keep them or an `Io` that bounds the operation.
    timeouts_unenforced: std.atomic.Value(u64) = .init(0),
};

/// The system's authorities, read once, at the first verifying handshake
/// that needs them.
pub const SystemTrust = struct {
    mutex: Io.Mutex = .init,
    trust: ?tls_mod.Trust = null,

    pub const init: SystemTrust = .{};

    pub fn deinit(s: *SystemTrust) void {
        if (s.trust) |*t| t.deinit();
        s.* = undefined;
    }

    /// The system's authorities, read now if they were not yet.
    pub fn get(s: *SystemTrust, gpa: Allocator, io: Io) tls_mod.Trust.AddError!*tls_mod.Trust {
        s.mutex.lockUncancelable(io);
        defer s.mutex.unlock(io);
        if (s.trust) |*t| return t;
        var t: tls_mod.Trust = .init(gpa);
        errdefer t.deinit();
        try t.addSystem(io);
        s.trust = t;
        return &s.trust.?;
    }
};

const testing = std.testing;

test "routes are equal without case in the host, and the shortest per-operation timeout is found" {
    const a: Route = .{ .secure = true, .host = "Example.com", .port = 443 };
    try testing.expect(a.eql(.{ .secure = true, .host = "example.COM", .port = 443 }));
    try testing.expect(!a.eql(.{ .secure = false, .host = "example.com", .port = 443 }));
    try testing.expect(!a.eql(.{ .secure = true, .host = "example.com", .port = 8443 }));
    const t: Timeouts = .{ .connect = .fromSeconds(1), .handshake = .fromSeconds(10), .activity = .fromSeconds(5) };
    try testing.expectEqual(@as(i96, 5 * std.time.ns_per_s), t.shortestPerOperation().?.nanoseconds);
    try testing.expectEqual(null, (Timeouts{ .connect = .fromSeconds(1) }).shortestPerOperation());
    const slow: Timeouts = .{ .low_speed = .{ .bytes_per_second = 1000, .window = .fromSeconds(2) } };
    try testing.expectEqual(@as(i96, 2 * std.time.ns_per_s), slow.shortestPerOperation().?.nanoseconds);
    try testing.expectEqual(@as(u64, 2000), Timeouts.lowSpeedNeed(slow.low_speed.?));
}

test "the environment's proxies are read once per scheme, and no_proxy applies per request" {
    const io = testing.io;
    var env: std.process.Environ.Map = .init(testing.allocator);
    defer env.deinit();
    try env.put("http_proxy", "http://user:pw@proxy.test:3128");
    try env.put("no_proxy", "internal.test");
    var p: Proxies = .init(testing.allocator, .{ .environment = .{ .env = &env, .rules = .curl } });
    defer p.deinit();
    const slot = (try p.forUrl(io, try url_mod.parse("http://git.test/x"))).?;
    try testing.expectEqualStrings("proxy.test", slot.proxy.host);
    try testing.expectEqualStrings("pw", slot.proxy.credential.?.password);
    try testing.expectEqual(slot, (try p.forUrl(io, try url_mod.parse("http://other.test/"))).?);
    try testing.expectEqual(null, try p.forUrl(io, try url_mod.parse("http://a.internal.test/")));
    try testing.expectEqual(null, try p.forUrl(io, try url_mod.parse("https://git.test/")));
    try env.put("https_proxy", "unsupported://x");
    var bad: Proxies = .init(testing.allocator, .{ .environment = .{ .env = &env, .rules = .curl } });
    defer bad.deinit();
    try testing.expectError(error.InvalidProxy, bad.forUrl(io, try url_mod.parse("https://git.test/")));
}

test "a zstd window is kept for the next body, and one past it freed" {
    var ctx: Context = .init(testing.allocator, .{ .max_free_buffers = 1, .max_zstd_window = 1 << 10 });
    defer ctx.deinit(testing.io);
    const a = try ctx.acquireZstdWindow();
    const b = try ctx.acquireZstdWindow();
    ctx.releaseZstdWindow(a);
    ctx.releaseZstdWindow(b);
    const c = try ctx.acquireZstdWindow();
    try testing.expectEqual(a.ptr, c.ptr);
    ctx.releaseZstdWindow(c);
}
