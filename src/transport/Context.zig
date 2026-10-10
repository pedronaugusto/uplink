//! What every connection a client makes shares: its settings, its buffers,
//! its deadlines, its proxies and their answers, its resolver and the
//! authorities it trusts. A client holds one, and each connection it opens
//! points at it, so the client must not move once it has opened one.

const std = @import("std");
const aegis = @import("aegis");
const reactor = @import("reactor");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const tls_mod = @import("../tls.zig");
const Resolver = @import("../net/Resolver.zig");
const wire = @import("uplink.wire");
const url_mod = wire.url;
const BufferPool = @import("BufferPool.zig");
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
timeouts: Timeouts,
dial: Dial,
/// What looks names up: the cache when there is one, around the caller's
/// resolver or the system's.
resolver: Resolver,
/// Private: the cache `resolver` goes through, when it does.
dns_cache: ?Resolver.Cache,
observer: ?Observer,
/// Private: one zstd buffer kept for the next zstd body: taken and given
/// back with one atomic swap, whose winner owns the buffer, and there is no
/// state beside it for a lock to guard.
zstd_window: std.atomic.Value(?[*]u8) = .init(null),
/// The largest frame window a zstd body may ask for.
zstd_max_window: aegis.units.Bytes(u32),
/// The length of a zstd buffer: the window, a block, and room after them
/// for the decoder's state.
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
    max_zstd_window: aegis.units.Bytes(u32) = .fromRaw(8 << 20),
    /// The most free buffers of each size kept.
    max_free_buffers: u32,
};

/// A context; it must not move once `resolve` has been called, since the
/// resolver points at its cache.
pub fn init(gpa: Allocator, options: Options) Context {
    return .{
        .gpa = gpa,
        .buffers = .init(gpa, options.max_free_buffers),
        .deadlines = .init(options.timeouts.shortestPerOperation() orelse .fromSeconds(10)),
        .proxies = .init(gpa, options.proxy),
        .tls = options.tls,
        .timeouts = options.timeouts,
        .dial = options.dial,
        .resolver = options.resolver orelse .system,
        .dns_cache = if (options.dns_cache) |o| .init(gpa, options.resolver orelse .system, o) else null,
        .observer = options.observer,
        .zstd_max_window = options.max_zstd_window,
        .zstd_window_len = zstdWindowLen(options.max_zstd_window),
    };
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
    if (ctx.dns_cache) |*c| c.deinit(io);
    if (ctx.zstd_window.load(.acquire)) |w| ctx.gpa.free(alignedZstd(w[0..ctx.zstd_window_len]));
    ctx.buffers.deinit(io);
    ctx.* = undefined;
}

/// The part of a zstd buffer the decoder reads into: the window and a
/// block. A length no address space holds is the largest there is, which
/// no allocation will give.
pub fn zstdBufferLen(ctx: *const Context) usize {
    return zstdReadLen(ctx.zstd_max_window).raw();
}

fn zstdReadLen(window: aegis.units.Bytes(u32)) aegis.units.Bytes(usize) {
    const room = window.convert(usize) catch return .fromRaw(std.math.maxInt(usize));
    return room.add(.fromRaw(std.compress.zstd.block_size_max)) catch .fromRaw(std.math.maxInt(usize));
}

/// A zstd buffer whole: the read part aligned, and the decoder's state.
fn zstdWindowLen(window: aegis.units.Bytes(u32)) usize {
    const read = std.mem.alignForward(usize, zstdReadLen(window).raw(), 64);
    const whole = aegis.int.Checked(usize).init(read).add(@sizeOf(std.compress.zstd.Decompress)) catch return std.math.maxInt(usize);
    return whole.raw();
}

/// A zstd buffer: the one kept, or a new one, aligned for its decoder.
pub fn acquireZstdWindow(ctx: *Context) Allocator.Error![]u8 {
    if (ctx.zstd_window.swap(null, .acq_rel)) |w| return w[0..ctx.zstd_window_len];
    return ctx.gpa.alignedAlloc(u8, .@"64", ctx.zstd_window_len);
}

/// Give a zstd buffer back: kept when none is, freed otherwise.
pub fn releaseZstdWindow(ctx: *Context, window: []u8) void {
    std.debug.assert(window.len == ctx.zstd_window_len);
    if (ctx.zstd_window.cmpxchgStrong(null, window.ptr, .acq_rel, .acquire) == null) return;
    ctx.gpa.free(alignedZstd(window));
}

fn alignedZstd(window: []u8) []align(64) u8 {
    return @alignCast(window); // safe: every zstd buffer is allocated 64-aligned
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
    /// `window`, while a request waits on it, is given up on: git's
    /// `http.lowSpeedLimit` and `http.lowSpeedTime`.
    low_speed: ?LowSpeed = null,

    pub const LowSpeed = struct {
        bytes_per_second: u32,
        window: Io.Duration,
    };

    /// The bytes a low-speed window must move.
    pub fn lowSpeedNeed(l: LowSpeed) aegis.units.Bytes(u64) {
        const ns: u128 = @intCast(@max(0, l.window.nanoseconds)); // safe: the larger of zero and a span
        const need = @as(u128, l.bytes_per_second) * ns / std.time.ns_per_s;
        return .fromRaw(aegis.int.cast(u64, need) catch std.math.maxInt(u64));
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
    /// Connect to this Unix socket instead, whatever the URL's host, for
    /// local daemons. The URL still names the `Host`.
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
        state: enum(u8) { unread, none, some, invalid } = .unread,
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
            if (e.state == .some) e.slot.auth.deinit(io);
            if (e.credential) |*c| c.deinit();
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
        var held = p.arena.acquireUncancelable(io);
        defer held.deinit(io);
        const slot = &p.from_env[@intFromBool(secure)];
        if (slot.state != .unread) return;
        const a = held.value().allocator();
        if (p.no_proxy == null) p.no_proxy = try a.dupe(u8, Proxy.noProxyValue(e.env, e.rules));
        const value = Proxy.environmentValue(e.env, secure, e.rules) orelse {
            @atomicStore(@TypeOf(slot.state), &slot.state, .none, .release);
            return;
        };
        const proxy = parseKept(p.gpa, a, &slot.credential, value, e.rules) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.InvalidProxy => {
                @atomicStore(@TypeOf(slot.state), &slot.state, .invalid, .release);
                return;
            },
        };
        slot.slot = .{ .proxy = proxy };
        @atomicStore(@TypeOf(slot.state), &slot.state, .some, .release);
    }

    /// `Proxy.parse` of `value`, its host in `arena` and its user and
    /// password in `credential`: parsed in scratch that is wiped, so the
    /// password is in no arena, whose memory is freed unwiped.
    fn parseKept(gpa: Allocator, arena: Allocator, credential: *?aegis.SecretBytes, value: []const u8, rules: Proxy.Rules) Error!Proxy {
        // The URL copied, the host, and the user and password unescaped: no
        // more than four times `value`, and a prefix of `http://`.
        const room = value.len * 4 + 64;
        var scratch: aegis.SecretBytes = try .init(gpa, room);
        defer scratch.deinit();
        scratch.resizeWithinCapacity(room) catch unreachable; // unreachable: `room` is the capacity just made
        var fixed: std.heap.FixedBufferAllocator = .init(scratch.exposeMut());
        var proxy = try Proxy.parse(fixed.allocator(), value, rules);
        proxy.host = try arena.dupe(u8, proxy.host);
        if (proxy.credential) |c| {
            var kept: aegis.SecretBytes = try .init(gpa, c.user.len + c.password.len);
            errdefer kept.deinit();
            kept.resizeWithinCapacity(c.user.len + c.password.len) catch unreachable; // unreachable: the capacity just made
            const bytes = kept.exposeMut();
            @memcpy(bytes[0..c.user.len], c.user);
            @memcpy(bytes[c.user.len..], c.password);
            proxy.credential = .{ .user = bytes[0..c.user.len], .password = bytes[c.user.len..], .method = c.method };
            credential.* = kept;
        }
        return proxy;
    }
};

/// What a client counts, without a lock: independent statistics that no
/// decision reads together, each one atomic.
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
    trust: aegis.BlockingGuarded(?tls_mod.Trust),

    pub const init: SystemTrust = .{ .trust = .init(null) };

    pub fn deinit(s: *SystemTrust, io: Io) void {
        var held = s.trust.acquireUncancelable(io);
        if (held.value().*) |*t| t.deinit();
        held.deinit(io);
        s.* = undefined;
    }

    /// The system's authorities, read now if they were not yet. The trust
    /// is made once and not moved or freed before `deinit`, so it outlives
    /// the lock it is read under.
    pub fn get(s: *SystemTrust, gpa: Allocator, io: Io) tls_mod.Trust.AddError!*tls_mod.Trust {
        var held = s.trust.acquireUncancelable(io);
        defer held.deinit(io);
        const slot = held.value();
        if (slot.*) |*t| return t;
        var t: tls_mod.Trust = .init(gpa);
        errdefer t.deinit();
        try t.addSystem(io);
        slot.* = t;
        return &slot.*.?;
    }
};

const testing = std.testing;
const test_io = @import("../testing/io.zig");
const Unwiped = @import("../testing/Unwiped.zig");

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

test "a zstd window is kept for the next body, and one past it freed" {
    var ctx: Context = .init(testing.allocator, .{ .max_free_buffers = 1, .max_zstd_window = .fromRaw(1 << 10) });
    defer ctx.deinit(test_io.io());
    const a = try ctx.acquireZstdWindow();
    const b = try ctx.acquireZstdWindow();
    ctx.releaseZstdWindow(a);
    ctx.releaseZstdWindow(b);
    const c = try ctx.acquireZstdWindow();
    try testing.expectEqual(a.ptr, c.ptr);
    ctx.releaseZstdWindow(c);
}
