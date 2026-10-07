//! What every connection a client makes shares: its settings, its buffers,
//! its timer, its proxy answer and the authorities it trusts. A client
//! holds one, and each connection it opens points at it, so the client must
//! not move once it has opened one.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const tls_mod = @import("../tls.zig");
const BufferPool = @import("BufferPool.zig");
const Proxy = @import("Proxy.zig");
const ProxyAuth = @import("ProxyAuth.zig");
const Timer = @import("Timer.zig");

const Context = @This();

gpa: Allocator,
buffers: BufferPool,
/// Null when no read, write or handshake timeout is set.
timer: ?Timer,
proxy: ?Proxy,
proxy_auth: ProxyAuth = .init,
tls: tls_mod.ClientOptions,
system_trust: SystemTrust = .init,
timeouts: Timeouts,
/// Turn Nagle's algorithm off on every socket.
nodelay: bool,
counters: Counters = .{},

/// Release what the connections shared. Every connection must be closed.
pub fn deinit(ctx: *Context, io: Io) void {
    if (ctx.timer) |*t| t.deinit(io);
    ctx.proxy_auth.deinit();
    ctx.system_trust.deinit();
    ctx.buffers.deinit();
    ctx.* = undefined;
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

    /// The shortest of the timeouts kept on the socket's reads and writes,
    /// or null: each handshake's and each operation's, and through a SOCKS
    /// proxy `connect`, which its negotiation runs within.
    pub fn shortestOnSocket(t: Timeouts, socks: bool) ?Io.Duration {
        var shortest: ?Io.Duration = null;
        for ([_]?Io.Duration{ t.handshake, t.activity, if (socks) t.connect else null }) |d| {
            const each = d orelse continue;
            if (shortest == null or each.nanoseconds < shortest.?.nanoseconds) shortest = each;
        }
        return shortest;
    }
};

/// Where a connection goes. Connections with equal routes are
/// interchangeable: the proxy and TLS settings are the client's, so they
/// are the same for every route of one client.
pub const Route = struct {
    /// TLS to the target.
    secure: bool,
    host: []const u8,
    port: u16,

    pub fn eql(a: Route, b: Route) bool {
        return a.secure == b.secure and a.port == b.port and std.ascii.eqlIgnoreCase(a.host, b.host);
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

test "routes are equal without case in the host, and the shortest timeout kept on the socket is found" {
    const a: Route = .{ .secure = true, .host = "Example.com", .port = 443 };
    try std.testing.expect(a.eql(.{ .secure = true, .host = "example.COM", .port = 443 }));
    try std.testing.expect(!a.eql(.{ .secure = false, .host = "example.com", .port = 443 }));
    try std.testing.expect(!a.eql(.{ .secure = true, .host = "example.com", .port = 8443 }));
    const t: Timeouts = .{ .connect = .fromSeconds(1), .handshake = .fromSeconds(10), .activity = .fromSeconds(5) };
    try std.testing.expectEqual(@as(i96, 5 * std.time.ns_per_s), t.shortestOnSocket(false).?.nanoseconds);
    try std.testing.expectEqual(@as(i96, std.time.ns_per_s), t.shortestOnSocket(true).?.nanoseconds);
    try std.testing.expectEqual(null, (Timeouts{ .connect = .fromSeconds(1) }).shortestOnSocket(false));
}
