//! What every connection of a server shares: its options, the buffers and
//! encoders requests borrow, the deadlines of its sockets, its counters,
//! and the list of connections being served, which `shutdown` walks.

const std = @import("std");
const aegis = @import("aegis");
const reactor = @import("reactor");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const cloak = @import("cloak");
const wire = @import("uplink.wire");
const h1 = wire.h1;
const tls = @import("../tls.zig");
const span = @import("../span.zig");
const Duration = span.Duration;
const BufferPool = @import("../transport/BufferPool.zig");
const Timed = @import("../net/Timed.zig");
const ZstdBuffer = @import("../coding/ZstdBuffer.zig");
const Encoder = @import("../coding/Encoder.zig");

const Context = @This();

gpa: Allocator,
options: Options,
/// The buffers connections and requests borrow.
buffers: BufferPool,
/// The deadlines of every connection's operations.
deadlines: reactor.net.Deadlines,
/// The buffer a zstd request body is decoded in.
zstd: ZstdBuffer,
/// The encoders compressed responses are written through, when
/// compression is on.
encoders: ?Encoder.Pool,
/// Private: the server's own ticket keys, when its TLS options ask for
/// them.
tickets: ?cloak.tls.TicketKeys,
/// Private: the connections being served.
live: aegis.BlockingGuarded(Live),
/// Private: set by `stop`.
stopping: std.atomic.Value(bool) = .init(false),
/// Private: set when the server is stopping and no connection is left.
drained: Io.Event = .unset,
counters: Counters = .{},

/// How plain connections may speak HTTP/2.
pub const H2c = enum {
    off,
    /// A connection that starts with HTTP/2's preface is HTTP/2, any other
    /// HTTP/1.1.
    alongside_http1,
    /// Every plain connection is HTTP/2: one that does not start with the
    /// preface gets a GOAWAY.
    only,
};

/// How a server reads, limits and answers.
pub const Options = struct {
    /// The largest request head, its blank line included, at most 64 KiB:
    /// past it, a 431. And the most fields in one.
    limits: h1.Limits = .{ .max_head = .literal("16KiB"), .max_fields = 100 },
    /// The largest request body: past it a 413, or, for a body whose
    /// length was not declared, a failed read. Null is no limit.
    max_body: ?aegis.units.Bytes(u64) = null,
    timeouts: Timeouts = .{},
    /// Connections served at once; past it, `serve` accepts no more until
    /// one ends. Null is no limit.
    max_connections: ?u32 = null,
    /// TLS on every connection; null serves plain HTTP.
    tls: ?tls.ServerOptions = null,
    /// HTTP/2 to a client that asks for it by ALPN, over TLS.
    http2: bool = true,
    /// HTTP/2 over plain TCP, by prior knowledge (RFC 9113 §3.3): off by
    /// default, as plain HTTP/2 is for clients that know the server, such
    /// as a proxy in front of it.
    h2c: H2c = .off,
    /// Decode a request body under gzip, deflate or zstd, as the client
    /// decodes a response's, its checksums verified; a body under any other
    /// coding is handed over as it came.
    decompress: bool = true,
    /// The largest zstd window a request body may ask for.
    max_zstd_window: aegis.units.Bytes(u32) = .literal("8MiB"),
    /// Turn TCP keepalive on for accepted sockets, probing one idle this
    /// long.
    keepalive: ?Duration = null,
    /// The most of a request body left unread that the server reads, after
    /// the handler, to keep the connection; past it, the connection closes.
    drain_limit: aegis.units.Bytes(u32) = .literal("64KiB"),
    /// Compress responses the client accepts a coding for; null sends every
    /// body as the handler wrote it.
    compression: ?Compression = null,
    /// Told every request, with its status and timing.
    observer: ?Observer = null,
    /// The most free buffers of each size kept.
    max_free_buffers: u32 = 64,
};

/// Which responses go compressed, and how.
pub const Compression = struct {
    /// The codings offered, the server's preference first; the client's
    /// weights decide between them.
    codings: []const Encoder.Coding = &.{ .zstd, .gzip },
    settings: Encoder.Settings = .{},
    /// A shorter body goes as it is: a coding's framing costs more than it
    /// saves on a few hundred bytes.
    min_size: aegis.units.Bytes(u32) = .literal("1KiB"),
    /// The media types compressed: a `Content-Type` that starts with one
    /// (`text/` covers `text/html; charset=utf-8`). Images, audio, video
    /// and archives are compressed already.
    types: []const []const u8 = &.{
        "text/",                 "application/json",              "application/javascript",    "application/xml",
        "application/xhtml+xml", "application/wasm",              "application/manifest+json", "application/ld+json",
        "application/rss+xml",   "application/atom+xml",          "image/svg+xml",             "font/ttf",
        "font/otf",              "application/vnd.ms-fontobject",
    },

    /// Whether a body of `content_type` is compressed.
    pub fn covers(c: Compression, content_type: []const u8) bool {
        for (c.types) |t| if (content_type.len >= t.len and std.ascii.eqlIgnoreCase(content_type[0..t.len], t)) return true;
        return false;
    }
};

/// How long each wait may take; null is no limit.
pub const Timeouts = struct {
    /// A whole request head, from its first byte (from the accept, for a
    /// connection's first): a client that sends a head a byte at a time is
    /// cut off here, whatever its pace.
    head: ?Duration = .literal("10s"),
    /// Between requests on a kept connection.
    idle: ?Duration = .literal("60s"),
    /// Any single read or write, while a request is answered, that moves
    /// nothing.
    activity: ?Duration = .literal("30s"),
    /// A TLS handshake.
    handshake: ?Duration = .literal("10s"),
    /// How long `shutdown` lets requests under way finish before it ends
    /// their connections.
    shutdown: Duration = .literal("10s"),
    /// How long a connection the server ends waits for its client to end
    /// it too, reading and dropping what still comes (RFC 9112 §9.6):
    /// closed with bytes unread, a connection is reset, and a reset can
    /// take the server's last bytes (a refusal, a TLS alert) from the
    /// client before it reads them. Null closes at once.
    linger: ?Duration = .literal("2s"),

    fn shortest(t: Timeouts) Duration {
        var d: ?Duration = null;
        for ([_]?Duration{ t.head, t.idle, t.activity, t.handshake }) |each| d = span.shorter(d, each);
        return d orelse .literal("10s");
    }
};

/// Every request as it is answered, with its timing, in one callback,
/// which must be quick and may be called from several tasks at once.
pub const Observer = struct {
    context: ?*anyopaque = null,
    eventFn: *const fn (context: ?*anyopaque, event: Event) void,

    pub fn emit(o: Observer, event: Event) void {
        o.eventFn(o.context, event);
    }

    pub const Event = union(enum) {
        /// A connection was accepted.
        accepted: struct { remote: ?Io.net.IpAddress },
        /// A request was answered: its response's status, and how long
        /// from its head's arrival to the response's end.
        answered: struct { method: []const u8, path: []const u8, status: u16, took: Duration },
        /// A request was refused before a handler saw it.
        refused: struct { status: u16, reason: []const u8 },
        /// A handler failed.
        failed: struct { method: []const u8, path: []const u8, error_name: []const u8, head_sent: bool },
        /// A connection waited past a timeout and was closed.
        timed_out: struct { phase: Timeout },
        /// A TLS handshake failed.
        handshake_failed: struct { error_name: []const u8 },
    };
};

/// Which limit a connection ran past.
pub const Timeout = enum { head, idle, activity, handshake };

/// What a server has done, counted as it went.
pub const Counters = struct {
    accepted: std.atomic.Value(u64) = .init(0),
    requests: std.atomic.Value(u64) = .init(0),
    /// Connections open now.
    open: std.atomic.Value(u32) = .init(0),
    /// Timeouts no task and no `Io` could keep.
    timeouts_unenforced: std.atomic.Value(u64) = .init(0),
};

/// The connections being served: each is on the list while it lives, and
/// marked idle while it waits for a request, when `shutdown` may end it.
const Live = struct {
    list: std.DoublyLinkedList = .{},
    count: u32 = 0,
};

/// One connection on the live list: what `stop` needs of it.
pub const Entry = struct {
    node: std.DoublyLinkedList.Node = .{},
    /// Waiting for a request; read and written under the list's lock.
    idle: bool = false,
    /// Its socket is closed, or about to be, before it leaves the list:
    /// `stop` leaves the handle alone, which may already name another
    /// socket. Under the list's lock.
    closed: bool = false,
    socket: Io.net.Socket.Handle,
};

/// A context for a server with `options`.
pub fn init(gpa: Allocator, options: Options) Context {
    aegis.assert.pre(options.limits.max_head.compare(.literal("64KiB")) != .gt, "a request head is at most 64 KiB");
    if (options.compression) |c| aegis.assert.pre(c.codings.len <= 3, "each coding is offered once");
    const own: ?tls.ServerOptions.Rotation = if (options.tls) |t| switch (t.tickets) {
        .own => |r| r,
        .none, .keys => null,
    } else null;
    if (own) |r| {
        const week: Duration = .literal("7d");
        aegis.assert.pre(r.lifetime.compare(.literal("1s")) != .lt and r.lifetime.compare(week) != .gt, "a ticket lives one second to seven days");
        aegis.assert.pre(r.rotation.compare(.literal("1s")) != .lt and r.rotation.compare(week) != .gt, "a ticket key issues one second to seven days");
    }
    return .{
        .gpa = gpa,
        .options = options,
        .buffers = .init(gpa, options.max_free_buffers),
        .deadlines = .init(span.toIo(options.timeouts.shortest())),
        .zstd = .init(options.max_zstd_window),
        .encoders = if (options.compression) |c| .init(gpa, c.settings, options.max_free_buffers) else null,
        .tickets = if (own) |r| cloak.tls.TicketKeys.init(gpa, .{ .lifetime = span.toIo(r.lifetime), .rotation = span.toIo(r.rotation) }) catch unreachable else null, // unreachable: both spans were checked above
        .live = .init(.{}),
    };
}

/// The ticket keys a handshake issues and resumes with: the server's own,
/// a fresh key drawn when none issues now; the caller's; or none.
pub fn ticketKeys(c: *Context, io: Io) error{ OutOfMemory, EntropyUnavailable, Canceled }!?*cloak.tls.TicketKeys {
    const options = c.options.tls orelse return null;
    switch (options.tickets) {
        .none => return null,
        .keys => |keys| return keys,
        .own => {},
    }
    const keys = &c.tickets.?;
    const now = Io.Clock.real.now(io);
    const seconds: i64 = @intCast(@divFloor(now.nanoseconds, std.time.ns_per_s)); // safe: the calendar clock's seconds fit an i64 for billions of years
    var snapshot = keys.acquire();
    const issuing = if (snapshot) |*s| s.ring().issuing(seconds) != null else false;
    if (snapshot) |*s| s.release();
    if (issuing) return keys;
    // Two handshakes that both find no key draw one each: the first is
    // replaced at once and opens the tickets it issued until they expire.
    var material: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &material);
    try io.randomSecure(&material);
    keys.rotate(&material, now) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        // 32 fresh bytes are neither all zeros nor a key the ring holds.
        error.InvalidKey, error.DuplicateKey => error.EntropyUnavailable,
    };
    return keys;
}

/// Release what the connections shared; every one must have ended.
pub fn deinit(c: *Context, io: Io) void {
    c.deadlines.deinit(io);
    c.zstd.deinit(c.gpa);
    if (c.encoders) |*e| e.deinit(io);
    if (c.tickets) |*t| t.deinit();
    c.buffers.deinit(io);
    c.* = undefined;
}

/// What keeps the deadlines of the server's connections.
pub fn keeper(c: *Context) Timed.Keeper {
    return .{ .deadlines = &c.deadlines, .unenforced = &c.counters.timeouts_unenforced };
}

/// Whether the server is stopping.
pub fn isStopping(c: *const Context) bool {
    return c.stopping.load(.acquire);
}

/// Put `entry` on the live list.
pub fn enter(c: *Context, io: Io, entry: *Entry) void {
    var held = c.live.acquireUncancelable(io);
    defer held.deinit(io);
    const live = held.value();
    live.list.append(&entry.node);
    live.count += 1;
}

/// Take `entry` off the live list.
pub fn leave(c: *Context, io: Io, entry: *Entry) void {
    var held = c.live.acquireUncancelable(io);
    defer held.deinit(io);
    const live = held.value();
    live.list.remove(&entry.node);
    live.count -= 1;
    if (live.count == 0 and c.isStopping()) c.drained.set(io);
}

/// `entry`'s socket is closing: nothing ends it from here on.
pub fn closing(c: *Context, io: Io, entry: *Entry) void {
    var held = c.live.acquireUncancelable(io);
    defer held.deinit(io);
    entry.closed = true;
}

/// Mark `entry` waiting for a request, or not: an idle connection is the
/// one `stop` ends at once. False when the server is stopping, and the
/// connection should not wait.
pub fn setIdle(c: *Context, io: Io, entry: *Entry, idle: bool) bool {
    var held = c.live.acquireUncancelable(io);
    defer held.deinit(io);
    entry.idle = idle;
    return !c.isStopping();
}

/// Stop: end the connections waiting for a request at once, let the rest
/// finish for up to `Timeouts.shutdown`, then end their sockets under them.
pub fn stop(c: *Context, io: Io) void {
    c.stopping.store(true, .release);
    c.abort(io, .idle);
    const until = Io.Clock.awake.now(io).addDuration(span.toIo(c.options.timeouts.shutdown));
    while (!c.drained.isSet()) {
        // A wait can wake early: it is tried again until the grace is out.
        c.drained.waitTimeout(io, .{ .deadline = .{ .raw = until, .clock = .awake } }) catch |err| switch (err) {
            error.Timeout => if (Io.Clock.awake.now(io).nanoseconds >= until.nanoseconds) break,
            // The caller is canceled: what is left ends now.
            error.Canceled => break,
        };
    }
    c.abort(io, .all);
}

/// End the sockets of the idle connections, or of all of them.
fn abort(c: *Context, io: Io, which: enum { idle, all }) void {
    var held = c.live.acquireUncancelable(io);
    defer held.deinit(io);
    const live = held.value();
    if (live.count == 0) c.drained.set(io);
    var it = live.list.first;
    while (it) |node| : (it = node.next) {
        const entry: *Entry = @fieldParentPtr("node", node);
        if (entry.closed) continue;
        if (which == .all or entry.idle) reactor.net.abort(io, entry.socket);
    }
}
