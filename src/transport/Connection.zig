//! One connection: a TCP socket, and the layers a route needs on it. TLS
//! to an `https` proxy, a `CONNECT` or SOCKS tunnel through the proxy, and
//! TLS to the target inside whatever came before: every layer is an
//! `Io.Reader` and `Io.Writer` over the one below, so a tunnel inside TLS
//! inside TCP is the same code as TLS alone.
//!
//! Every read and write on the socket goes through one place, which keeps
//! the connection's deadlines: the activity timeout of the operation, the
//! handshake's while one is under way, the request's own deadline, and the
//! low-speed window's end. The nearest is kept by the client's
//! `Deadlines`: in the kernel on a reactor runtime, by one task on any
//! other `Io`. Where no task can be had for that, the operation is bounded
//! by the `Io` itself where it can be (`operateTimeout`), and counted as
//! unenforced where it cannot. An operation with no deadline to keep reads
//! no clock. A connection whose deadline fired is never used again.
//!
//! The socket's buffers come from the client's pool. A connection put away
//! idle gives them back, keeping only what its TLS sessions need.

const std = @import("std");
const sync = @import("../sync.zig");
const aegis = @import("aegis");
const reactor = @import("reactor");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const cloak = @import("cloak");
const tls = @import("../tls.zig");
const wire = @import("uplink.wire");
const h1 = wire.h1;
const fields = wire.fields;
const socks = wire.socks;
const dial = @import("../net/dial.zig");
const Resolver = @import("../net/Resolver.zig");
const stream_owner = @import("../net/stream.zig");
const Context = @import("Context.zig");
const BufferPool = @import("BufferPool.zig");
const span = @import("../span.zig");
const Diagnostics = @import("Diagnostics.zig");
const Proxy = @import("Proxy.zig");
const Timed = @import("../net/Timed.zig");

const Connection = @This();

/// Private: the client's shared state.
ctx: *Context,
/// Private: the current exchange's `Io`, for the reader and writer
/// adapters, which cannot take one per call. A shared connection's stays
/// the one it was made shared with.
io: Io,
/// Private: what the bottom layer goes over.
bottom: Bottom,
/// Where the connection goes.
route: Context.Route,
/// Private: the socket's reader and writer.
input: SocketReader,
output: SocketWriter,
/// Private: TLS to the proxy (0) and to the target (1), as there are.
sessions: [2]cloak.tls.Session = undefined,
session_on: [2]bool = .{ false, false },
session_buffers: [2][2]BufferPool.Buffer = undefined,
/// Each session's client credential, which it borrows.
credentials: [2]cloak.tls.ClientCredential = undefined,
/// Requests name the whole URL: through a proxy, to an `http` target.
absolute_form: bool = false,
/// Private: the socket's operations, each ended at its deadline.
timed: Timed,
/// Private: when the handshake under way must be done, on the awake clock.
handshake_until: ?Io.Timestamp = null,
/// Private: the timeout `handshake_until` keeps, which for a SOCKS
/// negotiation may be `connect`'s.
handshake_bound: Diagnostics.Timeout = .handshake,
/// Private: the exchange's own deadline, on the awake clock.
deadline: ?Io.Timestamp = null,
/// Private: the low-speed window.
speed: Speed = .{},
/// Private: which limit the deadline last armed is.
armed: aegis.Atomic(Diagnostics.Timeout) = .init(.activity),
/// Why the first operation that failed did; `failed` reads it.
failure: aegis.Atomic(Failure) = .init(.none),
/// Private: HTTP/2: exchanges read and write it at once, one reading
/// while others write. No exchange's deadline bounds it, a write keeps
/// the activity timeout alone, and the low-speed window counts what is
/// read.
shared: bool = false,
/// The exchange this connection serves, for its failure details; null
/// between exchanges.
diagnostics: ?*Diagnostics = null,
/// Private: no timeout bounds its operations any more (`unbind`).
unbound: bool = false,

/// Why an operation failed.
pub const Failure = enum(u8) { none, timed_out, canceled, broken };

/// Errors from `open`.
pub const OpenError = error{
    InvalidHostName,
    NameNotResolved,
    ConnectionFailed,
    /// A socket option `Dial.socket` asked for is one the system has none
    /// of, or refuses.
    OptionUnsupported,
    /// Every address was refused to this process.
    AccessDenied,
    /// The name has no address of `Dial.local_address`'s family.
    AddressFamilyMismatch,
    /// `Dial.named_pipe` on a system with no named pipes: Windows' alone.
    NamedPipeUnsupported,
    TimedOut,
    TlsFailed,
    ClientCertificateRejected,
    ClientCertificateSchemeUnsupported,
    CertificateBundleUnreadable,
    ProxyRefused,
    ProxyAuthenticationRequired,
    ProxyAuthMethodUnsupported,
    ProxyAddressUnsupported,
    ProxyHostUnreachable,
    ProxyProtocolError,
    ConcurrencyUnavailable,
    OutOfMemory,
    Canceled,
};

/// Errors from a read or write on an open connection.
pub const IoError = error{
    ConnectionFailed,
    TimedOut,
    TlsFailed,
    ClientCertificateRejected,
    Canceled,
};

/// What a connection's bottom layer goes over.
const Bottom = union(enum) {
    /// A socket or pipe, and its one owner.
    endpoint: stream_owner.Owned,
    /// A tunnel an upper layer made, which the connection closes with itself.
    carrier: *Carrier,
};

/// What a connection goes over instead of a socket: its bytes both ways, each
/// operation ended at the deadline the connection gives it. One read and one
/// write may be under way at once, as on a socket.
pub const Carrier = struct {
    vtable: *const VTable,

    pub const Error = error{ EndOfStream, TimedOut, Canceled, Broken };

    pub const VTable = struct {
        read: *const fn (c: *Carrier, io: Io, dest: []u8, deadline: ?Io.Timestamp) Error!usize,
        /// `header`, every slice of `data` but the last, and the last
        /// `splat` times, whole: the bytes moved.
        write: *const fn (c: *Carrier, io: Io, header: []const u8, data: []const []const u8, splat: usize, deadline: ?Io.Timestamp) Error!usize,
        awaitReadable: *const fn (c: *Carrier, io: Io, timeout: Io.Duration) Io.Cancelable!Timed.Readiness,
        alive: *const fn (c: *Carrier, io: Io) bool,
        close: *const fn (c: *Carrier, io: Io) void,
    };
};

/// What `open` needs besides the route.
pub const OpenOptions = struct {
    /// Where a failure's details go.
    diagnostics: ?*Diagnostics = null,
    /// The exchange's own deadline, on the awake clock: the connection and
    /// every layer must be done by then.
    deadline: ?Io.Timestamp = null,
};

/// A connection to `route`, through its proxy, with every layer started.
pub fn open(ctx: *Context, io: Io, route: Context.Route, options: OpenOptions) OpenError!*Connection {
    // A proxy that asks for an answer to a tunnel is asked again on a new
    // connection, with the answer; and once more for a Digest nonce gone
    // stale.
    var attempts: u8 = 0;
    var ech: Ech = .published;
    // After a refused ECH: what the server gave for a retry, which cloak
    // writes over `untouched` only when the server authenticated as the
    // config's public name (RFC 9849 §6.1.6).
    var untouched: [1]u8 = undefined;
    // `untouched` is only an address that says cloak wrote no retry configs; its byte is never read
    var retry: []u8 = &untouched;
    defer if (retry.ptr != &untouched) ctx.gpa.free(retry);
    while (true) : (attempts += 1) {
        var again = false;
        return openOnce(ctx, io, route, options, &again, ech, if (ech == .published) &retry else null) catch |err| switch (err) {
            error.ProxyAuthenticationRequired => if (attempts < 2 and again) continue else error.ProxyAuthenticationRequired,
            // Tried once more on a new connection: with the configs the
            // server gave, or with ECH off when it gave none.
            error.EchRejected => if (ech == .published and retry.ptr != &untouched) {
                ech = if (retry.len == 0) .off else .{ .retry = retry };
                continue;
            } else error.TlsFailed,
            else => |e| e,
        };
    }
}

/// Where a target's ECH config comes from.
const Ech = union(enum) {
    /// The endpoint's HTTPS record, as the client's options say.
    published,
    /// A server's retry configs.
    retry: []const u8,
    /// None: the server turned ECH off.
    off,
};

/// What the target's handshake offers.
const Offer = struct {
    alpn: []const []const u8,
    ech: cloak.tls.ech.Mode = .off,
    /// Where cloak writes a refusing server's retry configs.
    ech_retry: ?*[]u8 = null,
};

fn openOnce(ctx: *Context, io: Io, route: Context.Route, options: OpenOptions, again: *bool, ech: Ech, ech_retry: ?*[]u8) (OpenError || error{EchRejected})!*Connection {
    const diagnostics = options.diagnostics;
    const proxy: ?Proxy = if (route.proxy) |slot| slot.proxy else null;
    const first_host = if (proxy) |p| p.host else route.host();
    const first_port = if (proxy) |p| p.port else route.port;
    if (diagnostics) |d| d.stage = .connect;
    const started = Io.Clock.awake.now(io);
    // The connect timeout, or what is left of the exchange's, whichever is
    // shorter.
    var limit = ctx.timeouts.connect;
    var limit_kind: Diagnostics.Timeout = .connect;
    if (options.deadline) |d| {
        const left = started.durationTo(d);
        if (left.nanoseconds <= 0) return timedOutBeforeOpen(diagnostics);
        if (limit == null or span.of(left).compare(limit.?) == .lt) {
            limit = span.of(left);
            limit_kind = .deadline;
        }
    }
    const dial_options: dial.Options = .{
        .socket = ctx.dial.socket,
        .local_address = ctx.dial.local_address,
        .interface = ctx.dial.interface,
        .timeout = limit,
        .resolver = ctx.resolve(),
        .attempt_delay = ctx.dial.attempt_delay,
    };
    const protocols = if (route.protocol == .negotiate) tls.client_protocols else tls.client_protocols_h1;
    // A direct `https` origin is dialed as its HTTPS records say; a proxy
    // looks the target up itself, so its records are not asked for here.
    var binding: ?Resolver.Binding = null;
    defer if (binding) |*b| b.deinit(ctx.gpa);
    var record: ?*const Resolver.Binding.Record = null;
    var dialed = (if (ctx.dial.named_pipe) |path|
        dial.dialPipe(io, path, dial_options)
    else if (ctx.dial.unix_socket) |path|
        dial.dialUnix(io, path, dial_options)
    else if (route.secure and proxy == null) found: {
        const d = try dial.dialHttps(io, ctx.gpa, first_host, first_port, .{ .protocols = protocols, .ech = ctx.tls.ech != .off and ech == .published }, dial_options);
        binding = d.binding;
        record = d.record;
        break :found d.dialed;
    } else dial.dial(io, first_host, first_port, dial_options)) catch |err| {
        if (err == error.TimedOut) if (diagnostics) |d| {
            d.timeout = limit_kind;
        };
        return switch (err) {
            error.InvalidHostName => if (proxy != null) error.ProxyHostUnreachable else error.InvalidHostName,
            else => |e| e,
        };
    };
    if (!dialed.timeout_enforced) sync.bump(&ctx.counters.timeouts_unenforced);
    sync.bump(&ctx.counters.opened);
    if (diagnostics) |d| d.peer = dialed.peer;
    if (ctx.observer) |o| o.emit(.{ .connected = .{
        .host = first_host,
        .port = first_port,
        .peer = dialed.peer,
        .lookup = dialed.lookup,
        .took = span.of(started.durationTo(Io.Clock.awake.now(io))),
    } });
    const conn = create(ctx, io, route, .{ .endpoint = &dialed.stream }, diagnostics) catch |err| {
        dialed.stream.deinit(io);
        return err;
    };
    conn.deadline = options.deadline;
    const offer: Offer = .{
        .alpn = if (record) |r| meet(protocols, r.service) else protocols,
        .ech = switch (ech) {
            .published => if (ctx.tls.ech == .off) .off else if (record) |r| (if (r.service.ech()) |list| .{ .config_list = list } else ctx.greaseOr()) else ctx.greaseOr(),
            .retry => |list| .{ .config_list = list },
            .off => .off,
        },
        .ech_retry = ech_retry,
    };
    conn.establish(proxy, started, again, offer) catch |err| {
        conn.teardown(io, false);
        return err;
    };
    return conn;
}

fn timedOutBeforeOpen(diagnostics: ?*Diagnostics) OpenError {
    if (diagnostics) |d| d.timeout = .deadline;
    return error.TimedOut;
}

/// A connection to `route` over `carrier`, which it now owns and closes on
/// failing: its TLS to the target started. `watched` is the endpoint under the
/// carrier, whose deadlines the connection never arms: the carrier keeps them.
pub fn openOver(ctx: *Context, io: Io, route: Context.Route, carrier: *Carrier, watched: stream_owner.Endpoint, options: OpenOptions) OpenError!*Connection {
    const conn = create(ctx, io, route, .{ .carrier = .{ .carrier = carrier, .watched = watched } }, options.diagnostics) catch |err| {
        carrier.vtable.close(carrier, io);
        return err;
    };
    conn.deadline = options.deadline;
    conn.startTls(1, route.host(), .{ .alpn = if (route.protocol == .negotiate) tls.client_protocols else tls.client_protocols_h1 }) catch |err| {
        conn.teardown(io, false);
        return switch (err) {
            // No ECH is offered through a tunnel, so none is refused.
            error.EchRejected => error.TlsFailed,
            else => |e| e,
        };
    };
    return conn;
}

/// What the connection's socket is: what `openOver` watches.
pub fn endpoint(conn: *Connection) stream_owner.Endpoint {
    return conn.bottom.endpoint.borrow().*;
}

/// Whether a connection opened to its proxy may speak HTTP/2 there: TLS agreed
/// `h2`, or there is no TLS and the proxy is spoken to by prior knowledge.
pub fn proxySpeaksH2(conn: *const Connection) bool {
    if (!conn.session_on[0]) return true;
    const info = conn.sessions[0].info() orelse return false;
    return std.mem.eql(u8, info.alpn, "h2");
}

/// A connection over `over`, with nothing on it yet. An endpoint's owner moves
/// into the connection only once nothing can fail.
fn create(ctx: *Context, io: Io, route: Context.Route, over: union(enum) {
    endpoint: *stream_owner.Owned,
    carrier: struct { carrier: *Carrier, watched: stream_owner.Endpoint },
}, diagnostics: ?*Diagnostics) Allocator.Error!*Connection {
    const conn = try ctx.gpa.create(Connection);
    errdefer ctx.gpa.destroy(conn);
    const read_buffer = try ctx.buffers.acquire(io, .record);
    errdefer ctx.buffers.release(io, read_buffer);
    const write_buffer = try ctx.buffers.acquire(io, .record);
    conn.* = .{
        .ctx = ctx,
        .io = io,
        .bottom = switch (over) {
            .endpoint => |owned| .{ .endpoint = owned.move() },
            .carrier => |c| .{ .carrier = c.carrier },
        },
        .route = route,
        .input = .init(read_buffer),
        .output = .init(write_buffer),
        .timed = undefined,
        .diagnostics = diagnostics,
    };
    // The owner is used first where it stays.
    conn.timed = .init(switch (over) {
        .endpoint => conn.bottom.endpoint.borrow().*,
        .carrier => |c| c.watched,
    });
    return conn;
}

/// The protocols of `protocols` an endpoint speaks, the client's order
/// kept; the dial took only an endpoint that speaks one.
fn meet(protocols: []const []const u8, s: wire.dns.Service) []const []const u8 {
    const two = protocols.len == 2 and s.speaks("h2");
    const one = s.speaks("http/1.1");
    if (two and one) return tls.client_protocols;
    if (two) return tls.client_protocols_h2;
    return tls.client_protocols_h1;
}

/// Start the proxy's layers and the target's TLS.
fn establish(conn: *Connection, proxy: ?Proxy, started: Io.Timestamp, again: *bool, offer: Offer) (OpenError || error{EchRejected})!void {
    if (proxy) |p| {
        if (p.kind.socks()) {
            const at = conn.observeStart();
            try conn.socksTunnel(p, started);
            conn.observeTunnel(at);
        } else {
            // A connection H2Tunnel opened, to the proxy itself, offers `h2`.
            if (p.kind == .https) try conn.startTls(0, p.host, .{ .alpn = if (conn.route.protocol == .h2_prior_knowledge) tls.client_protocols_h2 else tls.client_protocols_h1, .ech = conn.ctx.greaseOr() });
            if (conn.route.secure) {
                const at = conn.observeStart();
                try conn.tunnel(p, again);
                conn.observeTunnel(at);
            } else conn.absolute_form = true;
        }
    }
    if (conn.route.secure) try conn.startTls(1, conn.route.host(), offer);
}

/// The time now, when an observer will want a step's duration.
fn observeStart(conn: *Connection) ?Io.Timestamp {
    if (conn.ctx.observer == null) return null;
    return Io.Clock.awake.now(conn.io);
}

fn observeTunnel(conn: *Connection, at: ?Io.Timestamp) void {
    const o = conn.ctx.observer orelse return;
    o.emit(.{ .tunnel = .{ .took = span.of(at.?.durationTo(Io.Clock.awake.now(conn.io))) } });
}

/// Close politely: TLS close_notify, within the activity timeout, unless an
/// operation already failed; then the socket. Everything is released.
pub fn close(conn: *Connection, io: Io) void {
    conn.teardown(io, conn.failed() == .none);
}

fn teardown(conn: *Connection, io: Io, polite: bool) void {
    conn.io = io;
    var i: usize = conn.sessions.len;
    while (i > 0) {
        i -= 1;
        if (!conn.session_on[i]) continue;
        if (polite) {
            // glint-ignore: Z026 -- the close_notify is a courtesy, as below
            conn.sessions[i].finish() catch {};
            // glint-ignore: Z026 -- the close_notify is a courtesy; the socket is closed below whether or not the peer heard it
            conn.flushFrom(i) catch {};
        }
        conn.sessions[i].deinit();
        for (conn.session_buffers[i]) |b| conn.ctx.buffers.release(io, b);
        conn.session_on[i] = false;
    }
    conn.timed.deinit(io, conn.ctx.keeper());
    switch (conn.bottom) {
        .endpoint => |*owned| owned.deinit(io),
        .carrier => |carrier| carrier.vtable.close(carrier, io),
    }
    conn.releaseSocketBuffers(io);
    conn.ctx.gpa.destroy(conn);
}

fn releaseSocketBuffers(conn: *Connection, io: Io) void {
    for ([_]BufferPool.Buffer{ conn.input.reclaim(), conn.output.reclaim() }) |b| if (b.len != 0) conn.ctx.buffers.release(io, b);
}

/// Put the connection away idle: the socket's buffers go back to the pool
/// when they hold nothing. Only TLS sessions keep theirs.
pub fn park(conn: *Connection, io: Io) void {
    conn.diagnostics = null;
    conn.deadline = null;
    const r = &conn.input.interface;
    if (r.buffer.len != 0 and r.seek == r.end) conn.ctx.buffers.release(io, conn.input.reclaim());
    const w = &conn.output.interface;
    if (w.buffer.len != 0 and w.end == 0) conn.ctx.buffers.release(io, conn.output.reclaim());
}

/// Take a parked connection out for an exchange that must be done by
/// `deadline`.
pub fn unpark(conn: *Connection, io: Io, diagnostics: ?*Diagnostics, deadline: ?Io.Timestamp) Allocator.Error!void {
    conn.io = io;
    conn.diagnostics = diagnostics;
    conn.deadline = deadline;
    conn.speed = .{};
    if (conn.input.pooled.len == 0) conn.input.give(try conn.ctx.buffers.acquire(io, .record));
    if (conn.output.pooled.len == 0) conn.output.give(try conn.ctx.buffers.acquire(io, .record));
}

/// Whether a kept connection still looks usable: one look at its socket
/// that neither waits nor takes anything, or where the system has no such
/// look, one read through the `Io` that does not wait. Nothing to read is
/// alive. The end of the stream, an error, or bytes on a plain connection —
/// a server that sent something nobody asked for — is dead. Bytes on a TLS
/// connection are left for the session to read: a ticket or a key update
/// looks the same as the start of a close. Where the `Io` cannot read
/// without waiting either, the connection is taken as alive, and a failure
/// on it is retried as a stale one.
pub fn alive(conn: *Connection, io: Io) Io.Cancelable!bool {
    const r = &conn.input.interface;
    const secure = conn.session_on[0] or conn.session_on[1];
    if (r.seek != r.end) return secure;
    const stream_end = switch (conn.bottom) {
        .endpoint => |*owned| owned,
        .carrier => |carrier| return carrier.vtable.alive(carrier, io),
    };
    if (stream_end.borrow().socketStream()) |stream| if (reactor.net.peek(io, stream.socket.handle)) |seen| return switch (seen) {
        .idle => true,
        .readable => secure,
        .closed => false,
    };
    return switch (try Timed.awaitReadable(io, stream_end.borrow().*, r, .fromNanoseconds(0))) {
        .timed_out, .unbounded => true,
        // Nothing read is the stream's end, or its failure.
        .ready => r.end != 0 and secure,
    };
}

/// Wait up to `timeout` for the server to send something, keeping what it
/// sends for the reader: whether something came, or the connection ended.
/// False when the time ran out, or when the `Io` cannot wait for a bounded
/// time, which `Expect: 100-continue` then reads as the time run out.
pub fn readable(conn: *Connection, io: Io, timeout: Io.Duration) Io.Cancelable!bool {
    return try conn.awaitReadable(io, timeout) == .ready;
}

/// Wait up to `timeout` for the peer to send something, keeping it for
/// the reader, and say what the wait found; it ends nothing.
pub fn awaitReadable(conn: *Connection, io: Io, timeout: Io.Duration) Io.Cancelable!Timed.Readiness {
    if (!conn.shared) conn.io = io;
    if (conn.reader().bufferedLen() != 0) return .ready;
    return switch (conn.bottom) {
        .endpoint => |*owned| Timed.awaitReadable(io, owned.borrow().*, &conn.input.interface, timeout),
        // What a read left in the bottom reader may be all there is to come:
        // a record read whole, and not yet taken by the session above.
        .carrier => |carrier| if (conn.input.interface.bufferedLen() != 0) .ready else carrier.vtable.awaitReadable(carrier, io, timeout),
    };
}

/// The exchange is over, and what is left of its body must end by `until`
/// for the connection to be kept, as a drain's must: every operation from
/// here ends at the nearer of `until` and the exchange's own deadline. What
/// the drain meets is no longer the exchange's to hear of.
pub fn drainBy(conn: *Connection, until: Io.Timestamp) void {
    conn.diagnostics = null;
    if (conn.deadline == null or until.nanoseconds < conn.deadline.?.nanoseconds) conn.deadline = until;
}

/// Bound no read or write by a timeout any more: what the connection
/// carries now, after an upgrade, keeps its own.
pub fn unbind(conn: *Connection) void {
    conn.unbound = true;
    conn.deadline = null;
}

/// Whether the connection speaks HTTP/2: TLS to the target agreed `h2`,
/// or the route goes by prior knowledge.
pub fn speaksH2(conn: *const Connection) bool {
    if (conn.route.protocol == .h2_prior_knowledge) return true;
    if (!conn.session_on[1]) return false;
    const info = conn.sessions[1].info() orelse return false;
    return std.mem.eql(u8, info.alpn, "h2");
}

/// Whether the connection may carry another exchange: no operation failed
/// and no deadline fired.
pub fn reusable(conn: *const Connection) bool {
    return conn.failed() == .none and !conn.timed.fired();
}

/// The reader of the top layer.
pub fn reader(conn: *Connection) *Io.Reader {
    return conn.readerBelow(conn.sessions.len);
}

/// The writer of the top layer.
pub fn writer(conn: *Connection) *Io.Writer {
    return conn.writerBelow(conn.sessions.len);
}

/// The TLS session of the top layer, the one `reader` reads from; null
/// when that is the socket.
pub fn topSession(conn: *const Connection) ?*const cloak.tls.Session {
    var i: usize = conn.sessions.len;
    while (i > 0) {
        i -= 1;
        if (conn.session_on[i]) return &conn.sessions[i];
    }
    return null;
}

/// The reader below `slot` as an end that says why a read failed: the session's own, or the
/// socket's, its cause the connection's record (`failed`).
fn readEndBelow(conn: *Connection, slot: usize) aegis.io.ReadEnd {
    var i = slot;
    while (i > 0) {
        i -= 1;
        if (conn.session_on[i]) return conn.sessions[i].readEnd();
    }
    return .init(&conn.input.interface, conn, recordedCause);
}

/// The writer below `slot` as an end that says why a write failed.
fn writeEndBelow(conn: *Connection, slot: usize) aegis.io.WriteEnd {
    var i = slot;
    while (i > 0) {
        i -= 1;
        if (conn.session_on[i]) return conn.sessions[i].writeEnd();
    }
    return .init(&conn.output.interface, conn, recordedCause);
}

/// The top layer's reader and writer as ends (`readEndBelow`).
pub fn readEnd(conn: *Connection) aegis.io.ReadEnd {
    return conn.readEndBelow(conn.sessions.len);
}
pub fn writeEnd(conn: *Connection) aegis.io.WriteEnd {
    return conn.writeEndBelow(conn.sessions.len);
}

/// Why the socket's last read or write failed, as the connection recorded it: a cancel or a
/// timeout; null for a failure it names no cause for.
fn recordedCause(context: *const anyopaque) ?anyerror {
    const conn: *const Connection = @ptrCast(@alignCast(context));
    return switch (conn.failed()) {
        .canceled => error.Canceled,
        .timed_out => error.TimedOut,
        .none, .broken => null,
    };
}

fn readerBelow(conn: *Connection, slot: usize) *Io.Reader {
    var i = slot;
    while (i > 0) {
        i -= 1;
        if (conn.session_on[i]) return conn.sessions[i].reader();
    }
    return &conn.input.interface;
}

fn writerBelow(conn: *Connection, slot: usize) *Io.Writer {
    var i = slot;
    while (i > 0) {
        i -= 1;
        if (conn.session_on[i]) return conn.sessions[i].writer();
    }
    return &conn.output.interface;
}

/// Push everything written down through every layer to the socket.
pub fn flush(conn: *Connection) Io.Writer.Error!void {
    return conn.flushFrom(conn.sessions.len);
}

fn flushFrom(conn: *Connection, top: usize) Io.Writer.Error!void {
    var i: usize = @min(top + 1, conn.sessions.len);
    while (i > 0) {
        i -= 1;
        if (conn.session_on[i]) try conn.sessions[i].writer().flush();
    }
    try conn.output.interface.flush();
}

/// Why a read failed, by name.
pub fn readError(conn: *Connection) IoError {
    switch (conn.failed()) {
        .timed_out => return error.TimedOut,
        .canceled => return error.Canceled,
        .none, .broken => {},
    }
    if (conn.timed.fired()) return conn.timedOut(conn.armed.load(.monotonic));
    for (&conn.sessions, conn.session_on) |*s, on| {
        if (!on) continue;
        const err = s.failure() orelse continue;
        const seen = s.diagnostics();
        // TLS 1.3 finishes the handshake before the server has read the
        // client's certificate: its refusal is the first thing read.
        if (seen.alert_received) |alert| if (seen.certificate_requested and tls.refusesCertificate(alert)) {
            if (conn.diagnostics) |d| {
                d.tls_error = err;
                d.tls_alert = alert;
                d.tls_verification = seen.verification;
            }
            return error.ClientCertificateRejected;
        };
        // The socket broke beneath the session, no alert read: the failure
        // the session kept is the transport's, not TLS's.
        if (conn.failed() == .broken and seen.alert_received == null) break;
        if (conn.diagnostics) |d| {
            d.tls_error = err;
            d.tls_alert = seen.alert_received orelse seen.alert_sent;
            d.tls_verification = seen.verification;
        }
        return error.TlsFailed;
    }
    if (conn.missingCertificateReset()) return error.ClientCertificateRejected;
    return error.ConnectionFailed;
}

/// Why a write failed, by name.
pub fn writeError(conn: *Connection) IoError {
    switch (conn.failed()) {
        .timed_out => return error.TimedOut,
        .canceled => return error.Canceled,
        .none, .broken => {},
    }
    if (conn.timed.fired()) return conn.timedOut(conn.armed.load(.monotonic));
    // A server that refused the client's certificate after a TLS 1.3
    // handshake the client thinks is done has sent its alert and closed:
    // the write that failed is the request, and the alert is there to read.
    for (&conn.sessions, conn.session_on) |*s, on| {
        if (!on or !s.diagnostics().certificate_requested) continue;
        // glint-ignore: Z026 -- the read only takes the alert in; its failure lands in the session's failure, checked next
        _ = s.reader().peekByte() catch {};
        if (s.failure() != null) return conn.readError();
    }
    if (conn.missingCertificateReset()) return error.ClientCertificateRejected;
    return error.ConnectionFailed;
}

fn timedOut(conn: *Connection, kind: Diagnostics.Timeout) IoError {
    conn.noteTimedOut(kind);
    return error.TimedOut;
}

/// Why the first operation that failed did.
pub fn failed(conn: *const Connection) Failure {
    return conn.failure.load(.monotonic);
}

/// Carry exchanges at once from here on (HTTP/2). Called before a second
/// task has the connection.
pub fn share(conn: *Connection) void {
    conn.shared = true;
    conn.deadline = null;
    conn.diagnostics = null;
}

fn noteTimedOut(conn: *Connection, kind: Diagnostics.Timeout) void {
    conn.failure.store(.timed_out, .monotonic);
    if (conn.diagnostics) |d| d.timeout = kind;
}

/// Windows can report a server's refusal of a TLS client certificate as a
/// socket reset before the alert reaches the reader.
fn missingCertificateReset(conn: *Connection) bool {
    if (builtin.target.os.tag != .windows or conn.ctx.tls.client_auth != null) return false;
    for (&conn.sessions, conn.session_on) |*s, on| {
        if (on and s.diagnostics().certificate_requested) return true;
    }
    return false;
}

/// A deadline, and which limit it is.
const Limit = struct { at: Io.Timestamp, kind: Diagnostics.Timeout };

/// Whether the low-speed window counts an operation: every one, but on a
/// shared connection only reads, which one task does at a time.
fn paced(conn: *const Connection, reading: bool) bool {
    return reading or !conn.shared;
}

/// The deadline of an operation starting now, or null when none applies,
/// found without reading the clock.
fn operationLimit(conn: *Connection, io: Io, reading: bool) ?Limit {
    if (conn.unbound) return null;
    var t = conn.ctx.timeouts;
    if (!conn.paced(reading)) t.low_speed = null;
    if (conn.handshake_until == null and t.activity == null and conn.deadline == null and t.low_speed == null) return null;
    const now = Io.Clock.awake.now(io);
    var best: ?Limit = null;
    if (conn.handshake_until) |h| nearer(&best, .{ .at = h, .kind = conn.handshake_bound });
    if (t.activity) |a| nearer(&best, .{ .at = now.addDuration(span.toIo(a)), .kind = if (conn.handshake_until != null) .handshake else .activity });
    if (conn.deadline) |d| nearer(&best, .{ .at = d, .kind = .deadline });
    if (t.low_speed) |l| nearer(&best, .{ .at = conn.speed.deadline(now, l), .kind = .low_speed });
    return best;
}

fn nearer(best: *?Limit, candidate: Limit) void {
    if (best.* == null or candidate.at.nanoseconds < best.*.?.at.nanoseconds) best.* = candidate;
}

/// Perform one socket operation within the connection's deadline. A failure
/// is recorded in `failure`, and `error.Failed` returned. None after a
/// cancelation: the task was asked to stop, and a second cancelation point
/// would not say so again.
fn perform(conn: *Connection, op: Io.Operation) error{Failed}!Io.Operation.Result {
    if (conn.failed() == .canceled) return error.Failed;
    const io = conn.io;
    const limit = conn.operationLimit(io, op == .net_read);
    if (limit) |l| conn.armed.store(l.kind, .monotonic);
    return conn.timed.perform(io, conn.ctx.keeper(), op, if (limit) |l| l.at else null) catch |err| switch (err) {
        error.TimedOut => {
            conn.noteTimedOut(limit.?.kind);
            return error.Failed;
        },
        error.Canceled => conn.fail(.canceled),
    };
}

/// The deadline the next read or write over a carrier ends at, armed as a
/// socket operation's is.
fn limitAt(conn: *Connection, reading: bool) ?Io.Timestamp {
    const limit = conn.operationLimit(conn.io, reading) orelse return null;
    conn.armed.store(limit.kind, .monotonic);
    return limit.at;
}

/// A carrier's answer, a failure recorded as a socket operation's is.
fn carried(conn: *Connection, result: Carrier.Error!usize) error{ EndOfStream, Failed }!usize {
    return result catch |err| switch (err) {
        error.EndOfStream => error.EndOfStream,
        error.TimedOut => {
            conn.noteTimedOut(conn.armed.load(.monotonic));
            return error.Failed;
        },
        error.Canceled => conn.fail(.canceled),
        error.Broken => conn.fail(.broken),
    };
}

/// `n` bytes moved, for the low-speed window.
fn moved(conn: *Connection, n: usize, reading: bool) void {
    if (conn.ctx.timeouts.low_speed != null and conn.paced(reading)) conn.speed.bytes = conn.speed.bytes.add(.fromRaw(n)) catch .fromRaw(std.math.maxInt(u64));
}

/// The low-speed window: bytes moved since it started. A window counts
/// only time spent waiting on the network: one that ended while nothing
/// waited, the program busy elsewhere, starts over at the next operation.
const Speed = struct {
    /// On the awake clock; null before the first operation.
    start: ?Io.Timestamp = null,
    bytes: aegis.units.Bytes(u64) = .fromRaw(0),

    /// When an operation starting `now` gives up for want of speed.
    fn deadline(s: *Speed, now: Io.Timestamp, l: Context.Timeouts.LowSpeed) Io.Timestamp {
        const over = if (s.start) |start| now.nanoseconds >= start.addDuration(span.toIo(l.window)).nanoseconds else true;
        if (over) {
            s.start = now;
            s.bytes = .fromRaw(0);
        }
        const end = s.start.?.addDuration(span.toIo(l.window));
        // This window has moved enough: the operation may run into the
        // next, which must move enough by its own end.
        return if (s.bytes.sub(Context.Timeouts.lowSpeedNeed(l))) |_| end.addDuration(span.toIo(l.window)) else |_| end;
    }
};

fn fail(conn: *Connection, failure: Failure) error{Failed} {
    conn.note(failure);
    return error.Failed;
}

fn note(conn: *Connection, failure: Failure) void {
    _ = conn.failure.cmpxchgStrong(.none, failure, .monotonic, .monotonic);
}

const SocketReader = struct {
    interface: Io.Reader,
    /// The pool buffer the interface reads into, as the pool gave it.
    pooled: BufferPool.Buffer,

    fn init(buffer: BufferPool.Buffer) SocketReader {
        return .{ .interface = .{ .vtable = &.{ .stream = streamImpl, .readVec = readVec }, .buffer = buffer, .seek = 0, .end = 0 }, .pooled = buffer };
    }

    /// Read into `buffer` from now on, the reader having none.
    fn give(sr: *SocketReader, buffer: BufferPool.Buffer) void {
        aegis.assert.invariant(sr.pooled.len == 0, "sr.pooled.len == 0");
        sr.pooled = buffer;
        sr.interface.buffer = buffer;
    }

    /// The reader's buffer, for the pool: the reader is left with none,
    /// and what it held unread is dropped.
    fn reclaim(sr: *SocketReader) BufferPool.Buffer {
        const buffer = sr.pooled;
        sr.pooled = &.{};
        sr.interface.buffer = &.{};
        sr.interface.seek = 0;
        sr.interface.end = 0;
        return buffer;
    }

    fn connection(r: *Io.Reader) *Connection {
        const sr: *SocketReader = @alignCast(@fieldParentPtr("interface", r)); // safe: this vtable is installed only on a SocketReader's interface
        return @alignCast(@fieldParentPtr("input", sr)); // safe: a SocketReader lives only in a Connection's `input`
    }

    fn streamImpl(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const dest = limit.slice(try w.writableSliceGreedy(1));
        var data: [1][]u8 = .{dest};
        const n = try readVec(r, &data);
        w.advance(n);
        return n;
    }

    fn readVec(r: *Io.Reader, data: [][]u8) Io.Reader.Error!usize {
        const conn = connection(r);
        var iovecs: [8][]u8 = undefined;
        const dest_n, const data_size = try r.writableVector(&iovecs, data);
        const n = switch (conn.bottom) {
            .endpoint => |*owned| counted: {
                const result = conn.perform(owned.borrow().readOp(iovecs[0..dest_n])) catch return error.ReadFailed;
                break :counted stream_owner.Endpoint.readCount(result) catch {
                    conn.note(.broken);
                    return error.ReadFailed;
                };
            },
            .carrier => |carrier| conn.carried(carrier.vtable.read(carrier, conn.io, iovecs[0], conn.limitAt(true))) catch |err| switch (err) {
                error.EndOfStream => return error.EndOfStream,
                error.Failed => return error.ReadFailed,
            },
        };
        if (n == 0) return error.EndOfStream;
        conn.moved(n, true);
        if (n > data_size) {
            r.end += n - data_size;
            return data_size;
        }
        return n;
    }
};

const SocketWriter = struct {
    interface: Io.Writer,
    /// The pool buffer the interface writes through, as the pool gave it.
    pooled: BufferPool.Buffer,

    fn init(buffer: BufferPool.Buffer) SocketWriter {
        return .{ .interface = .{ .vtable = &.{ .drain = drain }, .buffer = buffer }, .pooled = buffer };
    }

    /// Write through `buffer` from now on, the writer having none.
    fn give(sw: *SocketWriter, buffer: BufferPool.Buffer) void {
        aegis.assert.invariant(sw.pooled.len == 0, "sw.pooled.len == 0");
        sw.pooled = buffer;
        sw.interface.buffer = buffer;
    }

    /// The writer's buffer, for the pool: the writer is left with none,
    /// and what it held unsent is dropped.
    fn reclaim(sw: *SocketWriter) BufferPool.Buffer {
        const buffer = sw.pooled;
        sw.pooled = &.{};
        sw.interface.buffer = &.{};
        sw.interface.end = 0;
        return buffer;
    }

    fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const sw: *SocketWriter = @alignCast(@fieldParentPtr("interface", w)); // safe: this vtable is installed only on a SocketWriter's interface
        const conn: *Connection = @alignCast(@fieldParentPtr("output", sw)); // safe: a SocketWriter lives only in a Connection's `output`
        const n = switch (conn.bottom) {
            .endpoint => |*owned| counted: {
                const result = conn.perform(owned.borrow().writeOp(w.buffered(), data, splat)) catch return error.WriteFailed;
                break :counted stream_owner.Endpoint.writeCount(result) catch {
                    conn.note(.broken);
                    return error.WriteFailed;
                };
            },
            .carrier => |carrier| conn.carried(carrier.vtable.write(carrier, conn.io, w.buffered(), data, splat, conn.limitAt(false))) catch return error.WriteFailed,
        };
        conn.moved(n, false);
        return w.consume(n);
    }
};

fn startTls(conn: *Connection, slot: usize, host: []const u8, offer: Offer) (OpenError || error{EchRejected})!void {
    const ctx = conn.ctx;
    const io = conn.io;
    if (conn.diagnostics) |d| d.stage = if (slot == 0) .proxy_tls else .tls;
    const trust = try conn.trustFor(slot);
    // The server's own versions and pins; a proxy's TLS keeps cloak's.
    const target = slot != 0;
    // Pins with nothing else checked: the leaf's key against them alone.
    const leaf_keys = target and ctx.tls.pins.len != 0 and trust == null;
    const auth = if (slot == 0) conn.route.proxy.?.proxy.tls.client_auth else ctx.tls.client_auth;
    // Borrowed by the session for its life.
    if (auth) |a| conn.credentials[slot] = .{ .auth = a };
    const read_buffer = try ctx.buffers.acquire(io, .record);
    errdefer ctx.buffers.release(io, read_buffer);
    const write_buffer = try ctx.buffers.acquire(io, .record);
    errdefer ctx.buffers.release(io, write_buffer);
    const started = conn.observeStart();
    if (ctx.timeouts.handshake) |limit| conn.handshake_until = Io.Clock.awake.now(io).addDuration(span.toIo(limit));
    defer conn.handshake_until = null;
    const session = &conn.sessions[slot];
    var report: cloak.tls.Session.Diagnostics = .{};
    var decoders = [_]tls.Decoder{ .init(.zstd, ctx.gpa), .init(.zlib, ctx.gpa) };
    var codecs = [_]*tls.Codec{ &decoders[0].codec, &decoders[1].codec };
    var namespace_buf: [Io.net.HostName.max_len + 32]u8 = undefined;
    session.open(ctx.gpa, io, conn.readEndBelow(slot), conn.writeEndBelow(slot), read_buffer, write_buffer, .{
        .identity = tls.reference(host),
        .trust = if (trust) |snapshot| .{ .snapshot = snapshot } else if (leaf_keys) .{ .leaf_keys = ctx.tls.pins } else .none,
        .pins = if (target and !leaf_keys) ctx.tls.pins else &.{},
        .min_version = if (target) ctx.tls.min_version else .tls12,
        .max_version = if (target) ctx.tls.max_version else .tls13,
        .credentials = if (auth != null) conn.credentials[slot .. slot + 1] else &.{},
        .key_log = if (ctx.key_log) |*sink| &sink.key_log else null,
        .alpn = offer.alpn,
        .resumption = if (ctx.tls.resumption) |r| .{
            .cache = try ctx.sessions.get(ctx.gpa, io, r),
            .namespace = conn.ticketNamespace(slot, &namespace_buf),
            .max_age = span.toIo(r.max_age),
            .tls12 = r.tls12,
        } else null,
        .certificate_compression = switch (ctx.tls.certificate_compression) {
            .zstd_zlib => &codecs,
            .none => &.{},
            .codecs => |c| c,
        },
        .ech = offer.ech,
        .ech_retry = offer.ech_retry,
        // HTTP says where a body ends by its length or its chunks, which see
        // a truncation; a body to the connection's end asks `closeNotified`.
        .eof = .allow,
        .diagnostics = &report,
    }) catch |err| return conn.handshakeFailed(err, report);
    conn.session_buffers[slot] = .{ read_buffer, write_buffer };
    conn.session_on[slot] = true;
    if (ctx.observer) |o| {
        const info = session.info().?;
        o.emit(.{ .tls = .{ .host = host, .proxy = slot == 0, .took = span.of(started.?.durationTo(Io.Clock.awake.now(io))), .resumed = info.resumed, .ech = info.ech_accepted } });
    }
}

/// What keeps a session's tickets apart from others with the same name:
/// the proxy a target is reached through, so a server cannot link a
/// client's connections through a proxy to its direct ones by a ticket.
fn ticketNamespace(conn: *const Connection, slot: usize, buf: []u8) []const u8 {
    if (slot == 0) return "";
    const p = (conn.route.proxy orelse return "").proxy;
    return std.mem.print(buf, "via {t} {s}:{d}", .{ p.kind, p.host, p.port }) catch unreachable; // unreachable: the buffer holds a host name and 32 bytes more, past the longest kind and port
}

/// The authorities a session in `slot` checks its server against, or null
/// for none. An `https` proxy of its own trust is always checked, whatever
/// `verify` says.
fn trustFor(conn: *Connection, slot: usize) OpenError!?cloak.Trust.Snapshot {
    const ctx = conn.ctx;
    if (slot == 0) switch (conn.route.proxy.?.proxy.tls.trust) {
        .as_target => {},
        .own => |own| return own orelse try conn.systemTrust(),
    };
    if (ctx.tls.verify == .none) return null;
    return ctx.tls.trust orelse try conn.systemTrust();
}

fn systemTrust(conn: *Connection) OpenError!cloak.Trust.Snapshot {
    return conn.ctx.system_trust.get(conn.ctx.gpa, conn.io) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.Canceled => error.Canceled,
        else => error.CertificateBundleUnreadable,
    };
}

fn handshakeFailed(conn: *Connection, err: cloak.tls.Session.OpenError, report: cloak.tls.Session.Diagnostics) (OpenError || error{EchRejected}) {
    if (conn.failed() == .timed_out or conn.timed.fired()) {
        if (conn.failed() != .timed_out) conn.noteTimedOut(conn.armed.load(.monotonic));
        return error.TimedOut;
    }
    // A cancel on a socket operation, or on one the session made itself (an
    // entropy draw, a signature, a key-log line): the caller's, not TLS's.
    if (conn.failed() == .canceled or err == error.Canceled) return error.Canceled;
    const alert = report.alert_received orelse report.alert_sent;
    if (conn.diagnostics) |d| {
        d.tls_error = err;
        d.tls_alert = alert;
        d.tls_verification = report.verification;
    }
    if (report.alert_received) |received| if (report.certificate_requested and tls.refusesCertificate(received)) return error.ClientCertificateRejected;
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        // A client key cloak does not sign with yet.
        error.SignerRequired => error.ClientCertificateSchemeUnsupported,
        error.EchRejected => error.EchRejected,
        error.ReadFailed => conn.readError(),
        error.WriteFailed => conn.writeError(),
        else => if (conn.missingCertificateReset()) error.ClientCertificateRejected else error.TlsFailed,
    };
}

/// Ask the proxy for a tunnel to the route with `CONNECT`.
fn tunnel(conn: *Connection, proxy: Proxy, again: *bool) OpenError!void {
    const ctx = conn.ctx;
    const io = conn.io;
    if (conn.diagnostics) |d| d.stage = .tunnel;
    if (ctx.timeouts.handshake) |limit| conn.handshake_until = Io.Clock.awake.now(io).addDuration(span.toIo(limit));
    defer conn.handshake_until = null;
    var authority_buf: [Io.net.HostName.max_len + 8]u8 = undefined;
    var aw: Io.Writer = .fixed(&authority_buf);
    writeAuthority(&aw, conn.route.host(), conn.route.port) catch return error.InvalidHostName;
    const authority = aw.buffered();
    const default_lines = [_]std.http.Header{
        .{ .name = "Proxy-Authorization", .value = "" },
        .{ .name = "Proxy-Connection", .value = "Keep-Alive" },
    };
    const lines = proxy.connect_headers orelse &default_lines;
    for (lines) |h| h1.checkHeader(h) catch return error.ProxyProtocolError;
    const w = conn.writer();
    (write: {
        w.print("CONNECT {s} HTTP/1.1\r\nHost: {s}\r\n", .{ authority, authority }) catch |e| break :write e;
        for (lines) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, "proxy-authorization") and h.value.len == 0) {
                _ = conn.route.proxy.?.auth.writeField(io, w, proxy.credential, "CONNECT", authority) catch |e| break :write e;
            } else h1.writeField(w, h) catch |e| break :write e;
        }
        w.writeAll("\r\n") catch |e| break :write e;
        conn.flush() catch |e| break :write e;
    }) catch return conn.writeError();
    var field_buf: [64]fields.Field = undefined;
    const parsed = readHeadInPlace(conn.reader(), &field_buf, 16 << 10) catch |err| return switch (err) {
        error.ReadFailed => conn.readError(),
        error.EndOfStream => error.ConnectionFailed,
        else => error.ProxyProtocolError,
    };
    const status = @backingInt(parsed.head.status);
    if (status / 100 == 2) {
        conn.reader().toss(parsed.len);
        return;
    }
    if (conn.diagnostics) |d| d.proxy_status = status;
    if (status != 407) return error.ProxyRefused;
    var offered_buf: [256]u8 = undefined;
    var offered: Io.Writer = .fixed(&offered_buf);
    if (conn.route.proxy.?.auth.challenged(ctx.gpa, io, proxy.credential, &parsed.head.headers, &offered) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ProxyAuthMethodUnsupported => {
            if (conn.diagnostics) |d| d.proxy_offered.set(offered.buffered(), offered.end == offered_buf.len);
            return error.ProxyAuthMethodUnsupported;
        },
    }) again.* = true;
    return error.ProxyAuthenticationRequired;
}

/// `host:port` as an authority has it, IPv6 bracketed.
pub fn writeAuthority(w: *Io.Writer, host: []const u8, port: u16) Io.Writer.Error!void {
    if (std.mem.findScalar(u8, host, ':') != null) try w.print("[{s}]:{d}", .{ host, port }) else try w.print("{s}:{d}", .{ host, port });
}

/// A response head parsed in `r`'s buffer, not taken from it: a head no
/// longer than `max` or the buffer.
fn readHeadInPlace(r: *Io.Reader, field_buf: []fields.Field, max: u32) (h1.ParseError || Io.Reader.Error)!h1.Parsed(h1.ResponseHead) {
    const limits: h1.Limits = .{ .max_head = .fromRaw(@intCast(@min(max, r.buffer.len))), .max_fields = @intCast(field_buf.len) };
    while (true) {
        if (try h1.parseResponse(r.buffer[r.seek..r.end], field_buf, limits)) |parsed| return parsed;
        if (limits.headFull(r.end - r.seek)) return error.HeadTooLarge;
        try r.fillMore();
    }
}

/// SOCKS negotiation, local lookup included, counts as connecting: it runs
/// within what is left of the connect timeout, and each step within the
/// handshake timeout too.
fn socksTunnel(conn: *Connection, proxy: Proxy, started: Io.Timestamp) OpenError!void {
    const ctx = conn.ctx;
    const io = conn.io;
    if (conn.diagnostics) |d| d.stage = .tunnel;
    var until: ?Io.Timestamp = null;
    var bound: Diagnostics.Timeout = .connect;
    if (ctx.timeouts.connect) |limit| until = started.addDuration(span.toIo(limit));
    if (ctx.timeouts.handshake) |limit| {
        const h = Io.Clock.awake.now(io).addDuration(span.toIo(limit));
        if (until == null or h.nanoseconds < until.?.nanoseconds) {
            until = h;
            bound = .handshake;
        }
    }
    if (conn.deadline) |d| if (until == null or d.nanoseconds < until.?.nanoseconds) {
        until = d;
        bound = .deadline;
    };
    conn.handshake_until = until;
    conn.handshake_bound = bound;
    // The deadlines tick fine enough for a negotiation bounded by `connect`
    // alone, which no per-operation timeout sets their tick for.
    if (until) |u| ctx.deadlines.tighten(io, Io.Clock.awake.now(io).durationTo(u));
    defer {
        conn.handshake_until = null;
        conn.handshake_bound = .handshake;
    }
    const version: socks.Version = switch (proxy.kind) {
        .socks4 => .socks4,
        .socks4a => .socks4a,
        .socks5 => .socks5,
        .socks5h => .socks5h,
        .http, .https => unreachable, // unreachable: only SOCKS proxies tunnel this way
    };
    const credential: ?socks.Credential = if (proxy.credential) |c| .{ .user = c.user, .password = c.password } else null;
    const host = conn.route.host();
    if ((version == .socks4 or version == .socks4a) and std.mem.findScalar(u8, host, ':') != null) return error.ProxyAddressUnsupported;
    if (version == .socks5 or version == .socks5h) socks.authenticate(conn.readEnd(), conn.writeEnd(), credential) catch |err| return conn.socksFailed(err);
    const literal = reactor.net.literal(host, conn.route.port);
    const address: ?Io.net.IpAddress = switch (version) {
        .socks4a => null,
        .socks5h => literal,
        .socks4, .socks5 => literal orelse try conn.socksLookup(version == .socks4, until),
    };
    socks.request(conn.writeEnd(), version, host, conn.route.port, address, credential) catch |err| return conn.socksFailed(err);
    var status: u16 = 0;
    socks.reply(conn.readEnd(), version, &status) catch |err| {
        if (conn.diagnostics) |d| d.proxy_status = status;
        return conn.socksFailed(err);
    };
}

/// The target's address, looked up here for SOCKS4 and SOCKS5: the first
/// IPv4 one for SOCKS4, which carries no other, and otherwise the first
/// IPv6 one, else the first.
fn socksLookup(conn: *Connection, ipv4: bool, until: ?Io.Timestamp) OpenError!Io.net.IpAddress {
    const io = conn.io;
    var storage: [reactor.net.max_addresses]Io.net.IpAddress = undefined;
    const timeout: ?Io.Duration = if (until) |u| Io.Clock.awake.now(io).durationTo(u) else null;
    if (timeout) |t| if (t.nanoseconds <= 0) return conn.timedOutOpen();
    var bounded = true;
    // Resolver.lookupWithin's contract returns the part of `out` it wrote; a resolver is any implementor's, behind a function pointer
    const addresses = conn.ctx.resolve().lookupWithin(io, conn.route.host(), conn.route.port, if (ipv4) .ip4 else null, &storage, if (timeout) |t| span.of(t) else null, &bounded) catch |err| return switch (err) {
        error.Canceled => error.Canceled,
        error.ConcurrencyUnavailable => error.ConcurrencyUnavailable,
        error.TimedOut => conn.timedOutOpen(),
        error.InvalidHostName, error.NameNotResolved => error.ProxyHostUnreachable,
    };
    if (!bounded) sync.bump(&conn.ctx.counters.timeouts_unenforced);
    var address: ?Io.net.IpAddress = null;
    for (addresses) |a| {
        if (address == null or (!ipv4 and address.? == .ip4 and a == .ip6)) address = a;
    }
    return address orelse error.ProxyHostUnreachable;
}

fn timedOutOpen(conn: *Connection) OpenError {
    conn.noteTimedOut(.connect);
    return error.TimedOut;
}

fn socksFailed(conn: *Connection, err: anyerror) OpenError {
    return switch (err) {
        error.ReadFailed => conn.readError(),
        error.Canceled => error.Canceled,
        error.EndOfStream => error.ConnectionFailed,
        error.WriteFailed => conn.writeError(),
        error.ProxyRefused, error.ProxyCommandUnsupported => error.ProxyRefused,
        error.ProxyAuthenticationRequired => error.ProxyAuthenticationRequired,
        error.ProxyAuthMethodUnsupported => error.ProxyAuthMethodUnsupported,
        error.ProxyHostUnreachable, error.ProxyNetworkUnreachable, error.ProxyTtlExpired => error.ProxyHostUnreachable,
        error.ProxyAddressUnsupported => error.ProxyAddressUnsupported,
        else => error.ProxyProtocolError,
    };
}
