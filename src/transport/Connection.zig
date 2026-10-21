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
const sys = @import("../net/sys.zig");
const Context = @import("Context.zig");
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
/// Private: the socket.
stream: Io.net.Stream,
/// Where the connection goes.
route: Context.Route,
/// Private: the socket's reader and writer.
input: SocketReader,
output: SocketWriter,
/// Private: TLS to the proxy (0) and to the target (1), as there are.
sessions: [2]cloak.tls.Session = undefined,
session_on: [2]bool = .{ false, false },
session_buffers: [2][2][]u8 = undefined,
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
armed: std.atomic.Value(Diagnostics.Timeout) = .init(.activity),
/// Why the first operation that failed did; `failed` reads it.
failure: std.atomic.Value(Failure) = .init(.none),
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
        .nodelay = ctx.dial.nodelay,
        .keepalive = ctx.dial.keepalive,
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
    const dialed = (if (ctx.dial.unix_socket) |path|
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
    if (!dialed.timeout_enforced) _ = ctx.counters.timeouts_unenforced.fetchAdd(1, .monotonic);
    _ = ctx.counters.opened.fetchAdd(1, .monotonic);
    if (diagnostics) |d| d.peer = dialed.peer;
    if (ctx.observer) |o| o.emit(.{ .connected = .{
        .host = first_host,
        .port = first_port,
        .peer = dialed.peer,
        .lookup = dialed.lookup,
        .took = span.of(started.durationTo(Io.Clock.awake.now(io))),
    } });
    const conn = create(ctx, io, route, dialed.stream, diagnostics) catch |err| {
        dialed.stream.close(io);
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

/// A connection over `stream`, with nothing on it yet.
fn create(ctx: *Context, io: Io, route: Context.Route, stream: Io.net.Stream, diagnostics: ?*Diagnostics) Allocator.Error!*Connection {
    const conn = try ctx.gpa.create(Connection);
    errdefer ctx.gpa.destroy(conn);
    const read_buffer = try ctx.buffers.acquire(io, .record);
    errdefer ctx.buffers.release(io, read_buffer);
    const write_buffer = try ctx.buffers.acquire(io, .record);
    conn.* = .{
        .ctx = ctx,
        .io = io,
        .stream = stream,
        .route = route,
        .input = .init(read_buffer),
        .output = .init(write_buffer),
        .timed = .init(stream.socket.handle),
        .diagnostics = diagnostics,
    };
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
            if (p.kind == .https) try conn.startTls(0, p.host, .{ .alpn = tls.client_protocols_h1, .ech = conn.ctx.greaseOr() });
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
    conn.stream.close(io);
    conn.releaseSocketBuffers(io);
    conn.ctx.gpa.destroy(conn);
}

fn releaseSocketBuffers(conn: *Connection, io: Io) void {
    if (conn.input.interface.buffer.len != 0) conn.ctx.buffers.release(io, conn.input.interface.buffer);
    if (conn.output.interface.buffer.len != 0) conn.ctx.buffers.release(io, conn.output.interface.buffer);
    conn.input.interface.buffer = &.{};
    conn.output.interface.buffer = &.{};
}

/// Put the connection away idle: the socket's buffers go back to the pool
/// when they hold nothing. Only TLS sessions keep theirs.
pub fn park(conn: *Connection, io: Io) void {
    conn.diagnostics = null;
    conn.deadline = null;
    const r = &conn.input.interface;
    if (r.buffer.len != 0 and r.seek == r.end) {
        conn.ctx.buffers.release(io, r.buffer);
        r.* = .{ .vtable = r.vtable, .buffer = &.{}, .seek = 0, .end = 0 };
    }
    const w = &conn.output.interface;
    if (w.buffer.len != 0 and w.end == 0) {
        conn.ctx.buffers.release(io, w.buffer);
        w.buffer = &.{};
    }
}

/// Take a parked connection out for an exchange that must be done by
/// `deadline`.
pub fn unpark(conn: *Connection, io: Io, diagnostics: ?*Diagnostics, deadline: ?Io.Timestamp) Allocator.Error!void {
    conn.io = io;
    conn.diagnostics = diagnostics;
    conn.deadline = deadline;
    conn.speed = .{};
    if (conn.input.interface.buffer.len == 0) conn.input.interface.buffer = try conn.ctx.buffers.acquire(io, .record);
    if (conn.output.interface.buffer.len == 0) conn.output.interface.buffer = try conn.ctx.buffers.acquire(io, .record);
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
    if (sys.peek(conn.stream.socket.handle)) |seen| return switch (seen) {
        .idle => true,
        .readable => secure,
        .closed => false,
    };
    r.seek = 0;
    r.end = 0;
    var data: [1][]u8 = .{r.buffer};
    const result = io.operateTimeout(.{ .net_read = .{ .socket_handle = conn.stream.socket.handle, .data = &data } }, .{
        .duration = .{ .raw = .fromNanoseconds(0), .clock = .awake },
    }) catch |err| return switch (err) {
        error.Timeout, error.ConcurrencyUnavailable => true,
        error.Canceled => error.Canceled,
    };
    const n = (result.net_read catch return false).data_len;
    if (n == 0) return false;
    r.end = n;
    return secure;
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
    return Timed.awaitReadable(io, conn.stream.socket.handle, &conn.input.interface, timeout);
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
            }
            return error.ClientCertificateRejected;
        };
        if (conn.diagnostics) |d| {
            d.tls_error = err;
            d.tls_alert = seen.alert_received orelse seen.alert_sent;
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

    fn init(buffer: []u8) SocketReader {
        return .{ .interface = .{ .vtable = &.{ .stream = streamImpl, .readVec = readVec }, .buffer = buffer, .seek = 0, .end = 0 } };
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
        const result = conn.perform(.{ .net_read = .{ .socket_handle = conn.stream.socket.handle, .data = iovecs[0..dest_n] } }) catch return error.ReadFailed;
        const n = (result.net_read catch {
            conn.note(.broken);
            return error.ReadFailed;
        }).data_len;
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

    fn init(buffer: []u8) SocketWriter {
        return .{ .interface = .{ .vtable = &.{ .drain = drain }, .buffer = buffer } };
    }

    fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const sw: *SocketWriter = @alignCast(@fieldParentPtr("interface", w)); // safe: this vtable is installed only on a SocketWriter's interface
        const conn: *Connection = @alignCast(@fieldParentPtr("output", sw)); // safe: a SocketWriter lives only in a Connection's `output`
        const result = conn.perform(.{ .net_write = .{
            .socket_handle = conn.stream.socket.handle,
            .header = w.buffered(),
            .data = data,
            .splat = splat,
        } }) catch return error.WriteFailed;
        const n = result.net_write catch {
            conn.note(.broken);
            return error.WriteFailed;
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
    var codecs = [_]cloak.tls.certificate_compression.Codec{ tls.decoder(.zstd, &ctx.gpa), tls.decoder(.zlib, &ctx.gpa) };
    var namespace_buf: [Io.net.HostName.max_len + 32]u8 = undefined;
    session.open(ctx.gpa, io, conn.readerBelow(slot), conn.writerBelow(slot), read_buffer, write_buffer, .{
        .identity = tls.reference(host),
        .trust = if (trust) |snapshot| .{ .snapshot = snapshot } else if (leaf_keys) .{ .leaf_keys = ctx.tls.pins } else .none,
        .pins = if (target and !leaf_keys) ctx.tls.pins else &.{},
        .min_version = if (target) ctx.tls.min_version else .tls12,
        .max_version = if (target) ctx.tls.max_version else .tls13,
        .credentials = if (auth != null) conn.credentials[slot .. slot + 1] else &.{},
        .key_log = if (ctx.tls.key_log) |sink| tls.keyLog(sink) else null,
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
        // HTTP says where a body ends, so an end without close_notify is
        // not a truncation it cannot see.
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
    if (conn.failed() == .canceled) return error.Canceled;
    const alert = report.alert_received orelse report.alert_sent;
    if (conn.diagnostics) |d| {
        d.tls_error = err;
        d.tls_alert = alert;
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
fn writeAuthority(w: *Io.Writer, host: []const u8, port: u16) Io.Writer.Error!void {
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
    if (version == .socks5 or version == .socks5h) socks.authenticate(conn.reader(), conn.writer(), credential) catch |err| return conn.socksFailed(err);
    const literal = reactor.net.literal(host, conn.route.port);
    const address: ?Io.net.IpAddress = switch (version) {
        .socks4a => null,
        .socks5h => literal,
        .socks4, .socks5 => literal orelse try conn.socksLookup(version == .socks4, until),
    };
    socks.request(conn.writer(), version, host, conn.route.port, address, credential) catch |err| return conn.socksFailed(err);
    var status: u16 = 0;
    socks.reply(conn.reader(), version, &status) catch |err| {
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
    const addresses = conn.ctx.resolve().lookupWithin(io, conn.route.host(), conn.route.port, if (ipv4) .ip4 else null, &storage, if (timeout) |t| span.of(t) else null, &bounded) catch |err| return switch (err) {
        error.Canceled => error.Canceled,
        error.ConcurrencyUnavailable => error.ConcurrencyUnavailable,
        error.TimedOut => conn.timedOutOpen(),
        error.InvalidHostName, error.NameNotResolved => error.ProxyHostUnreachable,
    };
    if (!bounded) _ = conn.ctx.counters.timeouts_unenforced.fetchAdd(1, .monotonic);
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
