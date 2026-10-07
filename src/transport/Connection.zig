//! One connection: a TCP socket, and the layers a route needs on it. TLS
//! to an `https` proxy, a `CONNECT` or SOCKS tunnel through the proxy, and
//! TLS to the target inside whatever came before: every layer is an
//! `Io.Reader` and `Io.Writer` over the one below, so a tunnel inside TLS
//! inside TCP is the same code as TLS alone.
//!
//! Every read and write on the socket goes through one place, which keeps
//! the connection's deadlines: the activity timeout of the operation, and
//! the handshake's while one is under way. With the client's timer running
//! the deadline is armed for the timer to keep; without one, the operation
//! is bounded by the `Io` itself where it can be (`operateTimeout`), and
//! counted as unenforced where it cannot. A connection whose deadline fired
//! is never used again.
//!
//! The socket's buffers come from the client's pool. A connection put away
//! idle gives them back, keeping only what its TLS sessions need.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const tls = @import("../tls.zig");
const h1 = @import("../wire/h1.zig");
const fields = @import("../wire/fields.zig");
const socks = @import("../wire/socks.zig");
const resolve = @import("../net/resolve.zig");
const dial = @import("../net/dial.zig");
const sys = @import("../net/sys.zig");
const Context = @import("Context.zig");
const Diagnostics = @import("Diagnostics.zig");
const Proxy = @import("Proxy.zig");
const Timer = @import("Timer.zig");

const Connection = @This();

/// Private: the client's shared state.
ctx: *Context,
/// Private: the current exchange's `Io`, for the reader and writer
/// adapters, which cannot take one per call.
io: Io,
/// Private: the socket.
stream: Io.net.Stream,
/// Where the connection goes; its host is in `host_storage`.
route: Context.Route,
/// Private.
host_storage: [Io.net.HostName.max_len]u8 = undefined,
/// Private: the socket's reader and writer.
input: SocketReader,
output: SocketWriter,
/// Private: TLS to the proxy (0) and to the target (1), as there are.
sessions: [2]tls.Session = .{ .{}, .{} },
session_on: [2]bool = .{ false, false },
session_buffers: [2][2][]u8 = undefined,
/// Requests name the whole URL: through a proxy, to an `http` target.
absolute_form: bool = false,
/// Private: how deadlines are kept.
mode: Mode = .untimed,
/// Private: the operation deadline the timer keeps.
watch: Timer.Watch,
/// Private: when the handshake under way must be done, on the awake clock.
handshake_until: ?Io.Timestamp = null,
/// Private: the timeout `handshake_until` keeps, which for a SOCKS
/// negotiation may be `connect`'s.
handshake_bound: Diagnostics.Timeout = .handshake,
/// Why the last operation failed.
failure: Failure = .none,
/// The exchange this connection serves, for its failure details; null
/// between exchanges.
diagnostics: ?*Diagnostics = null,

const Mode = enum {
    /// No timeout to keep.
    untimed,
    /// The client's timer keeps them.
    timer,
    /// `Io.operateTimeout` keeps them.
    operate,
    /// Asked for, and nothing could keep them.
    unenforced,
};

/// Why an operation failed.
pub const Failure = enum { none, timed_out, canceled, broken };

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

/// A connection to `route`, through the context's proxy, with every layer
/// started. `diagnostics` gets the details of a failure.
pub fn open(ctx: *Context, io: Io, route: Context.Route, diagnostics: ?*Diagnostics) OpenError!*Connection {
    // A proxy that asks for an answer to a tunnel is asked again on a new
    // connection, as curl asks, with the answer; and once more for a
    // Digest nonce gone stale.
    var attempts: u8 = 0;
    while (true) : (attempts += 1) {
        var again = false;
        return openOnce(ctx, io, route, diagnostics, &again) catch |err| switch (err) {
            error.ProxyAuthenticationRequired => if (attempts < 2 and again) continue else err,
            else => err,
        };
    }
}

fn openOnce(ctx: *Context, io: Io, route: Context.Route, diagnostics: ?*Diagnostics, again: *bool) OpenError!*Connection {
    if (route.host.len > Io.net.HostName.max_len) return error.InvalidHostName;
    const proxy = ctx.proxy;
    const first_host = if (proxy) |p| p.host else route.host;
    const first_port = if (proxy) |p| p.port else route.port;
    if (diagnostics) |d| d.stage = .connect;
    const started = Io.Clock.awake.now(io);
    const dialed = dial.dial(io, first_host, first_port, .{ .nodelay = ctx.nodelay, .timeout = ctx.timeouts.connect }) catch |err| {
        if (err == error.TimedOut) if (diagnostics) |d| {
            d.timeout = .connect;
        };
        return switch (err) {
            error.InvalidHostName => if (proxy != null) error.ProxyHostUnreachable else error.InvalidHostName,
            else => |e| e,
        };
    };
    if (!dialed.timeout_enforced) _ = ctx.counters.timeouts_unenforced.fetchAdd(1, .monotonic);
    _ = ctx.counters.opened.fetchAdd(1, .monotonic);
    if (diagnostics) |d| d.peer = dialed.stream.socket.address;
    const conn = create(ctx, io, route, dialed.stream, diagnostics) catch |err| {
        dialed.stream.close(io);
        return err;
    };
    conn.establish(proxy, started, again) catch |err| {
        conn.teardown(io, false);
        return err;
    };
    return conn;
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
        .watch = .{ .handle = stream.socket.handle },
        .diagnostics = diagnostics,
    };
    @memcpy(conn.host_storage[0..route.host.len], route.host);
    conn.route.host = conn.host_storage[0..route.host.len];
    conn.startWatch(io);
    return conn;
}

/// Start the proxy's layers and the target's TLS.
fn establish(conn: *Connection, proxy: ?Proxy, started: Io.Timestamp, again: *bool) OpenError!void {
    if (proxy) |p| {
        if (p.kind.socks()) {
            try conn.socksTunnel(p, started);
        } else {
            if (p.kind == .https) try conn.startTls(0, p.host);
            if (conn.route.secure) try conn.tunnel(p, again) else conn.absolute_form = true;
        }
    }
    if (conn.route.secure) try conn.startTls(1, conn.route.host);
}

/// Close politely: TLS close_notify, within the activity timeout, unless an
/// operation already failed; then the socket. Everything is released.
pub fn close(conn: *Connection, io: Io) void {
    conn.teardown(io, conn.failure == .none);
}

fn teardown(conn: *Connection, io: Io, polite: bool) void {
    conn.io = io;
    var i: usize = conn.sessions.len;
    while (i > 0) {
        i -= 1;
        if (!conn.session_on[i]) continue;
        if (polite) {
            // ziglint-ignore: Z026 the close_notify is a courtesy, as below
            conn.sessions[i].end() catch {};
            // ziglint-ignore: Z026 the close_notify is a courtesy; the socket is closed below whether or not the peer heard it
            conn.flushFrom(i) catch {};
        }
        for (conn.session_buffers[i]) |b| conn.ctx.buffers.release(io, b);
        conn.session_on[i] = false;
    }
    if (conn.mode == .timer) conn.ctx.timer.?.remove(io, &conn.watch);
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

/// Take a parked connection out for an exchange.
pub fn unpark(conn: *Connection, io: Io, diagnostics: ?*Diagnostics) Allocator.Error!void {
    conn.io = io;
    conn.diagnostics = diagnostics;
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

/// Whether the connection may carry another exchange: no operation failed
/// and no deadline fired.
pub fn reusable(conn: *const Connection) bool {
    return conn.failure == .none and !conn.watch.fired.load(.acquire);
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
    switch (conn.failure) {
        .timed_out => return error.TimedOut,
        .canceled => return error.Canceled,
        .none, .broken => {},
    }
    if (conn.watch.fired.load(.acquire)) return conn.timedOut(.activity);
    for (&conn.sessions, conn.session_on) |*s, on| {
        if (!on) continue;
        const err = s.readError() orelse continue;
        // TLS 1.3 finishes the handshake before the server has read the
        // client's certificate: its refusal is the first thing read.
        if (err == error.TlsAlert and s.certificate_requested) {
            if (s.readAlert()) |alert| if (tls.Session.refusesCertificate(alert.description)) {
                if (conn.diagnostics) |d| {
                    d.tls_error = tls.Session.alertError(alert.description);
                    d.tls_alert = alert.description;
                }
                return error.ClientCertificateRejected;
            };
        }
        if (conn.diagnostics) |d| d.tls_error = err;
        return error.TlsFailed;
    }
    if (conn.missingCertificateReset()) return error.ClientCertificateRejected;
    return error.ConnectionFailed;
}

/// Why a write failed, by name.
pub fn writeError(conn: *Connection) IoError {
    switch (conn.failure) {
        .timed_out => return error.TimedOut,
        .canceled => return error.Canceled,
        .none, .broken => {},
    }
    if (conn.watch.fired.load(.acquire)) return conn.timedOut(.activity);
    // A server that refused the client's certificate after a TLS 1.3
    // handshake the client thinks is done has sent its alert and closed:
    // the write that failed is the request, and the alert is there to read.
    for (&conn.sessions, conn.session_on) |*s, on| {
        if (!on or !s.certificate_requested) continue;
        // ziglint-ignore: Z026 the read only takes the alert in; its failure lands in the session's read error, checked next
        _ = s.reader().peekByte() catch {};
        if (s.readError() != null) return conn.readError();
    }
    if (conn.missingCertificateReset()) return error.ClientCertificateRejected;
    return error.ConnectionFailed;
}

fn timedOut(conn: *Connection, kind: Diagnostics.Timeout) IoError {
    conn.noteTimedOut(kind);
    return error.TimedOut;
}

fn noteTimedOut(conn: *Connection, kind: Diagnostics.Timeout) void {
    conn.failure = .timed_out;
    if (conn.diagnostics) |d| d.timeout = if (conn.handshake_until != null) conn.handshake_bound else kind;
}

/// Windows can report a server's refusal of a TLS client certificate as a
/// socket reset before the alert reaches the reader.
fn missingCertificateReset(conn: *Connection) bool {
    if (builtin.target.os.tag != .windows or conn.ctx.tls.client_auth != null) return false;
    for (conn.sessions, conn.session_on) |s, on| {
        if (on and s.certificate_requested) return true;
    }
    return false;
}

fn startWatch(conn: *Connection, io: Io) void {
    const timer = if (conn.ctx.timer) |*t| t else return;
    const tunneled = if (conn.ctx.proxy) |p| p.kind.socks() else false;
    if (conn.ctx.timeouts.shortestOnSocket(tunneled) == null) return;
    if (timer.add(io, &conn.watch)) {
        conn.mode = .timer;
    } else {
        conn.mode = .operate;
    }
}

/// The deadline of an operation starting now, or null.
fn operationDeadline(conn: *Connection, io: Io) ?Io.Timestamp {
    var deadline: ?Io.Timestamp = conn.handshake_until;
    if (conn.ctx.timeouts.activity) |a| {
        const d = Io.Clock.awake.now(io).addDuration(a);
        if (deadline == null or d.nanoseconds < deadline.?.nanoseconds) deadline = d;
    }
    return deadline;
}

/// Perform one socket operation within the connection's deadline. A failure
/// is recorded in `failure`, and `error.Failed` returned.
fn perform(conn: *Connection, op: Io.Operation) error{Failed}!Io.Operation.Result {
    const io = conn.io;
    const deadline = switch (conn.mode) {
        .untimed, .unenforced => null,
        .timer, .operate => conn.operationDeadline(io),
    } orelse return io.operate(op) catch return conn.fail(.canceled);
    switch (conn.mode) {
        .timer => {
            const timer = &conn.ctx.timer.?;
            timer.arm(io, &conn.watch, deadline);
            defer timer.disarm(&conn.watch);
            return io.operate(op) catch return conn.fail(.canceled);
        },
        .operate => return io.operateTimeout(op, .{ .deadline = .{ .raw = deadline, .clock = .awake } }) catch |err| switch (err) {
            error.Timeout => {
                conn.noteTimedOut(.activity);
                return error.Failed;
            },
            error.Canceled => conn.fail(.canceled),
            error.ConcurrencyUnavailable => {
                // This `Io` cannot bound a socket operation: from here on
                // the connection runs unbounded, counted once.
                conn.mode = .unenforced;
                _ = conn.ctx.counters.timeouts_unenforced.fetchAdd(1, .monotonic);
                return io.operate(op) catch return conn.fail(.canceled);
            },
        },
        .untimed, .unenforced => unreachable, // unreachable: these returned above, having no deadline
    }
}

fn fail(conn: *Connection, failure: Failure) error{Failed} {
    conn.note(failure);
    return error.Failed;
}

fn note(conn: *Connection, failure: Failure) void {
    if (conn.failure == .none) conn.failure = failure;
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
        if (n == 0) {
            // A socket the timer shut reads as ended.
            if (conn.watch.fired.load(.acquire)) {
                conn.noteTimedOut(.activity);
                return error.ReadFailed;
            }
            return error.EndOfStream;
        }
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
        return w.consume(n);
    }
};

fn startTls(conn: *Connection, slot: usize, host: []const u8) OpenError!void {
    const ctx = conn.ctx;
    const io = conn.io;
    if (conn.diagnostics) |d| d.stage = if (slot == 0) .proxy_tls else .tls;
    const trust = try conn.trustFor(slot);
    const read_buffer = try ctx.buffers.acquire(io, .record);
    errdefer ctx.buffers.release(io, read_buffer);
    const write_buffer = try ctx.buffers.acquire(io, .record);
    errdefer ctx.buffers.release(io, write_buffer);
    if (ctx.timeouts.handshake) |limit| conn.handshake_until = Io.Clock.awake.now(io).addDuration(limit);
    defer conn.handshake_until = null;
    const session = &conn.sessions[slot];
    session.start(io, conn.readerBelow(slot), conn.writerBelow(slot), read_buffer, write_buffer, .{
        .host = host,
        .trust = trust,
        .client_auth = if (slot == 0) ctx.proxy.?.tls.client_auth else ctx.tls.client_auth,
        .key_log = ctx.tls.key_log,
    }) catch |err| return conn.handshakeFailed(session, err);
    conn.session_buffers[slot] = .{ read_buffer, write_buffer };
    conn.session_on[slot] = true;
}

/// The authorities a session in `slot` checks its server against, or null
/// for none. An `https` proxy of its own trust is always checked, as curl
/// checks it whatever `verify` says.
fn trustFor(conn: *Connection, slot: usize) OpenError!?*tls.Trust {
    const ctx = conn.ctx;
    if (slot == 0) switch (ctx.proxy.?.tls.trust) {
        .as_target => {},
        .own => |own| return own orelse try conn.systemTrust(),
    };
    if (ctx.tls.verify == .none) return null;
    return ctx.tls.trust orelse try conn.systemTrust();
}

fn systemTrust(conn: *Connection) OpenError!*tls.Trust {
    return conn.ctx.system_trust.get(conn.ctx.gpa, conn.io) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.Canceled => error.Canceled,
        else => error.CertificateBundleUnreadable,
    };
}

fn handshakeFailed(conn: *Connection, session: *tls.Session, err: tls.Session.StartError) OpenError {
    if (conn.failure == .timed_out or conn.watch.fired.load(.acquire)) {
        conn.failure = .timed_out;
        if (conn.diagnostics) |d| d.timeout = .handshake;
        return error.TimedOut;
    }
    if (conn.failure == .canceled) return error.Canceled;
    const alert = session.handshake_alert;
    if (conn.diagnostics) |d| {
        d.tls_error = if (alert) |a| tls.Session.alertError(a.description) else err;
        if (alert) |a| d.tls_alert = a.description;
    }
    if (alert) |a| if (session.certificate_requested and tls.Session.refusesCertificate(a.description)) return error.ClientCertificateRejected;
    return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.ClientCertificateSchemeUnsupported => error.ClientCertificateSchemeUnsupported,
        error.ReadFailed => conn.readError(),
        error.WriteFailed => conn.writeError(),
        else => if (conn.missingCertificateReset()) error.ClientCertificateRejected else error.TlsFailed,
    };
}

/// Ask the proxy for a tunnel to the route with `CONNECT`, as curl asks.
fn tunnel(conn: *Connection, proxy: Proxy, again: *bool) OpenError!void {
    const ctx = conn.ctx;
    const io = conn.io;
    if (conn.diagnostics) |d| d.stage = .tunnel;
    if (ctx.timeouts.handshake) |limit| conn.handshake_until = Io.Clock.awake.now(io).addDuration(limit);
    defer conn.handshake_until = null;
    var authority_buf: [Io.net.HostName.max_len + 8]u8 = undefined;
    var aw: Io.Writer = .fixed(&authority_buf);
    writeAuthority(&aw, conn.route.host, conn.route.port) catch return error.InvalidHostName;
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
                _ = ctx.proxy_auth.writeField(io, w, proxy.credential, "CONNECT", authority) catch |e| break :write e;
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
    if (ctx.proxy_auth.challenged(ctx.gpa, io, proxy.credential, &parsed.head.headers, &offered) catch |err| switch (err) {
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
    const limits: h1.Limits = .{ .max_head = @intCast(@min(max, r.buffer.len)), .max_fields = @intCast(field_buf.len) };
    while (true) {
        if (try h1.parseResponse(r.buffer[r.seek..r.end], field_buf, limits)) |parsed| return parsed;
        if (r.end - r.seek >= limits.max_head) return error.HeadTooLarge;
        try r.fillMore();
    }
}

/// Curl counts SOCKS negotiation, local lookup included, as connecting:
/// it runs within what is left of the connect timeout, and each step
/// within the handshake timeout too.
fn socksTunnel(conn: *Connection, proxy: Proxy, started: Io.Timestamp) OpenError!void {
    const ctx = conn.ctx;
    const io = conn.io;
    if (conn.diagnostics) |d| d.stage = .tunnel;
    var until: ?Io.Timestamp = null;
    var bound: Diagnostics.Timeout = .connect;
    if (ctx.timeouts.connect) |limit| until = started.addDuration(limit);
    if (ctx.timeouts.handshake) |limit| {
        const h = Io.Clock.awake.now(io).addDuration(limit);
        if (until == null or h.nanoseconds < until.?.nanoseconds) {
            until = h;
            bound = .handshake;
        }
    }
    conn.handshake_until = until;
    conn.handshake_bound = bound;
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
    const host = conn.route.host;
    if ((version == .socks4 or version == .socks4a) and std.mem.findScalar(u8, host, ':') != null) return error.ProxyAddressUnsupported;
    if (version == .socks5 or version == .socks5h) socks.authenticate(conn.reader(), conn.writer(), credential) catch |err| return conn.socksFailed(err);
    const literal = resolve.literal(host, conn.route.port);
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
/// IPv4 one for SOCKS4, which carries no other, and the first of curl's
/// preferred family otherwise.
fn socksLookup(conn: *Connection, ipv4: bool, until: ?Io.Timestamp) OpenError!Io.net.IpAddress {
    const io = conn.io;
    var storage: [resolve.max_addresses]Io.net.IpAddress = undefined;
    const timeout: ?Io.Duration = if (until) |u| Io.Clock.awake.now(io).durationTo(u) else null;
    if (timeout) |t| if (t.nanoseconds <= 0) return conn.timedOutOpen();
    var bounded = true;
    const addresses = resolve.lookupWithin(io, conn.route.host, conn.route.port, if (ipv4) .ip4 else null, &storage, timeout, &bounded) catch |err| return switch (err) {
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
    conn.failure = .timed_out;
    if (conn.diagnostics) |d| d.timeout = .connect;
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
