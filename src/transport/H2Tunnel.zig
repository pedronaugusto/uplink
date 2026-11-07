//! A tunnel through an HTTP/2 proxy (RFC 9113 §8.5): a connection to the proxy
//! that speaks HTTP/2 (`H2`), one `CONNECT` stream on it, and the target's
//! connection going over that stream as another's goes over a socket.
//!
//! One stream to one proxy connection, as curl's HTTP/2 proxy filter holds: the
//! tunnel owns what it runs on, and the target's connection closes it all. A
//! proxy that will not speak HTTP/2 is refused rather than asked again over
//! HTTP/1.1: a caller who named `Proxy.http2` gets it or hears why not.

const std = @import("std");
const aegis = @import("aegis");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const wire = @import("uplink.wire");
const h2_message = wire.h2.message;
const hpack = wire.hpack;
const h1 = wire.h1;
const fields = wire.fields;
const span = @import("../span.zig");
const Connection = @import("Connection.zig");
const Context = @import("Context.zig");
const H2 = @import("H2.zig");
const Timed = @import("../net/Timed.zig");

const H2Tunnel = @This();

gpa: Allocator,
h2: *H2,
stream: *H2.Stream,
carrier: Connection.Carrier = .{ .vtable = &.{
    .read = read,
    .write = write,
    .awaitReadable = awaitReadable,
    .alive = alive,
    .close = close,
} },

/// Whether `route` goes through a tunnel of this kind: an `http` target goes
/// through such a proxy as through any other, in HTTP/1.1's absolute form.
pub fn serves(route: Context.Route) bool {
    const slot = route.proxy orelse return false;
    return route.secure and slot.proxy.http2;
}

/// The connection to `route`, which `serves` it, through a new stream to its
/// proxy. A proxy that asks for an answer is asked again on a new connection,
/// with the answer, and once more for a Digest nonce gone stale.
pub fn open(ctx: *Context, io: Io, route: Context.Route, options: Connection.OpenOptions) Connection.OpenError!*Connection {
    var attempts: u8 = 0;
    while (true) : (attempts += 1) {
        var again = false;
        return openOnce(ctx, io, route, options, &again) catch |err| switch (err) {
            error.ProxyAuthenticationRequired => if (attempts < 2 and again) continue else error.ProxyAuthenticationRequired,
            else => |e| e,
        };
    }
}

fn openOnce(ctx: *Context, io: Io, route: Context.Route, options: Connection.OpenOptions, again: *bool) Connection.OpenError!*Connection {
    const slot = route.proxy.?;
    // The proxy as a target of its own: its TLS, if it has any, offers `h2`;
    // nothing is tunneled on it but by the stream below.
    var to_proxy = route;
    to_proxy.secure = false;
    to_proxy.protocol = .h2_prior_knowledge;
    const below = try Connection.open(ctx, io, to_proxy, options);
    if (!below.proxySpeaksH2()) {
        below.close(io);
        return error.ProxyProtocolError;
    }
    const h = H2.create(ctx, io, below) catch |err| {
        below.close(io);
        return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            error.ConnectionFailed => error.ConnectionFailed,
        };
    };

    if (options.diagnostics) |d| d.stage = .tunnel;
    const started = if (ctx.observer != null) Io.Clock.awake.now(io) else null;
    const st = connect(ctx, io, h, route, slot, options, again) catch |err| {
        h.close(io);
        return err;
    };
    if (ctx.observer) |o| o.emit(.{ .tunnel = .{ .took = span.of(started.?.durationTo(Io.Clock.awake.now(io))) } });

    const tunnel = ctx.gpa.create(H2Tunnel) catch {
        h.finish(io, st);
        h.close(io);
        return error.OutOfMemory;
    };
    tunnel.* = .{ .gpa = ctx.gpa, .h2 = h, .stream = st };
    // From here the target's connection owns the tunnel, and closes it on failing.
    return Connection.openOver(ctx, io, route, &tunnel.carrier, below.endpoint(), options);
}

/// Ask the proxy for the route with `CONNECT`, and wait for its answer: the
/// stream, once a 2xx opened it.
fn connect(ctx: *Context, io: Io, h: *H2, route: Context.Route, slot: *Context.Proxies.Slot, options: Connection.OpenOptions, again: *bool) Connection.OpenError!*H2.Stream {
    const proxy = slot.proxy;
    var authority_buf: [Io.net.HostName.max_len + 8]u8 = undefined;
    var aw: Io.Writer = .fixed(&authority_buf);
    Connection.writeAuthority(&aw, route.host(), route.port) catch return error.InvalidHostName;
    const authority = aw.buffered();

    // The lines of a `CONNECT` as HTTP/1.1 writes them, then as fields: what a
    // connection's own they name stays behind.
    var lines_buf: [4096]u8 = undefined;
    var lw: Io.Writer = .fixed(&lines_buf);
    const default_lines = [_]std.http.Header{.{ .name = "Proxy-Authorization", .value = "" }};
    const lines = proxy.connect_headers orelse &default_lines;
    for (lines) |line| {
        h1.checkHeader(line) catch return error.ProxyProtocolError;
        if (std.ascii.eqlIgnoreCase(line.name, "proxy-authorization") and line.value.len == 0) {
            _ = slot.auth.writeField(io, &lw, proxy.credential, "CONNECT", authority) catch return error.ProxyProtocolError;
        } else h1.writeField(&lw, line) catch return error.ProxyProtocolError;
    }
    var list: [32]hpack.Field = undefined;
    list[0] = .{ .name = ":method", .value = "CONNECT" };
    list[1] = .{ .name = ":authority", .value = authority };
    const n = h2_message.appendLines(&list, 2, lines_buf[0..lw.end]) catch return error.ProxyProtocolError;

    var until = options.deadline;
    if (ctx.timeouts.handshake) |limit| {
        const bound = Io.Clock.awake.now(io).addDuration(span.toIo(limit));
        if (until == null or bound.nanoseconds < until.?.nanoseconds) until = bound;
    }
    const st = h.open(io, list[0..n], false, false) catch |err| return streamError(err);
    errdefer h.finish(io, st);
    h.awaitHead(io, st, until) catch |err| return streamError(err);
    const status = st.status.?;
    if (status / 100 == 2) {
        // What the stream carries keeps its own time, as the connection over it says.
        st.unbound = true;
        return st;
    }
    if (options.diagnostics) |d| d.proxy_status = status;
    if (status != 407) return error.ProxyRefused;
    const headers: fields.Headers = .init(st.fields);
    var offered_buf: [256]u8 = undefined;
    var offered: Io.Writer = .fixed(&offered_buf);
    if (slot.auth.challenged(ctx.gpa, io, proxy.credential, &headers, &offered) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ProxyAuthMethodUnsupported => {
            if (options.diagnostics) |d| d.proxy_offered.set(offered.buffered(), offered.end == offered_buf.len);
            return error.ProxyAuthMethodUnsupported;
        },
    }) again.* = true;
    return error.ProxyAuthenticationRequired;
}

fn streamError(err: H2.Error) Connection.OpenError {
    return switch (err) {
        error.ConnectionFailed => error.ConnectionFailed,
        error.TlsFailed => error.TlsFailed,
        error.ClientCertificateRejected => error.ClientCertificateRejected,
        // The proxy went away before it took the stream.
        error.Refused => error.ProxyRefused,
        error.TimedOut => error.TimedOut,
        error.Canceled => error.Canceled,
        error.OutOfMemory => error.OutOfMemory,
    };
}

fn of(carrier: *Connection.Carrier) *H2Tunnel {
    return @alignCast(@fieldParentPtr("carrier", carrier));
}

fn carried(err: H2.Error) Connection.Carrier.Error {
    return switch (err) {
        error.TimedOut => error.TimedOut,
        error.Canceled => error.Canceled,
        else => error.Broken,
    };
}

fn read(carrier: *Connection.Carrier, io: Io, dest: []u8, deadline: ?Io.Timestamp) Connection.Carrier.Error!usize {
    const st = of(carrier).stream;
    st.read_deadline = deadline;
    var w: Io.Writer = .fixed(dest);
    return st.reader(io).stream(&w, .limited(dest.len)) catch |err| switch (err) {
        error.EndOfStream => error.EndOfStream,
        error.WriteFailed => aegis.assert.never("`.limited` keeps a read to the room `dest` has"),
        error.ReadFailed => carried(st.read_failure.?),
    };
}

fn write(carrier: *Connection.Carrier, io: Io, header: []const u8, data: []const []const u8, splat: usize, deadline: ?Io.Timestamp) Connection.Carrier.Error!usize {
    const t = of(carrier);
    var n: usize = header.len;
    t.h2.send(io, t.stream, header, false, deadline) catch |err| return carried(err);
    for (data[0 .. data.len - 1]) |bytes| {
        t.h2.send(io, t.stream, bytes, false, deadline) catch |err| return carried(err);
        n += bytes.len;
    }
    for (0..splat) |_| {
        t.h2.send(io, t.stream, data[data.len - 1], false, deadline) catch |err| return carried(err);
        n += data[data.len - 1].len;
    }
    return n;
}

fn awaitReadable(carrier: *Connection.Carrier, io: Io, timeout: Io.Duration) Io.Cancelable!Timed.Readiness {
    return of(carrier).stream.awaitReadable(io, timeout);
}

fn alive(carrier: *Connection.Carrier, io: Io) bool {
    return of(carrier).h2.usable(io);
}

fn close(carrier: *Connection.Carrier, io: Io) void {
    const t = of(carrier);
    const gpa = t.gpa;
    t.h2.finish(io, t.stream);
    t.h2.close(io);
    gpa.destroy(t);
}
