//! A connection a response handed over: after a `101 Switching Protocols`,
//! or a 2xx to a `CONNECT` the caller sent, what follows on it is no longer
//! HTTP. This is the raw two-way stream, TLS and proxy tunnel included,
//! which the caller now owns: a connection of its own, or, after an
//! extended `CONNECT` over HTTP/2 (RFC 8441), one stream of a shared
//! connection, its bytes the stream's data. The client's activity timeout
//! still bounds each read and write; the request's own deadline no longer
//! applies.
//!
//! One task may read while another writes. An `Upgraded` must not move
//! once `reader` or `writer` has been called.

const std = @import("std");
const Io = std.Io;
const BufferPool = @import("../transport/BufferPool.zig");
const Connection = @import("../transport/Connection.zig");
const Context = @import("../transport/Context.zig");
const H2 = @import("../transport/H2.zig");
const Pool = @import("../pool/Pool.zig");
const Timed = @import("../net/Timed.zig");

const Upgraded = @This();

/// Private: the connection, and what counts it.
ctx: *Context,
pool: *Pool,
/// Private: what carries the new protocol.
carrier: Carrier,
/// Private: a stream's writer, its bytes sent as DATA, through a buffer
/// of the client's pool.
tunnel: Io.Writer = .{ .vtable = &.{ .drain = drainTunnel }, .buffer = &.{} },
tunnel_buffer: BufferPool.Buffer = &.{},
/// Private: the buffer a stream is read through, as a connection's
/// reader has one.
tunnel_in: BufferPool.Buffer = &.{},
/// Private: the task writing, and why its last write failed.
write_io: Io = undefined,
write_failure: ?H2.Error = null,

/// What a switched exchange goes on.
pub const Carrier = union(enum) {
    /// A connection of its own.
    conn: *Connection,
    /// One stream of a shared HTTP/2 connection.
    stream: struct { h2: *H2, stream: *H2.Stream },
};

/// What the peer sends, starting with any bytes that came with the
/// response's head.
pub fn reader(u: *Upgraded, io: Io) *Io.Reader {
    switch (u.carrier) {
        .conn => |conn| {
            conn.io = io;
            return conn.reader();
        },
        .stream => |s| return s.stream.reader(io),
    }
}

/// What goes to the peer, once `flush` pushes it out.
pub fn writer(u: *Upgraded, io: Io) *Io.Writer {
    switch (u.carrier) {
        .conn => |conn| {
            conn.io = io;
            return conn.writer();
        },
        .stream => {
            u.write_io = io;
            return &u.tunnel;
        },
    }
}

/// Errors from a read or write, by name, after `reader` or `writer`
/// reported a failure.
pub const Error = Connection.IoError;

/// Push what was written through every layer to the peer.
pub fn flush(u: *Upgraded, io: Io) Error!void {
    switch (u.carrier) {
        .conn => |conn| {
            conn.io = io;
            conn.flush() catch return conn.writeError();
        },
        .stream => {
            u.write_io = io;
            u.tunnel.flush() catch return ioError(u.write_failure orelse error.ConnectionFailed);
        },
    }
}

/// Why the last read failed.
pub fn readFailure(u: *Upgraded) Error {
    return switch (u.carrier) {
        .conn => |conn| conn.readError(),
        .stream => |s| ioError(s.stream.read_failure orelse error.ConnectionFailed),
    };
}

/// Wait up to `timeout` for the peer to send something; the wait ends
/// nothing when nothing comes.
pub fn awaitReadable(u: *Upgraded, io: Io, timeout: Io.Duration) Io.Cancelable!Timed.Readiness {
    return switch (u.carrier) {
        .conn => |conn| conn.awaitReadable(io, timeout),
        .stream => |s| s.stream.awaitReadable(io, timeout),
    };
}

/// Bound no read or write by the client's timeouts any more: the protocol
/// the stream carries keeps its own, as WebSocket does.
pub fn unbind(u: *Upgraded) void {
    switch (u.carrier) {
        .conn => |conn| conn.unbind(),
        .stream => |s| s.stream.unbound = true,
    }
}

/// Close the stream; TLS close_notify is sent as a courtesy. A stream of
/// an HTTP/2 connection is ended, or reset when its peer has not ended
/// its side, and the connection goes on for the others.
pub fn close(u: *Upgraded, io: Io) void {
    _ = u.ctx.counters.in_use.fetchSubWrapping(.fromRaw(1), .monotonic);
    switch (u.carrier) {
        .conn => |conn| u.pool.close(io, .{ .h1 = conn }),
        .stream => |s| {
            if (!s.stream.sent_end) {
                // glint-ignore: Z026 -- a stream that cannot be ended is reset by finish, which ends it too
                s.h2.send(io, s.stream, "", true, null) catch {};
            }
            s.h2.finish(io, s.stream);
            u.pool.unshare(io, s.h2);
            for ([_]BufferPool.Buffer{ u.tunnel_buffer, u.tunnel_in }) |b| if (b.len != 0) u.ctx.buffers.release(io, b);
        },
    }
    u.* = undefined;
}

/// A stream's failure, as a connection's would read.
fn ioError(err: H2.Error) Error {
    return switch (err) {
        error.TimedOut => error.TimedOut,
        error.TlsFailed => error.TlsFailed,
        error.ClientCertificateRejected => error.ClientCertificateRejected,
        error.Canceled => error.Canceled,
        error.ConnectionFailed, error.Refused, error.OutOfMemory => error.ConnectionFailed,
    };
}

fn drainTunnel(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
    const u: *Upgraded = @alignCast(@fieldParentPtr("tunnel", w)); // safe: this vtable is installed only on an Upgraded's `tunnel`
    const s = u.carrier.stream;
    const io = u.write_io;
    s.h2.send(io, s.stream, w.buffered(), false, null) catch |err| return u.tunnelFailed(err);
    var n: usize = 0;
    for (data[0 .. data.len - 1]) |d| {
        s.h2.send(io, s.stream, d, false, null) catch |err| return u.tunnelFailed(err);
        n += d.len;
    }
    for (0..splat) |_| {
        s.h2.send(io, s.stream, data[data.len - 1], false, null) catch |err| return u.tunnelFailed(err);
        n += data[data.len - 1].len;
    }
    w.end = 0;
    return n;
}

fn tunnelFailed(u: *Upgraded, err: H2.Error) error{WriteFailed} {
    u.write_failure = err;
    return error.WriteFailed;
}
