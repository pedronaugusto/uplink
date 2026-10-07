//! A request whose body the caller writes: through `writer`, then `finish`
//! for the response. A body of a declared length must be written exactly;
//! otherwise it goes in chunks.
//!
//! `finish` follows the client's policy from the first response on, as
//! `send` does, except that a body the caller streamed is never sent
//! again: a 307 or 308 fails with `BodyNotReplayable`, a 401 or 407 and a
//! status the retries cover are handed back.
//!
//! `finish` leaves the value valid whatever happens: `deinit` is still owed,
//! closes the connection when the exchange did not complete, and does
//! nothing more after a successful `finish`. An `Outgoing` must not move
//! once `writer` has been called.

const std = @import("std");
const Io = std.Io;
const h1 = @import("../wire/h1.zig");
const Connection = @import("../transport/Connection.zig");
const Response = @import("Response.zig");
const Run = @import("Run.zig");

const Outgoing = @This();

/// Private: the request's run, and the connection it is written on.
run: Run,
conn: ?*Connection,
/// Private: the body writer's buffer, from the pool.
buffer: []u8,
body: Writer,

const Writer = union(enum) {
    length: h1.LengthWriter,
    chunked: h1.ChunkedWriter,
};

/// Errors from `finish`.
pub const FinishError = error{
    InvalidUrl,
    UnsupportedScheme,
    InvalidHeader,
    NameNotResolved,
    ConnectionFailed,
    TimedOut,
    TlsFailed,
    ClientCertificateRejected,
    ClientCertificateSchemeUnsupported,
    CertificateBundleUnreadable,
    InvalidProxy,
    ProxyRefused,
    ProxyAuthenticationRequired,
    ProxyAuthMethodUnsupported,
    ProxyAddressUnsupported,
    ProxyHostUnreachable,
    ProxyProtocolError,
    HttpProtocolError,
    /// Fewer bytes were written than the declared length.
    BodyIncomplete,
    InvalidBody,
    BodyReadFailed,
    BodyNotReplayable,
    TooManyRedirects,
    InsecureRedirect,
    InvalidRedirect,
    CredentialsUnavailable,
    PrepareFailed,
    ConcurrencyUnavailable,
    OutOfMemory,
    Canceled,
    /// More bytes were written than the declared length.
    BodyTooLong,
    /// `finish` was already called, or the connection is gone.
    ExchangeOver,
};

/// Set up the body writer for a head already written on `conn`.
pub fn init(run: Run, conn: *Connection, buffer: []u8, length: ?u64) Outgoing {
    const out = conn.writer();
    return .{
        .run = run,
        .conn = conn,
        .buffer = buffer,
        .body = if (length) |n| .{ .length = .init(out, n, buffer) } else .{ .chunked = .init(out, buffer) },
    };
}

/// Where the body is written. Writing past a declared length fails, and
/// `finish` then says `BodyTooLong`.
pub fn writer(o: *Outgoing) *Io.Writer {
    return switch (o.body) {
        inline else => |*w| &w.interface,
    };
}

/// End the body, read the response, and follow the policy. On success the
/// connection belongs to the response.
pub fn finish(o: *Outgoing, io: Io) FinishError!Response {
    const conn = o.conn orelse return error.ExchangeOver;
    conn.io = io;
    if (o.run.request.diagnostics) |d| d.stage = .write;
    switch (o.body) {
        .length => |*lw| {
            if (lw.overflowed) return error.BodyTooLong;
            lw.interface.flush() catch return o.writeFailed(conn);
            if (lw.remaining != 0) return error.BodyIncomplete;
        },
        .chunked => |*cw| cw.end() catch return conn.writeError(),
    }
    conn.flush() catch return conn.writeError();
    const c = o.run.client;
    const first = try Response.receive(io, &c.context, &c.pool, conn, .{
        .method = o.run.method,
        .limits = c.options.limits,
        .decompress = c.options.decompress,
        .diagnostics = o.run.request.diagnostics,
        .progress = &o.run.progress,
    });
    // The response holds the connection now, and the run the response.
    o.conn = null;
    return o.run.complete(io, first);
}

fn writeFailed(o: *Outgoing, conn: *Connection) FinishError {
    if (o.body == .length and o.body.length.overflowed) return error.BodyTooLong;
    return conn.writeError();
}

/// Close the connection unless `finish` handed it on, and give back what
/// the request borrowed.
pub fn deinit(o: *Outgoing, io: Io) void {
    const c = o.run.client;
    if (o.conn) |conn| Response.release(io, &c.context, &c.pool, conn, false);
    c.context.buffers.release(io, o.buffer);
    o.run.deinit(io);
    o.* = undefined;
}
