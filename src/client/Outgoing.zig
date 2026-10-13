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
const wire = @import("uplink.wire");
const h1 = wire.h1;
const Connection = @import("../transport/Connection.zig");
const H2 = @import("../transport/H2.zig");
const Response = @import("Response.zig");
const Run = @import("Run.zig");

const Outgoing = @This();

/// Private: the request's run, and the connection it is written on: one
/// of its own, or a stream of a shared HTTP/2 one.
run: Run,
conn: ?*Connection,
h2: ?*H2 = null,
stream: ?*H2.Stream = null,
/// Private: the body writer's buffer, from the pool.
buffer: []u8,
body: Writer,
/// Private: the server's answer before the body, which it refused.
early: ?Response = null,

const Writer = union(enum) {
    length: h1.LengthWriter,
    chunked: h1.ChunkedWriter,
    /// The server answered before the body: it goes nowhere.
    dropped: Io.Writer.Discarding,
    /// Data on an HTTP/2 stream.
    data: DataWriter,
};

/// A body written as an HTTP/2 stream's data, held to a declared length.
const DataWriter = struct {
    h2: *H2,
    stream: *H2.Stream,
    io: Io,
    deadline: ?Io.Timestamp,
    remaining: ?u64,
    overflowed: bool = false,
    failure: ?H2.Error = null,
    interface: Io.Writer,

    fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const dw: *DataWriter = @alignCast(@fieldParentPtr("interface", w)); // safe: this vtable is installed only on a DataWriter's interface
        try dw.put(w.buffered());
        w.end = 0;
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |d| {
            try dw.put(d);
            n += d.len;
        }
        const last = data[data.len - 1];
        for (0..splat) |_| {
            try dw.put(last);
            n += last.len;
        }
        return n;
    }

    fn put(dw: *DataWriter, bytes: []const u8) Io.Writer.Error!void {
        if (bytes.len == 0) return;
        if (dw.remaining) |*left| {
            if (bytes.len > left.*) {
                dw.overflowed = true;
                return error.WriteFailed;
            }
            left.* -= bytes.len;
        }
        dw.h2.send(dw.io, dw.stream, bytes, false, dw.deadline) catch |err| {
            dw.failure = err;
            return error.WriteFailed;
        };
    }
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

/// Set up the body writer for a request whose head opened `st` on `h`.
pub fn initStream(run: Run, io: Io, h: *H2, st: *H2.Stream, buffer: []u8, length: ?u64) Outgoing {
    const deadline = run.deadline;
    return .{
        .run = run,
        .conn = null,
        .h2 = h,
        .stream = st,
        .buffer = buffer,
        .body = .{ .data = .{
            .h2 = h,
            .stream = st,
            .io = io,
            .deadline = deadline,
            .remaining = length,
            .interface = .{ .vtable = &.{ .drain = DataWriter.drain }, .buffer = buffer },
        } },
    };
}

/// A request the server answered before its body: what is written is
/// dropped, and `finish` returns `response`.
pub fn refused(run: Run, response: Response, buffer: []u8) Outgoing {
    return .{ .run = run, .conn = null, .buffer = buffer, .body = .{ .dropped = .init(buffer) }, .early = response };
}

/// Where the body is written. Writing past a declared length fails, and
/// `finish` then says `BodyTooLong`.
pub fn writer(o: *Outgoing) *Io.Writer {
    return switch (o.body) {
        .length => |*w| &w.interface,
        .chunked => |*w| &w.interface,
        .dropped => |*d| &d.writer,
        .data => |*d| &d.interface,
    };
}

/// End the body, read the response, and follow the policy. On success the
/// connection belongs to the response.
pub fn finish(o: *Outgoing, io: Io) FinishError!Response {
    if (o.early) |answer| {
        o.early = null;
        return o.run.complete(io, answer);
    }
    if (o.stream != null) return o.finishStream(io);
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
        .dropped => unreachable, // unreachable: a dropped body has its answer in `early`, taken above
        .data => unreachable, // unreachable: a stream's body ends in `finishStream`
    }
    conn.flush() catch return conn.writeError();
    const first = try o.run.receive(io, conn, false);
    // The response holds the connection now, and the run the response.
    o.conn = null;
    return o.run.complete(io, first);
}

/// `finish` over HTTP/2: the data ended, the response's head read.
fn finishStream(o: *Outgoing, io: Io) FinishError!Response {
    const h = o.h2.?;
    const st = o.stream.?;
    const dw = &o.body.data;
    dw.io = io;
    if (dw.overflowed) return error.BodyTooLong;
    dw.interface.flush() catch return if (dw.overflowed) error.BodyTooLong else Run.noRefusal(o.run.h2Failure(io, dw.failure.?));
    if (dw.remaining) |n| if (n != 0) return error.BodyIncomplete;
    if (!st.sent_end) o.run.sendH2(io, h, st, "", true) catch |err| return Run.noRefusal(err);
    const first = o.run.receiveH2(io, h, st) catch |err| return Run.noRefusal(err);
    // The response holds the stream now, and the run the response.
    o.stream = null;
    o.h2 = null;
    return o.run.complete(io, first);
}

fn writeFailed(o: *Outgoing, conn: *Connection) FinishError {
    if (o.body == .length and o.body.length.overflowed) return error.BodyTooLong;
    return conn.writeError();
}

/// Close the connection unless `finish` handed it on, and give back what
/// the request borrowed.
pub fn deinit(o: *Outgoing, io: Io) void {
    const c = o.run.shared;
    if (o.conn) |conn| Response.release(io, &c.context, &c.pool, conn, false);
    if (o.stream) |st| {
        const h = o.h2.?;
        h.finish(io, st);
        Response.releaseShared(io, &c.context, &c.pool, h);
    }
    if (o.early) |*answer| answer.deinit(io);
    c.context.buffers.release(io, o.buffer);
    o.run.deinit(io);
    o.* = undefined;
}
