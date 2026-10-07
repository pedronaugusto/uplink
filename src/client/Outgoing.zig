//! A request whose body the caller writes: through `writer`, then `finish`
//! for the response. A body of a declared length must be written exactly;
//! otherwise it goes in chunks.
//!
//! `finish` leaves the value valid whatever happens: `deinit` is still owed,
//! closes the connection when the exchange did not complete, and does
//! nothing more after a successful `finish`. An `Outgoing` must not move
//! once `writer` has been called.

const std = @import("std");
const Io = std.Io;
const h1 = @import("../wire/h1.zig");
const Method = @import("../wire/Method.zig");
const Connection = @import("../transport/Connection.zig");
const Context = @import("../transport/Context.zig");
const Diagnostics = @import("../transport/Diagnostics.zig");
const Pool = @import("../pool/Pool.zig");
const Response = @import("Response.zig");

const Outgoing = @This();

/// Private: what the request goes over.
ctx: *Context,
pool: *Pool,
conn: ?*Connection,
method: Method,
limits: h1.Limits,
decompress: bool,
diagnostics: ?*Diagnostics,
/// Private: the body writer's buffer, from the pool.
buffer: []u8,
body: Writer,

const Writer = union(enum) {
    length: h1.LengthWriter,
    chunked: h1.ChunkedWriter,
};

/// Errors from `finish`.
pub const FinishError = error{
    ConnectionFailed,
    TimedOut,
    TlsFailed,
    ClientCertificateRejected,
    Canceled,
    HttpProtocolError,
    OutOfMemory,
    /// Fewer bytes were written than the declared length.
    BodyIncomplete,
    /// More bytes were written than the declared length.
    BodyTooLong,
    /// `finish` was already called, or the connection is gone.
    ExchangeOver,
};

/// Set up the body writer for a head already written to `conn`.
pub fn init(ctx: *Context, pool: *Pool, conn: *Connection, buffer: []u8, method: Method, length: ?u64, limits: h1.Limits, decompress: bool, diagnostics: ?*Diagnostics) Outgoing {
    const out = conn.writer();
    return .{
        .ctx = ctx,
        .pool = pool,
        .conn = conn,
        .method = method,
        .limits = limits,
        .decompress = decompress,
        .diagnostics = diagnostics,
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

/// End the body and read the response's head. On success the connection
/// belongs to the response.
pub fn finish(o: *Outgoing, io: Io) FinishError!Response {
    const conn = o.conn orelse return error.ExchangeOver;
    conn.io = io;
    if (o.diagnostics) |d| d.stage = .write;
    switch (o.body) {
        .length => |*lw| {
            if (lw.overflowed) return error.BodyTooLong;
            lw.interface.flush() catch return o.writeFailed(conn);
            if (lw.remaining != 0) return error.BodyIncomplete;
        },
        .chunked => |*cw| cw.end() catch return conn.writeError(),
    }
    conn.flush() catch return conn.writeError();
    var progress = false;
    const response = try Response.receive(io, o.ctx, o.pool, conn, .{
        .method = o.method,
        .limits = o.limits,
        .decompress = o.decompress,
        .diagnostics = o.diagnostics,
        .progress = &progress,
    });
    o.conn = null;
    return response;
}

fn writeFailed(o: *Outgoing, conn: *Connection) FinishError {
    if (o.body == .length and o.body.length.overflowed) return error.BodyTooLong;
    return conn.writeError();
}

/// Close the connection unless `finish` handed it to a response, and give
/// the buffer back.
pub fn deinit(o: *Outgoing, io: Io) void {
    if (o.conn) |c| Response.release(io, o.ctx, o.pool, c, false);
    o.ctx.buffers.release(io, o.buffer);
    o.* = undefined;
}
