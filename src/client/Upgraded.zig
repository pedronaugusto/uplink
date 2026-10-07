//! A connection a response handed over: after a `101 Switching Protocols`,
//! or a 2xx to a `CONNECT` the caller sent, what follows on it is no longer
//! HTTP. This is the raw two-way stream, TLS and proxy tunnel included,
//! which the caller now owns. The client's activity timeout still bounds
//! each read and write; the request's own deadline no longer applies.
//!
//! One task may read while another writes. An `Upgraded` must not move
//! once `reader` or `writer` has been called.

const std = @import("std");
const Io = std.Io;
const Connection = @import("../transport/Connection.zig");
const Context = @import("../transport/Context.zig");
const Pool = @import("../pool/Pool.zig");

const Upgraded = @This();

/// Private: the connection, and what counts it.
ctx: *Context,
pool: *Pool,
conn: *Connection,

/// What the peer sends, starting with any bytes that came with the
/// response's head.
pub fn reader(u: *Upgraded, io: Io) *Io.Reader {
    u.conn.io = io;
    return u.conn.reader();
}

/// What goes to the peer, once `flush` pushes it out.
pub fn writer(u: *Upgraded, io: Io) *Io.Writer {
    u.conn.io = io;
    return u.conn.writer();
}

/// Errors from a read or write, by name, after `reader` or `writer`
/// reported a failure.
pub const Error = Connection.IoError;

/// Push what was written through every layer to the peer.
pub fn flush(u: *Upgraded, io: Io) Error!void {
    u.conn.io = io;
    u.conn.flush() catch return u.conn.writeError();
}

/// Why the last read failed.
pub fn readFailure(u: *Upgraded) Error {
    return u.conn.readError();
}

/// Close the stream; TLS close_notify is sent as a courtesy.
pub fn close(u: *Upgraded, io: Io) void {
    _ = u.ctx.counters.in_use.fetchSub(1, .monotonic);
    const route = u.conn.route;
    u.conn.close(io);
    u.pool.closed(io, route);
    u.* = undefined;
}
