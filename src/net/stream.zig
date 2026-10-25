//! A connected stream with its one owner. A dial gives it, a client
//! connection or a server's socket keeps it, and whoever holds the owner
//! closes it: aegis checks that it is closed once, and in Debug that it is
//! not moved once in use.

const std = @import("std");
const Io = std.Io;
const aegis = @import("aegis");

/// The owner of a connected stream, closed by its `deinit(io)`.
pub const Owned = aegis.own.OwnedIo(Io.net.Stream, close);

fn close(handle: *Io.net.Stream, io: Io) void {
    handle.close(io);
}
