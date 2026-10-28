//! A connected stream with its one owner. A dial gives it, a client
//! connection or a server's socket keeps it, and whoever holds the owner
//! closes it: aegis checks that it is closed once, and in Debug that it is
//! not moved once in use.
//!
//! The stream is a socket, or a Windows named pipe's end: the operations
//! a connection reads and writes with are the stream's own kind, made
//! here, so nothing above asks which it is.

const std = @import("std");
const Io = std.Io;
const aegis = @import("aegis");
const reactor = @import("reactor");

/// What a connection's bytes go over.
pub const Endpoint = union(enum) {
    socket: Io.net.Stream,
    /// A named pipe's end, opened for overlapped calls (reactor's
    /// `connectPipe`, or a `PipeListener`'s accept).
    pipe: Io.File,

    /// A read into `data`.
    pub fn readOp(e: Endpoint, data: [][]u8) Io.Operation {
        return switch (e) {
            .socket => |s| .{ .net_read = .{ .socket_handle = s.socket.handle, .data = data } },
            .pipe => |f| .{ .file_read_streaming = .{ .file = f, .data = data } },
        };
    }

    /// A write of `header`, then `data`, the last of it `splat` times.
    pub fn writeOp(e: Endpoint, header: []const u8, data: []const []const u8, splat: usize) Io.Operation {
        return switch (e) {
            .socket => |s| .{ .net_write = .{ .socket_handle = s.socket.handle, .header = header, .data = data, .splat = splat } },
            .pipe => |f| .{ .file_write_streaming = .{ .file = f, .header = header, .data = data, .splat = splat } },
        };
    }

    /// How many bytes a read brought: 0 at the stream's end.
    pub fn readCount(result: Io.Operation.Result) error{Failed}!usize {
        return switch (result) {
            .net_read => |r| (r catch return error.Failed).data_len,
            .file_read_streaming => |r| r catch |err| switch (err) {
                error.EndOfStream => 0,
                else => error.Failed,
            },
            else => unreachable, // unreachable: a read's result is a read's
        };
    }

    /// How many bytes a write took.
    pub fn writeCount(result: Io.Operation.Result) error{Failed}!usize {
        return switch (result) {
            .net_write => |r| r catch error.Failed,
            .file_write_streaming => |r| r catch error.Failed,
            else => unreachable, // unreachable: a write's result is a write's
        };
    }

    /// The deadline watch for its operations.
    pub fn watch(e: Endpoint) reactor.net.Deadlines.Watch {
        return switch (e) {
            .socket => |s| .init(s.socket.handle),
            .pipe => |f| .initPipe(f),
        };
    }

    /// The socket, lent for what only a socket has: options, a peek, a
    /// half close; null for a pipe. The endpoint's owner closes it.
    pub fn socketStream(e: Endpoint) ?aegis.own.Lent(Io.net.Stream) {
        return switch (e) {
            .socket => |s| .{ .data = s },
            .pipe => null,
        };
    }
};

/// The owner of a connected stream, closed by its `deinit(io)`.
pub const Owned = aegis.own.OwnedIo(Endpoint, close);

fn close(e: *Endpoint, io: Io) void {
    switch (e.*) {
        .socket => |s| s.close(io),
        .pipe => |f| f.close(io),
    }
}
