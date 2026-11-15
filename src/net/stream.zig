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

/// What a connection's bytes go over, as a view: every endpoint names a
/// handle its one `Owned` keeps and closes, and a copy lends it.
pub const Endpoint = union(enum) {
    socket: aegis.own.Unowned(Io.net.Stream),
    /// A named pipe's end, opened for overlapped calls (reactor's
    /// `connectPipe`, or a `PipeListener`'s accept).
    pipe: aegis.own.Unowned(Io.File),

    /// The endpoint naming `stream`, which an `Owned` is to keep.
    pub fn ofSocket(stream: Io.net.Stream) Endpoint {
        return .{ .socket = .of(stream) };
    }

    /// The endpoint naming `file`, a pipe's end, which an `Owned` is to keep.
    pub fn ofPipe(file: Io.File) Endpoint {
        return .{ .pipe = .of(file) };
    }

    /// A read into `data`.
    pub fn readOp(e: Endpoint, data: [][]u8) Io.Operation {
        return switch (e) {
            .socket => |s| .{ .net_read = .{ .socket_handle = s.get().socket.handle, .data = data } },
            .pipe => |f| .{ .file_read_streaming = .{ .file = f.get(), .data = data } },
        };
    }

    /// A write of `header`, then `data`, the last of it `splat` times.
    pub fn writeOp(e: Endpoint, header: []const u8, data: []const []const u8, splat: usize) Io.Operation {
        return switch (e) {
            .socket => |s| .{ .net_write = .{ .socket_handle = s.get().socket.handle, .header = header, .data = data, .splat = splat } },
            .pipe => |f| .{ .file_write_streaming = .{ .file = f.get(), .header = header, .data = data, .splat = splat } },
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
            .socket => |s| .init(s.get().socket.handle),
            .pipe => |f| .initPipe(f.get()),
        };
    }

    /// The socket, lent for what only a socket has: options, a peek, a
    /// half close; null for a pipe. The endpoint's owner closes it.
    pub fn socketStream(e: Endpoint) ?Io.net.Stream {
        return switch (e) {
            .socket => |s| s.get(),
            .pipe => null,
        };
    }
};

/// The owner of a connected stream, closed by its `deinit(io)`: the one
/// holder that closes what its endpoint names.
pub const Owned = aegis.own.OwnedIo(Endpoint, close);

fn close(e: *Endpoint, io: Io) void {
    switch (e.*) {
        .socket => |s| s.get().close(io),
        .pipe => |f| f.get().close(io),
    }
}
