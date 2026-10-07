//! What Zig 0.17's `Io.Threaded` does with a timed socket operation, which
//! the connection's deadlines are built on (uplink's verification V1). If a
//! Zig release changes the answer, this test says so, and the design of
//! `Timer` and `Connection.perform` is revisited.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const testing = std.testing;

test "a timed read on a socket times out on POSIX and is refused on Windows" {
    const io = testing.io;
    var listener = try (try Io.net.IpAddress.parse("127.0.0.1", 0)).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    var buffer: [16]u8 = undefined;
    var data: [1][]u8 = .{&buffer};
    const op: Io.Operation = .{ .net_read = .{ .socket_handle = stream.socket.handle, .data = &data } };
    const timeout: Io.Timeout = .{ .duration = .{ .raw = .fromMilliseconds(50), .clock = .awake } };
    const want: anyerror = if (builtin.target.os.tag == .windows) error.ConcurrencyUnavailable else error.Timeout;
    try testing.expectError(want, io.operateTimeout(op, timeout));
    // A wait of nothing at all, as the liveness check makes it.
    const zero: Io.Timeout = .{ .duration = .{ .raw = .fromNanoseconds(0), .clock = .awake } };
    try testing.expectError(want, io.operateTimeout(op, zero));
}
