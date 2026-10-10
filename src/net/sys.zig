//! The few calls on a socket that `std.Io` does not make: socket options,
//! and a look that neither waits nor takes anything. Everything else uplink
//! does to a socket goes through the caller's `Io`, or reactor's networking
//! over it.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const IpAddress = Io.net.IpAddress;

const os = builtin.target.os.tag;

/// The socket options a connection is tuned with.
pub const Tuning = struct {
    /// Turn Nagle's algorithm off, so a request's last segment is not held
    /// back waiting for the server to acknowledge the one before it.
    nodelay: bool = true,
    /// Turn TCP keepalive on, first probing after this long idle; whole
    /// seconds, at least one.
    keepalive: ?Io.Duration = null,
};

/// Tune a connected socket, and, on the systems that have it, keep a write
/// to a closed peer from raising SIGPIPE: a library cannot count on its
/// program having ignored the signal. A refusal is not a reason to fail the
/// connection, and is not reported.
pub fn tune(io: Io, handle: Io.net.Socket.Handle, tuning: Tuning) void {
    const idle: ?u32 = if (tuning.keepalive) |k| @intCast(std.math.clamp(@divTrunc(k.nanoseconds, std.time.ns_per_s), 1, std.math.maxInt(i32))) else null;
    if (os == .windows) {
        const ws2_32 = std.os.windows.ws2_32;
        if (tuning.nodelay) setAfd(io, handle, ws2_32.IPPROTO.TCP, ws2_32.TCP.NODELAY, 1);
        if (idle) |seconds| {
            setAfd(io, handle, ws2_32.SOL.SOCKET, ws2_32.SO.KEEPALIVE, 1);
            setAfd(io, handle, ws2_32.IPPROTO.TCP, ws2_32.TCP.KEEPALIVE, seconds);
        }
        return;
    }
    if (os == .wasi) return;
    if (tuning.nodelay) setPosix(handle, std.posix.IPPROTO.TCP, std.posix.TCP.NODELAY, 1);
    if (@hasDecl(std.posix.SO, "NOSIGPIPE")) setPosix(handle, std.posix.SOL.SOCKET, std.posix.SO.NOSIGPIPE, 1);
    if (idle) |seconds| {
        setPosix(handle, std.posix.SOL.SOCKET, std.posix.SO.KEEPALIVE, 1);
        // Linux names the idle time TCP_KEEPIDLE; Apple's systems,
        // TCP_KEEPALIVE.
        if (@hasDecl(std.posix.TCP, "KEEPIDLE")) {
            setPosix(handle, std.posix.IPPROTO.TCP, std.posix.TCP.KEEPIDLE, seconds);
        } else if (@hasDecl(std.posix.TCP, "KEEPALIVE")) {
            setPosix(handle, std.posix.IPPROTO.TCP, std.posix.TCP.KEEPALIVE, seconds);
        }
    }
}

fn setPosix(handle: Io.net.Socket.Handle, level: i32, name: u32, value: u32) void {
    const bytes = std.mem.toBytes(@as(c_int, @intCast(value)));
    // glint-ignore: Z026 -- a refused option leaves a working socket; these are latency and liveness settings, not contracts
    std.posix.setsockopt(handle, level, name, &bytes) catch {};
}

/// A socket option on Windows, where `Io.Threaded`'s sockets are AFD
/// handles and options are set by AFD's own control code.
fn setAfd(io: Io, handle: Io.net.Socket.Handle, level: i32, name: u32, value: u32) void {
    const windows = std.os.windows;
    const info: windows.AFD.SOCKOPT_INFO = .{ .mode = .set, .level = level, .optname = name, .optval = &value, .optlen = @sizeOf(u32) };
    const operation: Io.Operation = .{ .device_io_control = .{
        .file = .{ .handle = handle, .flags = .{ .nonblocking = true } },
        .code = windows.IOCTL.AFD.SOCKOPT,
        .in = std.mem.asBytes(&info),
    } };
    // glint-ignore: Z026 -- as on POSIX, a refused option leaves a working socket
    _ = io.operate(operation) catch {};
}

/// What a look at an idle socket finds.
pub const Peek = enum {
    /// Nothing waiting: the peer has said nothing.
    idle,
    /// Bytes waiting.
    readable,
    /// The peer closed it, or it failed.
    closed,
};

/// Look at a socket without waiting and without taking anything from it:
/// one `recv` with `MSG_PEEK` and `MSG_DONTWAIT`, a few times cheaper than
/// a readiness check through the `Io`. Null where the system has no such
/// call: Windows and WASI.
pub fn peek(handle: Io.net.Socket.Handle) ?Peek {
    if (os == .windows or os == .wasi) return null;
    var byte: [1]u8 = undefined;
    while (true) {
        const rc = std.posix.system.recvfrom(handle, &byte, byte.len, std.posix.MSG.PEEK | std.posix.MSG.DONTWAIT, null, null);
        switch (std.posix.errno(rc)) {
            .SUCCESS => return if (rc == 0) .closed else .readable,
            .AGAIN => return .idle,
            .INTR => continue,
            else => return .closed,
        }
    }
}

const testing = std.testing;
const test_io = @import("../testing/io.zig");

/// A socket option's value, read back; null where this test cannot read
/// one.
fn readOption(handle: Io.net.Socket.Handle, level: i32, name: u32) ?c_int {
    var value: c_int = 0;
    var len: std.posix.socklen_t = @sizeOf(c_int);
    if (builtin.link_libc) {
        if (std.c.getsockopt(handle, level, name, &value, &len) != 0) return null;
    } else if (os == .linux) {
        const rc = std.os.linux.getsockopt(handle, level, name, @ptrCast(&value), &len); // safe: the option is a c_int, its bytes the buffer
        if (std.os.linux.errno(rc) != .SUCCESS) return null;
    } else return null;
    return value;
}

test "a tuned socket has Nagle's algorithm off and keepalive on at the idle time asked" {
    if (os == .windows or os == .wasi) return error.SkipZigTest;
    const io = test_io.io();
    var listener = try (try IpAddress.parse("127.0.0.1", 0)).listen(io, .{ .reuse_address = true });
    defer listener.deinit(io);
    const stream = try listener.socket.address.connect(io, .{ .mode = .stream });
    defer stream.close(io);
    const h = stream.socket.handle;
    tune(io, h, .{ .keepalive = .fromSeconds(45) });
    try testing.expect((readOption(h, std.posix.IPPROTO.TCP, std.posix.TCP.NODELAY) orelse return error.SkipZigTest) != 0);
    try testing.expect(readOption(h, std.posix.SOL.SOCKET, std.posix.SO.KEEPALIVE).? != 0);
    const idle_name: ?u32 = if (@hasDecl(std.posix.TCP, "KEEPIDLE")) std.posix.TCP.KEEPIDLE else if (@hasDecl(std.posix.TCP, "KEEPALIVE")) std.posix.TCP.KEEPALIVE else null;
    if (idle_name) |name| try testing.expectEqual(@as(?c_int, 45), readOption(h, std.posix.IPPROTO.TCP, name));
}
