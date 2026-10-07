//! The few calls on a socket that `std.Io` does not make: socket options,
//! a look that neither waits nor takes anything, and `getaddrinfo` on the
//! caller's own task. Everything else uplink does
//! to a socket goes through the caller's `Io`.

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
    // ziglint-ignore: Z026 a refused option leaves a working socket; these are latency and liveness settings, not contracts
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
    // ziglint-ignore: Z026 as on POSIX, a refused option leaves a working socket
    _ = io.operate(operation) catch {};
}

/// End every operation under way on a socket, from another task: on POSIX
/// a shutdown of both directions, which wakes a blocked `recvmsg` or
/// `sendmsg`; on Windows an abortive disconnect, since AFD's graceful one
/// leaves a pending receive waiting for the peer. The socket is not
/// closed; its owner closes it. A refusal means it is ended already.
pub fn abort(io: Io, handle: Io.net.Socket.Handle) void {
    if (os == .windows) {
        const windows = std.os.windows;
        const info: windows.AFD.PARTIAL_DISCONNECT_INFO = .{
            .DisconnectMode = .{ .SEND = true, .RECEIVE = true, .ABORTIVE = true },
            .Timeout = -1,
        };
        const operation: Io.Operation = .{ .device_io_control = .{
            .file = .{ .handle = handle, .flags = .{ .nonblocking = false } },
            .code = windows.IOCTL.AFD.PARTIAL_DISCONNECT,
            .in = std.mem.asBytes(&info),
        } };
        // ziglint-ignore: Z026 a socket that cannot be disconnected is ended already, which is what this asks
        _ = io.operate(operation) catch {};
        return;
    }
    // ziglint-ignore: Z026 a socket that cannot be shut down is ended already, which is what this asks
    io.vtable.netShutdown(io.userdata, handle, .both) catch {};
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

/// Whether this target has a name lookup that runs on the caller's own
/// task: libc's `getaddrinfo`.
pub const own_lookup = builtin.link_libc and os != .windows;

/// Errors from `getaddrinfo`.
pub const LookupError = error{
    /// The name has no address, or the resolver failed.
    LookupFailed,
};

/// `name`'s addresses by libc's `getaddrinfo`, called on this task: the
/// first `out.len` of them, in its order. It blocks until it answers, and
/// cannot be canceled, as std's own libc lookup cannot.
pub fn getaddrinfo(name: []const u8, port: u16, family: ?IpAddress.Family, out: []IpAddress) LookupError![]IpAddress {
    if (!own_lookup) @compileError("getaddrinfo needs libc");
    var name_buffer: [Io.net.HostName.max_len:0]u8 = undefined;
    if (name.len > Io.net.HostName.max_len) return error.LookupFailed;
    @memcpy(name_buffer[0..name.len], name);
    name_buffer[name.len] = 0;
    var port_buffer: [8]u8 = undefined;
    const port_text = std.mem.printSentinel(&port_buffer, "{d}", .{port}, 0) catch unreachable; // unreachable: a u16 is at most five digits
    const hints: std.c.addrinfo = .{
        .flags = .{ .NUMERICSERV = true },
        .family = if (family) |f| switch (f) {
            .ip4 => std.c.AF.INET,
            .ip6 => std.c.AF.INET6,
        } else std.c.AF.UNSPEC,
        .socktype = std.c.SOCK.STREAM,
        .protocol = std.c.IPPROTO.TCP,
        .canonname = null,
        .addr = null,
        .addrlen = 0,
        .next = null,
    };
    var list: ?*std.c.addrinfo = null;
    if (@backingInt(std.c.getaddrinfo(name_buffer[0..name.len :0].ptr, port_text.ptr, &hints, &list)) != 0) return error.LookupFailed;
    defer if (list) |first| std.c.freeaddrinfo(first);
    var count: usize = 0;
    var entry = list;
    while (entry) |info| : (entry = info.next) {
        const addr = info.addr orelse continue;
        if (addr.family != std.c.AF.INET and addr.family != std.c.AF.INET6) continue;
        if (count == out.len) break;
        out[count] = Io.Threaded.addressFromPosix(@alignCast(@fieldParentPtr("any", addr))); // safe: getaddrinfo's INET and INET6 entries point at a whole sockaddr of their family
        count += 1;
    }
    if (count == 0) return error.LookupFailed;
    return out[0..count];
}

const testing = std.testing;

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
    const io = testing.io;
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
