//! What a client does for a request, step by step, with how long each step
//! took, told as it happens, in one callback. An observer is called on the task sending the request; it
//! must be quick, and may be called from several tasks at once when the
//! client is shared. Every slice in an event is valid only during the call.
//!
//! Nothing is measured unless a client has an observer, so one that has
//! none pays for no clock reads.

const std = @import("std");
const Io = std.Io;
const Duration = @import("../span.zig").Duration;

const Observer = @This();

context: ?*anyopaque,
eventFn: *const fn (context: ?*anyopaque, event: Event) void,

/// Tell the observer `event`.
pub fn emit(o: Observer, event: Event) void {
    o.eventFn(o.context, event);
}

/// One step.
pub const Event = union(enum) {
    /// A kept connection was taken for the request.
    reused: struct { host: []const u8, port: u16 },
    /// A new connection was made: the name looked up and the address
    /// connected to, the proxy's when there is one.
    connected: struct {
        host: []const u8,
        port: u16,
        /// The address connected to; null for a Unix socket.
        peer: ?Io.net.IpAddress,
        /// The name's lookup; zero for an address.
        lookup: Duration,
        /// The lookup and the connection together.
        took: Duration,
    },
    /// A tunnel through the proxy was opened: `CONNECT` or SOCKS.
    tunnel: struct { took: Duration },
    /// A TLS handshake finished, with the proxy or with the server:
    /// `resumed` from a ticket, `ech` with the server's name hidden.
    tls: struct { host: []const u8, proxy: bool, took: Duration, resumed: bool = false, ech: bool = false },
    /// The request's head and body were written.
    sent: struct { method: []const u8, url: []const u8 },
    /// The response's head arrived, `wait` after the request was written.
    head: struct { status: u16, wait: Duration },
    /// A challenge is being answered and the request sent again: 401 from
    /// the server, 407 from the proxy.
    challenged: struct { status: u16 },
    /// A redirect is being followed to `url`.
    redirect: struct { status: u16, url: []const u8 },
    /// The request is being sent again after `delay`, attempt `attempt`
    /// (2 for the first retry): for a failed connection, `error_name` says
    /// why; for a status, `status` says which.
    retry: struct { attempt: u8, delay: Duration, status: ?u16, error_name: ?[]const u8 },
};

test "an observer is handed each event" {
    const Count = struct {
        n: u32 = 0,
        const Self = @This();
        fn on(context: ?*anyopaque, event: Event) void {
            const self: *Self = @ptrCast(@alignCast(context.?)); // safe: the test passes its own counter
            switch (event) {
                .head => |h| if (h.status == 200) {
                    self.n += 1;
                },
                else => {},
            }
        }
    };
    var count: Count = .{};
    const o: Observer = .{ .context = &count, .eventFn = Count.on };
    o.emit(.{ .head = .{ .status = 200, .wait = .fromRaw(0) } });
    o.emit(.{ .tunnel = .{ .took = .fromRaw(0) } });
    try std.testing.expectEqual(@as(u32, 1), count.n);
}
