//! One connection and what it is made of: the proxy, the layers, the
//! deadlines and the buffers.

/// One connection: a socket and the layers on it.
pub const Connection = @import("transport/Connection.zig");
/// What every connection a client makes shares.
pub const Context = @import("transport/Context.zig");
/// A proxy, read from settings or the environment.
pub const Proxy = @import("transport/Proxy.zig");
/// How a client answers its proxy.
pub const ProxyAuth = @import("transport/ProxyAuth.zig");
/// The I/O buffers connections and exchanges borrow.
pub const BufferPool = @import("transport/BufferPool.zig");
/// The task that keeps read and write timeouts.
pub const Timer = @import("transport/Timer.zig");
/// Why an exchange failed, in detail.
pub const Diagnostics = @import("transport/Diagnostics.zig");
/// Every step of a request, with its timing, as it happens.
pub const Observer = @import("transport/Observer.zig");

test {
    _ = Connection;
    _ = Context;
    _ = Proxy;
    _ = ProxyAuth;
    _ = BufferPool;
    _ = Timer;
    _ = Diagnostics;
    _ = Observer;
}
