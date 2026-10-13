//! One connection and what it is made of: the proxy, the layers, the
//! deadlines, the buffers and the bodies read from it.

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
/// The awake clock as a checked number.
pub const awake = @import("transport/awake.zig");
/// Why an exchange failed, in detail.
pub const Diagnostics = @import("transport/Diagnostics.zig");
/// Every step of a request, with its timing, as it happens.
pub const Observer = @import("transport/Observer.zig");
/// A message body as its framing delimits it.
pub const Body = @import("transport/Body.zig");
/// A message head gathered into a pooled buffer.
pub const Head = @import("transport/Head.zig");
/// One socket's operations, each ended at its deadline.
pub const Timed = @import("transport/Timed.zig");

test {
    _ = Connection;
    _ = Context;
    _ = Proxy;
    _ = ProxyAuth;
    _ = BufferPool;
    _ = awake;
    _ = Diagnostics;
    _ = Observer;
    _ = Body;
    _ = Timed;
    _ = Head;
}
