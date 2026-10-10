//! Names and connections: resolvers that override and cache lookup, TCP
//! connections raced over a name's addresses by Happy Eyeballs within one
//! deadline, Unix sockets, and the socket options std's `Io` does not set.
//! Looking a name up and connecting with a timeout are reactor's.

/// Connect to a host by name or address.
pub const dial = @import("net/dial.zig");
/// How host names become addresses: the system's, overrides, a cache.
pub const Resolver = @import("net/Resolver.zig");
/// Socket options.
pub const sys = @import("net/sys.zig");

test {
    _ = dial;
    _ = Resolver;
    _ = sys;
}
