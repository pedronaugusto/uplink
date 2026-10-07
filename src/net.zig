//! Names and connections: lookup with no task waiting on `io.async` work,
//! resolvers that override and cache it, TCP connections raced over a
//! name's addresses by Happy Eyeballs within one deadline, Unix sockets, and
//! the socket options std's `Io` does not set.

/// Connect to a host by name or address.
pub const dial = @import("net/dial.zig");
/// Look a host name up.
pub const resolve = @import("net/resolve.zig");
/// How host names become addresses: the system's, overrides, a cache.
pub const Resolver = @import("net/Resolver.zig");
/// Socket options and libc's lookup.
pub const sys = @import("net/sys.zig");

test {
    _ = dial;
    _ = resolve;
    _ = Resolver;
    _ = sys;
}
