//! Names and connections: lookup with no task waiting on `io.async` work,
//! TCP connections raced over a name's addresses within one deadline, and
//! the socket options std's `Io` does not set.

/// Connect to a host by name or address.
pub const dial = @import("net/dial.zig");
/// Look a host name up.
pub const resolve = @import("net/resolve.zig");
/// Socket options and libc's lookup.
pub const sys = @import("net/sys.zig");

test {
    _ = dial;
    _ = resolve;
    _ = sys;
}
