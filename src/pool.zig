//! Which connection serves which exchange.

/// The idle connections, per route.
pub const Pool = @import("pool/Pool.zig");

test {
    _ = Pool;
}
