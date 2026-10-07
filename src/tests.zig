//! The test root: every unit test, and the tests that drive the package
//! from outside.
test {
    _ = @import("uplink.zig");
    _ = @import("wire.zig");
    _ = @import("tls.zig");
    _ = @import("net.zig");
    _ = @import("transport.zig");
    _ = @import("pool.zig");
    _ = @import("client.zig");
    _ = @import("testing/tls_fork.zig");
    _ = @import("client/client_test.zig");
}
