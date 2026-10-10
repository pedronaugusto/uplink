//! The test root: every unit test, and the tests that drive the package
//! from outside.
test {
    _ = @import("uplink.zig");
    _ = @import("tls.zig");
    _ = @import("net.zig");
    _ = @import("transport.zig");
    _ = @import("pool.zig");
    _ = @import("client.zig");
    _ = @import("testing/tls_fork.zig");
    _ = @import("testing/Unwiped.zig");
    _ = @import("client/client_test.zig");
    _ = @import("client/policy_test.zig");
    _ = @import("client/tls_test.zig");
    _ = @import("transport/verify_test.zig");
}
