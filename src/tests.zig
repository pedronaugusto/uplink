//! The test root: every unit test, and the tests that drive the package
//! from outside.
test {
    _ = @import("wire.zig");
    _ = @import("tls.zig");
    _ = @import("net.zig");
    _ = @import("transport/Proxy.zig");
    _ = @import("testing/tls_fork.zig");
}
