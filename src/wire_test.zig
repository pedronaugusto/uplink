//! The test root of `uplink.wire`: its unit tests and the differential test
//! against the independent reader, built with aegis and shakedown alone.
//! The module's tests run here because a module's tests run only from the
//! build that has it as the root.
test {
    _ = @import("wire.zig");
    _ = @import("wire/differential_test.zig");
}
