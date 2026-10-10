//! What a project that builds an HTTP client writes, built by
//! `zig build check-cold-consumer` with no package fetched beforehand.
const std = @import("std");
const uplink = @import("uplink");

pub fn main() void {
    _ = &uplink.Client.init;
    _ = &uplink.wire.h1.parseResponse;
    _ = std;
}
