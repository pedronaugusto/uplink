//! What a project that depends on uplink and nothing else writes. Built by
//! `zig build check-consumer` with no packages to fetch, so uplink's
//! build.zig must work without any of its own CI or test dependencies.
const std = @import("std");
const uplink = @import("uplink");

pub fn main() void {
    _ = &uplink.Client.init;
    _ = &uplink.Client.send;
    _ = &uplink.Client.begin;
    _ = &uplink.Response.collect;
    _ = &uplink.Proxy.fromEnvironment;
    _ = &uplink.tls.Trust.addSystem;
    _ = &uplink.wire.h1.parseResponse;
    _ = std;
}
