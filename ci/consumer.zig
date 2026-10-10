//! What a project that depends on uplink and nothing else writes. Built by
//! `zig build check-consumer` with only aegis and reactor to fetch, so uplink's
//! build.zig must work without any of its own CI or test dependencies.
const std = @import("std");
const uplink = @import("uplink");
const wire = @import("uplink.wire");

pub fn main() void {
    comptime {
        // One declaration whichever way the codecs are named.
        std.debug.assert(uplink.wire.h1 == wire.h1);
        std.debug.assert(uplink.Method == wire.Method);
    }
    _ = &uplink.Client.init;
    _ = &uplink.Client.send;
    _ = &uplink.Client.begin;
    _ = &uplink.Response.collect;
    _ = &uplink.Proxy.fromEnvironment;
    _ = &uplink.CookieJar.writeField;
    _ = &uplink.Upgraded.close;
    _ = &uplink.net.Resolver.Static.parseEntry;
    _ = &uplink.wire.sse.Reader.next;
    _ = &uplink.tls.Trust.addSystem;
    _ = &wire.h1.parseResponse;
    _ = std;
}
