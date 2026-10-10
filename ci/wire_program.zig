//! What a project that reads and writes HTTP messages and nothing else
//! writes: `uplink.wire`, asked for with `.client = false`, so that neither
//! reactor nor anything the client needs is fetched. Built by
//! `zig build check-wire-consumer` with aegis the only package.
const std = @import("std");
const wire = @import("uplink.wire");

pub fn main() void {
    _ = &wire.h1.parseResponse;
    _ = &wire.h1.parseRequest;
    _ = &wire.fields.Headers.get;
    _ = &wire.url.parse;
    _ = &wire.sse.Reader.next;
    _ = &wire.cookie.parse;
    _ = &wire.auth.writeBasic;
    _ = wire.Method;
    _ = std;
}
