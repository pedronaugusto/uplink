//! What a project that reads and writes HTTP messages and nothing else
//! writes: `uplink.wire` alone, which compiles nothing of the client. Built
//! by `zig build check-wire-consumer` with fetching off.
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
