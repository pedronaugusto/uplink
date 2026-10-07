//! uplink: HTTP for Zig. An HTTP/1.1 client with keep-alive, proxies of
//! every common kind, TLS with client certificates, timeouts that need no
//! task per connection, and decompression; and the codecs it is built from.

const std = @import("std");
const client = @import("client.zig");
const transport = @import("transport.zig");

/// An HTTP/1.1 client.
pub const Client = client.Client;
/// A request: a value that owns nothing.
pub const Request = client.Request;
/// A response: its head, and its body read through `reader`.
pub const Response = client.Response;
/// A request whose body the caller writes.
pub const Outgoing = client.Outgoing;
/// A proxy, read from settings or the environment.
pub const Proxy = transport.Proxy;
/// How long each step of an exchange may take.
pub const Timeouts = transport.Context.Timeouts;
/// Why an exchange failed, in detail.
pub const Diagnostics = transport.Diagnostics;
/// TLS: the authorities trusted, client certificates and keys.
pub const tls = @import("tls.zig");
/// Name lookup and connections.
pub const net = @import("net.zig");
/// The codecs, sans I/O.
pub const wire = @import("wire.zig");
/// A request method: any token.
pub const Method = wire.Method;
/// A response status.
pub const Status = std.http.Status;
/// A field to send: a name and a value.
pub const Header = std.http.Header;
/// The HTTP version a message was exchanged in.
pub const Version = wire.Version;
/// A read-only view of a head's fields.
pub const Headers = wire.fields.Headers;

test {
    _ = client;
    _ = transport;
    _ = tls;
    _ = net;
    _ = wire;
    _ = @import("pool.zig");
}
