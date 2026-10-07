//! The client: requests, responses, and the bodies between them.

/// An HTTP/1.1 client.
pub const Client = @import("client/Client.zig");
/// A request: a value that owns nothing.
pub const Request = @import("client/Request.zig");
/// A response: its head, and its body read through `reader`.
pub const Response = @import("client/Response.zig");
/// A request whose body the caller writes.
pub const Outgoing = @import("client/Outgoing.zig");
/// A response body as its framing delimits it.
pub const Body = @import("client/Body.zig");

test {
    _ = Client;
    _ = Request;
    _ = Response;
    _ = Outgoing;
    _ = Body;
}
