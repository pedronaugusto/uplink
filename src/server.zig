//! The server: connections accepted and served, requests and the
//! responses that answer them.

/// An HTTP/1.1 server.
pub const Server = @import("server/Server.zig");
/// A request as the server received it.
pub const Request = @import("server/Request.zig");
/// The answer to a request.
pub const Response = @import("server/Response.zig");
/// Routes requests to handlers by pattern, as Go 1.22's `ServeMux`.
pub const Router = @import("server/Router.zig");
/// A route pattern and how two of them relate.
pub const Pattern = @import("server/Pattern.zig");

test {
    _ = Server;
    _ = Request;
    _ = Response;
    _ = Router;
    _ = Pattern;
    _ = @import("server/Connection.zig");
    _ = @import("server/server_test.zig");
}
