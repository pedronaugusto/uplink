//! The server: connections accepted and served, requests and the
//! responses that answer them.

/// An HTTP server: HTTP/1.1, and HTTP/2.
pub const Server = @import("server/Server.zig");
/// What a server does for each request.
pub const Handler = @import("server/Handler.zig");
/// A request as the server received it.
pub const Request = @import("server/Request.zig");
/// The answer to a request.
pub const Response = @import("server/Response.zig");
/// Routes requests to handlers by pattern, as Go 1.22's `ServeMux`.
pub const Router = @import("server/Router.zig");
/// A router whose patterns are known at compile time: a conflict is a
/// compile error, and captures are typed.
pub const Routes = @import("server/routes.zig").Routes;
/// The typed captures of a comptime route's pattern.
pub const Captures = @import("server/routes.zig").Captures;
/// Files from a directory, with conditional and range requests.
pub const Files = @import("server/Files.zig");
/// A route pattern and how two of them relate.
pub const Pattern = @import("server/Pattern.zig");

test {
    _ = Server;
    _ = Request;
    _ = Response;
    _ = Router;
    _ = Pattern;
    _ = Files;
    _ = @import("server/routes.zig");
    _ = Handler;
    _ = @import("server/Connection.zig");
    _ = @import("server/Context.zig");
    _ = @import("server/Socket.zig");
    _ = @import("server/h2.zig");
    _ = @import("server/server_test.zig");
}
