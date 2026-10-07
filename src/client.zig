//! The client: requests, responses, and the policy between them.

/// An HTTP/1.1 client.
pub const Client = @import("client/Client.zig");
/// A request: a value that owns nothing.
pub const Request = @import("client/Request.zig");
/// A response: its head, and its body read through `reader`.
pub const Response = @import("client/Response.zig");
/// A request whose body the caller writes.
pub const Outgoing = @import("client/Outgoing.zig");
/// A connection a response handed over: after a 101, or a `CONNECT`.
pub const Upgraded = @import("client/Upgraded.zig");
/// A response body as its framing delimits it.
pub const Body = @import("client/Body.zig");
/// Redirects followed, and failures and statuses tried again.
pub const policy = @import("client/policy.zig");
/// A cookie store, and the Netscape cookie file.
pub const CookieJar = @import("client/CookieJar.zig");
/// Where answers to servers' 401s come from.
pub const Credentials = @import("client/Credentials.zig");
/// The hook called before every attempt is written.
pub const Prepare = @import("client/Prepare.zig");

test {
    _ = Client;
    _ = Request;
    _ = Response;
    _ = Outgoing;
    _ = Upgraded;
    _ = Body;
    _ = policy;
    _ = CookieJar;
    _ = Credentials;
    _ = Prepare;
    _ = @import("client/OriginAuth.zig");
    _ = @import("client/Run.zig");
    _ = @import("client/Shared.zig");
}
