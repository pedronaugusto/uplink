//! The server's HTTP/2: the protocol state a connection's tasks share, and
//! the loop that serves its streams.

/// One HTTP/2 connection's shared state, and its streams.
pub const Session = @import("h2/Session.zig");
/// Serve a connection as HTTP/2.
pub const serve = @import("h2/serve.zig").serve;

test {
    _ = Session;
    _ = @import("h2/serve.zig");
}
