//! The HTTP version a message was exchanged in.

/// The versions uplink exchanges messages in are `http1_0` and `http1_1`.
/// `h2` and `h3` are named so that a `switch` over a version is exhaustive;
/// no message is read or written in either.
pub const Version = enum {
    http1_0,
    http1_1,
    h2,
    h3,

    /// The version as a request or status line spells it, for HTTP/1.x.
    pub fn text(v: Version) []const u8 {
        return switch (v) {
            .http1_0 => "HTTP/1.0",
            .http1_1 => "HTTP/1.1",
            .h2 => "HTTP/2",
            .h3 => "HTTP/3",
        };
    }
};
