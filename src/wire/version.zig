//! The HTTP version a message was exchanged in.

/// uplink exchanges messages in `http1_0`, `http1_1` and `h2`; `h3` is
/// named so that a `switch` over a version is exhaustive, and no message is
/// read or written in it.
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
