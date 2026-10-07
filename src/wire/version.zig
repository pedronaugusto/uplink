//! The HTTP version a message was exchanged in.

/// `h2` is spoken from uplink's HTTP/2 phase on; `h3` is reserved for the
/// QUIC package, so a `switch` written today stays exhaustive then.
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
