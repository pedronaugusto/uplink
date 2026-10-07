//! The wire: HTTP's message syntax and the formats around it, sans I/O.
//! Nothing here takes an `Io`, opens a socket or allocates per message;
//! these are the codecs the client is built from, public for anyone
//! building a stack of their own.

/// HTTP/1.1 message syntax: heads, framing, chunked bodies.
pub const h1 = @import("wire/h1.zig");
/// Header fields: names, values, lists, and the view a head is read through.
pub const fields = @import("wire/fields.zig");
/// Content and transfer codings.
pub const coding = @import("wire/coding.zig");
/// Authentication challenges and their Basic and Digest answers.
pub const auth = @import("wire/auth.zig");
/// SOCKS4, 4a, 5 and 5h CONNECT negotiation.
pub const socks = @import("wire/socks.zig");
/// The parts of an `http` or `https` URL a request is made from.
pub const url = @import("wire/url.zig");
/// A request method: any token.
pub const Method = @import("wire/Method.zig");
/// The HTTP version a message was exchanged in.
pub const Version = @import("wire/version.zig").Version;

test {
    _ = h1;
    _ = fields;
    _ = coding;
    _ = auth;
    _ = socks;
    _ = Method;
    _ = url;
}
