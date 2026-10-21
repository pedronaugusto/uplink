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
/// AWS Signature Version 4: a request signed, or a URL presigned, for S3
/// and S3-compatible storage.
pub const sigv4 = @import("wire/sigv4.zig");
/// SOCKS4, 4a, 5 and 5h CONNECT negotiation.
pub const socks = @import("wire/socks.zig");
/// The parts of an `http` or `https` URL a request is made from, and
/// references resolved against one.
pub const url = @import("wire/url.zig");
/// HTTP dates: read in their three forms, written in one.
pub const date = @import("wire/date.zig");
/// `Cache-Control` read, and how long a response stays fresh.
pub const cache = @import("wire/cache.zig");
/// `Set-Cookie` values, cookie dates, and the domain and path rules.
pub const cookie = @import("wire/cookie.zig");
/// Server-Sent Events, read and written.
pub const sse = @import("wire/sse.zig");
/// `application/x-www-form-urlencoded` bodies.
pub const form = @import("wire/form.zig");
/// `multipart/form-data` bodies, written.
pub const multipart = @import("wire/multipart.zig");
/// DNS messages, their records and `resolv.conf`.
pub const dns = @import("wire/dns.zig");
/// `.netrc`: a user's logins per machine.
pub const netrc = @import("wire/netrc.zig");
/// Byte ranges: `Range` read, `Content-Range` written.
pub const range = @import("wire/range.zig");
/// HTTP/2's frames, settings and error codes.
pub const h2 = @import("wire/h2.zig");
/// HPACK, HTTP/2's header compression.
pub const hpack = @import("wire/hpack.zig");
/// The WebSocket protocol's frames, keys, close codes and extension.
pub const ws = @import("wire/ws.zig");
/// A request method: any token.
pub const Method = @import("wire/Method.zig");
/// The HTTP version a message was exchanged in.
pub const Version = @import("wire/version.zig").Version;

test {
    _ = h1;
    _ = fields;
    _ = coding;
    _ = auth;
    _ = sigv4;
    _ = socks;
    _ = Method;
    _ = url;
    _ = date;
    _ = cache;
    _ = cookie;
    _ = sse;
    _ = form;
    _ = multipart;
    _ = range;
    _ = netrc;
    _ = dns;
    _ = ws;
    _ = hpack;
    _ = h2;
}
