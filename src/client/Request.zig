//! A request: a value that owns nothing. Everything it points at must live
//! until the request's response has been returned, or, for a body the
//! caller writes, until `Outgoing.finish` returns.

const std = @import("std");
const Io = std.Io;
const Method = @import("../wire/Method.zig");
const Diagnostics = @import("../transport/Diagnostics.zig");
const policy = @import("policy.zig");

const Request = @This();

method: Method = .GET,
/// An `http` or `https` URL. A space, a control character or a user and
/// password in it are refused.
url: []const u8,
/// Sent after uplink's own fields, in their order and case. `Host`,
/// `Content-Length` and `Transfer-Encoding` are uplink's to write and are
/// refused here. Every name and value is checked before a byte is sent.
/// An `Authorization` or `Cookie` given here is the caller's: the client
/// adds none of its own, and drops these, with `Proxy-Authorization`, when
/// a redirect leaves the origin.
headers: []const std.http.Header = &.{},
body: Body = .none,
/// The whole request — waiting for a connection, connecting, every
/// redirect and retry, the response's head — must be done by then, and
/// each read of its body too.
timeout: Io.Timeout = .none,
/// The client's redirect policy, for this request.
redirects: ?policy.Redirects = null,
/// The client's retry policy, for this request.
retries: ?policy.Retries = null,
/// Send the head with `Expect: 100-continue` and wait, up to the client's
/// `expect_continue_timeout`, for the server's go-ahead before the body,
/// so a refusal costs no upload. Only with a body.
expect_continue: bool = false,
/// Credentials sent from the first attempt, for this origin only: no
/// challenge needed, none answered.
auth: ?Auth = null,
/// Where a failure's details go.
diagnostics: ?*Diagnostics = null,

/// What follows the head.
pub const Body = union(enum) {
    /// Nothing. `POST`, `PUT` and `PATCH` say `Content-Length: 0`.
    none,
    /// These bytes, with their length; sent again for a redirect or retry
    /// that needs the body.
    bytes: []const u8,
    /// What `reader` gives: `length` bytes with that `Content-Length`, or
    /// to its end in chunks. Read once: a redirect or retry that would send
    /// it again fails with `BodyNotReplayable`.
    reader: struct { reader: *Io.Reader, length: ?u64 = null },
    /// `Client.begin` only: the caller writes it through `Outgoing.writer`,
    /// `length` bytes exactly, or in chunks.
    streamed: struct { length: ?u64 = null },

    /// Whether it can be sent more than once.
    pub fn replayable(b: Body) bool {
        return switch (b) {
            .none, .bytes => true,
            .reader, .streamed => false,
        };
    }
};

/// Credentials sent with the request from the start.
pub const Auth = union(enum) {
    basic: struct { user: []const u8, password: []const u8 },
    /// A token, sent as `Bearer`.
    bearer: []const u8,
};
