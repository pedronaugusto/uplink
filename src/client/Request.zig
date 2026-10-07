//! A request: a value that owns nothing. Everything it points at must live
//! until the exchange's head has been read.

const std = @import("std");
const Io = std.Io;
const Method = @import("../wire/Method.zig");
const Diagnostics = @import("../transport/Diagnostics.zig");

const Request = @This();

method: Method = .GET,
/// An `http` or `https` URL. A space, a control character or a user and
/// password in it are refused.
url: []const u8,
/// Sent after uplink's own fields, in their order and case. `Host`,
/// `Content-Length` and `Transfer-Encoding` are uplink's to write and are
/// refused here. Every name and value is checked before a byte is sent.
headers: []const std.http.Header = &.{},
body: Body = .none,
/// Where a failure's details go.
diagnostics: ?*Diagnostics = null,

/// What follows the head.
pub const Body = union(enum) {
    /// Nothing. `POST`, `PUT` and `PATCH` say `Content-Length: 0`.
    none,
    /// These bytes, with their length; sent again on a stale connection
    /// when the method is idempotent.
    bytes: []const u8,
    /// What `reader` gives: `length` bytes with that `Content-Length`, or
    /// to its end in chunks. Read once; never sent again.
    reader: struct { reader: *Io.Reader, length: ?u64 = null },
    /// `Client.begin` only: the caller writes it through `Outgoing.writer`,
    /// `length` bytes exactly, or in chunks.
    streamed: struct { length: ?u64 = null },
};
