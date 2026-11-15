//! A request method: any token (RFC 9110 §9). The nine standard methods are
//! constants, named in Zig's case for a value and spelled on the wire as
//! RFC 9110 spells them (`get` sends `GET`); an extension such as
//! `PROPFIND` or `MKCOL` is made with `parse`. Methods are compared as
//! written: RFC 9110 makes them case-sensitive.

const std = @import("std");
const fields = @import("fields.zig");

const Method = @This();

/// The method's name, as sent on the request line.
name: []const u8,

pub const get: Method = .{ .name = "GET" };
pub const head: Method = .{ .name = "HEAD" };
pub const post: Method = .{ .name = "POST" };
pub const put: Method = .{ .name = "PUT" };
pub const delete: Method = .{ .name = "DELETE" };
pub const connect: Method = .{ .name = "CONNECT" };
pub const options: Method = .{ .name = "OPTIONS" };
pub const trace: Method = .{ .name = "TRACE" };
pub const patch: Method = .{ .name = "PATCH" };

/// Errors from `parse`.
pub const ParseError = error{
    /// Empty, or a character a token does not allow.
    InvalidMethod,
};

/// The method named `token`, which must be a token. The slice is kept, not
/// copied.
pub fn parse(token: []const u8) ParseError!Method {
    if (!fields.isToken(token)) return error.InvalidMethod;
    return .{ .name = token };
}

/// Whether two methods are the same; case matters.
pub fn eql(a: Method, b: Method) bool {
    return std.mem.eql(u8, a.name, b.name);
}

/// Whether the method is safe (RFC 9110 §9.2.1): it asks for nothing to
/// change.
pub fn safe(m: Method) bool {
    return m.eql(get) or m.eql(head) or m.eql(options) or m.eql(trace);
}

/// Whether the method is idempotent (RFC 9110 §9.2.2): sending it twice is
/// sending it once, so a request lost to a broken connection may be sent
/// again.
pub fn idempotent(m: Method) bool {
    return m.safe() or m.eql(put) or m.eql(delete);
}

/// Whether a response to this method never has a body.
pub fn bodiless(m: Method) bool {
    return m.eql(head);
}

const testing = std.testing;

test "methods are tokens, compared with case, and classed as RFC 9110 classes them" {
    try testing.expect((try parse("PROPFIND")).eql(.{ .name = "PROPFIND" }));
    try testing.expectError(error.InvalidMethod, parse(""));
    try testing.expectError(error.InvalidMethod, parse("GE T"));
    try testing.expectError(error.InvalidMethod, parse("GET\r\n"));
    try testing.expect(!get.eql(try parse("get")));
    try testing.expect(get.safe() and head.safe() and options.safe() and trace.safe());
    try testing.expect(!post.safe() and !put.safe());
    try testing.expect(put.idempotent() and delete.idempotent() and get.idempotent());
    try testing.expect(!post.idempotent() and !patch.idempotent() and !connect.idempotent());
    try testing.expect(!(try parse("PROPFIND")).idempotent());
}
