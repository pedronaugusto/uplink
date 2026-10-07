//! A request method: any token (RFC 9110 §9). The nine standard methods are
//! constants; an extension such as `PROPFIND` or `MKCOL` is made with
//! `parse`. Methods are compared as written: RFC 9110 makes them
//! case-sensitive.

const std = @import("std");
const fields = @import("fields.zig");

const Method = @This();

/// The method's name, as sent on the request line.
name: []const u8,

// ziglint-ignore: Z006 the method as RFC 9110 spells it, which is how a caller writes it
pub const GET: Method = .{ .name = "GET" };
// ziglint-ignore: Z006 the method as RFC 9110 spells it, which is how a caller writes it
pub const HEAD: Method = .{ .name = "HEAD" };
// ziglint-ignore: Z006 the method as RFC 9110 spells it, which is how a caller writes it
pub const POST: Method = .{ .name = "POST" };
// ziglint-ignore: Z006 the method as RFC 9110 spells it, which is how a caller writes it
pub const PUT: Method = .{ .name = "PUT" };
// ziglint-ignore: Z006 the method as RFC 9110 spells it, which is how a caller writes it
pub const DELETE: Method = .{ .name = "DELETE" };
// ziglint-ignore: Z006 the method as RFC 9110 spells it, which is how a caller writes it
pub const CONNECT: Method = .{ .name = "CONNECT" };
// ziglint-ignore: Z006 the method as RFC 9110 spells it, which is how a caller writes it
pub const OPTIONS: Method = .{ .name = "OPTIONS" };
// ziglint-ignore: Z006 the method as RFC 9110 spells it, which is how a caller writes it
pub const TRACE: Method = .{ .name = "TRACE" };
// ziglint-ignore: Z006 the method as RFC 9110 spells it, which is how a caller writes it
pub const PATCH: Method = .{ .name = "PATCH" };

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
    return m.eql(GET) or m.eql(HEAD) or m.eql(OPTIONS) or m.eql(TRACE);
}

/// Whether the method is idempotent (RFC 9110 §9.2.2): sending it twice is
/// sending it once, so a request lost to a broken connection may be sent
/// again.
pub fn idempotent(m: Method) bool {
    return m.safe() or m.eql(PUT) or m.eql(DELETE);
}

/// Whether a response to this method never has a body.
pub fn bodiless(m: Method) bool {
    return m.eql(HEAD);
}

const testing = std.testing;

test "methods are tokens, compared with case, and classed as RFC 9110 classes them" {
    try testing.expect((try parse("PROPFIND")).eql(.{ .name = "PROPFIND" }));
    try testing.expectError(error.InvalidMethod, parse(""));
    try testing.expectError(error.InvalidMethod, parse("GE T"));
    try testing.expectError(error.InvalidMethod, parse("GET\r\n"));
    try testing.expect(!GET.eql(try parse("get")));
    try testing.expect(GET.safe() and HEAD.safe() and OPTIONS.safe() and TRACE.safe());
    try testing.expect(!POST.safe() and !PUT.safe());
    try testing.expect(PUT.idempotent() and DELETE.idempotent() and GET.idempotent());
    try testing.expect(!POST.idempotent() and !PATCH.idempotent() and !CONNECT.idempotent());
    try testing.expect(!(try parse("PROPFIND")).idempotent());
}
