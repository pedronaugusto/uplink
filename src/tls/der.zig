//! DER, as far as private keys need it: elements read with every length
//! checked against what is there, so a damaged key file is refused rather
//! than read past its end.

const std = @import("std");

/// A key file that is not the DER it claims to be.
pub const Error = error{MalformedKey};

/// Tags this reader names.
pub const Tag = struct {
    /// INTEGER.
    pub const integer: u8 = 0x02;
    /// BIT STRING.
    pub const bit_string: u8 = 0x03;
    /// OCTET STRING.
    pub const octet_string: u8 = 0x04;
    /// NULL.
    pub const null_value: u8 = 0x05;
    /// OBJECT IDENTIFIER.
    pub const oid: u8 = 0x06;
    /// SEQUENCE, constructed.
    pub const sequence: u8 = 0x30;
    /// `[0]`, constructed.
    pub const context0: u8 = 0xa0;
    /// `[1]`, constructed.
    pub const context1: u8 = 0xa1;
};

/// One element: its tag and its contents.
pub const Element = struct {
    tag: u8,
    body: []const u8,
};

/// Elements one after another.
pub const Reader = struct {
    bytes: []const u8,
    at: usize = 0,

    /// Whether every element has been read.
    pub fn done(r: *const Reader) bool {
        return r.at >= r.bytes.len;
    }

    /// The next element.
    pub fn next(r: *Reader) Error!Element {
        if (r.at + 2 > r.bytes.len) return error.MalformedKey;
        const tag = r.bytes[r.at];
        var len: usize = r.bytes[r.at + 1];
        r.at += 2;
        if (len & 0x80 != 0) {
            const n = len & 0x7f;
            if (n == 0 or n > 4 or r.at + n > r.bytes.len) return error.MalformedKey;
            len = 0;
            for (r.bytes[r.at..][0..n]) |b| len = (len << 8) | b;
            r.at += n;
        }
        if (len > r.bytes.len - r.at) return error.MalformedKey;
        const body = r.bytes[r.at..][0..len];
        r.at += len;
        return .{ .tag = tag, .body = body };
    }

    /// The next element, which must have `tag`: its contents.
    pub fn expect(r: *Reader, tag: u8) Error![]const u8 {
        const e = try r.next();
        if (e.tag != tag) return error.MalformedKey;
        return e.body;
    }

    /// The next element when it has `tag`, else nothing is taken.
    pub fn optional(r: *Reader, tag: u8) Error!?[]const u8 {
        if (r.done() or r.bytes[r.at] != tag) return null;
        const content = try r.expect(tag);
        return content;
    }
};

/// An unsigned integer's bytes, without the leading zero DER puts before a
/// high bit.
pub fn unsigned(body: []const u8) Error![]const u8 {
    if (body.len == 0) return error.MalformedKey;
    var b = body;
    while (b.len > 1 and b[0] == 0) b = b[1..];
    return b;
}

/// A small integer.
pub fn small(body: []const u8) Error!u64 {
    const b = try unsigned(body);
    if (b.len > 8) return error.MalformedKey;
    var v: u64 = 0;
    for (b) |c| v = (v << 8) | c;
    return v;
}

test "an element longer than what is there is refused" {
    var r: Reader = .{ .bytes = &.{ 0x30, 0x05, 0x02, 0x01 } };
    try std.testing.expectError(error.MalformedKey, r.next());
    var long: Reader = .{ .bytes = &.{ 0x04, 0x82, 0x00 } };
    try std.testing.expectError(error.MalformedKey, long.next());
    var fine: Reader = .{ .bytes = &.{ 0x02, 0x02, 0x00, 0x80 } };
    try std.testing.expectEqualSlices(u8, &.{0x80}, try unsigned(try fine.expect(Tag.integer)));
}
