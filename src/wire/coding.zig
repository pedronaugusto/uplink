//! Content and transfer codings (RFC 9110 §8.4, RFC 9112 §7): the names a
//! body may be compressed under, and the order they come off in.

const std = @import("std");
const Headers = @import("fields.zig").Headers;

/// A coding a body may carry. `br` and `zstd` are named so a response can
/// say what it holds; whether a client decodes them is its own choice.
pub const ContentCoding = enum {
    identity,
    gzip,
    deflate,
    zstd,
    br,

    /// The coding `name` names, without case: `x-gzip` is `gzip` (RFC 9110
    /// §8.4.1.3). Parameters after `;` are ignored.
    pub fn parse(element: []const u8) ?ContentCoding {
        const end = std.mem.findScalar(u8, element, ';') orelse element.len;
        const name = std.mem.trimEnd(u8, element[0..end], " \t");
        const table = [_]struct { []const u8, ContentCoding }{
            .{ "identity", .identity }, .{ "gzip", .gzip }, .{ "x-gzip", .gzip },
            .{ "deflate", .deflate },   .{ "zstd", .zstd }, .{ "br", .br },
        };
        for (table) |entry| if (std.ascii.eqlIgnoreCase(name, entry[0])) return entry[1];
        return null;
    }
};

/// The codings a body was put under, in the order they were applied:
/// transfer codings before `chunked`, then content codings. `identity` is
/// left out. At most `max` of them.
pub const Codings = struct {
    items: [max]ContentCoding = undefined,
    len: u8 = 0,

    pub const max = 4;

    /// Why a body's codings cannot be read.
    pub const Error = error{
        /// A coding with no name uplink knows.
        UnknownCoding,
        /// More than `max` codings.
        TooManyCodings,
    };

    /// The codings `headers` name: `Transfer-Encoding` without its final
    /// `chunked`, then `Content-Encoding`.
    pub fn of(headers: *const Headers) Error!Codings {
        var c: Codings = .{};
        var te = headers.values("transfer-encoding");
        while (te.next()) |element| {
            const name_end = std.mem.findScalar(u8, element, ';') orelse element.len;
            if (std.ascii.eqlIgnoreCase(std.mem.trimEnd(u8, element[0..name_end], " \t"), "chunked")) continue;
            try c.add(element);
        }
        var ce = headers.values("content-encoding");
        while (ce.next()) |element| try c.add(element);
        return c;
    }

    fn add(c: *Codings, element: []const u8) Error!void {
        const coding = ContentCoding.parse(element) orelse return error.UnknownCoding;
        if (coding == .identity) return;
        if (c.len == max) return error.TooManyCodings;
        c.items[c.len] = coding;
        c.len += 1;
    }

    /// The codings, first applied first.
    pub fn slice(c: *const Codings) []const ContentCoding {
        return c.items[0..c.len];
    }
};

const testing = std.testing;
const Field = @import("fields.zig").Field;

test "codings are read in the order they were applied, identity left out" {
    const fields = [_]Field{
        .{ .name = "Transfer-Encoding", .value = "gzip, chunked" },
        .{ .name = "Content-Encoding", .value = "identity, X-GZIP;q=1" },
    };
    const h: Headers = .init(&fields);
    const c = try Codings.of(&h);
    try testing.expectEqualSlices(ContentCoding, &.{ .gzip, .gzip }, c.slice());
    const unknown = [_]Field{.{ .name = "Content-Encoding", .value = "snappy" }};
    try testing.expectError(error.UnknownCoding, Codings.of(&Headers.init(&unknown)));
    const many = [_]Field{.{ .name = "Content-Encoding", .value = "gzip, br, zstd, deflate, gzip" }};
    try testing.expectError(error.TooManyCodings, Codings.of(&Headers.init(&many)));
    try testing.expectEqual(ContentCoding.br, ContentCoding.parse("BR").?);
    try testing.expectEqual(null, ContentCoding.parse("gzip2"));
}
