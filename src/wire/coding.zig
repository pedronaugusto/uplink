//! Content and transfer codings (RFC 9110 §8.4, RFC 9112 §7): the names a
//! body may be compressed under, and the order they come off in.

const std = @import("std");
const Headers = @import("fields.zig").Headers;
const ListIterator = @import("fields.zig").ListIterator;

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

/// The coding to answer with: of `offered`, in the server's order of
/// preference, the one `accept` (an `Accept-Encoding` value) rates highest
/// above zero (RFC 9110 §12.5.3), `*` rating any coding it does not name;
/// null for none, the body sent as it is. With no `Accept-Encoding` at all
/// the request accepts any coding, but a server answering one that did not
/// ask has no reason to: so null too.
pub fn negotiate(accept: ?[]const u8, offered: []const ContentCoding) ?ContentCoding {
    const value = accept orelse return null;
    var best: ?ContentCoding = null;
    var best_q: u16 = 0;
    for (offered) |coding| {
        const q = rating(value, coding);
        if (q > best_q) {
            best = coding;
            best_q = q;
        }
    }
    return best;
}

/// The quality `accept` gives `coding`, in thousandths.
fn rating(accept: []const u8, coding: ContentCoding) u16 {
    var star: ?u16 = null;
    var it: ListIterator = .{ .text = accept };
    while (it.next()) |element| {
        const semi = std.mem.findScalar(u8, element, ';');
        const name = std.mem.trim(u8, element[0 .. semi orelse element.len], " \t");
        const q = if (semi) |s| quality(element[s + 1 ..]) else 1000;
        if (std.mem.eql(u8, name, "*")) {
            star = q;
        } else if (ContentCoding.parse(name)) |c| if (c == coding) return q;
    }
    return star orelse 0;
}

/// A `q=` weight in thousandths; one that does not parse is 0.
fn quality(params: []const u8) u16 {
    var it = std.mem.splitScalar(u8, params, ';');
    while (it.next()) |raw| {
        const p = std.mem.trim(u8, raw, " \t");
        if (p.len < 2 or (p[0] != 'q' and p[0] != 'Q') or p[1] != '=') continue;
        const v = p[2..];
        if (v.len == 0 or v.len > 5) return 0;
        if (v[0] == '1') return 1000;
        if (v[0] != '0') return 0;
        if (v.len == 1) return 0;
        if (v[1] != '.') return 0;
        var n: u16 = 0;
        var scale: u16 = 100;
        for (v[2..]) |d| {
            if (d < '0' or d > '9') return 0;
            n += (d - '0') * scale;
            scale /= 10;
        }
        return n;
    }
    return 1000;
}

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

test "a coding is chosen by the client's weights, then the server's order" {
    const offered: []const ContentCoding = &.{ .zstd, .gzip };
    try testing.expectEqual(ContentCoding.zstd, negotiate("gzip, deflate, br, zstd", offered).?);
    try testing.expectEqual(ContentCoding.gzip, negotiate("gzip;q=1.0, zstd;q=0.5", offered).?);
    try testing.expectEqual(ContentCoding.gzip, negotiate("zstd;q=0, *", offered).?);
    try testing.expectEqual(null, negotiate("br", offered));
    try testing.expectEqual(null, negotiate("gzip;q=0, zstd;q=0.000", offered));
    try testing.expectEqual(null, negotiate(null, offered));
    try testing.expectEqual(ContentCoding.zstd, negotiate("*;q=0.1", offered).?);
    try testing.expectEqual(ContentCoding.gzip, negotiate("x-gzip", offered).?);
}
