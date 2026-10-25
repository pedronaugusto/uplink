//! HTTP/2 messages as fields (RFC 9113 §8): a header block checked as a
//! request, a response or a trailer section; fields written as HTTP/1.1
//! lines turned into a block; and a block kept in a buffer of its own.

const std = @import("std");
const hpack = @import("../hpack.zig");
const fields_mod = @import("../fields.zig");
const h1 = @import("../h1.zig");
const Method = @import("../Method.zig");
const Field = fields_mod.Field;

/// The fields that belong to one HTTP/1.1 connection, never sent over
/// HTTP/2 (§8.2.2); `te` is allowed with `trailers` alone.
const connection_own = [_][]const u8{ "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade" };

/// Whether `name` (lower case) with `value` may not go over HTTP/2.
pub fn connectionSpecific(name: []const u8, value: []const u8) bool {
    for (connection_own) |own| if (std.mem.eql(u8, name, own)) return true;
    return std.mem.eql(u8, name, "te") and !std.mem.eql(u8, value, "trailers");
}

/// A request's head, from its block.
pub const Request = struct {
    method: Method,
    /// Empty for a `CONNECT` without `:protocol`.
    path: []const u8,
    authority: ?[]const u8,
    scheme: ?[]const u8,
    /// RFC 8441's extended `CONNECT`.
    protocol: ?[]const u8,
    /// The regular fields, after the pseudo-fields.
    fields: []const Field,
    content_length: ?u64,
};

/// A response's final or interim head, from its block.
pub const Response = struct {
    status: u10,
    fields: []const Field,
    content_length: ?u64,
};

/// The regular fields of a block, checked: names in lower case and tokens,
/// none of a connection's own, values without controls or edge spaces,
/// every `content-length` the same number. Null for a malformed one.
fn checkRegular(fields: []const Field, content_length: *?u64) bool {
    for (fields) |f| {
        if (f.name.len == 0 or f.name[0] == ':') return false;
        for (f.name) |ch| if (ch >= 'A' and ch <= 'Z') return false;
        if (!fields_mod.isToken(f.name)) return false;
        if (connectionSpecific(f.name, f.value)) return false;
        if (fields_mod.hasControl(f.value) or (f.value.len != 0 and (f.value[0] == ' ' or f.value[f.value.len - 1] == ' '))) return false;
        if (std.mem.eql(u8, f.name, "content-length")) {
            const n = h1.parseLength(f.value) orelse return false;
            if (content_length.*) |was| if (was != n) return false;
            content_length.* = n;
        }
    }
    return true;
}

/// Where the pseudo-fields end: they come first, each in lower case.
fn pseudoEnd(fields: []const Field) usize {
    for (fields, 0..) |f, i| if (f.name.len == 0 or f.name[0] != ':') return i;
    return fields.len;
}

/// A request's block, checked as §8.3.1 asks: its pseudo-fields first,
/// each once, those a request needs. Null for a malformed one.
pub fn checkRequest(fields: []const Field) ?Request {
    var h: Request = .{ .method = undefined, .path = "", .authority = null, .scheme = null, .protocol = null, .fields = &.{}, .content_length = null };
    var method: ?[]const u8 = null;
    var path: ?[]const u8 = null;
    const end = pseudoEnd(fields);
    for (fields[0..end]) |f| {
        const slot: *?[]const u8 = if (std.mem.eql(u8, f.name, ":method")) &method else if (std.mem.eql(u8, f.name, ":path")) &path else if (std.mem.eql(u8, f.name, ":authority")) &h.authority else if (std.mem.eql(u8, f.name, ":scheme")) &h.scheme else if (std.mem.eql(u8, f.name, ":protocol")) &h.protocol else return null;
        if (slot.* != null) return null;
        slot.* = f.value;
    }
    h.fields = fields[end..];
    if (!checkRegular(h.fields, &h.content_length)) return null;
    const m = method orelse return null;
    if (!fields_mod.isToken(m)) return null;
    h.method = .{ .name = m };
    if (h.method.eql(.CONNECT) and h.protocol == null) {
        // CONNECT: an authority, no scheme or path.
        if (h.authority == null or h.scheme != null or path != null) return null;
        h.path = "";
    } else {
        h.path = path orelse return null;
        if (h.path.len == 0 or h.scheme == null) return null;
        if (h.protocol != null and !h.method.eql(.CONNECT)) return null;
    }
    return h;
}

/// A response's block, checked as §8.3.2 asks: `:status` alone, first,
/// three digits. Null for a malformed one.
pub fn checkResponse(fields: []const Field) ?Response {
    const end = pseudoEnd(fields);
    if (end != 1 or !std.mem.eql(u8, fields[0].name, ":status")) return null;
    const text = fields[0].value;
    if (text.len != 3) return null;
    for (text) |ch| if (!std.ascii.isDigit(ch)) return null;
    const status = std.fmt.parseUnsigned(u10, text, 10) catch return null;
    if (status < 100) return null;
    var r: Response = .{ .status = status, .fields = fields[1..], .content_length = null };
    if (!checkRegular(r.fields, &r.content_length)) return null;
    return r;
}

/// A trailer section's block: regular fields alone (§8.1).
pub fn checkTrailers(fields: []const Field) bool {
    var ignored: ?u64 = null;
    return checkRegular(fields, &ignored);
}

/// Add the fields of `lines`, each `Name: value\r\n` as an HTTP/1.1 head
/// is written, to `out` after its first `n`: names turned to lower case
/// in place, the fields of a connection's own left out. The count after.
pub fn appendLines(out: []hpack.Field, n: usize, lines: []u8) error{TooManyFields}!usize {
    var count = n;
    var at: usize = 0;
    while (at < lines.len) {
        const line_end = std.mem.findPos(u8, lines, at, "\r\n") orelse lines.len;
        const line = lines[at..line_end];
        at = @min(line_end + 2, lines.len);
        const colon = std.mem.findScalar(u8, line, ':') orelse continue;
        const name = line[0..colon];
        for (name) |*ch| ch.* = std.ascii.toLower(ch.*);
        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        if (connectionSpecific(name, value)) continue;
        if (count == out.len) return error.TooManyFields;
        out[count] = .{ .name = name, .value = value };
        count += 1;
    }
    return count;
}

/// The room `copy` needs for `fields`.
pub fn copySize(fields: []const hpack.Field) usize {
    var n: usize = fields.len * @sizeOf(Field) + @alignOf(Field);
    for (fields) |f| n += f.name.len + f.value.len;
    return n;
}

/// Copy `fields`, as decoded, into `buffer`, which is aligned for a
/// `Field`: their strings first, then the fields.
pub fn copy(buffer: []u8, fields: []const hpack.Field) error{NoSpaceLeft}![]Field {
    var bytes: usize = 0;
    for (fields) |f| bytes += f.name.len + f.value.len;
    const fields_at = std.mem.alignForward(usize, bytes, @alignOf(Field));
    if (fields_at + fields.len * @sizeOf(Field) > buffer.len) return error.NoSpaceLeft;
    std.debug.assert(std.mem.isAligned(@intFromPtr(buffer.ptr), @alignOf(Field))); // safe: the address is only tested for alignment
    const out: [*]Field = @ptrCast(@alignCast(buffer.ptr + fields_at)); // aegis: internal: `buffer` is aligned for a Field (asserted) and so is `fields_at`, inside it
    var at: usize = 0;
    for (fields, 0..) |f, i| {
        @memcpy(buffer[at..][0..f.name.len], f.name);
        @memcpy(buffer[at + f.name.len ..][0..f.value.len], f.value);
        out[i] = .{ .name = buffer[at..][0..f.name.len], .value = buffer[at + f.name.len ..][0..f.value.len] };
        at += f.name.len + f.value.len;
    }
    return out[0..fields.len];
}

const testing = std.testing;

test "a request block is checked as RFC 9113 asks" {
    const ok = [_]Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = ":path", .value = "/a" },
        .{ .name = "accept", .value = "*/*" },
        .{ .name = "te", .value = "trailers" },
    };
    const r = checkRequest(&ok).?;
    try testing.expectEqualStrings("/a", r.path);
    try testing.expectEqual(2, r.fields.len);
    const bad = [_][]const Field{
        &.{ .{ .name = ":method", .value = "GET" }, .{ .name = ":scheme", .value = "https" } },
        &.{ .{ .name = ":method", .value = "GET" }, .{ .name = ":scheme", .value = "https" }, .{ .name = ":path", .value = "/" }, .{ .name = "Accept", .value = "x" } },
        &.{ .{ .name = ":method", .value = "GET" }, .{ .name = ":scheme", .value = "https" }, .{ .name = ":path", .value = "/" }, .{ .name = "connection", .value = "close" } },
        &.{ .{ .name = ":method", .value = "GET" }, .{ .name = ":scheme", .value = "https" }, .{ .name = ":path", .value = "/" }, .{ .name = "te", .value = "gzip" } },
        &.{ .{ .name = ":method", .value = "GET" }, .{ .name = "a", .value = "b" }, .{ .name = ":scheme", .value = "https" }, .{ .name = ":path", .value = "/" } },
        &.{ .{ .name = ":method", .value = "GET" }, .{ .name = ":scheme", .value = "https" }, .{ .name = ":path", .value = "/" }, .{ .name = ":path", .value = "/" } },
        &.{ .{ .name = ":method", .value = "CONNECT" }, .{ .name = ":authority", .value = "a:1" }, .{ .name = ":path", .value = "/" } },
        &.{ .{ .name = ":method", .value = "GET" }, .{ .name = ":scheme", .value = "https" }, .{ .name = ":path", .value = "/" }, .{ .name = "content-length", .value = "1" }, .{ .name = "content-length", .value = "2" } },
    };
    for (bad) |b| try testing.expectEqual(null, checkRequest(b));
}

test "a response block has its status alone among the pseudo-fields" {
    const ok = [_]Field{ .{ .name = ":status", .value = "204" }, .{ .name = "content-length", .value = "0" } };
    const r = checkResponse(&ok).?;
    try testing.expectEqual(204, r.status);
    try testing.expectEqual(0, r.content_length.?);
    const bad = [_][]const Field{
        &.{.{ .name = "a", .value = "b" }},
        &.{.{ .name = ":status", .value = "20" }},
        &.{.{ .name = ":status", .value = "2x0" }},
        &.{ .{ .name = ":status", .value = "200" }, .{ .name = ":path", .value = "/" } },
        &.{ .{ .name = ":status", .value = "200" }, .{ .name = "upgrade", .value = "h2c" } },
    };
    for (bad) |b| try testing.expectEqual(null, checkResponse(b));
    try testing.expect(!checkTrailers(&.{.{ .name = ":status", .value = "200" }}));
    try testing.expect(checkTrailers(&.{.{ .name = "grpc-status", .value = "0" }}));
}

test "lines become fields, lower case, a connection's own left out" {
    var text = "Accept: */*\r\nConnection: keep-alive\r\nX-Two: a b\r\nTE: trailers\r\n".*;
    var out: [8]hpack.Field = undefined;
    const n = try appendLines(&out, 0, &text);
    try testing.expectEqual(3, n);
    try testing.expectEqualStrings("accept", out[0].name);
    try testing.expectEqualStrings("x-two", out[1].name);
    try testing.expectEqualStrings("a b", out[1].value);
    try testing.expectEqualStrings("te", out[2].name);
    try testing.expectError(error.TooManyFields, appendLines(out[0..1], 0, &text));
}

test "a block is copied into a buffer of its own" {
    var buffer: [256]u8 align(@alignOf(Field)) = undefined;
    const kept = try copy(&buffer, &.{ .{ .name = ":status", .value = "200" }, .{ .name = "a", .value = "b" } });
    try testing.expectEqualStrings(":status", kept[0].name);
    try testing.expectEqualStrings("b", kept[1].value);
    var small: [8]u8 align(@alignOf(Field)) = undefined;
    try testing.expectError(error.NoSpaceLeft, copy(&small, &.{.{ .name = "abc", .value = "def" }}));
}
