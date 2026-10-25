//! Files from a directory, as Go's `FileServer` and tower-http's
//! `ServeDir` serve them: `GET` and `HEAD`, a `Content-Type` from the
//! name, `Last-Modified` and a strong `ETag`, the conditional requests of
//! RFC 9110 §13 answered in their order (`If-Match`, `If-Unmodified-Since`,
//! `If-None-Match`, `If-Modified-Since`, `If-Range`), byte ranges (one, or
//! several as `multipart/byteranges`), a directory's index file, and a
//! directory named without its `/` redirected to it.
//!
//! Nothing outside the root is reached: a path with a `..` segment, a
//! backslash or a NUL is refused before the directory is asked, and every
//! open is relative to the root. A path is matched with its escapes undone.

const std = @import("std");
const aegis = @import("aegis");
const Io = std.Io;
const wire = @import("uplink.wire");
const range = wire.range;
const Request = @import("Request.zig");
const Response = @import("Response.zig");
const Handler = @import("Handler.zig");
const Router = @import("Router.zig");
const Pattern = @import("Pattern.zig");

const Files = @This();

/// The directory served; the caller keeps it open.
root: Io.Dir,
options: Options,
/// Private: the file server as a handler.
handling: Handler = .{ .handleFn = handled },

pub const Options = struct {
    /// The file a directory is answered with; null answers a directory 404.
    index: ?[]const u8 = "index.html",
    /// The start of the request path that names the root, `/static/` for a
    /// directory mounted there; the rest names the file.
    prefix: []const u8 = "/",
    /// Sent as `Cache-Control` with every file.
    cache_control: ?[]const u8 = null,
};

/// Files under `root`.
pub fn init(root: Io.Dir, options: Options) Files {
    return .{ .root = root, .options = options };
}

/// The file server as the server's handler.
pub fn handler(f: *const Files) *const Handler {
    return &f.handling;
}

fn handled(h: *const Handler, io: Io, request: *Request, response: *Response) anyerror!void {
    const f: *const Files = @alignCast(@fieldParentPtr("handling", h));
    return f.serve(io, request, response);
}

/// Answer `request` from the directory.
pub fn serve(f: *const Files, io: Io, request: *Request, response: *Response) anyerror!void {
    if (!request.method.eql(.GET) and !request.method.eql(.HEAD)) {
        try response.header("Allow", "GET, HEAD");
        return Router.plain(io, response, .method_not_allowed, "method not allowed\n");
    }
    const path = request.path;
    if (!std.mem.startsWith(u8, path, f.options.prefix)) return Router.plain(io, response, .not_found, "not found\n");
    const rest = path[f.options.prefix.len..];
    const scratch = try request.scratchBuffer(io, rest.len + 1);
    const name = Pattern.unescape(rest, scratch) orelse return Router.plain(io, response, .bad_request, "bad request\n");
    if (!safe(name)) return Router.plain(io, response, .not_found, "not found\n");
    const relative = if (name.len == 0) "." else std.mem.trimEnd(u8, name, "/");
    const stat = f.root.statFile(io, if (relative.len == 0) "." else relative, .{}) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return Router.plain(io, response, .not_found, "not found\n"),
    };
    if (stat.kind == .directory) {
        if (path[path.len - 1] != '/') return redirectTo(io, request, response, "/");
        const index = f.options.index orelse return Router.plain(io, response, .not_found, "not found\n");
        var joined: [4096]u8 = undefined;
        const index_path = std.mem.print(&joined, "{s}/{s}", .{ relative, index }) catch return Router.plain(io, response, .not_found, "not found\n");
        return f.serveFile(io, request, response, index_path);
    }
    if (f.options.index) |index| if (std.mem.endsWith(u8, path, index) and path.len > index.len and path[path.len - index.len - 1] == '/')
        return redirectTo(io, request, response, "./");
    if (stat.kind != .file or path[path.len - 1] == '/') return Router.plain(io, response, .not_found, "not found\n");
    return f.serveFile(io, request, response, relative);
}

/// Whether `name` stays under the root: no `..` segment, no backslash, no
/// NUL, not absolute.
fn safe(name: []const u8) bool {
    if (std.mem.findAny(u8, name, "\\\x00") != null) return false;
    if (name.len != 0 and name[0] == '/') return false;
    var it = std.mem.splitScalar(u8, name, '/');
    while (it.next()) |seg| if (std.mem.eql(u8, seg, "..")) return false;
    return true;
}

fn redirectTo(io: Io, request: *const Request, response: *Response, suffix: []const u8) anyerror!void {
    var buf: [8192]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    if (std.mem.eql(u8, suffix, "./")) {
        // `/dir/index.html` to `/dir/`.
        const cut = std.mem.findScalarLast(u8, request.path, '/').?;
        try w.writeAll(request.path[0 .. cut + 1]);
    } else {
        try w.writeAll(request.path);
        try w.writeAll(suffix);
    }
    if (request.query) |q| try w.print("?{s}", .{q});
    response.status = .moved_permanently;
    try response.header("Location", w.buffered());
    return Router.plain(io, response, .moved_permanently, "");
}

/// A file's modification time to the nanosecond, for its entity tag.
const Mtime = aegis.units.Instant(.real, .nanosecond, i96);

fn serveFile(f: *const Files, io: Io, request: *Request, response: *Response, relative: []const u8) anyerror!void {
    const file = f.root.openFile(io, relative, .{}) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return Router.plain(io, response, .not_found, "not found\n"),
    };
    defer file.close(io);
    const stat = try file.stat(io);
    if (stat.kind != .file) return Router.plain(io, response, .not_found, "not found\n");
    const size = stat.size;
    // The last whole second, as HTTP dates name it; a file a calendar can
    // no longer hold is at its end.
    const modified = wire.date.Second.fromTimestamp(stat.mtime, .down) catch wire.date.Second.fromRaw(std.math.maxInt(i64));
    var etag_buf: [48]u8 = undefined;
    const etag = try std.mem.print(&etag_buf, "\"{x}-{x}\"", .{ size, @as(u96, @bitCast(Mtime.fromTimestamp(stat.mtime, .exact).raw())) });
    var date_buf: [wire.date.formatted_len]u8 = undefined;
    const last_modified = wire.date.format(modified, &date_buf);

    // RFC 9110 §13.2.2, in its order.
    const h = &request.headers;
    if (h.get("if-match")) |v| {
        if (!matchesEtag(v, etag, .strong)) return precondition(io, response);
    } else if (h.get("if-unmodified-since")) |v| {
        if (wire.date.parse(v)) |since| if (modified.compare(since) == .gt) return precondition(io, response);
    }
    try response.header("ETag", etag);
    try response.header("Last-Modified", last_modified);
    try response.header("Accept-Ranges", "bytes");
    if (f.options.cache_control) |cc| try response.header("Cache-Control", cc);
    if (h.get("if-none-match")) |v| {
        if (matchesEtag(v, etag, .weak)) return notModified(io, response);
    } else if (h.get("if-modified-since")) |v| {
        if (wire.date.parse(v)) |since| if (modified.compare(since) != .gt) return notModified(io, response);
    }
    const content_type = typeOf(relative);
    var spans: [range.max_ranges]range.Span = undefined;
    const ranges: range.Ranges = if (h.get("range")) |v| ranges: {
        if (h.get("if-range")) |cond| if (!ifRange(cond, etag, modified)) break :ranges .whole;
        break :ranges range.parse(v, size, &spans);
    } else .whole;
    switch (ranges) {
        .whole => {
            try response.header("Content-Type", content_type);
            try response.setLength(size);
            return copy(io, response, file, 0, size);
        },
        .unsatisfiable => {
            var cr: [64]u8 = undefined;
            try response.header("Content-Range", try std.mem.print(&cr, "bytes */{d}", .{size}));
            return Router.plain(io, response, .range_not_satisfiable, "");
        },
        .some => |list| {
            response.status = .partial_content;
            if (list.len == 1) {
                var cr: [96]u8 = undefined;
                var w: Io.Writer = .fixed(&cr);
                try range.writeContentRange(&w, list[0], size);
                try response.header("Content-Range", w.buffered());
                try response.header("Content-Type", content_type);
                try response.setLength(list[0].len());
                return copy(io, response, file, list[0].first, list[0].len());
            }
            return multipart(io, response, file, list, size, content_type);
        },
    }
}

/// Several ranges as `multipart/byteranges` (RFC 9110 §14.6), with its
/// length counted before the body is sent.
fn multipart(io: Io, response: *Response, file: Io.File, list: []const range.Span, size: u64, content_type: []const u8) anyerror!void {
    var boundary_bytes: [12]u8 = undefined;
    io.random(&boundary_bytes);
    var boundary_buf: [24]u8 = undefined;
    const boundary = std.mem.print(&boundary_buf, "{x}", .{&boundary_bytes}) catch unreachable; // unreachable: 12 bytes are 24 hex digits
    var type_buf: [128]u8 = undefined;
    try response.header("Content-Type", try std.mem.print(&type_buf, "multipart/byteranges; boundary={s}", .{boundary}));
    var total: u64 = 0;
    for (list) |span| {
        var buf: [256]u8 = undefined;
        total += partHead(&buf, boundary, content_type, span, size).len + span.len() + 2;
    }
    total += 2 + boundary.len + 4;
    try response.setLength(total);
    const w = try response.writer(io);
    for (list) |span| {
        var buf: [256]u8 = undefined;
        try w.writeAll(partHead(&buf, boundary, content_type, span, size));
        try copyTo(io, w, file, span.first, span.len());
        try w.writeAll("\r\n");
    }
    try w.print("--{s}--\r\n", .{boundary});
    return response.end(io);
}

/// A part's head, in `buf`.
fn partHead(buf: *[256]u8, boundary: []const u8, content_type: []const u8, span: range.Span, size: u64) []const u8 {
    return std.mem.print(buf, "--{s}\r\nContent-Type: {s}\r\nContent-Range: bytes {d}-{d}/{d}\r\n\r\n", .{ boundary, content_type, span.first, span.last, size }) catch unreachable; // unreachable: a part's head is under 256 bytes: a 24-byte boundary, a type of our table and three numbers
}

fn copy(io: Io, response: *Response, file: Io.File, offset: u64, len: u64) anyerror!void {
    try copyTo(io, try response.writer(io), file, offset, len);
    return response.end(io);
}

/// `len` bytes of `file` from `offset` onto `w`.
fn copyTo(io: Io, w: *Io.Writer, file: Io.File, offset: u64, len: u64) anyerror!void {
    var at = offset;
    var left = len;
    while (left > 0) {
        const dest = try w.writableSliceGreedy(1);
        const want = dest[0..@intCast(@min(dest.len, left))];
        const n = try file.readPositional(io, &.{want}, at);
        if (n == 0) return error.FileShrank;
        w.advance(n);
        at += n;
        left -= n;
    }
}

const Strength = enum { strong, weak };

/// Whether a list of entity tags (`If-Match`, `If-None-Match`) names `etag`
/// or is `*`; `weak` compares without the `W/`.
fn matchesEtag(list: []const u8, etag: []const u8, strength: Strength) bool {
    var it: wire.fields.ListIterator = .{ .text = list };
    while (it.next()) |raw| {
        if (std.mem.eql(u8, raw, "*")) return true;
        const weak = std.mem.startsWith(u8, raw, "W/");
        if (weak and strength == .strong) continue;
        const tag = if (weak) raw[2..] else raw;
        if (std.mem.eql(u8, tag, etag)) return true;
    }
    return false;
}

/// Whether `If-Range` lets the ranges stand: the strong tag, or the exact
/// modification date.
fn ifRange(cond: []const u8, etag: []const u8, modified: wire.date.Second) bool {
    const v = std.mem.trim(u8, cond, " \t");
    if (v.len != 0 and (v[0] == '"' or std.mem.startsWith(u8, v, "W/"))) return std.mem.eql(u8, v, etag);
    const date = wire.date.parse(v) orelse return false;
    return date.eql(modified);
}

fn precondition(io: Io, response: *Response) anyerror!void {
    return Router.plain(io, response, .precondition_failed, "");
}

fn notModified(io: Io, response: *Response) anyerror!void {
    response.status = .not_modified;
    return response.end(io);
}

/// The media type of a name, by its extension.
pub fn typeOf(name: []const u8) []const u8 {
    const dot = std.mem.findScalarLast(u8, name, '.') orelse return "application/octet-stream";
    const ext = name[dot + 1 ..];
    const table = [_]struct { []const u8, []const u8 }{
        .{ "html", "text/html; charset=utf-8" },         .{ "htm", "text/html; charset=utf-8" },
        .{ "css", "text/css; charset=utf-8" },           .{ "js", "text/javascript; charset=utf-8" },
        .{ "mjs", "text/javascript; charset=utf-8" },    .{ "json", "application/json" },
        .{ "txt", "text/plain; charset=utf-8" },         .{ "md", "text/markdown; charset=utf-8" },
        .{ "xml", "application/xml" },                   .{ "svg", "image/svg+xml" },
        .{ "png", "image/png" },                         .{ "jpg", "image/jpeg" },
        .{ "jpeg", "image/jpeg" },                       .{ "gif", "image/gif" },
        .{ "webp", "image/webp" },                       .{ "avif", "image/avif" },
        .{ "ico", "image/vnd.microsoft.icon" },          .{ "wasm", "application/wasm" },
        .{ "pdf", "application/pdf" },                   .{ "zip", "application/zip" },
        .{ "gz", "application/gzip" },                   .{ "zst", "application/zstd" },
        .{ "tar", "application/x-tar" },                 .{ "woff", "font/woff" },
        .{ "woff2", "font/woff2" },                      .{ "ttf", "font/ttf" },
        .{ "otf", "font/otf" },                          .{ "mp4", "video/mp4" },
        .{ "webm", "video/webm" },                       .{ "mp3", "audio/mpeg" },
        .{ "ogg", "audio/ogg" },                         .{ "wav", "audio/wav" },
        .{ "csv", "text/csv; charset=utf-8" },           .{ "map", "application/json" },
        .{ "webmanifest", "application/manifest+json" },
    };
    for (table) |entry| if (std.ascii.eqlIgnoreCase(ext, entry[0])) return entry[1];
    return "application/octet-stream";
}

const testing = std.testing;

test "names that leave the root are refused, and types are found by extension" {
    try testing.expect(safe("a/b.txt"));
    try testing.expect(safe(""));
    try testing.expect(!safe("a/../b"));
    try testing.expect(!safe(".."));
    try testing.expect(!safe("/etc/passwd"));
    try testing.expect(!safe("a\\b"));
    try testing.expect(!safe("a\x00b"));
    try testing.expectEqualStrings("text/html; charset=utf-8", typeOf("x/index.HTML"));
    try testing.expectEqualStrings("application/octet-stream", typeOf("noext"));
    try testing.expect(matchesEtag("W/\"a\", \"b\"", "\"a\"", .weak));
    try testing.expect(!matchesEtag("W/\"a\"", "\"a\"", .strong));
    try testing.expect(matchesEtag("*", "\"z\"", .strong));
}
