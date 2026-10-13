//! A request as the server received it: its head, parsed in a buffer of
//! the server's pool, and its body, read through `reader`. Everything here
//! is valid until the handler returns.
//!
//! A request must not move once `reader` has been called: the reader
//! points into it.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const wire = @import("uplink.wire");
const h1 = wire.h1;
const fields = wire.fields;
const coding = wire.coding;
const Method = wire.Method;
const Version = wire.Version;
const Body = @import("../transport/Body.zig");
const BufferPool = @import("../transport/BufferPool.zig");
const Decoder = @import("../coding/Decoder.zig");
const Socket = @import("Socket.zig");

const Request = @This();

method: Method,
/// The request target as it came: a path and query (origin form), a whole
/// URL (absolute form), `host:port` for `CONNECT`, or `*`.
target: []const u8,
/// The target's path, its escapes left in: `/` at least for a request to
/// a resource, empty for `CONNECT` and `*`.
path: []const u8,
/// What follows the `?`, without it; null when there is no `?`.
query: ?[]const u8,
version: Version,
headers: fields.Headers,
/// The host the request names: its `Host` field, or the authority of an
/// absolute target, port included when one was given.
host: []const u8,
/// The peer, when the connection is over IP.
remote: ?Io.net.IpAddress,
/// Whether the request came over TLS.
secure: bool,
/// What a router captured from the path, by name.
params: Params = .{},

/// Private: the connection's I/O.
socket: *Socket,
/// Private: the body as its framing delimits it.
body: Body,
/// Private: the body's codings undone, when the server decodes them.
decoder: ?Decoder = null,
decoded: ?*Io.Reader = null,
/// Private: whether the body reader was asked for.
started: bool = false,
/// Private: the client waits for `100 Continue` before it sends the body.
expects_continue: bool,
/// Private: `100 Continue` was sent, or a final head that makes it moot.
continued: bool = false,
/// Private: the trailer's fields, once parsed.
trailer_fields: ?fields.Headers = null,
/// Private: a buffer of the server's for what is made from the request
/// (captures with their escapes undone), given back when it is done.
scratch: []u8 = &.{},
/// Private: a scratch buffer replaced by a larger one.
retired: []u8 = &.{},

/// Captures by name, at most `max` of them; a value is the path's segment
/// with its escapes undone, or for a `{name...}` capture the rest of the
/// path.
pub const Params = struct {
    names: [max][]const u8 = undefined,
    values: [max][]const u8 = undefined,
    len: u8 = 0,

    pub const max = 16;

    /// The value captured as `name`, or null.
    pub fn get(p: *const Params, name: []const u8) ?[]const u8 {
        for (p.names[0..p.len], p.values[0..p.len]) |n, v| if (std.mem.eql(u8, n, name)) return v;
        return null;
    }

    /// Add a capture; past `max`, the router refused the pattern already.
    pub fn put(p: *Params, name: []const u8, value: []const u8) void {
        std.debug.assert(p.len < max);
        p.names[p.len] = name;
        p.values[p.len] = value;
        p.len += 1;
    }
};

/// Why reading the body failed.
pub const ReadError = error{
    /// The connection failed, or a wait for the body ran past the activity
    /// timeout.
    ConnectionFailed,
    TimedOut,
    Canceled,
    /// Chunk framing that does not parse.
    HttpProtocolError,
    /// A coded body that does not decode, or whose checksum is wrong.
    BadContentEncoding,
    /// The connection ended before the body did.
    BodyIncomplete,
    /// The body passed `Options.max_body`.
    BodyTooLarge,
};

/// Why `collect` failed.
pub const CollectError = ReadError || error{ OutOfMemory, StreamTooLong };

/// A buffer of at least `len` bytes, valid until the handler returns:
/// the request keeps one, taken from the server's pool, replaced by a
/// larger one when asked for more (the old one's bytes then stay valid
/// too, until the request is done).
pub fn scratchBuffer(r: *Request, io: Io, len: usize) error{OutOfMemory}![]u8 {
    if (r.scratch.len >= len) return r.scratch;
    const pool = &r.socket.context.buffers;
    const class = BufferPool.Class.fitting(len) orelse return error.OutOfMemory;
    const buffer = try pool.acquire(io, class);
    if (r.scratch.len != 0) r.retired = r.scratch;
    r.scratch = buffer;
    return buffer;
}

/// Give back the request's buffers.
pub fn release(r: *Request, io: Io) void {
    const pool = &r.socket.context.buffers;
    for ([_][]u8{ r.scratch, r.retired }) |b| if (b.len != 0) pool.release(io, b);
    r.scratch = &.{};
    r.retired = &.{};
}

/// The value captured as `name` by the router.
pub fn param(r: *const Request, name: []const u8) ?[]const u8 {
    return r.params.get(name);
}

/// The body, decoded per `Content-Encoding` when the server decompresses
/// and every coding is gzip, deflate or zstd; under any other it is handed
/// over as it came. The first call sends `100 Continue` to a client
/// waiting for it.
pub fn reader(r: *Request, io: Io) *Io.Reader {
    r.socket.io = io;
    if (!r.started) {
        r.started = true;
        if (r.expects_continue and !r.continued) {
            r.continued = true;
            r.socket.sendContinue();
        }
        if (r.decoder) |*d| r.decoded = d.start(&r.body.interface, &r.socket.context.zstd);
    }
    return r.decoded orelse &r.body.interface;
}

/// The whole body, at most `limit` bytes, in `gpa`.
pub fn collect(r: *Request, gpa: Allocator, io: Io, limit: Io.Limit) CollectError![]u8 {
    return r.reader(io).allocRemaining(gpa, limit) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.StreamTooLong => error.StreamTooLong,
        error.ReadFailed => r.failure(),
    };
}

/// Why the last read of the body failed.
pub fn failure(r: *const Request) ReadError {
    return switch (r.body.state) {
        .incomplete => error.BodyIncomplete,
        .malformed => error.HttpProtocolError,
        .too_large => error.BodyTooLarge,
        .read_failed => r.socket.readError(),
        .reading, .done => error.BadContentEncoding,
    };
}

/// Why a coded body did not decode, after a read failed with
/// `BadContentEncoding`.
pub fn decodingFailure(r: *const Request) ?Decoder.Error {
    const d = &(r.decoder orelse return null);
    return d.failure(&r.socket.context.zstd);
}

/// After the body's end: the fields of a chunked body's trailer section,
/// or null when it had none or the body is not read to its end.
pub fn trailers(r: *Request) ?fields.Headers {
    if (r.trailer_fields) |t| return t;
    const bytes = r.body.trailerBytes() orelse return null;
    const end = std.mem.alignForward(usize, bytes.len, @alignOf(fields.Field));
    const field_ptr: [*]fields.Field = @ptrCast(@alignCast(r.body.trailer.ptr + end)); // safe: pool buffers are 64-aligned and `end` is aligned for a Field, with room for `trailer_fields` of them
    const parsed = h1.parseTrailer(bytes, field_ptr[0..Body.trailer_fields]) catch return null;
    r.trailer_fields = parsed;
    return parsed;
}

/// Whether the body was read to its end.
pub fn bodyComplete(r: *const Request) bool {
    return r.body.complete();
}

/// Where a request target's path and query are, and its host for the
/// absolute form.
pub const Target = struct {
    path: []const u8,
    query: ?[]const u8,
    /// The authority of an absolute target.
    authority: ?[]const u8 = null,

    /// Why a target is refused.
    pub const Error = error{InvalidTarget};

    /// Split `target` as `method` sends it (RFC 9112 §3.2): origin form
    /// for any method, absolute form (`http://` or `https://`, as a server
    /// must accept it), authority form only for `CONNECT`, and `*` only
    /// for `OPTIONS`.
    pub fn parse(method: Method, target: []const u8) Error!Target {
        if (target.len == 0) return error.InvalidTarget;
        if (method.eql(.CONNECT)) {
            if (target.len == 0 or target[0] == '/' or std.mem.findScalar(u8, target, '/') != null) return error.InvalidTarget;
            return .{ .path = "", .query = null, .authority = target };
        }
        if (std.mem.eql(u8, target, "*")) {
            if (!method.eql(.OPTIONS)) return error.InvalidTarget;
            return .{ .path = "", .query = null };
        }
        var rest = target;
        var authority: ?[]const u8 = null;
        if (target[0] != '/') {
            const scheme_end = std.mem.find(u8, target, "://") orelse return error.InvalidTarget;
            const scheme = target[0..scheme_end];
            if (!std.ascii.eqlIgnoreCase(scheme, "http") and !std.ascii.eqlIgnoreCase(scheme, "https")) return error.InvalidTarget;
            const after = target[scheme_end + 3 ..];
            const slash = std.mem.findAny(u8, after, "/?") orelse after.len;
            authority = after[0..slash];
            if (authority.?.len == 0) return error.InvalidTarget;
            rest = after[slash..];
        }
        const q = std.mem.findScalar(u8, rest, '?');
        const path = rest[0 .. q orelse rest.len];
        return .{
            .path = if (path.len == 0) "/" else path,
            .query = if (q) |i| rest[i + 1 ..] else null,
            .authority = authority,
        };
    }
};

const testing = std.testing;

test "a target is split into its path and query, in every form a server takes" {
    const origin = try Target.parse(.GET, "/a/b?x=1&y");
    try testing.expectEqualStrings("/a/b", origin.path);
    try testing.expectEqualStrings("x=1&y", origin.query.?);
    try testing.expectEqual(null, origin.authority);
    const absolute = try Target.parse(.GET, "http://example.com:8080?q");
    try testing.expectEqualStrings("/", absolute.path);
    try testing.expectEqualStrings("q", absolute.query.?);
    try testing.expectEqualStrings("example.com:8080", absolute.authority.?);
    const connect = try Target.parse(.CONNECT, "example.com:443");
    try testing.expectEqualStrings("example.com:443", connect.authority.?);
    try testing.expectEqualStrings("", (try Target.parse(.OPTIONS, "*")).path);
    try testing.expectError(error.InvalidTarget, Target.parse(.GET, "*"));
    try testing.expectError(error.InvalidTarget, Target.parse(.GET, "ftp://x/"));
    try testing.expectError(error.InvalidTarget, Target.parse(.CONNECT, "/x"));
    try testing.expectError(error.InvalidTarget, Target.parse(.GET, "http:///x"));
}

test "params are found by name" {
    var p: Params = .{};
    p.put("id", "42");
    p.put("rest", "a/b");
    try testing.expectEqualStrings("42", p.get("id").?);
    try testing.expectEqualStrings("a/b", p.get("rest").?);
    try testing.expectEqual(null, p.get("none"));
}
