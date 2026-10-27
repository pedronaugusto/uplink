//! A reverse proxy: a server `Handler` that sends each request on to an
//! upstream through a `Client` and writes back what came, the bytes as they
//! came both ways. Go's `httputil.ReverseProxy` is the model.
//!
//! The fields that belong to one connection stay on it, `Forwarded` says
//! who asked (RFC 7239), no redirect is followed and no status tried
//! again, and a body streams through without being decoded or gathered.
//! An upstream that cannot be reached is a 502, one that runs out of time
//! a 504. Neither `Client` nor `Server` knows a proxy exists.
//!
//! A proxy must not move once a server holds its `handler`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const wire = @import("uplink.wire");
const fields = wire.fields;
const Url = wire.url.Url;
const Client = @import("client/Client.zig");
const ClientRequest = @import("client/Request.zig");
const ClientResponse = @import("client/Response.zig");
const Handler = @import("server/Handler.zig");
const Request = @import("server/Request.zig");
const Response = @import("server/Response.zig");

const ReverseProxy = @This();

/// What a server calls: the proxy finds itself from it.
handler: Handler = .{ .handleFn = handle },
/// Private: where each request's outbound URL and fields are made.
gpa: Allocator,
client: *Client,
options: Options,
/// Private: the upstream, taken apart.
upstream: Url,

/// Where requests go, and how.
pub const Options = struct {
    /// An `http` or `https` URL: a request goes to its scheme and
    /// authority, the request's path joined after the upstream's, and the
    /// request's query after the upstream's. Its text must outlive the
    /// proxy.
    upstream: []const u8,
    /// Changes each request's outbound URL and fields; null sends them as
    /// the proxy made them.
    rewrite: ?*const Rewrite = null,
    /// Each request's time upstream: connecting, the head, each read of
    /// the body. Past it, a 504, or the connection ended when the head has
    /// gone out.
    timeout: Io.Timeout = .none,
};

/// A request on its way upstream, for a `Rewrite` to change.
pub const Outbound = struct {
    /// Where it goes: the upstream with the request's path and query.
    url: []const u8,
    /// What it carries: the request's fields, those of its connection left
    /// out, then the proxy's `Forwarded`.
    headers: std.ArrayList(std.http.Header),
    /// Where a rewrite makes what it sets: freed when the request is done.
    arena: Allocator,
};

/// The hook that decides where a request goes: a field of the type that
/// decides, found from here by `@fieldParentPtr`. What it sets must live
/// until the handler returns: the request's own bytes, the caller's, or
/// `Outbound.arena`'s. An error answers the request with a 500.
pub const Rewrite = struct {
    rewriteFn: *const fn (r: *const Rewrite, io: Io, request: *const Request, out: *Outbound) anyerror!void,

    pub fn rewrite(r: *const Rewrite, io: Io, request: *const Request, out: *Outbound) anyerror!void {
        return r.rewriteFn(r, io, request, out);
    }
};

/// Why a proxy was not made.
pub const InitError = error{
    /// Not an `http` or `https` URL.
    InvalidUpstream,
    /// A client with a cookie jar, which would add its cookies to
    /// requests that came without.
    ClientKeepsCookies,
    /// A client with credentials, which would answer the upstream's 401s
    /// for whoever asked.
    ClientAnswersChallenges,
    /// A client with a `User-Agent` of its own, sent for requests that
    /// came without one.
    ClientNamesItself,
};

/// A proxy to `options.upstream` through `client`, which must outlive it
/// and add nothing of its own to a request.
pub fn init(gpa: Allocator, client: *Client, options: Options) InitError!ReverseProxy {
    const o = &client.shared.options;
    if (o.cookies != null) return error.ClientKeepsCookies;
    if (o.credentials != null) return error.ClientAnswersChallenges;
    if (o.user_agent != null) return error.ClientNamesItself;
    const upstream = wire.url.parse(options.upstream) catch return error.InvalidUpstream;
    return .{ .gpa = gpa, .client = client, .options = options, .upstream = upstream };
}

/// Why a request could not be answered. Every failure upstream is a
/// status sent instead; these are the downstream's, after its head went.
pub const Error = error{
    /// Writing to the client failed.
    WriteFailed,
    /// The task answering was canceled, or the connection's.
    Canceled,
    /// The upstream's body failed after the head went out: the connection
    /// is ended, so the client sees it cut.
    UpstreamFailed,
    /// The upstream sent a trailer after a body whose length had gone out
    /// in the head, where no trailer can follow. It announced none.
    TrailerAfterLength,
    /// The request's body could not be read.
    BodyFailed,
    /// The rewrite hook failed: answered with a 500.
    RewriteFailed,
    OutOfMemory,
};

fn handle(h: *const Handler, io: Io, request: *Request, response: *Response) anyerror!void {
    const p: *const ReverseProxy = @alignCast(@fieldParentPtr("handler", h));
    return p.forward(io, request, response);
}

/// Send `request` upstream and answer it with what came back.
pub fn forward(p: *const ReverseProxy, io: Io, request: *Request, response: *Response) Error!void {
    if (request.method.eql(.CONNECT)) return answer(io, response, .not_implemented);
    var arena_state: std.heap.ArenaAllocator = .init(p.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var out: Outbound = .{ .url = try p.join(arena, request), .headers = .empty, .arena = arena };
    try outboundFields(arena, request, &out.headers);
    if (p.options.rewrite) |r| r.rewrite(io, request, &out) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        else => return error.RewriteFailed,
    };
    const length = declaredLength(&request.headers) catch return answer(io, response, .bad_request);
    const body: ClientRequest.Body = if (length == 0 or (length == null and request.bodyComplete()))
        .none
    else
        .{ .reader = .{ .reader = request.rawReader(io), .length = length } };
    var upstream = p.client.send(io, .{
        .method = request.method,
        .url = out.url,
        .headers = out.headers.items,
        .body = body,
        .timeout = p.options.timeout,
        .redirects = .none,
        .retries = .none,
        .expect_continue = request.headers.hasToken("expect", "100-continue") and body != .none,
    }) catch |err| return failedUpstream(io, request, response, err);
    defer upstream.deinit(io);
    return answerWith(io, response, &upstream);
}

/// Answer with the upstream's response: its status, its fields but those
/// of its connection, its body as it came, and its trailer.
fn answerWith(io: Io, response: *Response, upstream: *ClientResponse) Error!void {
    response.status = upstream.status;
    const h = &upstream.headers;
    for (h.fields) |f| {
        if (hopByHop(h, f.name) or std.ascii.eqlIgnoreCase(f.name, "content-length")) continue;
        response.header(f.name, f.value) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            // A field the server cannot send is a broken upstream.
            else => return answerReset(io, response, .bad_gateway),
        };
    }
    const announced = h.get("trailer") != null;
    const length = declaredLength(h) catch return answerReset(io, response, .bad_gateway);
    if (length) |n| if (!announced) response.setLength(n) catch unreachable; // unreachable: the head has not gone out
    const from = upstream.reader(io);
    const to = response.writer(io) catch |err| return sendFailed(err);
    while (true) {
        const n = from.stream(to, .unlimited) catch |err| switch (err) {
            error.EndOfStream => break,
            error.WriteFailed => return response.failure(),
            error.ReadFailed => {
                const failed = upstream.failure();
                if (failed == error.Canceled) return error.Canceled;
                if (response.headSent()) return error.UpstreamFailed;
                return answerReset(io, response, if (failed == error.TimedOut) .gateway_timeout else .bad_gateway);
            },
        };
        // A body of no declared length streams: what came goes on now,
        // as an event stream needs it to.
        if (length == null and n != 0) response.flush(io) catch |err| return sendFailed(err);
    }
    if (upstream.trailers()) |t| {
        if (length != null and !announced) return error.TrailerAfterLength;
        for (t.fields) |f| response.trailer(f.name, f.value) catch |err| return sendFailed(err);
    }
    response.end(io) catch |err| return sendFailed(err);
}

/// The status a failure to send stands for, or the failure itself when it
/// is the downstream's.
fn failedUpstream(io: Io, request: *Request, response: *Response, err: Client.SendError) Error!void {
    return switch (err) {
        error.Canceled => error.Canceled,
        error.OutOfMemory => error.OutOfMemory,
        error.TimedOut => answer(io, response, .gateway_timeout),
        // The request's own body failed: the client's fault, or its
        // connection's.
        error.BodyReadFailed, error.BodyIncomplete => if (request.bodyFault()) |status|
            answer(io, response, status)
        else switch (request.failure()) {
            error.Canceled => error.Canceled,
            else => error.BodyFailed,
        },
        else => answer(io, response, .bad_gateway),
    };
}

/// Send `status` alone, as the whole answer.
fn answer(io: Io, response: *Response, status: std.http.Status) Error!void {
    response.status = status;
    response.send(io, "") catch |err| return sendFailed(err);
}

/// Forget what was set from the upstream and send `status` instead.
fn answerReset(io: Io, response: *Response, status: std.http.Status) Error!void {
    response.reset(io);
    return answer(io, response, status);
}

fn sendFailed(err: Response.Error) Error {
    return switch (err) {
        error.Canceled => error.Canceled,
        error.OutOfMemory => error.OutOfMemory,
        else => error.WriteFailed,
    };
}

/// The upstream's URL with the request's path joined after its own, and
/// the request's query after its own.
fn join(p: *const ReverseProxy, arena: Allocator, request: *const Request) error{OutOfMemory}![]const u8 {
    const u = p.upstream;
    var w: Io.Writer.Allocating = .init(arena);
    const query_at = std.mem.findScalar(u8, u.target, '?') orelse u.target.len;
    const base_path = std.mem.trimEnd(u8, u.target[0..query_at], "/");
    const base_query: ?[]const u8 = if (query_at < u.target.len) u.target[query_at + 1 ..] else null;
    write: {
        w.writer.writeAll(if (u.secure) "https://" else "http://") catch break :write;
        u.writeAuthority(&w.writer, false) catch break :write;
        w.writer.writeAll(base_path) catch break :write;
        if (request.path.len == 0 or request.path[0] != '/') w.writer.writeByte('/') catch break :write;
        w.writer.writeAll(request.path) catch break :write;
        if (base_query != null or request.query != null) w.writer.writeByte('?') catch break :write;
        if (base_query) |q| w.writer.writeAll(q) catch break :write;
        if (base_query != null and request.query != null) w.writer.writeByte('&') catch break :write;
        if (request.query) |q| w.writer.writeAll(q) catch break :write;
        return w.written();
    }
    return error.OutOfMemory;
}

/// The request's fields but its connection's, `Host` and its length,
/// which the client writes, then the proxy's `Forwarded` element.
fn outboundFields(arena: Allocator, request: *const Request, out: *std.ArrayList(std.http.Header)) error{OutOfMemory}!void {
    const h = &request.headers;
    try out.ensureTotalCapacity(arena, h.count() + 3);
    var offers_codings = false;
    for (h.fields) |f| {
        if (std.ascii.eqlIgnoreCase(f.name, "te")) {
            // `trailers` is the one element that reaches past a hop: it
            // says the client reads a trailer.
            if (fields.ListIterator.contains(f.value, "trailers")) out.appendAssumeCapacity(.{ .name = "TE", .value = "trailers" });
            continue;
        }
        if (hopByHop(h, f.name)) continue;
        if (std.ascii.eqlIgnoreCase(f.name, "host") or std.ascii.eqlIgnoreCase(f.name, "content-length") or
            std.ascii.eqlIgnoreCase(f.name, "expect")) continue;
        if (std.ascii.eqlIgnoreCase(f.name, "accept-encoding")) offers_codings = true;
        out.appendAssumeCapacity(.{ .name = f.name, .value = f.value });
    }
    // The client's own codings would be decoded for a requester that
    // asked for none: it is sent what it can read.
    if (!offers_codings) out.appendAssumeCapacity(.{ .name = "Accept-Encoding", .value = "identity" });
    out.appendAssumeCapacity(.{ .name = "Forwarded", .value = try forwardedElement(arena, request) });
}

/// `for`, `host` and `proto` of RFC 7239 for this hop.
fn forwardedElement(arena: Allocator, request: *const Request) error{OutOfMemory}![]const u8 {
    var w: Io.Writer.Allocating = .init(arena);
    write: {
        w.writer.writeAll("for=") catch break :write;
        if (request.remote) |remote| {
            var buf: [64]u8 = undefined;
            var node: Io.Writer = .fixed(&buf);
            remote.format(&node) catch unreachable; // unreachable: an address and port fit 64 bytes
            writeValue(&w.writer, node.buffered()) catch break :write;
        } else w.writer.writeAll("unknown") catch break :write;
        w.writer.writeAll(";host=") catch break :write;
        writeValue(&w.writer, request.host) catch break :write;
        w.writer.writeAll(if (request.secure) ";proto=https" else ";proto=http") catch break :write;
        return w.written();
    }
    return error.OutOfMemory;
}

/// A token as it is, anything else as a quoted string.
fn writeValue(w: *Io.Writer, value: []const u8) Io.Writer.Error!void {
    if (fields.isToken(value)) return w.writeAll(value);
    try w.writeByte('"');
    for (value) |c| {
        if (c == '"' or c == '\\') try w.writeByte('\\');
        try w.writeByte(c);
    }
    try w.writeByte('"');
}

/// The fields that belong to one connection (RFC 9110 §7.6.1), and the
/// ones its `Connection` names.
fn hopByHop(h: *const fields.Headers, name: []const u8) bool {
    const always = [_][]const u8{ "connection", "keep-alive", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade", "proxy-authenticate", "proxy-authorization" };
    for (always) |n| if (std.ascii.eqlIgnoreCase(name, n)) return true;
    var named = h.values("connection");
    while (named.next()) |n| if (std.ascii.eqlIgnoreCase(name, n)) return true;
    return false;
}

/// The body's declared length, null when it declares none.
fn declaredLength(h: *const fields.Headers) error{InvalidLength}!?u64 {
    var length: ?u64 = null;
    var values = h.values("content-length");
    while (values.next()) |v| {
        const n = std.fmt.parseUnsigned(u64, v, 10) catch return error.InvalidLength;
        if (length) |l| if (l != n) return error.InvalidLength;
        length = n;
    }
    return length;
}
