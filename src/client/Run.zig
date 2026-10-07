//! One request carried out under its client's policy: the attempts it
//! takes — a connection reused or made, the head and body written, the
//! response's head read — and what is done between them. A stale kept
//! connection is replaced; a proxy's 407 and a server's 401 are answered;
//! a redirect is followed; a failed connection or a status the retries
//! cover is tried again after a wait; cookies are stored and sent; the
//! prepare hook sees every attempt. `Client.send` runs one to its end;
//! `Client.begin` starts one whose body the caller writes, and
//! `Outgoing.finish` ends it.
//!
//! A run owns nothing the caller passed; it borrows the final URL's buffer
//! from the client's pool when a redirect was followed, and hands it to the
//! response.

const std = @import("std");
const Io = std.Io;
const h1 = @import("../wire/h1.zig");
const fields = @import("../wire/fields.zig");
const url_mod = @import("../wire/url.zig");
const auth = @import("../wire/auth.zig");
const Method = @import("../wire/Method.zig");
const Connection = @import("../transport/Connection.zig");
const Context = @import("../transport/Context.zig");
const Diagnostics = @import("../transport/Diagnostics.zig");
const BufferPool = @import("../transport/BufferPool.zig");
const Shared = @import("Shared.zig");
const Request = @import("Request.zig");
const Response = @import("Response.zig");
const OriginAuth = @import("OriginAuth.zig");
const Prepare = @import("Prepare.zig");
const policy = @import("policy.zig");

const Run = @This();

shared: *Shared,
/// The request as the caller gave it.
request: Request,
/// What the next attempt sends: a redirect may change all three.
method: Method,
body: Request.Body,
url: url_mod.Url,
url_text: []const u8,
/// Private: where `url_text` lives once a redirect was followed.
url_buffer: []u8 = &.{},
/// On the awake clock.
deadline: ?Io.Timestamp,
redirects: policy.Redirects,
retries: policy.Retries,
/// Attempts made in all, for the prepare hook.
attempts: u8 = 0,
/// Attempts made at the current URL, for `retries.max_attempts`.
tries: u8 = 1,
hops: u8 = 0,
/// Set once a redirect left the first origin: the caller's credentials,
/// its own `Authorization`, `Cookie` and `Proxy-Authorization` and
/// `request.auth`, are no longer sent.
left_origin: bool = false,
/// Set once a redirect turned the request into a GET: the caller's fields
/// that describe a body are no longer sent.
body_dropped: bool = false,
/// Whether a byte of the current attempt may have reached the server.
sent: bool = false,
/// Whether the current attempt saw a byte of a response.
progress: bool = false,
/// The cached answer the current attempt sent, held until judged.
origin_entry: ?*OriginAuth.Entry = null,
/// A 401 was answered with a filled secret in this run.
filled: bool = false,
/// A stale Digest nonce was answered again in this run.
refreshed: bool = false,
/// 407s answered for requests sent whole to an HTTP proxy.
proxy_answers: u8 = 0,
/// When the current attempt's request was written, for the observer.
sent_at: ?Io.Timestamp = null,
/// The prepare hook's view of the current attempt; its added fields are
/// written from here.
prepared: Prepare.Attempt = undefined,
has_prepared: bool = false,

/// Errors from a run.
pub const Error = Shared.SendError;

/// A run of `request`, checked whole before anything is sent.
pub fn init(c: *Shared, io: Io, request: Request) Error!Run {
    if (request.diagnostics) |d| d.reset();
    const url = url_mod.parse(request.url) catch |err| return switch (err) {
        error.InvalidUrl => error.InvalidUrl,
        error.UnsupportedScheme => error.UnsupportedScheme,
    };
    if (!fields.isToken(request.method.name)) return error.InvalidHeader;
    for (request.headers) |h| {
        h1.checkHeader(h) catch return error.InvalidHeader;
        for ([_][]const u8{ "host", "content-length", "transfer-encoding" }) |own| {
            if (std.ascii.eqlIgnoreCase(h.name, own)) return error.InvalidHeader;
        }
    }
    if (c.options.user_agent) |ua| if (!fields.isFieldValue(ua)) return error.InvalidHeader;
    if (request.auth) |a| switch (a) {
        .basic => {},
        .bearer => |t| if (!fields.isFieldValue(t) or t.len == 0) return error.InvalidHeader,
    };
    var deadline: ?Io.Timestamp = null;
    if (request.timeout.toTimestamp(io)) |t| {
        deadline = t.toClock(io, .awake).raw;
        c.context.timer.tighten(io, Io.Clock.awake.now(io).durationTo(deadline.?));
    }
    return .{
        .shared = c,
        .request = request,
        .method = request.method,
        .body = request.body,
        .url = url,
        .url_text = request.url,
        .deadline = deadline,
        .redirects = request.redirects orelse c.options.redirects,
        .retries = request.retries orelse c.options.retries,
    };
}

/// Give back what the run borrowed and the response did not take.
pub fn deinit(run: *Run, io: Io) void {
    run.releaseEntry(io);
    if (run.url_buffer.len != 0) run.shared.context.buffers.release(io, run.url_buffer);
    run.* = undefined;
}

fn releaseEntry(run: *Run, io: Io) void {
    const e = run.origin_entry orelse return;
    run.shared.origin_auth.release(io, e);
    run.origin_entry = null;
}

/// Carry the run through from `first`, a response already read, or from a
/// new attempt, to its final response.
pub fn complete(run: *Run, io: Io, first: ?Response) Error!Response {
    var pending = first;
    while (true) {
        var response = pending orelse run.attempt(io) catch |err| {
            if (try run.retryFailure(io, err)) continue;
            return err;
        };
        pending = null;
        if (try run.decide(io, &response)) continue;
        return run.finish(response);
    }
}

/// Hand the run's final URL to `response`.
fn finish(run: *Run, response: Response) Response {
    var r = response;
    r.url = run.url_text;
    r.url_buffer = run.url_buffer;
    run.url_buffer = &.{};
    return r;
}

fn diagnostics(run: *const Run) ?*Diagnostics {
    return run.request.diagnostics;
}

/// The route of the current URL, through the proxy the client chooses
/// for it.
pub fn route(run: *Run, io: Io) Error!Context.Route {
    const proxy = run.shared.context.proxies.forUrl(io, run.url) catch |err| return switch (err) {
        error.InvalidProxy => error.InvalidProxy,
        error.OutOfMemory => error.OutOfMemory,
    };
    return .{ .secure = run.url.secure, .host = run.url.host, .port = run.url.port, .proxy = proxy };
}

/// Whether requests to the current URL go to an HTTP proxy whole, as
/// absolute URLs.
fn absoluteForm(r: Context.Route) bool {
    const slot = r.proxy orelse return false;
    return !r.secure and !slot.proxy.kind.socks();
}

/// A connection for an attempt.
pub const Lease = struct { conn: *Connection, reused: bool };

/// A kept connection to `r` that still looks alive, or a new one, waiting
/// for one while the route is at its limit.
pub fn acquire(run: *Run, io: Io, r: Context.Route) Error!Lease {
    const c = run.shared;
    const d = run.diagnostics();
    while (true) {
        var waited = false;
        if (c.pool.options.max_per_route != 0) if (d) |x| {
            x.stage = .wait;
        };
        const got = c.pool.acquire(io, r, run.deadline, &waited) catch |err| return switch (err) {
            error.TimedOut => {
                if (d) |x| x.timeout = .deadline;
                return error.TimedOut;
            },
            error.Canceled => error.Canceled,
            error.OutOfMemory => error.OutOfMemory,
        };
        switch (got) {
            .expired => |k| Response.closeConnection(io, &c.pool, k.h1),
            .idle => |k| {
                const conn = k.h1;
                conn.unpark(io, d, run.deadline) catch {
                    Response.closeConnection(io, &c.pool, conn);
                    return error.OutOfMemory;
                };
                const alive = conn.alive(io) catch {
                    Response.closeConnection(io, &c.pool, conn);
                    return error.Canceled;
                };
                if (!alive) {
                    Response.closeConnection(io, &c.pool, conn);
                    continue;
                }
                _ = c.context.counters.in_use.fetchAdd(1, .monotonic);
                if (c.context.observer) |o| o.emit(.{ .reused = .{ .host = r.host, .port = r.port } });
                return .{ .conn = conn, .reused = true };
            },
            .open => {
                const conn = Connection.open(&c.context, io, r, .{ .diagnostics = d, .deadline = run.deadline }) catch |err| {
                    c.pool.closed(io, r);
                    return switch (err) {
                        error.InvalidHostName => error.InvalidUrl,
                        else => |e| e,
                    };
                };
                _ = c.context.counters.in_use.fetchAdd(1, .monotonic);
                return .{ .conn = conn, .reused = false };
            },
        }
    }
}

/// One attempt: a connection, the request on it, the response's head. A
/// kept connection that fails before a byte of the response comes back is
/// replaced once, when the request can go again.
fn attempt(run: *Run, io: Io) Error!Response {
    const c = run.shared;
    const r = try run.route(io);
    var resent = false;
    while (true) {
        run.sent = false;
        run.progress = false;
        run.releaseEntry(io);
        const lease = try run.acquire(io, r);
        const response = run.exchange(io, lease.conn, r) catch |err| {
            Response.release(io, &c.context, &c.pool, lease.conn, false);
            const replayable = switch (run.body) {
                .none => true,
                .bytes => run.method.idempotent(),
                .reader, .streamed => false,
            };
            if (err == error.ConnectionFailed and lease.reused and !resent and !run.progress and replayable) {
                resent = true;
                continue;
            }
            return err;
        };
        if (lease.reused) _ = c.context.counters.reused.fetchAdd(1, .monotonic);
        return response;
    }
}

/// Write the request on `conn` and read its response's head.
fn exchange(run: *Run, io: Io, conn: *Connection, r: Context.Route) Error!Response {
    const framing: h1.Framing = switch (run.body) {
        .none => if (run.method.eql(.POST) or run.method.eql(.PUT) or run.method.eql(.PATCH)) .{ .length = 0 } else .none,
        .bytes => |b| .{ .length = b.len },
        .reader => |rd| if (rd.length) |n| .{ .length = n } else .chunked,
        .streamed => unreachable, // unreachable: a body the caller writes goes through `begin`
    };
    const has_body = switch (framing) {
        .length => |n| n != 0,
        .chunked => true,
        .none, .until_close => false,
    };
    const expect = run.request.expect_continue and has_body;
    try run.prepareAttempt(io);
    if (run.diagnostics()) |d| d.stage = .write;
    run.sent = true;
    run.writeHead(io, conn, r, framing, expect) catch return conn.writeError();
    if (expect) {
        conn.flush() catch return conn.writeError();
        if (try run.awaitContinue(io, conn)) |refused| return refused;
    }
    switch (run.body) {
        .none, .streamed => {},
        .bytes => |b| conn.writer().writeAll(b) catch return conn.writeError(),
        .reader => |rd| try run.writeReader(io, conn, rd.reader, rd.length),
    }
    conn.flush() catch return conn.writeError();
    return run.receive(io, conn, false);
}

/// After a head that asked `Expect: 100-continue`: wait for the server's
/// word. Null to send the body — a 100 came, or nothing came in time;
/// else the server's final answer, sent before the body, which then is
/// never sent and the connection never reused.
pub fn awaitContinue(run: *Run, io: Io, conn: *Connection) Error!?Response {
    if (!try conn.readable(io, run.shared.options.expect_continue_timeout)) return null;
    var interim = try run.receive(io, conn, true);
    if (interim.status == .@"continue") {
        interim.releaseHead(io);
        return null;
    }
    interim.keep_alive = false;
    return interim;
}

/// Read the response's head, telling the observer the request went and
/// how long its answer took; `want_continue` reads the go-ahead a request
/// waits for before its body, which is not yet the request sent.
pub fn receive(run: *Run, io: Io, conn: *Connection, want_continue: bool) Error!Response {
    const c = run.shared;
    if (c.context.observer) |o| {
        if (!want_continue) o.emit(.{ .sent = .{ .method = run.method.name, .url = run.url_text } });
        run.sent_at = Io.Clock.awake.now(io);
    }
    const response = try Response.receive(io, &c.context, &c.pool, conn, .{
        .method = run.method,
        .limits = c.options.limits,
        .decompress = c.options.decompress,
        .diagnostics = run.diagnostics(),
        .progress = &run.progress,
        .want_continue = want_continue,
    });
    if (c.context.observer) |o| o.emit(.{ .head = .{ .status = @backingInt(response.status), .wait = run.sent_at.?.durationTo(Io.Clock.awake.now(io)) } });
    return response;
}

/// Run the prepare hook for the attempt about to be written.
pub fn prepareAttempt(run: *Run, io: Io) Error!void {
    run.attempts +|= 1;
    run.has_prepared = false;
    const hook = run.shared.options.prepare orelse return;
    run.prepared = .{
        .method = run.method,
        .url = run.url_text,
        .headers = run.request.headers,
        .body = switch (run.body) {
            .bytes => |b| b,
            .none, .reader, .streamed => null,
        },
        .number = run.attempts,
    };
    hook.run(io, &run.prepared) catch |err| return switch (err) {
        error.PrepareFailed => error.PrepareFailed,
        error.Canceled => error.Canceled,
    };
    run.has_prepared = true;
}

/// A body from a reader: exactly `length` bytes, or in chunks to its end.
fn writeReader(run: *Run, io: Io, conn: *Connection, source: *Io.Reader, length: ?u64) Error!void {
    const w = conn.writer();
    if (length) |n| {
        source.streamExact64(w, n) catch |err| return switch (err) {
            error.ReadFailed => error.BodyReadFailed,
            error.EndOfStream => error.BodyIncomplete,
            error.WriteFailed => conn.writeError(),
        };
        return;
    }
    const buffer = try run.shared.context.buffers.acquire(io, .record);
    defer run.shared.context.buffers.release(io, buffer);
    var chunked: h1.ChunkedWriter = .init(w, buffer);
    _ = source.streamRemaining(&chunked.interface) catch |err| return switch (err) {
        error.ReadFailed => error.BodyReadFailed,
        error.WriteFailed => conn.writeError(),
    };
    chunked.end() catch return conn.writeError();
}

/// Write the request line and fields, everything checked by `init` or as
/// it is added, into the connection's writer.
pub fn writeHead(run: *Run, io: Io, conn: *Connection, r: Context.Route, framing: h1.Framing, expect: bool) Io.Writer.Error!void {
    const c = run.shared;
    const w = conn.writer();
    const url = run.url;
    try w.writeAll(run.method.name);
    try w.writeByte(' ');
    if (run.method.eql(.CONNECT)) {
        try url.writeAuthority(w, true);
    } else {
        if (conn.absolute_form) {
            try w.writeAll("http://");
            try url.writeAuthority(w, false);
        }
        try url.writeTarget(w);
    }
    try w.writeAll(" HTTP/1.1\r\nHost: ");
    try url.writeAuthority(w, false);
    try w.writeAll("\r\n");
    if (conn.absolute_form) {
        // Answered for with the path as the Digest target, as curl answers.
        const path = if (url.target.len != 0 and url.target[0] == '/') url.target else "/";
        const slot = r.proxy.?;
        _ = try slot.auth.writeField(io, w, slot.proxy.credential, run.method.name, path);
    }
    if (c.options.user_agent) |ua| if (!named(run.request.headers, "user-agent")) try h1.writeField(w, .{ .name = "User-Agent", .value = ua });
    if (c.options.decompress and !named(run.request.headers, "accept-encoding")) try w.writeAll("Accept-Encoding: gzip, deflate, zstd\r\n");
    try run.writeAuthorization(io, w);
    // The jar's cookies, unless the caller's own `Cookie` is still sent.
    if (c.options.cookies) |jar| if (run.left_origin or !named(run.request.headers, "cookie")) {
        _ = try jar.writeField(io, w, url);
    };
    for (run.request.headers) |h| {
        if (run.left_origin and isCredential(h.name)) continue;
        if (run.body_dropped and describesBody(h.name)) continue;
        try h1.writeField(w, h);
    }
    if (run.has_prepared) for (run.prepared.addedHeaders()) |h| try h1.writeField(w, h);
    if (expect) try w.writeAll("Expect: 100-continue\r\n");
    switch (framing) {
        .none, .until_close => {},
        .length => |n| try w.print("Content-Length: {d}\r\n", .{n}),
        .chunked => try w.writeAll("Transfer-Encoding: chunked\r\n"),
    }
    try w.writeAll("\r\n");
}

/// `Authorization`, from the request's own credentials while they apply,
/// else from the answers the client keeps for the origin; none when the
/// caller wrote the field.
fn writeAuthorization(run: *Run, io: Io, w: *Io.Writer) Io.Writer.Error!void {
    if (run.request.auth == null and run.shared.origin_auth.live.load(.acquire) == 0) return;
    if (named(run.request.headers, "authorization") and !run.left_origin) return;
    if (run.request.auth) |a| if (!run.left_origin) {
        try w.writeAll("Authorization: ");
        switch (a) {
            .basic => |b| try auth.writeBasic(w, b.user, b.password),
            .bearer => |t| try auth.writeBearer(w, t),
        }
        try w.writeAll("\r\n");
        return;
    };
    // The target a Digest answer names: the path and query as the request
    // line has them, `/` first.
    var target_buf: [2048]u8 = undefined;
    const t = run.url.target;
    const target = if (t.len != 0 and t[0] == '/') t else std.mem.print(&target_buf, "/{s}", .{t}) catch "/";
    run.origin_entry = try run.shared.origin_auth.writeField(io, w, run.url, run.method.name, target);
}

fn named(headers: []const std.http.Header, name: []const u8) bool {
    for (headers) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return true;
    return false;
}

/// Fields that carry the caller's credentials, dropped when a redirect
/// leaves the origin.
fn isCredential(name: []const u8) bool {
    for ([_][]const u8{ "authorization", "cookie", "proxy-authorization" }) |n| if (std.ascii.eqlIgnoreCase(name, n)) return true;
    return false;
}

/// Fields that describe a request's body, dropped when a redirect turns
/// it into a GET (the Fetch standard's list).
fn describesBody(name: []const u8) bool {
    for ([_][]const u8{ "content-type", "content-encoding", "content-language", "content-location" }) |n| if (std.ascii.eqlIgnoreCase(name, n)) return true;
    return false;
}

/// After a response: whether the run goes on with another attempt — a
/// challenge answered, a redirect followed, a status tried again — in
/// which case the response has been released. On an error it is released
/// too.
fn decide(run: *Run, io: Io, response: *Response) Error!bool {
    const next = run.judge(io, response) catch |err| {
        response.deinit(io);
        return err;
    };
    switch (next) {
        .done => return false,
        .again => {
            response.deinit(io);
            return true;
        },
        .wait => |w| {
            response.deinit(io);
            try run.pause(io, w.duration, w.status, null);
            return true;
        },
    }
}

/// What follows a response.
const Next = union(enum) {
    /// It is the run's answer.
    done,
    /// Another attempt, at once.
    again,
    /// Another attempt, after a wait, for a status the retries cover.
    wait: struct { duration: Io.Duration, status: u16 },
};

/// Decide what follows `response`, which stays the caller's to release.
fn judge(run: *Run, io: Io, response: *Response) Error!Next {
    const c = run.shared;
    if (c.options.cookies) |jar| try jar.storeAll(io, run.url, &response.headers);
    const status = response.status;
    if (status == .proxy_auth_required) return if (try run.answerProxy(io, response)) .again else .done;
    if (status == .unauthorized) {
        if (try run.answerOrigin(io, response)) return .again;
    } else if (run.origin_entry) |e| {
        run.origin_entry = null;
        c.origin_auth.settle(io, e, c.options.credentials, true);
    }
    if (try run.followRedirect(io, response)) return .again;
    return run.retryStatus(io, response);
}

/// A 407 from an HTTP proxy the request went to whole: answered, and the
/// request sent again, as curl does; a stale Digest nonce once more.
fn answerProxy(run: *Run, io: Io, response: *Response) Error!bool {
    const r = try run.route(io);
    if (!absoluteForm(r)) return false;
    if (run.diagnostics()) |d| d.proxy_status = 407;
    if (run.proxy_answers == 2 or !run.body.replayable()) return false;
    var offered_buf: [256]u8 = undefined;
    var offered: Io.Writer = .fixed(&offered_buf);
    const slot = r.proxy.?;
    const again = slot.auth.challenged(run.shared.context.gpa, io, slot.proxy.credential, &response.headers, &offered) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.ProxyAuthMethodUnsupported => {
            if (run.diagnostics()) |d| d.proxy_offered.set(offered.buffered(), offered.end == offered_buf.len);
            return error.ProxyAuthMethodUnsupported;
        },
    };
    if (!again) return false;
    run.proxy_answers += 1;
    run.emitChallenged(407);
    return true;
}

/// A 401: the answer the run sent is judged, a stale Digest nonce answered
/// again, and a secret filled once from the client's credentials.
fn answerOrigin(run: *Run, io: Io, response: *Response) Error!bool {
    const c = run.shared;
    const credentials = c.options.credentials;
    if (named(run.request.headers, "authorization") and !run.left_origin) return false;
    if (run.request.auth != null and !run.left_origin) return false;
    if (response.headers.getKnown(.@"www-authenticate") == null) {
        if (run.origin_entry) |e| {
            run.origin_entry = null;
            c.origin_auth.settle(io, e, credentials, false);
        }
        return false;
    }
    var arena: std.heap.ArenaAllocator = .init(c.context.gpa);
    defer arena.deinit();
    var challenges: std.ArrayList(auth.Challenge) = .empty;
    var it = response.headers.iterator();
    while (it.next()) |f| {
        if (!std.ascii.eqlIgnoreCase(f.name, "www-authenticate")) continue;
        const list = auth.parse(arena.allocator(), f.value) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.MalformedChallenge => continue,
        };
        try challenges.appendSlice(arena.allocator(), list);
    }
    if (run.origin_entry) |e| {
        if (!run.refreshed and run.body.replayable() and try c.origin_auth.refreshNonce(io, e, challenges.items)) {
            run.refreshed = true;
            run.emitChallenged(401);
            return true;
        }
        run.origin_entry = null;
        c.origin_auth.settle(io, e, credentials, false);
    }
    const creds = credentials orelse return false;
    if (run.filled or !run.body.replayable()) return false;
    run.filled = true;
    const answered = c.origin_auth.answer(io, creds, run.url, run.url_text, challenges.items) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.Canceled => error.Canceled,
        error.CredentialsUnavailable => error.CredentialsUnavailable,
    };
    if (!answered) return false;
    run.emitChallenged(401);
    return true;
}

fn emitChallenged(run: *Run, status: u16) void {
    if (run.shared.context.observer) |o| o.emit(.{ .challenged = .{ .status = status } });
}

/// A redirect the policy follows: the next URL, method and body set.
fn followRedirect(run: *Run, io: Io, response: *Response) Error!bool {
    const follow = switch (run.redirects) {
        .none => return false,
        .follow => |f| f,
    };
    const code = @backingInt(response.status);
    const hop = policy.hop(code, run.method) orelse return false;
    const location = response.headers.getKnown(.location) orelse return false;
    const resolved = try run.resolveLocation(io, location);
    var keep = true;
    defer if (keep) run.shared.context.buffers.release(io, resolved.buffer);
    const next = url_mod.parse(resolved.text) catch return error.InvalidRedirect;
    if (!try policy.mayFollow(follow, run.url, next, run.hops)) return false;
    const same = url_mod.sameOrigin(run.url, next);
    if (hop.keep_body and !run.body.replayable()) {
        const empty = switch (run.body) {
            .reader => |rd| rd.length != null and rd.length.? == 0,
            .streamed => |st| st.length != null and st.length.? == 0,
            .none, .bytes => true,
        };
        if (!empty) return error.BodyNotReplayable;
    }
    // A body that cannot go again goes again only when it was empty: as
    // none, which a POST still sends with its zero length.
    const body: Request.Body = if (hop.keep_body and run.body.replayable()) run.body else .none;
    if (run.shared.context.observer) |o| o.emit(.{ .redirect = .{ .status = code, .url = resolved.text } });
    keep = false;
    if (run.url_buffer.len != 0) run.shared.context.buffers.release(io, run.url_buffer);
    run.url_buffer = resolved.buffer;
    run.url_text = resolved.text;
    run.url = next;
    run.left_origin = run.left_origin or !same;
    if (!hop.keep_body) run.body_dropped = true;
    run.body = body;
    run.method = hop.method;
    run.hops += 1;
    run.tries = 1;
    run.filled = false;
    run.refreshed = false;
    if (run.diagnostics()) |d| d.redirects = run.hops;
    return true;
}

const Resolved = struct { buffer: []u8, text: []u8 };

/// `location` resolved against the current URL, in a buffer from the
/// pool.
fn resolveLocation(run: *Run, io: Io, location: []const u8) Error!Resolved {
    const buffers = &run.shared.context.buffers;
    for ([_]BufferPool.Class{ .small, .record, .large }) |class| {
        const buffer = try buffers.acquire(io, class);
        const text = url_mod.resolve(run.url_text, location, buffer) catch |err| {
            buffers.release(io, buffer);
            switch (err) {
                error.NoSpaceLeft => continue,
                error.InvalidUrl => return error.InvalidRedirect,
            }
        };
        return .{ .buffer = buffer, .text = text };
    }
    return error.InvalidRedirect;
}

/// A status the retries cover: how long to wait before sending again.
fn retryStatus(run: *Run, io: Io, response: *Response) Error!Next {
    const r = run.retries;
    if (!r.retriesStatus(response.status)) return .done;
    if (run.tries >= r.max_attempts or !run.body.replayable()) return .done;
    if (!run.method.idempotent() and !policy.notActedOn(response.status)) return .done;
    var wait = r.backoff(run.tries + 1, random(io));
    if (response.headers.getKnown(.@"retry-after")) |value| if (policy.retryAfter(value, Io.Clock.real.now(io).toSeconds())) |asked| {
        if (asked.nanoseconds > r.max_wait.nanoseconds) return .done;
        wait = asked;
    };
    if (!run.withinDeadline(io, wait)) return .done;
    return .{ .wait = .{ .duration = wait, .status = @backingInt(response.status) } };
}

/// After a failed attempt: whether to try again, having waited.
fn retryFailure(run: *Run, io: Io, err: Error) Error!bool {
    const r = run.retries;
    if (err != error.ConnectionFailed or !r.connection) return false;
    if (run.tries >= r.max_attempts or run.progress) return false;
    // Some of it may have gone: only an idempotent request whose body can
    // go again. None went: anything whose body has not been read.
    if (run.sent and !(run.method.idempotent() and run.body.replayable())) return false;
    if (!run.sent and run.body == .streamed) return false;
    const wait = r.backoff(run.tries + 1, random(io));
    if (!run.withinDeadline(io, wait)) return false;
    try run.pause(io, wait, null, @errorName(err));
    return true;
}

fn withinDeadline(run: *const Run, io: Io, wait: Io.Duration) bool {
    const d = run.deadline orelse return true;
    return Io.Clock.awake.now(io).addDuration(wait).nanoseconds < d.nanoseconds;
}

/// Wait before the next try, counting it.
fn pause(run: *Run, io: Io, wait: Io.Duration, status: ?u16, error_name: ?[]const u8) Error!void {
    run.tries += 1;
    if (run.diagnostics()) |d| d.retries +|= 1;
    if (run.shared.context.observer) |o| o.emit(.{ .retry = .{ .attempt = run.tries, .delay = wait, .status = status, .error_name = error_name } });
    if (wait.nanoseconds > 0) io.sleep(wait, .awake) catch return error.Canceled;
}

fn random(io: Io) u64 {
    var bytes: [8]u8 = undefined;
    io.random(&bytes);
    return std.mem.readInt(u64, &bytes, .little);
}
