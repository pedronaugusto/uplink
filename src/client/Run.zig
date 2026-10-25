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
const span = @import("../span.zig");
const Duration = span.Duration;
const wire = @import("uplink.wire");
const h1 = wire.h1;
const fields = wire.fields;
const url_mod = wire.url;
const auth = wire.auth;
const Method = wire.Method;
const hpack = wire.hpack;
const h2_message = wire.h2.message;
const Connection = @import("../transport/Connection.zig");
const H2 = @import("../transport/H2.zig");
const Pool = @import("../pool/Pool.zig");
const Context = @import("../transport/Context.zig");
const Diagnostics = @import("../transport/Diagnostics.zig");
const BufferPool = @import("../transport/BufferPool.zig");
const Shared = @import("Shared.zig");
const Request = @import("Request.zig");
const Response = @import("Response.zig");
const OriginAuth = @import("OriginAuth.zig");
const Prepare = @import("Prepare.zig");
const Cache = @import("Cache.zig");
const policy = @import("policy.zig");
const rules = wire.cache;
const xenoglyph = @import("xenoglyph");

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
/// When the current attempt was asked for, by the real clock, in seconds:
/// a stored response's age counts from it.
requested_at: wire.date.Second = .fromRaw(0),
/// A stale stored variant the current attempt asks the origin about (its
/// validators sent), held until the answer.
revalidating: ?Revalidating = null,

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
        c.context.deadlines.tighten(io, Io.Clock.awake.now(io).durationTo(deadline.?));
    }
    const ascii = try asciiUrl(c, io, request.url, url);
    return .{
        .shared = c,
        .request = request,
        .method = request.method,
        .body = request.body,
        .url = ascii.url,
        .url_text = ascii.text,
        .url_buffer = ascii.buffer,
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
    defer run.endRevalidating(io);
    while (true) {
        var response = pending orelse try run.fromCache(io) orelse network: {
            run.requested_at = span.calendar(io);
            const answered = run.attempt(io) catch |err| {
                if (try run.retryFailure(io, err)) continue;
                return err;
            };
            break :network try run.throughCache(io, answered);
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
    var r = Context.Route.init(run.url.secure, run.url.host, run.url.port, proxy) catch return error.InvalidUrl;
    r.protocol = run.protocolFor(r);
    return r;
}

/// Which HTTP the request may go in: HTTP/2 as the client allows it, but
/// HTTP/1.1 for what only it carries — a `CONNECT`, an `Upgrade`, a
/// request sent whole to an HTTP proxy.
fn protocolFor(run: *const Run, r: Context.Route) Context.Route.Protocol {
    const choice = run.shared.options.http2;
    if (choice == .off or run.method.eql(.CONNECT) or named(run.request.headers, "upgrade") or absoluteForm(r)) return .http1;
    if (r.secure) return .negotiate;
    return switch (choice) {
        .prior_knowledge => .h2_prior_knowledge,
        .upgrade => .h2c_upgrade,
        .off, .negotiate => .http1,
    };
}

/// Whether requests to the current URL go to an HTTP proxy whole, as
/// absolute URLs.
fn absoluteForm(r: Context.Route) bool {
    const slot = r.proxy orelse return false;
    return !r.secure and !slot.proxy.kind.socks();
}

/// A connection for an attempt: one of its own over HTTP/1.1, or a share
/// of an HTTP/2 one.
pub const Lease = struct { kind: Pool.Kind, reused: bool };

/// Give back a lease whose exchange failed: an HTTP/1.1 connection is
/// closed, a share of an HTTP/2 one returned.
pub fn releaseFailed(run: *Run, io: Io, lease: Lease) void {
    const c = run.shared;
    switch (lease.kind) {
        .h1 => |conn| Response.release(io, &c.context, &c.pool, conn, false),
        .h2 => |h| Response.releaseShared(io, &c.context, &c.pool, h),
    }
}

/// A kept connection to `r` that still looks alive, or a new one, waiting
/// for one while the route is at its limit.
pub fn acquire(run: *Run, io: Io, r: Context.Route) Error!Lease {
    const c = run.shared;
    const d = run.diagnostics();
    while (true) {
        var waited = false;
        if (c.pool.options.max_per_route != null) if (d) |x| {
            x.stage = .wait;
        };
        const got = c.pool.acquire(io, &r, run.deadline, &waited) catch |err| return switch (err) {
            error.TimedOut => {
                if (d) |x| x.timeout = .deadline;
                return error.TimedOut;
            },
            error.Canceled => error.Canceled,
            error.OutOfMemory => error.OutOfMemory,
        };
        switch (got) {
            .expired => |k| c.pool.close(io, k),
            .shared => |h| {
                _ = c.context.counters.in_use.fetchAdd(1, .monotonic);
                if (c.context.observer) |o| o.emit(.{ .reused = .{ .host = r.host(), .port = r.port } });
                return .{ .kind = .{ .h2 = h }, .reused = true };
            },
            .idle => |k| {
                // Only HTTP/1.1 connections are kept idle.
                const conn = k.h1;
                conn.unpark(io, d, run.deadline) catch {
                    c.pool.close(io, .{ .h1 = conn });
                    return error.OutOfMemory;
                };
                const alive = conn.alive(io) catch {
                    c.pool.close(io, .{ .h1 = conn });
                    return error.Canceled;
                };
                if (!alive) {
                    c.pool.close(io, .{ .h1 = conn });
                    continue;
                }
                _ = c.context.counters.in_use.fetchAdd(1, .monotonic);
                if (c.context.observer) |o| o.emit(.{ .reused = .{ .host = r.host(), .port = r.port } });
                return .{ .kind = .{ .h1 = conn }, .reused = true };
            },
            .open => {
                const conn = Connection.open(&c.context, io, r, .{ .diagnostics = d, .deadline = run.deadline }) catch |err| {
                    c.pool.closed(io, &r);
                    return switch (err) {
                        error.InvalidHostName => error.InvalidUrl,
                        else => |e| e,
                    };
                };
                _ = c.context.counters.in_use.fetchAdd(1, .monotonic);
                if (!conn.speaksH2()) return .{ .kind = .{ .h1 = conn }, .reused = false };
                return .{ .kind = .{ .h2 = try run.multiplex(io, conn) }, .reused = false };
            },
        }
    }
}

/// Speak HTTP/2 on `conn`, just opened, and share it with the route's
/// other exchanges.
fn multiplex(run: *Run, io: Io, conn: *Connection) Error!*H2 {
    const c = run.shared;
    const h = H2.create(&c.context, io, conn) catch |err| {
        _ = c.context.counters.in_use.fetchSub(1, .monotonic);
        c.pool.close(io, .{ .h1 = conn });
        return err;
    };
    h.users.store(1, .monotonic);
    c.pool.share(io, h) catch {
        _ = c.context.counters.in_use.fetchSub(1, .monotonic);
        h.users.store(0, .monotonic);
        c.pool.close(io, .{ .h2 = h });
        return error.OutOfMemory;
    };
    return h;
}

/// One attempt: a connection, the request on it, the response's head. A
/// kept connection that fails before a byte of the response comes back is
/// replaced once, when the request can go again; a request an HTTP/2
/// server refused unprocessed goes again on another connection.
fn attempt(run: *Run, io: Io) Error!Response {
    const c = run.shared;
    const r = try run.route(io);
    var resent = false;
    var refusals: u8 = 0;
    while (true) {
        run.sent = false;
        run.progress = false;
        run.releaseEntry(io);
        var lease = try run.acquire(io, r);
        const result = switch (lease.kind) {
            .h1 => run.exchange(io, &lease, r),
            .h2 => |h| run.exchangeH2(io, h),
        };
        const response = result catch |failure| {
            run.releaseFailed(io, lease);
            const err = switch (failure) {
                error.Refused => {
                    refusals += 1;
                    if (refusals < max_refusals) continue;
                    return error.ConnectionFailed;
                },
                else => |e| e,
            };
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

/// Requests an HTTP/2 server refuses unprocessed are sent again, on
/// another connection, this many times in all.
const max_refusals = 3;

/// Write the request on `conn` and read its response's head.
fn exchange(run: *Run, io: Io, lease: *Lease, r: Context.Route) H2Error!Response {
    const conn = lease.kind.h1;
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
    // curl asks no `100-continue` of a request that asks to upgrade.
    const expect = run.request.expect_continue and has_body and r.protocol != .h2c_upgrade;
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
    var response = try run.receive(io, conn, false);
    if (!switches(r, &response)) return response;
    return run.switchToH2(io, &response, lease);
}

/// Whether `response` is the 101 that switches a request's connection to
/// HTTP/2: the request asked (`h2c_upgrade`), and the server named `h2c`.
pub fn switches(r: Context.Route, response: *const Response) bool {
    if (r.protocol != .h2c_upgrade or response.status != .switching_protocols) return false;
    const upgrade = response.headers.get("upgrade") orelse return false;
    return std.ascii.eqlIgnoreCase(std.mem.trim(u8, upgrade, " \t"), "h2c");
}

/// After the 101 to the request's `Upgrade: h2c`: the connection goes on in
/// HTTP/2, shared, and the request's response comes on stream 1. `lease`
/// follows the connection: a share of the HTTP/2 one once it is made, the
/// HTTP/1.1 one still while it is not.
pub fn switchToH2(run: *Run, io: Io, switched: *Response, lease: *Lease) H2Error!Response {
    const c = run.shared;
    // unreachable: `switches` took a 101 whose body nobody read
    const conn = (switched.upgrade(io) catch unreachable).conn;
    switched.deinit(io);
    const up = H2.upgraded(&c.context, io, conn, run.method.eql(.HEAD)) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.ConnectionFailed => conn.writeError(),
    };
    up.h2.users.store(1, .monotonic);
    c.pool.share(io, up.h2) catch {
        up.h2.abandon();
        return error.OutOfMemory;
    };
    lease.kind = .{ .h2 = up.h2 };
    return run.receiveH2(io, up.h2, up.stream);
}

/// Errors from an exchange over HTTP/2: `Refused` when the server took
/// none of it, and it may go again.
pub const H2Error = Error || error{Refused};

/// The exchange as a stream of `h`: the head as fields, the body as data,
/// the response's head read.
fn exchangeH2(run: *Run, io: Io, h: *H2) H2Error!Response {
    const length: ?u64 = switch (run.body) {
        .none => if (run.method.eql(.POST) or run.method.eql(.PUT) or run.method.eql(.PATCH)) 0 else null,
        .bytes => |b| b.len,
        .reader => |rd| rd.length,
        .streamed => unreachable, // unreachable: a body the caller writes goes through `begin`
    };
    const has_body = switch (run.body) {
        .none => false,
        .bytes => |b| b.len != 0,
        .reader => |rd| rd.length != 0,
        .streamed => unreachable, // unreachable: as above
    };
    const expect = run.request.expect_continue and has_body;
    try run.prepareAttempt(io);
    if (run.diagnostics()) |d| d.stage = .write;
    run.sent = true;
    const st = try run.openStream(io, h, length, !has_body, expect);
    errdefer h.finish(io, st);
    if (expect) if (try run.awaitContinueH2(io, h, st)) |refused| return refused;
    switch (run.body) {
        .none, .streamed => {},
        .bytes => |b| if (b.len != 0) try run.sendH2(io, h, st, b, true),
        .reader => |rd| if (has_body) try run.sendReaderH2(io, h, st, rd.reader, rd.length),
    }
    return run.receiveH2(io, h, st);
}

/// Open the request's stream on `h`: its head as HTTP/2 fields, the
/// pseudo-fields first, then the fields HTTP/1.1 would write, less those
/// of a connection's own; `end_stream` when no body follows.
pub fn openStream(run: *Run, io: Io, h: *H2, length: ?u64, end_stream: bool, expect: bool) H2Error!*H2.Stream {
    const c = run.shared;
    const buffer = try c.context.buffers.acquire(io, .large);
    defer c.context.buffers.release(io, buffer);
    var w: Io.Writer = .fixed(buffer);
    var list: [max_fields]hpack.Field = undefined;
    const r = h.conn.route;
    run.url.writeAuthority(&w, false) catch return error.InvalidHeader;
    const authority_end = w.end;
    run.url.writeTarget(&w) catch return error.InvalidHeader;
    const target = buffer[authority_end..w.end];
    list[0] = .{ .name = ":method", .value = run.method.name };
    list[1] = .{ .name = ":scheme", .value = if (r.secure) "https" else "http" };
    list[2] = .{ .name = ":authority", .value = buffer[0..authority_end] };
    list[3] = .{ .name = ":path", .value = if (target.len == 0) "/" else target };
    const lines_start = w.end;
    const framing: h1.Framing = if (length) |n| .{ .length = n } else .none;
    run.writeFields(io, &w, r, false, framing, expect) catch return error.InvalidHeader;
    const n = h2_message.appendLines(&list, 4, buffer[lines_start..w.end]) catch return error.InvalidHeader;
    for (list[4..n]) |*f| f.never_index = isCredential(f.name);
    return h.open(io, list[0..n], end_stream, run.method.eql(.HEAD)) catch |err| run.h2Failure(io, err);
}

/// A run's error where nothing can go again: a refusal is a failed
/// connection, as a body the caller streamed cannot be sent twice.
pub fn noRefusal(err: H2Error) Error {
    return switch (err) {
        error.Refused => error.ConnectionFailed,
        else => |e| e,
    };
}

/// The most fields a request sends over HTTP/2.
const max_fields = 256;

/// What a stream's failure means for the run.
pub fn h2Failure(run: *Run, io: Io, err: H2.Error) H2Error {
    return switch (err) {
        error.TimedOut => {
            if (run.diagnostics()) |d| d.timeout = if (run.deadline) |t| (if (Io.Clock.awake.now(io).nanoseconds >= t.nanoseconds) .deadline else .activity) else .activity;
            return error.TimedOut;
        },
        error.Refused => error.Refused,
        error.ConnectionFailed => error.ConnectionFailed,
        error.TlsFailed => error.TlsFailed,
        error.ClientCertificateRejected => error.ClientCertificateRejected,
        error.Canceled => error.Canceled,
        error.OutOfMemory => error.OutOfMemory,
    };
}

/// Send `bytes` of the body on `st`.
pub fn sendH2(run: *Run, io: Io, h: *H2, st: *H2.Stream, bytes: []const u8, end_stream: bool) H2Error!void {
    h.send(io, st, bytes, end_stream, run.deadline) catch |err| return run.h2Failure(io, err);
}

/// A body from a reader, as data: exactly `length` bytes, or to its end.
fn sendReaderH2(run: *Run, io: Io, h: *H2, st: *H2.Stream, source: *Io.Reader, length: ?u64) H2Error!void {
    const buffer = try run.shared.context.buffers.acquire(io, .record);
    defer run.shared.context.buffers.release(io, buffer);
    var left = length;
    while (true) {
        const want: usize = if (left) |n| @min(n, buffer.len) else buffer.len;
        if (want == 0) return run.sendH2(io, h, st, "", true);
        const got = source.readSliceShort(buffer[0..want]) catch return error.BodyReadFailed;
        if (got == 0) {
            if (left != null) return error.BodyIncomplete;
            return run.sendH2(io, h, st, "", true);
        }
        if (left) |*n| n.* -= got;
        try run.sendH2(io, h, st, buffer[0..got], false);
    }
}

/// After a head that asked `Expect: 100-continue` on `st`: null to send
/// the body — an interim head came, or nothing in time; else the server's
/// final answer, and the body is never sent.
pub fn awaitContinueH2(run: *Run, io: Io, h: *H2, st: *H2.Stream) H2Error!?Response {
    const until = Io.Clock.awake.now(io).addDuration(span.toIo(run.shared.options.expect_continue_timeout));
    h.awaitInterim(io, st, until) catch |err| return run.h2Failure(io, err);
    if (st.status == null) return null;
    return try run.receiveH2(io, h, st);
}

/// Read the response's head on `st`, which the response then holds.
pub fn receiveH2(run: *Run, io: Io, h: *H2, st: *H2.Stream) H2Error!Response {
    const c = run.shared;
    if (c.context.observer) |o| {
        o.emit(.{ .sent = .{ .method = run.method.name, .url = run.url_text } });
        run.sent_at = Io.Clock.awake.now(io);
    }
    if (run.diagnostics()) |d| d.stage = .head;
    h.awaitHead(io, st, run.deadline) catch |err| return run.h2Failure(io, err);
    run.progress = true;
    const response = try Response.fromStream(io, &c.context, &c.pool, h, st, .{
        .method = run.method,
        .decompress = c.options.decompress,
        .deadline = run.deadline,
    });
    if (run.diagnostics()) |d| d.stage = .body;
    if (c.context.observer) |o| o.emit(.{ .head = .{ .status = @backingInt(response.status), .wait = span.of(run.sent_at.?.durationTo(Io.Clock.awake.now(io))) } });
    return response;
}

/// After a head that asked `Expect: 100-continue`: wait for the server's
/// word. Null to send the body — a 100 came, or nothing came in time;
/// else the server's final answer, sent before the body, which then is
/// never sent and the connection never reused.
pub fn awaitContinue(run: *Run, io: Io, conn: *Connection) Error!?Response {
    if (!try conn.readable(io, span.toIo(run.shared.options.expect_continue_timeout))) return null;
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
    if (c.context.observer) |o| o.emit(.{ .head = .{ .status = @backingInt(response.status), .wait = span.of(run.sent_at.?.durationTo(Io.Clock.awake.now(io))) } });
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
    if (r.protocol == .h2c_upgrade) {
        // curl's `Curl_http2_request_upgrade`, its fields as it writes them.
        var b64: [H2.upgrade_settings_len]u8 = undefined;
        try w.print("Connection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: {s}\r\n", .{H2.upgradeSettings(&b64)});
    }
    try run.writeFields(io, w, r, conn.absolute_form, framing, expect);
    try w.writeAll("\r\n");
}

/// The request's fields after `Host`, each a line, as HTTP/1.1 writes them
/// and HTTP/2 takes them in.
fn writeFields(run: *Run, io: Io, w: *Io.Writer, r: Context.Route, absolute_form: bool, framing: h1.Framing, expect: bool) Io.Writer.Error!void {
    const c = run.shared;
    const url = run.url;
    if (absolute_form) {
        // Answered for with the path as the Digest target.
        const path = if (url.target.len != 0 and url.target[0] == '/') url.target else "/";
        const slot = r.proxy.?;
        _ = try slot.auth.writeField(io, w, slot.proxy.credential, run.method.name, path);
    }
    if (c.options.user_agent) |ua| if (!named(run.request.headers, "user-agent")) try h1.writeField(w, .{ .name = "User-Agent", .value = ua });
    if (c.options.decompress and run.offersCodings()) try w.writeAll("Accept-Encoding: gzip, deflate, zstd\r\n");
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
    if (run.revalidating) |*v| {
        if (v.etag) |etag| if (!named(run.request.headers, "if-none-match")) try h1.writeField(w, .{ .name = "If-None-Match", .value = etag });
        if (v.modified) |modified| if (!named(run.request.headers, "if-modified-since")) try h1.writeField(w, .{ .name = "If-Modified-Since", .value = modified });
    }
    if (expect) try w.writeAll("Expect: 100-continue\r\n");
    switch (framing) {
        .none, .until_close => {},
        .length => |n| try w.print("Content-Length: {d}\r\n", .{n}),
        .chunked => try w.writeAll("Transfer-Encoding: chunked\r\n"),
    }
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

/// Whether the client offers its codings: not when the request names its
/// own, asks for a range, whose bytes would be the coded ones, or is a
/// `HEAD`, whose length would be the coded one.
fn offersCodings(run: *const Run) bool {
    const headers = run.request.headers;
    return !run.method.eql(.HEAD) and !named(headers, "accept-encoding") and !named(headers, "range");
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
    wait: struct { duration: Duration, status: u16 },
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
/// request sent again; a stale Digest nonce once more.
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
    const located = try run.resolveLocation(io, location);
    const located_url = url_mod.parse(located.text) catch {
        run.shared.context.buffers.release(io, located.buffer);
        return error.InvalidRedirect;
    };
    // The name as DNS has it: the Location's text, or a copy with its host
    // in IDNA's ASCII form, which the resolved text's buffer then gives way
    // to.
    const ascii = asciiUrl(run.shared, io, located.text, located_url) catch |err| {
        run.shared.context.buffers.release(io, located.buffer);
        return switch (err) {
            error.InvalidUrl => error.InvalidRedirect,
            else => err,
        };
    };
    var resolved = located;
    if (ascii.buffer.len != 0) {
        run.shared.context.buffers.release(io, located.buffer);
        resolved = .{ .buffer = ascii.buffer, .text = ascii.text };
    }
    var keep = true;
    defer if (keep) run.shared.context.buffers.release(io, resolved.buffer);
    const next = ascii.url;
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

const Resolved = struct { buffer: []u8, text: []const u8 };

/// `location` resolved against the current URL, in a buffer from the
/// pool.
/// A URL with its host as DNS has it, and the pooled buffer its text is in
/// (empty when it is the text it came from).
const AsciiUrl = struct { url: url_mod.Url, text: []const u8, buffer: []u8 };

/// `text`, which parsed as `u`, with its host in IDNA's ASCII form (UTS #46
/// ToASCII with the URL Standard's options, xenoglyph's `idna`): `text`
/// itself when its host is that already, else a copy in a pooled buffer.
/// A host IDNA refuses is an invalid URL.
fn asciiUrl(c: *Shared, io: Io, text: []const u8, u: url_mod.Url) Error!AsciiUrl {
    if (u.ipv6()) return .{ .url = u, .text = text, .buffer = &.{} };
    var host_bytes: [256]u8 = undefined;
    var w: Io.Writer = .fixed(&host_bytes);
    const failures = xenoglyph.idna.toAscii(u.host, &w, .url) catch return error.InvalidUrl;
    if (failures.any()) return error.InvalidUrl;
    const host = w.buffered();
    if (std.mem.eql(u8, host, u.host)) return .{ .url = u, .text = text, .buffer = &.{} };
    const buffers = &c.context.buffers;
    for ([_]BufferPool.Class{ .small, .record, .large }) |class| {
        const buffer = try buffers.acquire(io, class);
        const mapped = url_mod.withHost(text, u, host, buffer) catch {
            buffers.release(io, buffer);
            continue;
        };
        const parsed = url_mod.parse(mapped) catch {
            buffers.release(io, buffer);
            return error.InvalidUrl;
        };
        return .{ .url = parsed, .text = mapped, .buffer = buffer };
    }
    return error.InvalidUrl;
}

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
    if (response.headers.getKnown(.@"retry-after")) |value| if (policy.retryAfter(value, span.calendar(io))) |asked| {
        if (asked.compare(r.max_wait) == .gt) return .done;
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

fn withinDeadline(run: *const Run, io: Io, wait: Duration) bool {
    const d = run.deadline orelse return true;
    return Io.Clock.awake.now(io).addDuration(span.toIo(wait)).nanoseconds < d.nanoseconds;
}

/// Wait before the next try, counting it.
fn pause(run: *Run, io: Io, wait: Duration, status: ?u16, error_name: ?[]const u8) Error!void {
    run.tries += 1;
    if (run.diagnostics()) |d| d.retries +|= 1;
    if (run.shared.context.observer) |o| o.emit(.{ .retry = .{ .attempt = run.tries, .delay = wait, .status = status, .error_name = error_name } });
    if (wait.compare(.fromRaw(0)) == .gt) io.sleep(span.toIo(wait), .awake) catch return error.Canceled;
}

fn random(io: Io) u64 {
    var bytes: [8]u8 = undefined;
    io.random(&bytes);
    return std.mem.readInt(u64, &bytes, .little);
}

// The cache (RFC 9111): a stored response answers when it may, a stale
// one is revalidated, a response from the network is stored as it is read,
// and an unsafe method's success invalidates.

/// A stored variant parsed for its rules: its head copied with its fields,
/// held with the variant.
const Revalidating = struct {
    entry: Cache.Entry,
    parsed: Parsed,
    etag: ?[]const u8,
    modified: ?[]const u8,
};

/// A stored head parsed into memory of the client's allocator.
const Parsed = struct {
    bytes: []u8,
    fields: []fields.Field,
    status: u16,
    headers: fields.Headers,

    fn deinit(p: *Parsed, gpa: std.mem.Allocator) void {
        gpa.free(p.bytes);
        gpa.free(p.fields);
        p.* = undefined;
    }
};

fn parseStored(run: *Run, head: []const u8) ?Parsed {
    const gpa = run.shared.context.gpa;
    const limits = run.shared.options.limits;
    const bytes = gpa.alloc(u8, head.len + 2) catch return null;
    @memcpy(bytes[0..head.len], head);
    @memcpy(bytes[head.len..], "\r\n");
    const storage = gpa.alloc(fields.Field, limits.max_fields) catch {
        gpa.free(bytes);
        return null;
    };
    const parsed = (h1.parseResponse(bytes, storage, limits) catch null) orelse {
        gpa.free(bytes);
        gpa.free(storage);
        return null;
    };
    return .{ .bytes = bytes, .fields = storage, .status = @backingInt(parsed.head.status), .headers = parsed.head.headers };
}

fn endRevalidating(run: *Run, io: Io) void {
    var v = run.revalidating orelse return;
    run.revalidating = null;
    v.parsed.deinit(run.shared.context.gpa);
    run.shared.options.cache.?.store.release(io, &v.entry);
}

fn cacheFailed(run: *Run, err: anyerror) void {
    if (run.shared.context.observer) |o| o.emit(.{ .cache_failed = .{ .error_name = @errorName(err) } });
}

fn cacheSaid(run: *Run, status: Response.CacheStatus) void {
    if (run.shared.context.observer) |o| o.emit(.{ .cache = .{ .url = run.url_text, .status = @tagName(status) } });
}

/// The request's fields as the cache's rules read them.
fn requestFields(run: *Run, out: []fields.Field) fields.Headers {
    const n = @min(out.len, run.request.headers.len);
    for (run.request.headers[0..n], out[0..n]) |h, *f| f.* = .{ .name = h.name, .value = h.value };
    return .init(out[0..n]);
}

/// The value the request sends for a field `Vary` names: the caller's,
/// else the client's own (`User-Agent`, `Accept-Encoding`).
fn fieldValue(run: *Run, name: []const u8) ?[]const u8 {
    for (run.request.headers) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    if (std.ascii.eqlIgnoreCase(name, "user-agent")) return run.shared.options.user_agent;
    if (std.ascii.eqlIgnoreCase(name, "accept-encoding") and run.shared.options.decompress and run.offersCodings()) return "gzip, deflate, zstd";
    return null;
}

/// A response the cache gives for the current URL without going to the
/// network, or null to go: then, for a stale variant with validators,
/// `revalidating` holds it and the attempt asks the origin about it.
fn fromCache(run: *Run, io: Io) Error!?Response {
    const c = run.shared;
    const cache = c.options.cache orelse return null;
    if (!run.method.eql(.GET)) return null;
    run.endRevalidating(io);
    var field_buf: [64]fields.Field = undefined;
    const request_fields = run.requestFields(&field_buf);
    const asked = rules.readRequest(&request_fields);
    if (asked.no_store and !asked.only_if_cached) return null;
    var found: [Cache.max_variants]Cache.Entry = undefined;
    const n = cache.store.lookup(io, run.url_text, &found) catch |err| {
        run.cacheFailed(err);
        return null;
    };
    var chosen: ?Cache.Entry = null;
    for (found[0..n]) |*e| {
        if (chosen == null and Cache.varyMatches(e.meta.vary, run, fieldValue)) chosen = e.* else cache.store.release(io, e);
    }
    const entry = chosen orelse {
        if (asked.only_if_cached) return try run.synthesized(io, cache);
        run.cacheSaid(.miss);
        return null;
    };
    var parsed = run.parseStored(entry.head) orelse {
        cache.store.release(io, &entry);
        run.cacheFailed(error.StoreFailed);
        return null;
    };
    const now = span.calendar(io);
    const age = rules.currentAge(&parsed.headers, .{ .requested = entry.meta.requested, .received = entry.meta.received }, now);
    const life = rules.lifetime(cache.options.kind, parsed.status, &parsed.headers, cache.options.heuristic_cap.raw()) orelse 0;
    switch (rules.use(cache.options.kind, &parsed.headers, life, age, asked)) {
        .fresh, .stale => |use| {
            parsed.deinit(c.context.gpa);
            return try run.serve(io, cache, entry, age, if (use == .fresh) .hit else .stale);
        },
        .revalidate => {
            const etag = parsed.headers.get("etag");
            const modified = parsed.headers.get("last-modified");
            if (asked.only_if_cached or (etag == null and modified == null)) {
                parsed.deinit(c.context.gpa);
                cache.store.release(io, &entry);
                if (asked.only_if_cached) return try run.synthesized(io, cache);
                run.cacheSaid(.miss);
                return null;
            }
            run.revalidating = .{ .entry = entry, .parsed = parsed, .etag = etag, .modified = modified };
            return null;
        },
    }
}

/// A stored variant served, `age` seconds old (§4, §5.1): its head with
/// `Age` and its body's length, its body from the store.
fn serve(run: *Run, io: Io, cache: *Cache, entry: Cache.Entry, age: u32, status: Response.CacheStatus) Error!Response {
    const c = run.shared;
    const head = c.context.gpa.print("{s}Age: {d}\r\nContent-Length: {d}\r\n\r\n", .{ entry.head, age, entry.body.len() }) catch {
        cache.store.release(io, &entry);
        return error.OutOfMemory;
    };
    defer c.context.gpa.free(head);
    const response = Response.fromStored(io, &c.context, &c.pool, cache, entry, head, status, .{ .method = run.method, .limits = c.options.limits, .decompress = c.options.decompress }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.HttpProtocolError => {
            run.cacheFailed(error.StoreFailed);
            return error.HttpProtocolError;
        },
    };
    run.cacheSaid(status);
    return response;
}

/// The 504 `only-if-cached` gets when nothing stored may answer
/// (§5.2.1.7).
fn synthesized(run: *Run, io: Io, cache: *Cache) Error!Response {
    const c = run.shared;
    const response = Response.fromStored(io, &c.context, &c.pool, cache, null, "HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 0\r\n\r\n", .synthesized, .{ .method = run.method, .limits = c.options.limits, .decompress = false }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.HttpProtocolError => unreachable, // unreachable: the head is this file's own, and parses
    };
    run.cacheSaid(.synthesized);
    return response;
}

/// A response from the network, through the cache: a 304 answering a
/// revalidation becomes the stored variant with its head brought up to
/// date (§4.3.4); a 5xx answering one, the stale variant where
/// `stale-if-error` allows (RFC 5861); an unsafe method's success removes
/// what it changed (§4.4); and a response that may be stored goes into
/// the store as it is read (§3).
fn throughCache(run: *Run, io: Io, response: Response) Error!Response {
    const c = run.shared;
    const cache = c.options.cache orelse return response;
    var r = response;
    const status = @backingInt(r.status);
    if (!run.method.safe()) {
        if (status < 400) run.invalidate(io, cache, &r);
        return r;
    }
    if (!run.method.eql(.GET)) return r;
    r.cache = .miss;
    if (run.revalidating) |*v| {
        const now = span.calendar(io);
        if (status == 304) {
            const merged = mergeHead(c.context.gpa, &v.parsed, &r.headers) catch {
                run.cacheFailed(error.OutOfMemory);
                return r;
            };
            defer c.context.gpa.free(merged);
            const meta: Cache.Meta = .{ .requested = run.requested_at, .received = now, .vary = v.entry.meta.vary };
            cache.store.update(io, &v.entry, meta, merged) catch |err| run.cacheFailed(err);
            const entry = v.entry;
            v.parsed.deinit(c.context.gpa);
            run.revalidating = null;
            r.deinit(io);
            // `entry` still names the variant's old head; the merged one
            // is the head served.
            var served = entry;
            served.head = merged;
            return try run.serve(io, cache, served, 0, .revalidated);
        }
        if (status >= 500) {
            const stored = rules.readResponse(&v.parsed.headers);
            const age = rules.currentAge(&v.parsed.headers, .{ .requested = v.entry.meta.requested, .received = v.entry.meta.received }, now);
            const life = rules.lifetime(cache.options.kind, v.parsed.status, &v.parsed.headers, cache.options.heuristic_cap.raw()) orelse 0;
            if (stored.stale_if_error) |allowed| if (age -| life <= allowed and !stored.must_revalidate) {
                const entry = v.entry;
                v.parsed.deinit(c.context.gpa);
                run.revalidating = null;
                r.deinit(io);
                return try run.serve(io, cache, entry, age, .stale);
            };
        }
        run.endRevalidating(io);
    }
    var field_buf: [64]fields.Field = undefined;
    const request_fields = run.requestFields(&field_buf);
    if (!rules.storable(cache.options.kind, true, status, &request_fields, &r.headers)) {
        run.cacheSaid(.miss);
        return r;
    }
    const vary = (Cache.varyOf(c.context.gpa, r.headers.get("vary"), run, fieldValue) catch {
        run.cacheFailed(error.OutOfMemory);
        return r;
    }) orelse {
        run.cacheSaid(.miss);
        return r;
    };
    defer c.context.gpa.free(vary);
    const head = storedHead(c.context.gpa, &r) catch {
        run.cacheFailed(error.OutOfMemory);
        return r;
    };
    defer c.context.gpa.free(head);
    const meta: Cache.Meta = .{ .requested = run.requested_at, .received = span.calendar(io), .vary = vary };
    const writing = cache.store.begin(io, run.url_text, meta, head) catch |err| {
        run.cacheFailed(err);
        return r;
    };
    if (writing) |w| r.storeInto(cache, w);
    run.cacheSaid(.miss);
    return r;
}

/// Fields a cache neither stores nor takes from a 304: the connection's
/// own (RFC 9110 §7.6.1), the framing, which a stored body has its own of,
/// and `Age`, which the cache sets (§3.1, §3.2).
fn notStored(name: []const u8) bool {
    for ([_][]const u8{ "connection", "keep-alive", "proxy-connection", "te", "transfer-encoding", "upgrade", "trailer", "proxy-authenticate", "proxy-authorization", "content-length", "age" }) |n| if (std.ascii.eqlIgnoreCase(name, n)) return true;
    return false;
}

/// A response's head as the store keeps it: its status line and the fields
/// a cache keeps, each a line, with no blank line after.
fn storedHead(gpa: std.mem.Allocator, r: *const Response) std.mem.Allocator.Error![]u8 {
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    const w = &out.writer;
    w.print("HTTP/1.1 {d} {s}\r\n", .{ @backingInt(r.status), if (r.reason.len != 0) r.reason else r.status.phrase() orelse "" }) catch return error.OutOfMemory;
    var it = r.headers.iterator();
    while (it.next()) |f| if (!notStored(f.name)) h1.writeField(w, .{ .name = f.name, .value = f.value }) catch return error.OutOfMemory;
    return out.toOwnedSlice() catch return error.OutOfMemory;
}

/// The stored head brought up to date by a 304's fields (§3.2): each field
/// the 304 sends replaces the stored ones of its name; the rest stay.
fn mergeHead(gpa: std.mem.Allocator, stored: *const Parsed, answered: *const fields.Headers) std.mem.Allocator.Error![]u8 {
    var out: std.Io.Writer.Allocating = .init(gpa);
    errdefer out.deinit();
    const w = &out.writer;
    const line_end = std.mem.findScalar(u8, stored.bytes, '\n').? + 1;
    w.writeAll(stored.bytes[0..line_end]) catch return error.OutOfMemory;
    var kept = stored.headers.iterator();
    while (kept.next()) |f| {
        if (notStored(f.name)) continue;
        if (answered.get(f.name) != null and !notStored(f.name)) continue;
        h1.writeField(w, .{ .name = f.name, .value = f.value }) catch return error.OutOfMemory;
    }
    var fresh = answered.iterator();
    while (fresh.next()) |f| if (!notStored(f.name)) h1.writeField(w, .{ .name = f.name, .value = f.value }) catch return error.OutOfMemory;
    return out.toOwnedSlice() catch return error.OutOfMemory;
}

/// An unsafe method's success removes the stored responses of its URL, and
/// of `Location` and `Content-Location` on the same origin (§4.4).
fn invalidate(run: *Run, io: Io, cache: *Cache, r: *const Response) void {
    cache.store.remove(io, run.url_text) catch |err| run.cacheFailed(err);
    for ([_][]const u8{ "location", "content-location" }) |name| {
        const reference = r.headers.get(name) orelse continue;
        var buffer: [2048]u8 = undefined;
        const target = url_mod.resolve(run.url_text, reference, &buffer) catch continue;
        const parsed = url_mod.parse(target) catch continue;
        if (!sameOrigin(run.url, parsed)) continue;
        cache.store.remove(io, target) catch |err| run.cacheFailed(err);
    }
}

fn sameOrigin(a: url_mod.Url, b: url_mod.Url) bool {
    return a.secure == b.secure and std.ascii.eqlIgnoreCase(a.host, b.host) and a.port == b.port;
}
