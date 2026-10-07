//! An HTTP/1.1 client: requests over kept connections, through a proxy when
//! one is set, with TLS, timeouts, decompression, redirects, retries,
//! cookies and answers to servers' and proxies' challenges.
//!
//! A client may be used by several tasks at once. It must not move once it
//! has made a request: connections point at its shared state.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Request = @import("Request.zig");
const Response = @import("Response.zig");
const Outgoing = @import("Outgoing.zig");
const Run = @import("Run.zig");
const Shared = @import("Shared.zig");

const Client = @This();

/// Private: the connections, the pool, the answers and the options.
shared: Shared,

/// A client with `options`. Nothing is allocated until the first request.
pub fn init(gpa: Allocator, options: Options) Client {
    var o = options;
    o.limits.max_head = @min(o.limits.max_head, 64 << 10);
    o.limits.max_fields = @min(o.limits.max_fields, 256);
    return .{ .shared = .{
        .context = .init(gpa, .{
            .proxy = options.proxy,
            .tls = options.tls,
            .timeouts = options.timeouts,
            .dial = options.dial,
            .resolver = options.resolver,
            .dns_cache = options.dns_cache,
            .observer = options.observer,
            .max_zstd_window = options.max_zstd_window,
            .max_free_buffers = @as(u32, options.pool.max_idle) * 2 + 4,
        }),
        .pool = .init(gpa, options.pool),
        .origin_auth = .init(gpa),
        .options = o,
    } };
}

/// Close every kept connection, TLS close_notify sent as a courtesy within
/// the activity timeout, and release everything. Exchanges still holding
/// connections must have been released first.
pub fn deinit(c: *Client, io: Io) void {
    const s = &c.shared;
    while (s.pool.drain(io)) |k| switch (k) {
        .h1 => |conn| Response.closeConnection(io, &s.pool, conn),
    };
    s.pool.deinit();
    s.origin_auth.deinit();
    s.context.deinit(io);
    c.* = undefined;
}

/// How a client connects and what it does with what comes back.
pub const Options = Shared.Options;

/// Why a request failed.
pub const SendError = Shared.SendError;

/// A request, to its final response: connect or reuse, write the request,
/// read the response's head, and follow the policy — redirects, retries,
/// challenges answered — until a response is the answer. The body is read
/// through the response.
pub fn send(c: *Client, io: Io, request: Request) SendError!Response {
    if (request.body == .streamed) return error.InvalidBody;
    var run: Run = try .init(&c.shared, io, request);
    defer run.deinit(io);
    return run.complete(io, null);
}

/// Start a request whose body the caller writes: the request's body must
/// be `.streamed`, or `.none` for chunks. The head goes out with the body;
/// `Outgoing.finish` reads the response and follows the policy, though no
/// redirect or retry can send a body the caller streamed again.
pub fn begin(c: *Client, io: Io, request: Request) SendError!Outgoing {
    const length: ?u64 = switch (request.body) {
        .streamed => |s| s.length,
        .none => null,
        .bytes, .reader => return error.InvalidBody,
    };
    const s = &c.shared;
    var run: Run = try .init(s, io, request);
    errdefer run.deinit(io);
    run.body = .{ .streamed = .{ .length = length } };
    const r = try run.route(io);
    const lease = try run.acquire(io, r);
    errdefer Response.release(io, &s.context, &s.pool, lease.conn, false);
    const buffer = try s.context.buffers.acquire(io, .record);
    errdefer s.context.buffers.release(io, buffer);
    try run.prepareAttempt(io);
    if (request.diagnostics) |d| d.stage = .write;
    run.sent = true;
    run.writeHead(io, lease.conn, r, if (length) |n| .{ .length = n } else .chunked, false) catch
        return lease.conn.writeError();
    if (lease.reused) _ = s.context.counters.reused.fetchAdd(1, .monotonic);
    return .init(run, lease.conn, buffer, length);
}

/// What a client has done, read without a lock.
pub const Stats = struct {
    connections_opened: u64,
    /// Exchanges that went over a kept connection: a stale one replaced
    /// by a new connection does not count.
    reused: u64,
    idle: u32,
    in_use: u32,
    /// Timeouts asked for that could not be kept: no task to keep them, and
    /// an `Io` that cannot bound the operation itself.
    timeouts_unenforced: u64,
};

pub fn stats(c: *const Client) Stats {
    const k = &c.shared.context.counters;
    return .{
        .connections_opened = k.opened.load(.monotonic),
        .reused = k.reused.load(.monotonic),
        .idle = c.shared.pool.count(),
        .in_use = k.in_use.load(.monotonic),
        .timeouts_unenforced = k.timeouts_unenforced.load(.monotonic),
    };
}
