//! An HTTP/1.1 server: it accepts connections, reads the requests on each
//! in order, pipelined ones included, and hands every request to one
//! `Handler`, which answers it through a `Response`. TLS is cloak's.
//!
//! `serve` accepts until `shutdown`, each connection a task of its own
//! started with `io.concurrent`. On an `Io` with no task to spare it
//! serves one connection at a time, to its end, and then the next: it never
//! deadlocks, and says so here because it is slower. `serveConnection`
//! serves one connection a caller accepted itself.
//!
//! Every wait has a limit (`Timeouts`): the whole of a request's head
//! (slowloris), the time between requests, each read and write while a
//! request is answered, the TLS handshake. Like the client's, they are kept
//! by reactor's deadlines, in the kernel on a reactor runtime and by one
//! task on any other `Io`, never a task per connection.
//!
//! The grammar is strict, as a server's must be: a bare LF or a folded
//! field is a 400, a request with both `Transfer-Encoding` and
//! `Content-Length`, or whose last coding is not `chunked`, is a 400 and
//! closes its connection, a head past `max_head` is a 431 and a body past
//! `max_body` a 413.
//!
//! A server must not move once `serve` or `serveConnection` was called:
//! its connections point at it.

const std = @import("std");
const aegis = @import("aegis");
const reactor = @import("reactor");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const wire = @import("uplink.wire");
const h1 = wire.h1;
const tls = @import("../tls.zig");
const span = @import("../span.zig");
const Duration = span.Duration;
const sys = @import("../net/sys.zig");
const BufferPool = @import("../transport/BufferPool.zig");
const Timed = @import("../transport/Timed.zig");
const ZstdBuffer = @import("../coding/ZstdBuffer.zig");
const Connection = @import("Connection.zig");
const Request = @import("Request.zig");
const Response = @import("Response.zig");

const Server = @This();

gpa: Allocator,
options: Options,
handler: Handler,
/// Private: the buffers connections and requests borrow.
buffers: BufferPool,
/// Private: the deadlines of every connection's operations.
deadlines: reactor.net.Deadlines,
/// Private: the buffer a zstd request body is decoded in.
zstd: ZstdBuffer,
/// Private: the connections being served, for `shutdown`.
live: aegis.BlockingGuarded(Live),
/// Private: set by `shutdown`.
stopping: std.atomic.Value(bool) = .init(false),
/// Private: the connection tasks `serve` started.
tasks: Io.Group = .init,
/// Private: the accept loop, when it runs as a task of its own.
acceptor: Io.Group = .init,
/// Private: set when the accept loop has stopped.
accepting_done: Io.Event = .unset,
/// Private: whether `serve` or `shutdown` has taken the accept loop's
/// group to cancel: one of them, once, since a group is not canceled from
/// two tasks at once.
acceptor_taken: std.atomic.Value(bool) = .init(false),
/// Private: set when `shutdown` finds no connection left.
drained: Io.Event = .unset,
counters: Counters = .{},

/// What the server does for each request.
pub const Handler = struct {
    context: ?*anyopaque,
    handleFn: *const fn (context: ?*anyopaque, io: Io, request: *Request, response: *Response) anyerror!void,

    /// Answer `request` through `response`. An error before the response's
    /// head was sent is answered with a 500; after it, the connection is
    /// closed, an unfinished chunked body cut without its last chunk, so
    /// the client sees a truncation, never a short success. A handler's own
    /// errors pass through whatever they are: the server needs to know only
    /// that one happened, and the observer is told its name.
    pub fn handle(h: Handler, io: Io, request: *Request, response: *Response) anyerror!void {
        return h.handleFn(h.context, io, request, response);
    }

    /// A handler calling `function` with `context`, a pointer whose type
    /// the function takes.
    pub fn init(context: anytype, comptime function: fn (@TypeOf(context), Io, *Request, *Response) anyerror!void) Handler {
        const Context = @TypeOf(context);
        return .{
            .context = @ptrCast(@constCast(context)),
            .handleFn = struct {
                fn call(erased: ?*anyopaque, io: Io, request: *Request, response: *Response) anyerror!void {
                    const typed: Context = @ptrCast(@alignCast(erased)); // safe: `init` erased a pointer of this type
                    return function(typed, io, request, response);
                }
            }.call,
        };
    }

    /// A handler calling `function`, which needs no context.
    pub fn of(comptime function: fn (Io, *Request, *Response) anyerror!void) Handler {
        return .{ .context = null, .handleFn = struct {
            fn call(_: ?*anyopaque, io: Io, request: *Request, response: *Response) anyerror!void {
                return function(io, request, response);
            }
        }.call };
    }
};

/// How a server reads, limits and answers.
pub const Options = struct {
    /// The largest request head, its blank line included, at most 64 KiB:
    /// past it, a 431. And the most fields in one.
    limits: h1.Limits = .{ .max_head = .literal("16KiB"), .max_fields = 100 },
    /// The largest request body: past it a 413, or, for a body whose
    /// length was not declared, a failed read. Null is no limit.
    max_body: ?aegis.units.Bytes(u64) = null,
    timeouts: Timeouts = .{},
    /// Connections served at once; past it, `serve` accepts no more until
    /// one ends. Null is no limit.
    max_connections: ?u32 = null,
    /// TLS on every connection; null serves plain HTTP.
    tls: ?tls.ServerOptions = null,
    /// Decode a request body under gzip, deflate or zstd, as the client
    /// decodes a response's, its checksums verified; a body under any other
    /// coding is handed over as it came.
    decompress: bool = true,
    /// The largest zstd window a request body may ask for.
    max_zstd_window: aegis.units.Bytes(u32) = .literal("8MiB"),
    /// Turn TCP keepalive on for accepted sockets, probing one idle this
    /// long.
    keepalive: ?Duration = null,
    /// The most of a request body left unread that the server reads, after
    /// the handler, to keep the connection; past it, the connection closes.
    drain_limit: aegis.units.Bytes(u32) = .literal("64KiB"),
    /// Told every request, with its status and timing.
    observer: ?Observer = null,
    /// The most free buffers of each size kept.
    max_free_buffers: u32 = 64,
};

/// How long each wait may take; null is no limit.
pub const Timeouts = struct {
    /// A whole request head, from its first byte (from the accept, for a
    /// connection's first): a client that sends a head a byte at a time is
    /// cut off here, whatever its pace.
    head: ?Duration = .literal("10s"),
    /// Between requests on a kept connection.
    idle: ?Duration = .literal("60s"),
    /// Any single read or write, while a request is answered, that moves
    /// nothing.
    activity: ?Duration = .literal("30s"),
    /// A TLS handshake.
    handshake: ?Duration = .literal("10s"),
    /// How long `shutdown` lets requests under way finish before it ends
    /// their connections.
    shutdown: Duration = .literal("10s"),

    fn shortest(t: Timeouts) Duration {
        var d: ?Duration = null;
        for ([_]?Duration{ t.head, t.idle, t.activity, t.handshake }) |each| d = span.shorter(d, each);
        return d orelse .literal("10s");
    }
};

/// Every request as it is answered, with its timing, in one callback,
/// which must be quick and may be called from several tasks at once.
pub const Observer = struct {
    context: ?*anyopaque = null,
    eventFn: *const fn (context: ?*anyopaque, event: Event) void,

    pub fn emit(o: Observer, event: Event) void {
        o.eventFn(o.context, event);
    }

    pub const Event = union(enum) {
        /// A connection was accepted.
        accepted: struct { remote: ?Io.net.IpAddress },
        /// A request was answered: its response's status, and how long
        /// from its head's arrival to the response's end.
        answered: struct { method: []const u8, path: []const u8, status: u16, took: Duration },
        /// A request was refused before a handler saw it.
        refused: struct { status: u16, reason: []const u8 },
        /// A handler failed.
        failed: struct { method: []const u8, path: []const u8, error_name: []const u8, head_sent: bool },
        /// A connection waited past a timeout and was closed.
        timed_out: struct { phase: Timeout },
        /// A TLS handshake failed.
        handshake_failed: struct { error_name: []const u8 },
    };
};

/// Which limit a connection ran past.
pub const Timeout = enum { head, idle, activity, handshake };

/// What a server has done, counted as it went.
pub const Counters = struct {
    accepted: std.atomic.Value(u64) = .init(0),
    requests: std.atomic.Value(u64) = .init(0),
    /// Connections open now.
    open: std.atomic.Value(u32) = .init(0),
    /// Timeouts no task and no `Io` could keep.
    timeouts_unenforced: std.atomic.Value(u64) = .init(0),
};

/// The connections being served: each is on the list while it lives, and
/// marked idle while it waits for a request, when `shutdown` may end it.
const Live = struct {
    list: std.DoublyLinkedList = .{},
    count: u32 = 0,
};

/// A server answering every request with `handler`.
pub fn init(gpa: Allocator, options: Options, handler: Handler) Server {
    aegis.assert.pre(options.limits.max_head.raw() <= 64 << 10, "a request head is at most 64 KiB");
    return .{
        .gpa = gpa,
        .options = options,
        .handler = handler,
        .buffers = .init(gpa, options.max_free_buffers),
        .deadlines = .init(span.toIo(options.timeouts.shortest())),
        .zstd = .init(options.max_zstd_window),
        .live = .init(.{}),
    };
}

/// Release what the server holds. `serve` must have returned and every
/// `serveConnection` ended.
pub fn deinit(s: *Server, io: Io) void {
    s.tasks.cancel(io);
    s.reapAcceptor(io);
    s.deadlines.deinit(io);
    s.zstd.deinit(s.gpa);
    s.buffers.deinit(io);
    s.* = undefined;
}

/// What keeps the deadlines of the server's connections.
pub fn keeper(s: *Server) Timed.Keeper {
    return .{ .deadlines = &s.deadlines, .unenforced = &s.counters.timeouts_unenforced };
}

/// Why `serve` stopped before `shutdown`.
pub const ServeError = error{
    /// The listener failed: its socket was closed or the system refused.
    AcceptFailed,
    Canceled,
};

/// Accept connections on `listener` and serve each, until `shutdown`.
/// Returns once accepting has stopped; connections still being served
/// are `shutdown`'s to finish.
pub fn serve(s: *Server, io: Io, listener: *Io.net.Server) ServeError!void {
    var result: ServeError!void = {};
    s.acceptor.concurrent(io, acceptLoop, .{ s, io, listener, &result }) catch {
        // No task to spare: accept here, one connection at a time.
        acceptLoop(s, io, listener, &result);
        return result;
    };
    s.accepting_done.wait(io) catch |err| {
        s.reapAcceptor(io);
        return err;
    };
    s.reapAcceptor(io);
    return result;
}

/// Cancel the accept loop's task and wait for it, unless the other of
/// `serve` and `shutdown` has.
fn reapAcceptor(s: *Server, io: Io) void {
    if (!s.acceptor_taken.swap(true, .acq_rel)) s.acceptor.cancel(io);
}

fn acceptLoop(s: *Server, io: Io, listener: *Io.net.Server, result: *ServeError!void) void {
    defer s.accepting_done.set(io);
    while (!s.stopping.load(.acquire)) {
        if (s.options.max_connections) |max| s.waitForRoom(io, max) catch |err| {
            result.* = err;
            return;
        };
        const stream = listener.accept(io) catch |err| switch (err) {
            error.Canceled => {
                if (!s.stopping.load(.acquire)) result.* = error.Canceled;
                return;
            },
            // A peer gone before its accept, or a resource short for a
            // moment: the next accept may succeed.
            error.ConnectionAborted, error.ProcessFdQuotaExceeded, error.SystemFdQuotaExceeded, error.SystemResources => continue,
            else => {
                result.* = error.AcceptFailed;
                return;
            },
        };
        if (s.stopping.load(.acquire)) {
            stream.close(io);
            return;
        }
        s.tasks.concurrent(io, serveTask, .{ s, io, stream }) catch {
            // No task to spare: this connection is served here, to its end.
            s.serveConnection(io, stream);
        };
    }
}

fn serveTask(s: *Server, io: Io, stream: Io.net.Stream) void {
    s.serveConnection(io, stream);
}

/// Wait while `max` connections are open. A connection's end wakes it.
fn waitForRoom(s: *Server, io: Io, max: u32) Io.Cancelable!void {
    while (true) {
        const open = s.counters.open.load(.acquire);
        if (open < max) return;
        try io.futexWait(u32, &s.counters.open.raw, open);
    }
}

/// Serve `stream`, which the server now owns, to its end on the caller's
/// task: every request on it, until the client closes it, a timeout, an
/// answer that closes it, or `shutdown`.
pub fn serveConnection(s: *Server, io: Io, stream: Io.net.Stream) void {
    _ = s.counters.accepted.fetchAdd(1, .monotonic);
    _ = s.counters.open.fetchAdd(1, .acq_rel);
    defer {
        _ = s.counters.open.fetchSub(1, .acq_rel);
        io.futexWake(u32, &s.counters.open.raw, 1);
    }
    sys.tune(io, stream.socket.handle, .{ .nodelay = true, .keepalive = s.options.keepalive });
    if (s.options.observer) |o| o.emit(.{ .accepted = .{ .remote = stream.socket.address } });
    var conn: Connection = .init(s, io, stream);
    s.enter(io, &conn);
    defer s.leave(io, &conn);
    conn.run();
}

fn enter(s: *Server, io: Io, conn: *Connection) void {
    var held = s.live.acquireUncancelable(io);
    defer held.deinit(io);
    const live = held.value();
    live.list.append(&conn.node);
    live.count += 1;
}

fn leave(s: *Server, io: Io, conn: *Connection) void {
    var held = s.live.acquireUncancelable(io);
    defer held.deinit(io);
    const live = held.value();
    live.list.remove(&conn.node);
    live.count -= 1;
    if (live.count == 0 and s.stopping.load(.acquire)) s.drained.set(io);
}

/// Mark `conn` waiting for a request, or not: an idle connection is the
/// one `shutdown` ends at once. False when the server is stopping, and
/// the connection should not wait.
pub fn setIdle(s: *Server, io: Io, conn: *Connection, idle: bool) bool {
    var held = s.live.acquireUncancelable(io);
    defer held.deinit(io);
    conn.idle = idle;
    return !s.stopping.load(.acquire);
}

/// Stop: accept no more, end the connections waiting for a request at
/// once, let those answering one finish it (their responses say
/// `Connection: close`) for up to `Timeouts.shutdown`, then end the rest.
/// Call it from a task other than `serve`'s; `serve` then returns.
pub fn shutdown(s: *Server, io: Io) void {
    s.stopping.store(true, .release);
    // A task of its own takes its accept's cancel; inline, the accept
    // returns at the next connection, which it closes.
    s.reapAcceptor(io);
    {
        var held = s.live.acquireUncancelable(io);
        defer held.deinit(io);
        const live = held.value();
        if (live.count == 0) s.drained.set(io);
        var it = live.list.first;
        while (it) |node| : (it = node.next) {
            const conn: *Connection = @alignCast(@fieldParentPtr("node", node)); // safe: only connections are on the live list
            if (conn.idle) reactor.net.abort(io, conn.stream.socket.handle);
        }
    }
    const until = Io.Clock.awake.now(io).addDuration(span.toIo(s.options.timeouts.shutdown));
    while (!s.drained.isSet()) {
        // A wait can wake early: it is tried again until the grace is out.
        s.drained.waitTimeout(io, .{ .deadline = .{ .raw = until, .clock = .awake } }) catch |err| switch (err) {
            error.Timeout => if (Io.Clock.awake.now(io).nanoseconds >= until.nanoseconds) break,
            // The caller is canceled: what is left ends now.
            error.Canceled => break,
        };
    }
    // What is left ends now: its tasks are canceled, and a connection served
    // on a caller's task has its socket ended under it.
    {
        var held = s.live.acquireUncancelable(io);
        defer held.deinit(io);
        var it = held.value().list.first;
        while (it) |node| : (it = node.next) {
            const conn: *Connection = @alignCast(@fieldParentPtr("node", node)); // safe: only connections are on the live list
            reactor.net.abort(io, conn.stream.socket.handle);
        }
    }
    s.tasks.cancel(io);
}

/// Whether the server is stopping.
pub fn isStopping(s: *const Server) bool {
    return s.stopping.load(.acquire);
}
