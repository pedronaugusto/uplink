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
const Allocator = std.mem.Allocator;
const Io = std.Io;
const sys = @import("../net/sys.zig");
const Context = @import("Context.zig");
const Connection = @import("Connection.zig");

const Server = @This();

/// What the server does for each request.
pub const Handler = @import("Handler.zig");
/// How a server reads, limits and answers.
pub const Options = Context.Options;
/// How long each wait may take.
pub const Timeouts = Context.Timeouts;
/// Which responses go compressed, and how.
pub const Compression = Context.Compression;
/// Every request as it is answered.
pub const Observer = Context.Observer;
/// Which limit a connection ran past.
pub const Timeout = Context.Timeout;

/// Private: what the connections share.
context: Context,
handler: Handler,
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

/// A server answering every request with `handler`.
pub fn init(gpa: Allocator, options: Options, handler: Handler) Server {
    return .{ .context = .init(gpa, options), .handler = handler };
}

/// Release what the server holds. `serve` must have returned and every
/// `serveConnection` ended.
pub fn deinit(s: *Server, io: Io) void {
    s.tasks.cancel(io);
    s.reapAcceptor(io);
    s.context.deinit(io);
    s.* = undefined;
}

/// What a server has done, counted as it went.
pub const Stats = struct {
    accepted: u64,
    requests: u64,
    /// Connections open now.
    open: u32,
    /// Timeouts no task and no `Io` could keep.
    timeouts_unenforced: u64,
};

/// The server's counts now.
pub fn stats(s: *const Server) Stats {
    const k = &s.context.counters;
    return .{
        .accepted = k.accepted.load(.monotonic),
        .requests = k.requests.load(.monotonic),
        .open = k.open.load(.monotonic),
        .timeouts_unenforced = k.timeouts_unenforced.load(.monotonic),
    };
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
    while (!s.context.isStopping()) {
        if (s.context.options.max_connections) |max| s.waitForRoom(io, max) catch |err| {
            result.* = err;
            return;
        };
        const stream = listener.accept(io) catch |err| switch (err) {
            error.Canceled => {
                if (!s.context.isStopping()) result.* = error.Canceled;
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
        if (s.context.isStopping()) {
            stream.close(io);
            return;
        }
        // Counted open before its task starts, so the next turn's wait for
        // room sees it.
        s.opened();
        s.tasks.concurrent(io, serveOpened, .{ s, io, stream }) catch {
            // No task to spare: this connection is served here, to its end.
            s.serveOpened(io, stream);
        };
    }
}

/// Wait while `max` connections are open. A connection's end wakes it.
fn waitForRoom(s: *Server, io: Io, max: u32) Io.Cancelable!void {
    const open = &s.context.counters.open;
    while (true) {
        const now = open.load(.acquire);
        if (now < max) return;
        try io.futexWait(u32, &open.raw, now);
    }
}

/// Serve `stream`, which the server now owns, to its end on the caller's
/// task: every request on it, until the client closes it, a timeout, an
/// answer that closes it, or `shutdown`.
pub fn serveConnection(s: *Server, io: Io, stream: Io.net.Stream) void {
    s.opened();
    s.serveOpened(io, stream);
}

fn opened(s: *Server) void {
    const k = &s.context.counters;
    _ = k.accepted.fetchAdd(1, .monotonic);
    _ = k.open.fetchAdd(1, .acq_rel);
}

/// Serve a connection already counted open, and count it closed.
fn serveOpened(s: *Server, io: Io, stream: Io.net.Stream) void {
    const k = &s.context.counters;
    defer {
        _ = k.open.fetchSub(1, .acq_rel);
        io.futexWake(u32, &k.open.raw, 1);
    }
    sys.tune(io, stream.socket.handle, .{ .nodelay = true, .keepalive = s.context.options.keepalive });
    if (s.context.options.observer) |o| o.emit(.{ .accepted = .{ .remote = stream.socket.address } });
    Connection.serve(&s.context, s.handler, io, stream);
}

/// Stop: accept no more, end the connections waiting for a request at
/// once, let those answering one finish it (their responses say
/// `Connection: close`) for up to `Timeouts.shutdown`, then end the rest.
/// Call it from a task other than `serve`'s; `serve` then returns.
pub fn shutdown(s: *Server, io: Io) void {
    s.context.stopping.store(true, .release);
    // A task of its own takes its accept's cancel; inline, the accept
    // returns at the next connection, which it closes.
    s.reapAcceptor(io);
    s.context.stop(io);
    s.tasks.cancel(io);
}
