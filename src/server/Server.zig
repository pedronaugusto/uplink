//! An HTTP server: it accepts connections, reads the requests on each in
//! order, pipelined ones included, or the streams of an HTTP/2 connection
//! each on a task of its own, and hands every request to one `Handler`,
//! which answers it through a `Response`. TLS is cloak's.
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
const sync = @import("../sync.zig");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const stream_owner = @import("../net/stream.zig");
const Endpoint = stream_owner.Endpoint;
const OwnedEndpoint = stream_owner.Owned;
const reactor = @import("reactor");
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
/// How plain connections may speak HTTP/2.
pub const H2c = Context.H2c;
/// Which limit a connection ran past.
pub const Timeout = Context.Timeout;

/// Private: what the connections share.
context: Context,
handler: *const Handler,
/// Private: the connection tasks `serve` started.
tasks: Io.Group = .init,
/// Private: the accept loop, when it runs as a task of its own.
acceptor: Io.Group = .init,
/// Private: whether the accept loop has stopped, and the wait for it.
accepting_done: aegis.BlockingGuarded(bool) = .init(false),
accepting_ended: aegis.Condition = .initLimit(std.math.maxInt(usize)),
/// Private: whether `serve` or `shutdown` has taken the accept loop's
/// group to cancel: one of them, once, since a group is not canceled from
/// two tasks at once.
acceptor_taken: sync.Latch = .init(.clear),

/// A server answering every request with `handler`.
pub fn init(gpa: Allocator, options: Options, handler: *const Handler) Server {
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

/// The server's counts now. The connections open are read under the lock
/// their count is kept under.
pub fn stats(s: *Server, io: Io) Stats {
    const k = &s.context.counters;
    return .{
        .accepted = k.accepted.load(.monotonic).raw(),
        .requests = k.requests.load(.monotonic).raw(),
        .open = s.context.openNow(io),
        .timeouts_unenforced = k.timeouts_unenforced.load(.monotonic).raw(),
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
    return s.serveFrom(io, .{ .socket = listener });
}

/// `serve` on a Windows named pipe's listener (reactor's `listenPipe`),
/// a client's end accepted per connection, as Docker's daemon serves its
/// API on `\\.\pipe\docker_engine`. A request's `remote` is null.
pub fn servePipe(s: *Server, io: Io, listener: *reactor.net.PipeListener) ServeError!void {
    return s.serveFrom(io, .{ .pipe = listener });
}

/// Where connections are accepted from.
const Listener = union(enum) {
    socket: *Io.net.Server,
    pipe: *reactor.net.PipeListener,
};

fn serveFrom(s: *Server, io: Io, listener: Listener) ServeError!void {
    var result: ServeError!void = {};
    s.acceptor.concurrent(io, acceptLoop, .{ s, io, listener, &result }) catch {
        // No task to spare: accept here, one connection at a time.
        acceptLoop(s, io, listener, &result);
        return result;
    };
    s.awaitAccepting(io) catch |err| {
        s.reapAcceptor(io);
        return err;
    };
    s.reapAcceptor(io);
    return result;
}

/// Cancel the accept loop's task and wait for it, unless the other of
/// `serve` and `shutdown` has.
fn reapAcceptor(s: *Server, io: Io) void {
    if (s.acceptor_taken.swap(.set, .acq_rel) == .clear) s.acceptor.cancel(io);
}

/// Wait for the accept loop to stop.
fn awaitAccepting(s: *Server, io: Io) Io.Cancelable!void {
    var held = try s.accepting_done.acquire(io);
    defer held.deinit(io);
    while (!held.value().*) s.accepting_ended.wait(io, &held, .none) catch |err| switch (err) {
        error.Canceled => return error.Canceled,
        // No deadline, and no limit on the waiters.
        error.Timeout, error.WaiterLimit => unreachable,
    };
}

/// Say the accept loop has stopped.
fn acceptingStopped(s: *Server, io: Io) void {
    {
        var held = s.accepting_done.acquireUncancelable(io);
        defer held.deinit(io);
        held.value().* = true;
    }
    s.accepting_ended.broadcast(io);
}

fn acceptLoop(s: *Server, io: Io, listener: Listener, result: *ServeError!void) void {
    defer s.acceptingStopped(io);
    while (!s.context.isStopping()) {
        if (s.context.options.max_connections) |max| s.context.waitForRoom(io, max) catch |err| {
            result.* = err;
            return;
        };
        const endpoint: Endpoint = switch (listener) {
            .socket => |l| .{
                .socket = l.accept(io) catch |err| switch (err) {
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
                },
            },
            .pipe => |l| .{ .pipe = l.accept(io) catch |err| switch (err) {
                error.Canceled => {
                    if (!s.context.isStopping()) result.* = error.Canceled;
                    return;
                },
                error.SystemResources => continue,
                error.Unexpected => {
                    result.* = error.AcceptFailed;
                    return;
                },
            } },
        };
        if (s.context.isStopping()) {
            var owned: OwnedEndpoint = .init(endpoint);
            owned.deinit(io);
            return;
        }
        // Counted open before its task starts, so the next turn's wait for
        // room sees it.
        s.opened(io);
        s.tasks.concurrent(io, serveOpened, .{ s, io, endpoint }) catch {
            // No task to spare: this connection is served here, to its end.
            s.serveOpened(io, endpoint);
        };
    }
}

/// Serve `stream`, which the server now owns, to its end on the caller's
/// task: every request on it, until the client closes it, a timeout, an
/// answer that closes it, or `shutdown`.
pub fn serveConnection(s: *Server, io: Io, stream: Io.net.Stream) void {
    s.opened(io);
    s.serveOpened(io, .{ .socket = stream });
}

fn opened(s: *Server, io: Io) void {
    sync.bump(&s.context.counters.accepted);
    s.context.opened(io);
}

/// Serve a connection already counted open, and count it closed.
fn serveOpened(s: *Server, io: Io, endpoint: Endpoint) void {
    defer s.context.ended(io);
    // A pipe has no socket options, and no address to tell.
    if (endpoint.socketStream()) |lent| {
        const stream = lent.get();
        reactor.net.setOptions(stream.socket, s.context.options.socket) catch |err| {
            if (s.context.options.observer) |o| o.emit(.{ .option_refused = .{ .error_name = @errorName(err) } });
            var owned: OwnedEndpoint = .init(endpoint);
            owned.deinit(io);
            return;
        };
        if (s.context.options.observer) |o| o.emit(.{ .accepted = .{ .remote = stream.socket.address } });
    }
    Connection.serve(&s.context, s.handler, io, endpoint);
}

/// Stop: accept no more, end the connections waiting for a request at
/// once, let those answering one finish it (their responses say
/// `Connection: close`) for up to `Timeouts.shutdown`, then end the rest.
/// Call it from a task other than `serve`'s; `serve` then returns.
pub fn shutdown(s: *Server, io: Io) void {
    s.context.stopping.store(.set, .release);
    // A task of its own takes its accept's cancel; inline, the accept
    // returns at the next connection, which it closes.
    s.reapAcceptor(io);
    s.context.stop(io);
    s.tasks.cancel(io);
}
