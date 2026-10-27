//! One connection's I/O on a server: the socket and its TLS session, and
//! the deadline each wait is kept to. Every read and write goes through one
//! place, which keeps the deadline of the wait at hand: the TLS handshake,
//! the time between requests, the whole of a request's head, or, while a
//! request is answered, the activity timeout of each operation. A plain
//! connection keeps a 4 KiB read buffer between requests and nothing
//! else; its write buffer is borrowed while it answers.

const std = @import("std");
const aegis = @import("aegis");
const Io = std.Io;
const cloak = @import("cloak");
const tls = @import("../tls.zig");
const span = @import("../span.zig");
const Timed = @import("../net/Timed.zig");
const sys = @import("../net/sys.zig");
const stream_owner = @import("../net/stream.zig");
const reactor = @import("reactor");
const Context = @import("Context.zig");
const BufferPool = @import("../transport/BufferPool.zig");

const Socket = @This();

/// Private: what the server's connections share.
context: *Context,
/// Private: the `Io` the connection's task runs on, for the adapters.
/// Moved only by the task that has the connection to itself (`adopt`).
io: Io,
/// Private: the socket, and its one owner.
stream: stream_owner.Owned,
/// Private: the connection's place on the server's live list.
entry: Context.Entry,
/// Private: the socket's operations, each ended at its deadline.
timed: Timed,
input: SocketReader,
output: SocketWriter,
/// Private: TLS, when the server speaks it.
session: cloak.tls.Session = undefined,
secure: bool = false,
session_buffers: [2]BufferPool.Buffer = .{ &.{}, &.{} },
/// Which wait the next operation is part of; on a multiplexed connection,
/// the next read.
phase: Phases.Runtime(void) = .init({}),
/// The end of the handshake, the idle wait or the head, on the awake
/// clock.
until: ?Io.Timestamp = null,
/// Why the first operation that failed did; `failed` reads it.
failure: aegis.Atomic(Failure) = .init(.none),
/// HTTP/2: one task reads while the streams' tasks write, each write
/// within the activity timeout whatever the reading task waits for.
multiplexed: bool = false,
/// The handler took the connection over.
hijacked: bool = false,

pub const Phase = enum {
    handshake,
    idle,
    head,
    answer,
    /// Reading what a request left of its body, by the drain's time.
    drain,
    /// The handler took the connection over: it keeps its own time.
    hijacked,
    /// HTTP/2 with streams open: a read waits as long as they take.
    h2,
};

/// What starts a phase: the next wait the connection does, or the handler
/// taking it over.
pub const Start = enum { handshake, idle, head, answer, drain, h2, hijack };

/// Which wait an operation belongs to. TLS's handshake comes first and only
/// first; a handler that takes the connection over ends it; any other wait
/// may follow any other.
const Phases = aegis.state.Machine(Phase, Start, .{ .initial = .head, .terminal = &.{.hijacked}, .edges = &phase_edges });
const phase_edges = edges: {
    const Edge = aegis.state.Edge(Phase, Start);
    const waits = [_]Phase{ .idle, .head, .answer, .drain, .h2 };
    var list: [4 + waits.len * (waits.len + 1)]Edge = undefined;
    var n: usize = 0;
    list[n] = .{ .from = .head, .on = .handshake, .to = .handshake };
    n += 1;
    for ([_]Phase{ .idle, .head, .h2 }) |to| {
        list[n] = .{ .from = .handshake, .on = @field(Start, @tagName(to)), .to = to };
        n += 1;
    }
    for (waits) |from| {
        for (waits) |to| {
            list[n] = .{ .from = from, .on = @field(Start, @tagName(to)), .to = to };
            n += 1;
        }
        list[n] = .{ .from = from, .on = .hijack, .to = .hijacked };
        n += 1;
    }
    const all = list;
    break :edges all;
};

/// Begin the phase `start` starts.
pub fn enter(c: *Socket, start: Start) void {
    _ = c.phase.step(start) catch unreachable; // unreachable: the handshake starts first, and nothing follows a takeover
}

/// Why an operation failed.
pub const Failure = enum(u8) { none, timed_out, canceled, broken };

/// Why a read failed.
pub const ReadError = error{
    /// The connection failed.
    ConnectionFailed,
    /// A wait ran past its timeout.
    TimedOut,
    Canceled,
};

/// A socket over `stream`, with nothing on it yet.
pub fn init(context: *Context, io: Io, stream: Io.net.Stream) Socket {
    return .{
        .context = context,
        .io = io,
        .stream = .init(stream),
        .entry = .{ .socket = stream.socket.handle },
        .timed = .init(stream.socket.handle),
        .input = .init(&.{}),
        .output = .init(&.{}),
    };
}

/// Start the wait for a head: until the head timeout from now.
pub fn startHead(c: *Socket, io: Io) void {
    c.enter(.head);
    c.until = if (c.context.options.timeouts.head) |d| Io.Clock.awake.now(io).addDuration(span.toIo(d)) else null;
}

/// Start the wait between requests: until the idle timeout from now.
pub fn startIdle(c: *Socket, io: Io) void {
    c.enter(.idle);
    c.until = if (c.context.options.timeouts.idle) |d| Io.Clock.awake.now(io).addDuration(span.toIo(d)) else null;
}

/// From here on the connection is HTTP/2: one task reads and others write.
/// Called before any other task has the socket.
pub fn multiplex(c: *Socket) void {
    c.multiplexed = true;
}

/// Run the connection's adapters on `io` from here on. A no-op on a
/// multiplexed connection, whose tasks share the `Io` it started on.
pub fn adopt(c: *Socket, io: Io) void {
    if (!c.multiplexed) c.io = io;
}

/// Serve HTTP/2 streams: reads wait as long as the streams take.
pub fn startH2(c: *Socket) void {
    c.enter(.h2);
    c.until = null;
}

/// The protocol ALPN agreed, empty without TLS or without one.
pub fn alpn(c: *const Socket) []const u8 {
    if (!c.secure) return "";
    const info = c.session.info() orelse return "";
    return info.alpn;
}

/// Read what a request left of its body: until `time` from now.
pub fn startDrain(c: *Socket, io: Io, time: span.Duration) void {
    c.enter(.drain);
    c.until = Io.Clock.awake.now(io).addDuration(span.toIo(time));
}

/// Answer a request: each operation ends at the activity timeout.
pub fn startAnswer(c: *Socket) void {
    c.enter(.answer);
    c.until = null;
}

/// Wait up to `timeout` for the peer to send something; the wait ends
/// nothing when nothing comes.
pub fn awaitReadable(c: *Socket, io: Io, timeout: Io.Duration) Io.Cancelable!Timed.Readiness {
    c.adopt(io);
    if (c.reader().bufferedLen() != 0) return .ready;
    return Timed.awaitReadable(io, c.stream.borrow().socket.handle, &c.input.interface, timeout);
}

/// Wait up to `timeout` for the client to end the connection while a
/// request is answered, its body read: whether it did (its FIN or a reset),
/// or the connection failed. What the client sends meanwhile (its next
/// request, TLS records) is read into the input buffer and kept for the
/// reader; once that buffer is full the wait can only run out. False too
/// when the `Io` cannot wait for a bounded time. One wait at a time, from
/// any task, while the handler runs.
pub fn awaitEnd(c: *Socket, io: Io, timeout: Io.Timeout) Io.Cancelable!bool {
    if (c.failed() != .none) return true;
    const until = timeout.toDeadline(io);
    const r = &c.input.interface;
    while (true) {
        if (r.seek == r.end) {
            r.seek = 0;
            r.end = 0;
        }
        if (r.end == r.buffer.len) return waitOut(io, until);
        // A look that neither waits nor takes answers at once where the
        // system has one: what a query with no time to wait needs.
        if (sys.peek(c.stream.borrow().socket.handle)) |seen| switch (seen) {
            .closed => return true,
            .readable => {},
            .idle => if (expired(io, until)) return false,
        };
        var data: [1][]u8 = .{r.buffer[r.end..]};
        const read: Io.Operation = .{ .net_read = .{ .socket_handle = c.stream.borrow().socket.handle, .data = &data } };
        const result = io.operateTimeout(read, until) catch |err| switch (err) {
            error.Timeout => return false,
            error.Canceled => return error.Canceled,
            // This `Io` cannot bound a read of a socket (std's `Io.Threaded`
            // on Windows): reactor waits, within the time, for the socket to
            // have something to read (its end or a reset among them), and the
            // read then finds it.
            error.ConcurrencyUnavailable => blk: {
                reactor.wait(io, .{ .readable = c.stream.borrow().socket.handle }, until) catch |waited| switch (waited) {
                    error.Timeout => return false,
                    error.Canceled => return error.Canceled,
                    // A socket the system cannot watch has failed.
                    error.Unsupported, error.Unexpected => return true,
                };
                break :blk try io.operate(read);
            },
        };
        const n = (result.net_read catch return true).data_len;
        if (n == 0) return true;
        r.end += n;
    }
}

fn expired(io: Io, until: Io.Timeout) bool {
    const left = until.toDurationFromNow(io) orelse return false;
    return left.raw.nanoseconds <= 0;
}

/// Wait out `until`, which nothing ends sooner but a cancelation.
fn waitOut(io: Io, until: Io.Timeout) Io.Cancelable!bool {
    try until.sleep(io);
    return false;
}

/// The task serving the connection was canceled: no operation follows.
pub fn noteCanceled(c: *Socket) void {
    c.note(.canceled);
}

/// Tell the observer a wait ran out.
pub fn noteTimeout(c: *Socket, phase: Context.Timeout) void {
    if (c.context.options.observer) |o| o.emit(.{ .timed_out = .{ .phase = phase } });
}

/// Close the connection: TLS's close_notify first unless an operation
/// failed, then the socket, and every buffer back to the pool.
pub fn close(c: *Socket) void {
    const io = c.io;
    const pool = &c.context.buffers;
    if (c.secure) {
        if (c.failed() == .none and !c.timed.fired()) {
            // glint-ignore: Z026 -- the close_notify is a courtesy; the socket closes whether or not the peer heard it
            c.session.finish() catch {};
            // glint-ignore: Z026 -- as above
            c.output.interface.flush() catch {};
        }
        c.session.deinit();
        for (c.session_buffers) |b| pool.release(io, b);
        c.secure = false;
    }
    c.linger();
    c.timed.deinit(io, c.context.keeper());
    c.context.closing(io, &c.entry);
    c.stream.deinit(io);
    for ([_]BufferPool.Buffer{ c.input.reclaim(), c.output.reclaim() }) |b| if (b.len != 0) pool.release(io, b);
}

/// End the sending side, then read and drop what the client still sends
/// until it ends its side too, or for `Timeouts.linger` (RFC 9112 §9.6):
/// a socket closed with bytes unread is reset, and the reset can reach the
/// client before it has read the server's last bytes. A socket that failed
/// has nothing left to deliver.
fn linger(c: *Socket) void {
    const io = c.io;
    const time = c.context.options.timeouts.linger orelse return;
    if (c.failed() != .none or c.timed.fired()) return;
    c.stream.borrow().shutdown(io, .send) catch return;
    const until = Io.Clock.awake.now(io).addDuration(span.toIo(time));
    var buf: [4096]u8 = undefined;
    var data: [1][]u8 = .{&buf};
    while (true) {
        // A deadline that ends the wait aborts the socket, which is
        // closing anyway.
        const result = c.timed.perform(io, c.context.keeper(), .{ .net_read = .{ .socket_handle = c.stream.borrow().socket.handle, .data = &data } }, until) catch return;
        const n = (result.net_read catch return).data_len;
        if (n == 0) return;
    }
}

pub fn handshake(c: *Socket, options: tls.ServerOptions) error{Failed}!void {
    const s = c.context;
    const io = c.io;
    const pool = &s.buffers;
    c.output.give(pool.acquire(io, .record) catch return error.Failed);
    const read_buffer = pool.acquire(io, .record) catch return error.Failed;
    const write_buffer = pool.acquire(io, .record) catch {
        pool.release(io, read_buffer);
        return error.Failed;
    };
    c.enter(.handshake);
    c.until = if (s.options.timeouts.handshake) |t| Io.Clock.awake.now(io).addDuration(span.toIo(t)) else null;
    const tickets = s.ticketKeys(io) catch |err| {
        if (err == error.Canceled) c.note(.canceled);
        pool.release(io, read_buffer);
        pool.release(io, write_buffer);
        if (s.options.observer) |o| o.emit(.{ .handshake_failed = .{ .error_name = @errorName(err) } });
        return error.Failed;
    };
    var report: cloak.tls.Session.Diagnostics = .{};
    c.session.accept(s.gpa, io, &c.input.interface, &c.output.interface, read_buffer, write_buffer, .{
        .credentials = options.credentials,
        .alpn = if (s.options.http2) tls.server_protocols else tls.server_protocols_h1,
        .client_auth = options.client_certificate,
        .client_trust = if (options.client_trust) |t| .{ .snapshot = t } else .none,
        .key_log = if (options.key_log) |w| tls.keyLog(w) else null,
        .tickets = tickets,
        .tls12_tickets = options.tls12_tickets,
        .ech_keys = options.ech_keys,
        // HTTP says where a message ends: a bare end of the transport is
        // the end of the connection, not an attack on a body.
        .eof = .allow,
        .diagnostics = &report,
    }) catch |err| {
        pool.release(io, read_buffer);
        pool.release(io, write_buffer);
        if (s.options.observer) |o| o.emit(.{ .handshake_failed = .{ .error_name = @errorName(err) } });
        if (c.failed() == .timed_out) c.noteTimeout(.handshake);
        return error.Failed;
    };
    c.session_buffers = .{ read_buffer, write_buffer };
    c.secure = true;
}

/// Between requests a plain connection gives its write buffer back.
pub fn park(c: *Socket) void {
    if (c.secure) return;
    const w = &c.output.interface;
    if (w.buffer.len != 0 and w.end == 0) c.context.buffers.release(c.io, c.output.reclaim());
}

/// Send `100 Continue` to a client waiting for it before its body.
pub fn sendContinue(c: *Socket) void {
    const w = c.writer();
    // A client that cannot hear it sends the body after its own wait, or
    // the read that follows fails and says why.
    w.writeAll("HTTP/1.1 100 Continue\r\n\r\n") catch return;
    c.flush() catch return;
}

/// The reader of the top layer.
pub fn reader(c: *Socket) *Io.Reader {
    return if (c.secure) c.session.reader() else &c.input.interface;
}

/// The writer of the top layer.
pub fn writer(c: *Socket) *Io.Writer {
    return if (c.secure) c.session.writer() else &c.output.interface;
}

/// Push everything written through every layer to the socket.
pub fn flush(c: *Socket) Io.Writer.Error!void {
    if (c.secure) try c.session.writer().flush();
    try c.output.interface.flush();
}

/// Why a read failed, by name.
pub fn readError(c: *const Socket) ReadError {
    return switch (c.failed()) {
        .timed_out => error.TimedOut,
        .canceled => error.Canceled,
        .none, .broken => error.ConnectionFailed,
    };
}

/// Why the first operation that failed did.
pub fn failed(c: *const Socket) Failure {
    return c.failure.load(.monotonic);
}

/// The deadline of an operation starting now. The phase belongs to the
/// reading task: a multiplexed connection's writes, from any task, keep
/// the activity timeout alone.
fn deadline(c: *Socket, op: Io.Operation) ?Io.Timestamp {
    if (c.multiplexed and op != .net_read) return c.activityDeadline();
    return switch (c.phase.current()) {
        .handshake, .idle, .head, .drain => c.until,
        .hijacked, .h2 => null,
        .answer => c.activityDeadline(),
    };
}

fn activityDeadline(c: *Socket) ?Io.Timestamp {
    const a = c.context.options.timeouts.activity orelse return null;
    return Io.Clock.awake.now(c.io).addDuration(span.toIo(a));
}

/// One socket operation within the deadline of the wait at hand. None
/// after a cancelation: the task was asked to stop, and a second
/// cancelation point would not say so again.
fn perform(c: *Socket, op: Io.Operation) error{Failed}!Io.Operation.Result {
    if (c.failed() == .canceled) return error.Failed;
    return c.timed.perform(c.io, c.context.keeper(), op, c.deadline(op)) catch |err| {
        c.note(switch (err) {
            error.TimedOut => .timed_out,
            error.Canceled => .canceled,
        });
        return error.Failed;
    };
}

fn note(c: *Socket, failure: Failure) void {
    _ = c.failure.cmpxchgStrong(.none, failure, .monotonic, .monotonic);
}

const SocketReader = struct {
    interface: Io.Reader,
    /// The pool buffer the interface reads into, as the pool gave it.
    pooled: BufferPool.Buffer,

    fn init(buffer: BufferPool.Buffer) SocketReader {
        return .{ .interface = .{ .vtable = &.{ .stream = streamImpl, .readVec = readVec }, .buffer = buffer, .seek = 0, .end = 0 }, .pooled = buffer };
    }

    /// Read into `buffer` from now on, the reader having none.
    pub fn give(sr: *SocketReader, buffer: BufferPool.Buffer) void {
        std.debug.assert(sr.pooled.len == 0);
        sr.pooled = buffer;
        sr.interface.buffer = buffer;
    }

    /// The reader's buffer, for the pool: the reader is left with none,
    /// and what it held unread is dropped.
    pub fn reclaim(sr: *SocketReader) BufferPool.Buffer {
        const buffer = sr.pooled;
        sr.pooled = &.{};
        sr.interface.buffer = &.{};
        sr.interface.seek = 0;
        sr.interface.end = 0;
        return buffer;
    }

    fn socket(r: *Io.Reader) *Socket {
        const sr: *SocketReader = @alignCast(@fieldParentPtr("interface", r)); // safe: this vtable is installed only on a SocketReader's interface
        return @alignCast(@fieldParentPtr("input", sr)); // safe: a SocketReader lives only in a Socket's `input`
    }

    fn streamImpl(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
        const dest = limit.slice(try w.writableSliceGreedy(1));
        var data: [1][]u8 = .{dest};
        const n = try readVec(r, &data);
        w.advance(n);
        return n;
    }

    fn readVec(r: *Io.Reader, data: [][]u8) Io.Reader.Error!usize {
        const c = socket(r);
        var iovecs: [8][]u8 = undefined;
        const dest_n, const data_size = try r.writableVector(&iovecs, data);
        const result = c.perform(.{ .net_read = .{ .socket_handle = c.stream.borrow().socket.handle, .data = iovecs[0..dest_n] } }) catch return error.ReadFailed;
        const n = (result.net_read catch {
            c.note(.broken);
            return error.ReadFailed;
        }).data_len;
        if (n == 0) return error.EndOfStream;
        if (n > data_size) {
            r.end += n - data_size;
            return data_size;
        }
        return n;
    }
};

const SocketWriter = struct {
    interface: Io.Writer,
    /// The pool buffer the interface writes through, as the pool gave it.
    pooled: BufferPool.Buffer,

    fn init(buffer: BufferPool.Buffer) SocketWriter {
        return .{ .interface = .{ .vtable = &.{ .drain = drain }, .buffer = buffer }, .pooled = buffer };
    }

    /// Write through `buffer` from now on, the writer having none.
    pub fn give(sw: *SocketWriter, buffer: BufferPool.Buffer) void {
        std.debug.assert(sw.pooled.len == 0);
        sw.pooled = buffer;
        sw.interface.buffer = buffer;
    }

    /// The writer's buffer, for the pool: the writer is left with none,
    /// and what it held unsent is dropped.
    pub fn reclaim(sw: *SocketWriter) BufferPool.Buffer {
        const buffer = sw.pooled;
        sw.pooled = &.{};
        sw.interface.buffer = &.{};
        sw.interface.end = 0;
        return buffer;
    }

    fn drain(w: *Io.Writer, data: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const sw: *SocketWriter = @alignCast(@fieldParentPtr("interface", w)); // safe: this vtable is installed only on a SocketWriter's interface
        const c: *Socket = @alignCast(@fieldParentPtr("output", sw)); // safe: a SocketWriter lives only in a Socket's `output`
        const result = c.perform(.{ .net_write = .{
            .socket_handle = c.stream.borrow().socket.handle,
            .header = w.buffered(),
            .data = data,
            .splat = splat,
        } }) catch return error.WriteFailed;
        const n = result.net_write catch {
            c.note(.broken);
            return error.WriteFailed;
        };
        return w.consume(n);
    }
};
