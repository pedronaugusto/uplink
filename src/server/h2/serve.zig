//! A server's HTTP/2 connection (RFC 9113), from its preface to its end:
//! the reading task reads frames and hands each to the protocol state, a
//! sending task writes what every task encoded (`Session`), and every
//! request a stream carries is answered by the handler on a task of its
//! own, as the HTTP/1.1 connection's requests are, through the same
//! `Request` and `Response`. On an `Io` with no task to spare the streams
//! are answered one at a time, on the reading task, which writes as it
//! goes, and the server says so by allowing one stream at once.

const std = @import("std");
const sync = @import("../../sync.zig");
const Io = std.Io;
const wire = @import("uplink.wire");
const h2 = wire.h2;
const hpack = wire.hpack;
const Field = wire.fields.Field;
const span = @import("../../span.zig");
const BufferPool = @import("../../transport/BufferPool.zig");
const Decoder = @import("../../coding/Decoder.zig");
const Context = @import("../Context.zig");
const Socket = @import("../Socket.zig");
const Request = @import("../Request.zig");
const Response = @import("../Response.zig");
const Handler = @import("../Handler.zig");
const Session = @import("Session.zig");
const Stream = Session.Stream;

/// Serve `socket` as HTTP/2 to its end. The client's preface is the next
/// thing on it.
pub fn serve(context: *Context, handler: *const Handler, socket: *Socket) void {
    run(context, handler, socket, null);
}

/// What an HTTP/1.1 request that switched the connection brings: the
/// request, as HTTP/2 fields, and the client's settings from its
/// `HTTP2-Settings`.
const Upgrade = struct { fields: []const hpack.Field, client_settings: []const u8 };

/// Serve `socket` as HTTP/2 to its end after a 101 to an HTTP/1.1
/// request's `Upgrade: h2c` (RFC 7540 §3.2): the request, as `fields`, is
/// stream 1, already ended on the client's side, and `client_settings` the
/// settings its `HTTP2-Settings` carried. The client's preface is the next
/// thing on the socket.
pub fn serveUpgraded(context: *Context, handler: *const Handler, socket: *Socket, fields: []const hpack.Field, client_settings: []const u8) void {
    run(context, handler, socket, .{ .fields = fields, .client_settings = client_settings });
}

fn run(context: *Context, handler: *const Handler, socket: *Socket, upgrade: ?Upgrade) void {
    const io = socket.io;
    // A frame and its head must fit the read buffer.
    if (socket.input.interface.buffer.len < h2.head_len + 16384 and !socket.secure) {
        if (!grow(context, socket)) return;
    }
    // Before any stream's task: from here on the streams write while this
    // task reads.
    socket.multiplex();
    var tasks: Io.Group = .init;
    const concurrent = probeConcurrency(io);
    var session = Session.init(context, socket, if (concurrent) 100 else 1) catch return;
    defer session.deinit();
    defer tasks.cancel(io);
    if (concurrent) session.startSending(&tasks);
    if (start(&session, upgrade)) {
        // The upgraded request is answered as any stream's is.
        if (upgrade) |u| if (upgraded(&session, u.fields)) |st| {
            if (concurrent) tasks.concurrent(io, answer, .{ &session, handler, st }) catch answer(&session, handler, st) else answer(&session, handler, st);
        };
        readFrames(&session, handler, &tasks, concurrent);
    }
    {
        var held = session.shared.acquireUncancelable(io);
        defer held.deinit(io);
        held.value().closed = true;
    }
    // The streams end, and the sending task once what is encoded (a
    // GOAWAY, say) has gone.
    session.changed.broadcast(io);
    // glint-ignore: Z026 -- the streams' tasks end with the connection; a cancel here is the caller's, already on its way
    tasks.await(io) catch {};
}

/// Take the client's preface and send the server's, after taking an
/// upgrade's settings as the client's: false when the connection goes no
/// further.
fn start(session: *Session, upgrade: ?Upgrade) bool {
    const socket = session.socket;
    const io = socket.io;
    const in = socket.reader();
    const preface = in.peek(h2.preface.len) catch return false;
    var held = session.shared.acquireUncancelable(io);
    defer held.deinit(io);
    const shared = held.value();
    // The settings were checked before the 101 went.
    if (upgrade) |u| shared.conn.upgradeServer(u.client_settings) catch return false;
    if (!shared.conn.checkPreface(preface)) {
        // glint-ignore: Z026 -- the connection closes next whether or not the GOAWAY reached the peer
        shared.conn.goaway(Session.out(shared), .protocol_error) catch {};
        session.post(shared);
        return false;
    }
    in.toss(h2.preface.len);
    shared.conn.start(Session.out(shared)) catch return false;
    session.post(shared);
    return true;
}

/// The upgraded request's stream 1, made as a stream whose HEADERS came;
/// null when it is refused.
fn upgraded(session: *Session, fields: []const hpack.Field) ?*Stream {
    var held = session.shared.acquireUncancelable(session.socket.io);
    defer held.deinit(session.socket.io);
    const shared = held.value();
    defer session.post(shared);
    return startStream(session, shared, 1, fields, true) catch null;
}

/// Whether this `Io` can run a stream's handler beside the reading task.
fn probeConcurrency(io: Io) bool {
    var f = io.concurrent(struct {
        fn nothing() void {}
    }.nothing, .{}) catch return false;
    f.await(io);
    return true;
}

/// A plain connection reads into a buffer that holds a whole frame.
fn grow(context: *Context, socket: *Socket) bool {
    const r = &socket.input.interface;
    const larger = context.buffers.acquire(socket.io, .record) catch return false;
    const buffered = r.buffered();
    @memcpy(larger[0..buffered.len], buffered);
    const len = buffered.len;
    context.buffers.release(socket.io, socket.input.reclaim());
    socket.input.give(larger);
    r.end = len;
    return true;
}

fn readFrames(session: *Session, handler: *const Handler, tasks: *Io.Group, concurrent: bool) void {
    const socket = session.socket;
    const context = session.context;
    const io = socket.io;
    const in = socket.reader();
    while (true) {
        // Between streams the wait is the idle timeout's; while any is
        // open, a read waits as long as the streams take.
        const busy = blk: {
            var held = session.shared.acquireUncancelable(io);
            defer held.deinit(io);
            break :blk held.value().streams.items.len != 0;
        };
        if (busy) socket.startH2() else socket.startIdle(io);
        if (context.isStopping()) {
            var held = session.shared.acquireUncancelable(io);
            defer held.deinit(io);
            const shared = held.value();
            if (shared.conn.goaway_sent == null) {
                // glint-ignore: Z026 -- the connection drains its streams and ends either way
                shared.conn.goaway(Session.out(shared), .no_error) catch {};
                session.post(shared);
            }
            if (shared.streams.items.len == 0) return;
        }
        const head_bytes = in.peek(h2.head_len) catch return;
        const head = h2.Head.parse(head_bytes[0..h2.head_len]);
        socket.startH2();
        // A frame past the read buffer is past any size this end allows;
        // the protocol state answers it from its head.
        const whole = h2.head_len + @as(usize, head.len);
        const payload: []const u8 = if (whole <= in.buffer.len) (in.peek(whole) catch return)[h2.head_len..] else &.{};
        var spawn: ?*Stream = null;
        const handled = blk: {
            var held = session.shared.acquireUncancelable(io);
            defer held.deinit(io);
            const shared = held.value();
            const event = shared.conn.receive(Session.out(shared), head, payload) catch {
                shared.closed = true;
                session.post(shared);
                break :blk false;
            };
            if (event) |e| spawn = handle(session, shared, e) catch {
                shared.closed = true;
                session.post(shared);
                break :blk false;
            };
            session.post(shared);
            break :blk !shared.closed;
        };
        const consumed = handled and if (whole <= in.buffer.len) consumed: {
            in.toss(whole);
            break :consumed true;
        } else if (in.discardAll(whole)) |_| true else |_| false;
        session.changed.broadcast(io);
        if (spawn) |st| {
            // A request the connection ends under is not answered.
            if (!consumed) {
                finish(session, st);
            } else if (concurrent) {
                tasks.concurrent(io, answer, .{ session, handler, st }) catch answer(session, handler, st);
            } else answer(session, handler, st);
        }
        if (!consumed) return;
    }
}

/// What the reading task does with an event, under the lock; a new
/// request's stream to answer.
fn handle(session: *Session, shared: *Session.Shared, event: h2.Connection.Event) error{OutOfMemory}!?*Stream {
    const gpa = session.context.gpa;
    switch (event) {
        .headers => |hd| {
            if (Session.find(shared, hd.stream)) |st| {
                // Trailers: kept for the request, which ends with them.
                st.trailer_buffer = session.context.buffers.acquire(session.socket.io, BufferPool.Class.fitting(h2.message.copySize(hd.fields)) orelse .large) catch return null;
                const kept = h2.message.copy(st.trailer_buffer, hd.fields) catch null;
                if (kept == null or !h2.message.checkTrailers(kept.?)) {
                    // A malformed trailer section is the stream's error (RFC 9113 §8.1.1).
                    // glint-ignore: Z026 -- the reset is the answer; a failed write ends the connection at its next read
                    shared.conn.reset(Session.out(shared), st.id, .protocol_error) catch {};
                    st.reset_code = .protocol_error;
                    return null;
                }
                st.trailers = kept;
                st.recv_end = true;
                return null;
            }
            const st = try startStream(session, shared, hd.stream, hd.fields, hd.end_stream);
            return st;
        },
        .data => |d| {
            const st = Session.find(shared, d.stream) orelse {
                // A stream already answered: its data is given back.
                shared.conn.giveBack(Session.out(shared), d.stream, d.bytes.len) catch {
                    shared.closed = true;
                };
                return null;
            };
            try st.deliver(gpa, d.bytes, d.end_stream);
        },
        .reset => |rs| if (Session.find(shared, rs.stream)) |st| {
            st.reset_code = rs.code;
        },
        .reset_sent => |rs| if (Session.find(shared, rs.stream)) |st| {
            st.reset_code = rs.code;
        },
        .goaway => {},
        .window, .settings, .settings_ack, .ping_ack => {},
    }
    return null;
}

/// A new request's stream: its fields kept, its state made.
fn startStream(session: *Session, shared: *Session.Shared, id: u31, fields: []const hpack.Field, end_stream: bool) error{OutOfMemory}!?*Stream {
    const gpa = session.context.gpa;
    const pool = &session.context.buffers;
    const io = session.socket.io;
    const class = BufferPool.Class.fitting(h2.message.copySize(fields) + 1024) orelse {
        // glint-ignore: Z026 -- a head too large to keep is refused; the connection goes on
        shared.conn.reset(Session.out(shared), id, .refused_stream) catch {};
        return null;
    };
    const buffer = try pool.acquire(io, class);
    errdefer pool.release(io, buffer);
    const kept = h2.message.copy(buffer, fields) catch unreachable; // unreachable: the class fits the fields
    // A malformed request is a stream error at once (RFC 9113 §8.1.1), and a
    // declared length is checked against the data as it comes.
    const head = h2.message.checkRequest(kept) orelse {
        pool.release(io, buffer);
        // glint-ignore: Z026 -- the reset is the answer; a failed write ends the connection at its next read
        shared.conn.reset(Session.out(shared), id, .protocol_error) catch {};
        return null;
    };
    if (shared.conn.stream(id)) |s| s.content_length = head.content_length;
    const st = try gpa.create(Stream);
    errdefer gpa.destroy(st);
    st.* = .{ .session = session, .id = id, .head_buffer = buffer, .fields = kept, .recv_end = end_stream, .content_length = head.content_length, .interface = undefined };
    st.initReader();
    try shared.streams.append(gpa, st);
    return st;
}

/// Answer the request on `st` with the handler, then forget the stream.
fn answer(session: *Session, handler: *const Handler, st: *Stream) void {
    const context = session.context;
    const io = session.socket.io;
    defer finish(session, st);
    const head = h2.message.checkRequest(st.fields).?; // `startStream` refused a malformed head
    const target_text = if (head.method.eql(.CONNECT) and head.protocol == null) head.authority.? else head.path;
    const parsed = if (head.protocol != null) Request.Target.parseExtended(target_text) else Request.Target.parse(head.method, target_text);
    const target = parsed catch return st.reset(io, .protocol_error);
    // Whether the request's data is still to come, as the reading task left
    // it by now; the stream's state is read under the session's lock.
    const body_coming = !st.dataEnded();
    var request: Request = .{
        .method = head.method,
        .target = target_text,
        .path = target.path,
        .query = target.query,
        .version = .h2,
        .protocol = head.protocol,
        .headers = .init(head.fields),
        .host = head.authority orelse "",
        .remote = if (session.socket.stream.borrow().socket.address == .ip4 or session.socket.stream.borrow().socket.address == .ip6) session.socket.stream.borrow().socket.address else null,
        .secure = session.socket.secure,
        .peer_certificate = session.socket.peerCertificate(),
        .socket = session.socket,
        .body = .init(Io.Reader.ending, .none, &.{}),
        .stream = st,
        .expects_continue = std.ascii.eqlIgnoreCase(std.mem.trim(u8, requestExpect(head.fields), " \t"), "100-continue") and body_coming,
    };
    defer request.release(io);
    if (context.options.decompress and body_coming) {
        const headers: wire.fields.Headers = .init(head.fields);
        if (wire.coding.Codings.of(&headers)) |codings| {
            if (codings.len != 0 and Decoder.decodes(codings.slice()))
                request.decoder = Decoder.init(io, context.gpa, &context.buffers, &context.zstd, codings.slice()) catch return st.reset(io, .internal_error);
        } else |_| {}
    }
    defer if (request.decoder) |*d| d.deinit(io, context.gpa, &context.buffers, &context.zstd);
    var response: Response = .init(session.socket, head.method.eql(.HEAD), false, request.headers.getKnown(.@"accept-encoding"));
    response.stream = st;
    defer response.release(io);
    sync.bump(&context.counters.requests);
    const arrived = Io.Clock.awake.now(io);
    handler.handle(io, &request, &response) catch |err| {
        if (context.options.observer) |o| o.emit(.{ .failed = .{ .method = head.method.name, .path = target.path, .error_name = @errorName(err), .head_sent = response.headSent() } });
        if (response.headSent()) return st.reset(io, .internal_error);
        // A canceled task answers nothing more: the stream is reset.
        if (err == error.Canceled) return st.reset(io, .cancel);
        response.reset(io);
        response.stream = st;
        response.status = request.bodyFault() orelse .internal_server_error;
        // glint-ignore: Z026 -- a 500 that cannot be written leaves the stream reset below
        response.send(io, "") catch {};
        return;
    };
    response.end(io) catch return st.reset(io, .internal_error);
    if (context.options.observer) |o| o.emit(.{ .answered = .{ .method = head.method.name, .path = target.path, .status = @backingInt(response.status), .took = span.of(arrived.durationTo(Io.Clock.awake.now(io))) } });
    // A request body the handler left: the client is told to stop sending.
    st.refuseRest(io);
}

fn requestExpect(fields: []const Field) []const u8 {
    for (fields) |f| if (std.mem.eql(u8, f.name, "expect")) return f.value;
    return "";
}

/// Forget `st`: off the session's list, its slot freed once it is closed
/// both ways, its buffers back.
fn finish(session: *Session, st: *Stream) void {
    const io = session.socket.io;
    const pool = &session.context.buffers;
    {
        var held = session.shared.acquireUncancelable(io);
        defer held.deinit(io);
        const shared = held.value();
        for (shared.streams.items, 0..) |s, i| if (s == st) {
            _ = shared.streams.swapRemove(i);
            break;
        };
        if (shared.conn.stream(st.id)) |s| {
            if (s.state == .closed) shared.conn.release(st.id) else if (st.recv_end or st.reset_code != null) shared.conn.release(st.id);
        }
    }
    pool.release(io, st.head_buffer);
    if (st.trailer_buffer.len != 0) pool.release(io, st.trailer_buffer);
    if (st.recv.len != 0) session.context.gpa.free(st.recv);
    session.context.gpa.destroy(st);
    session.changed.broadcast(io);
}
