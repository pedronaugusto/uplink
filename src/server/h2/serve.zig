//! A server's HTTP/2 connection (RFC 9113), from its preface to its end:
//! the reading task reads frames and hands each to the protocol state, and
//! every request a stream carries is answered by the handler on a task of
//! its own, as the HTTP/1.1 connection's requests are, through the same
//! `Request` and `Response`. On an `Io` with no task to spare the streams
//! are answered one at a time, on the reading task, and the server says so
//! by allowing one stream at once.

const std = @import("std");
const Io = std.Io;
const wire = @import("uplink.wire");
const h2 = wire.h2;
const hpack = wire.hpack;
const Field = wire.fields.Field;
const Method = wire.Method;
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
pub fn serve(context: *Context, handler: Handler, socket: *Socket) void {
    const io = socket.io;
    // A frame and its head must fit the read buffer.
    if (socket.input.interface.buffer.len < h2.head_len + 16384 and !socket.secure) {
        if (!grow(context, socket)) return;
    }
    var tasks: Io.Group = .init;
    const concurrent = probeConcurrency(io);
    var session = Session.init(context, socket, if (concurrent) 100 else 1) catch return;
    defer session.deinit();
    defer tasks.cancel(io);
    const in = socket.reader();
    const preface = in.peek(h2.preface.len) catch return;
    {
        var held = session.shared.acquireUncancelable(io);
        defer held.deinit(io);
        const shared = held.value();
        if (!shared.conn.checkPreface(preface)) {
            // glint-ignore: Z026 -- the connection closes next whether or not the GOAWAY reached the peer
            shared.conn.goaway(socket.writer(), .protocol_error) catch {};
            session.flushLocked(shared);
            return;
        }
        in.toss(h2.preface.len);
        shared.conn.start(socket.writer()) catch return;
        session.flushLocked(shared);
    }
    readFrames(&session, handler, &tasks, concurrent);
    {
        var held = session.shared.acquireUncancelable(io);
        defer held.deinit(io);
        held.value().closed = true;
    }
    session.changed.broadcast(io);
    // glint-ignore: Z026 -- the streams' tasks end with the connection; a cancel here is the caller's, already on its way
    tasks.await(io) catch {};
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
    context.buffers.release(socket.io, r.buffer);
    r.buffer = larger;
    r.seek = 0;
    r.end = buffered.len;
    return true;
}

fn readFrames(session: *Session, handler: Handler, tasks: *Io.Group, concurrent: bool) void {
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
                shared.conn.goaway(socket.writer(), .no_error) catch {};
                session.flushLocked(shared);
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
        {
            var held = session.shared.acquireUncancelable(io);
            defer held.deinit(io);
            const shared = held.value();
            const event = shared.conn.receive(socket.writer(), head, payload) catch {
                shared.closed = true;
                session.flushLocked(shared);
                session.changed.broadcast(io);
                return;
            };
            if (event) |e| spawn = handle(session, shared, e) catch {
                shared.closed = true;
                session.flushLocked(shared);
                session.changed.broadcast(io);
                return;
            };
            session.flushLocked(shared);
            if (shared.closed) return;
        }
        if (whole <= in.buffer.len) in.toss(whole) else {
            in.discardAll(whole) catch return;
        }
        session.changed.broadcast(io);
        if (spawn) |st| {
            if (concurrent) {
                tasks.concurrent(io, answer, .{ session, handler, st }) catch answer(session, handler, st);
            } else answer(session, handler, st);
        }
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
                st.trailer_buffer = session.context.buffers.acquire(session.socket.io, BufferPool.Class.fitting(fieldBytes(hd.fields)) orelse .large) catch return null;
                st.trailers = copyFields(st.trailer_buffer, hd.fields, false) catch null;
                st.recv_end = true;
                return null;
            }
            const st = try startStream(session, shared, hd.stream, hd.fields, hd.end_stream);
            return st;
        },
        .data => |d| {
            const st = Session.find(shared, d.stream) orelse {
                // A stream already answered: its data is given back.
                shared.conn.giveBack(session.socket.writer(), d.stream, d.bytes.len) catch {
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

fn fieldBytes(fields: []const hpack.Field) usize {
    var n: usize = fields.len * @sizeOf(Field) + @alignOf(Field);
    for (fields) |f| n += f.name.len + f.value.len;
    return n;
}

/// Copy `fields` into `buffer`: the strings first, then the fields; the
/// pseudo-fields left out unless `pseudo`.
fn copyFields(buffer: []u8, fields: []const hpack.Field, pseudo: bool) error{NoSpaceLeft}![]Field {
    var count: usize = 0;
    var bytes: usize = 0;
    for (fields) |f| {
        if (!pseudo and f.name.len != 0 and f.name[0] == ':') continue;
        count += 1;
        bytes += f.name.len + f.value.len;
    }
    const fields_at = std.mem.alignForward(usize, bytes, @alignOf(Field));
    if (fields_at + count * @sizeOf(Field) > buffer.len) return error.NoSpaceLeft;
    const out: [*]Field = @ptrCast(@alignCast(buffer.ptr + fields_at)); // safe: pool buffers are 64-aligned and `fields_at` is aligned for a Field, inside the buffer
    var at: usize = 0;
    var i: usize = 0;
    for (fields) |f| {
        if (!pseudo and f.name.len != 0 and f.name[0] == ':') continue;
        @memcpy(buffer[at..][0..f.name.len], f.name);
        @memcpy(buffer[at + f.name.len ..][0..f.value.len], f.value);
        out[i] = .{ .name = buffer[at..][0..f.name.len], .value = buffer[at + f.name.len ..][0..f.value.len] };
        at += f.name.len + f.value.len;
        i += 1;
    }
    return out[0..count];
}

/// A new request's stream: its fields kept, its state made.
fn startStream(session: *Session, shared: *Session.Shared, id: u31, fields: []const hpack.Field, end_stream: bool) error{OutOfMemory}!?*Stream {
    const gpa = session.context.gpa;
    const pool = &session.context.buffers;
    const io = session.socket.io;
    const class = BufferPool.Class.fitting(fieldBytes(fields) + 1024) orelse {
        // glint-ignore: Z026 -- a head too large to keep is refused; the connection goes on
        shared.conn.reset(session.socket.writer(), id, .refused_stream) catch {};
        return null;
    };
    const buffer = try pool.acquire(io, class);
    errdefer pool.release(io, buffer);
    const kept = copyFields(buffer, fields, true) catch unreachable; // unreachable: the class fits the fields
    // A malformed request is a stream error at once (RFC 9113 §8.1.1), and a
    // declared length is checked against the data as it comes.
    const head = checkHead(kept) orelse {
        pool.release(io, buffer);
        // glint-ignore: Z026 -- the reset is the answer; a failed write ends the connection at its next read
        shared.conn.reset(session.socket.writer(), id, .protocol_error) catch {};
        return null;
    };
    if (shared.conn.stream(id)) |s| s.content_length = head.content_length;
    const st = try gpa.create(Stream);
    errdefer gpa.destroy(st);
    st.* = .{ .session = session, .id = id, .head_buffer = buffer, .fields = kept, .recv_end = end_stream, .interface = undefined };
    st.initReader();
    try shared.streams.append(gpa, st);
    return st;
}

/// The request on `st`, checked as RFC 9113 §8.3 asks: its pseudo-fields
/// first, each once, those a request needs; names in lower case; no field
/// of a connection's own; `te` only `trailers`. Null for a malformed one.
const Head = struct {
    method: Method,
    path: []const u8,
    authority: ?[]const u8,
    scheme: ?[]const u8,
    protocol: ?[]const u8,
    fields: []const Field,
    content_length: ?u64,
};

fn checkHead(fields: []const Field) ?Head {
    var h: Head = .{ .method = undefined, .path = "", .authority = null, .scheme = null, .protocol = null, .fields = &.{}, .content_length = null };
    var method: ?[]const u8 = null;
    var path: ?[]const u8 = null;
    var regular_from: ?usize = null;
    for (fields, 0..) |f, i| {
        for (f.name) |ch| if (ch >= 'A' and ch <= 'Z') return null;
        if (f.name.len != 0 and f.name[0] == ':') {
            if (regular_from != null) return null;
            const slot: *?[]const u8 = if (std.mem.eql(u8, f.name, ":method")) &method else if (std.mem.eql(u8, f.name, ":path")) &path else if (std.mem.eql(u8, f.name, ":authority")) &h.authority else if (std.mem.eql(u8, f.name, ":scheme")) &h.scheme else if (std.mem.eql(u8, f.name, ":protocol")) &h.protocol else return null;
            if (slot.* != null) return null;
            slot.* = f.value;
            continue;
        }
        if (regular_from == null) regular_from = i;
        if (!wire.fields.isToken(f.name)) return null;
        const forbidden = [_][]const u8{ "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade" };
        for (forbidden) |name| if (std.mem.eql(u8, f.name, name)) return null;
        if (std.mem.eql(u8, f.name, "te") and !std.mem.eql(u8, f.value, "trailers")) return null;
        if (wire.fields.hasControl(f.value) or (f.value.len != 0 and (f.value[0] == ' ' or f.value[f.value.len - 1] == ' '))) return null;
        if (std.mem.eql(u8, f.name, "content-length")) {
            const n = wire.h1.parseLength(f.value) orelse return null;
            if (h.content_length) |was| if (was != n) return null;
            h.content_length = n;
        }
    }
    const m = method orelse return null;
    if (!wire.fields.isToken(m)) return null;
    h.method = .{ .name = m };
    if (h.method.eql(.CONNECT) and h.protocol == null) {
        // CONNECT: an authority, no scheme or path.
        if (h.authority == null or h.scheme != null or path != null) return null;
        h.path = "";
    } else {
        h.path = path orelse return null;
        if (h.path.len == 0 or h.scheme == null) return null;
        if (h.protocol != null and !h.method.eql(.CONNECT)) return null;
    }
    h.fields = fields[regular_from orelse fields.len ..];
    return h;
}

/// Answer the request on `st` with the handler, then forget the stream.
fn answer(session: *Session, handler: Handler, st: *Stream) void {
    const context = session.context;
    const io = session.socket.io;
    defer finish(session, st);
    const head = checkHead(st.fields).?; // `startStream` refused a malformed head
    const target_text = if (head.method.eql(.CONNECT) and head.protocol == null) head.authority.? else head.path;
    const target = Request.Target.parse(head.method, target_text) catch return st.reset(io, .protocol_error);
    var request: Request = .{
        .method = head.method,
        .target = target_text,
        .path = target.path,
        .query = target.query,
        .version = .h2,
        .headers = .init(head.fields),
        .host = head.authority orelse "",
        .remote = if (session.socket.stream.socket.address == .ip4 or session.socket.stream.socket.address == .ip6) session.socket.stream.socket.address else null,
        .secure = session.socket.secure,
        .socket = session.socket,
        .body = .init(Io.Reader.ending, .none, &.{}),
        .stream = st,
        .expects_continue = std.ascii.eqlIgnoreCase(std.mem.trim(u8, requestExpect(head.fields), " \t"), "100-continue") and !st.recv_end,
    };
    defer request.release(io);
    if (context.options.decompress and !st.recv_end) {
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
    _ = context.counters.requests.fetchAdd(1, .monotonic);
    const arrived = Io.Clock.awake.now(io);
    handler.handle(io, &request, &response) catch |err| {
        if (context.options.observer) |o| o.emit(.{ .failed = .{ .method = head.method.name, .path = target.path, .error_name = @errorName(err), .head_sent = response.headSent() } });
        if (response.headSent()) return st.reset(io, .internal_error);
        response.reset(io);
        response.stream = st;
        response.status = .internal_server_error;
        // glint-ignore: Z026 -- a 500 that cannot be written leaves the stream reset below
        response.send(io, "") catch {};
        return;
    };
    response.end(io) catch return st.reset(io, .internal_error);
    if (context.options.observer) |o| o.emit(.{ .answered = .{ .method = head.method.name, .path = target.path, .status = @backingInt(response.status), .took = span.of(arrived.durationTo(Io.Clock.awake.now(io))) } });
    // A request body the handler left: the client is told to stop sending.
    if (!st.recv_end and st.reset_code == null) st.reset(io, .no_error);
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
