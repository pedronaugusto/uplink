//! Test-only: an HTTP/1.1 server on 127.0.0.1 that answers each request on
//! a connection by a function of the request, and records what it saw.
//! Every connection runs as a task of its own.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;

const Server = @This();

io: Io,
gpa: Allocator,
listener: Io.net.Server,
port: u16,
handler: Handler,
task: Io.Future(void) = undefined,
group: Io.Group = .init,
stopping: std.atomic.Value(bool) = .init(false),
/// Connections accepted.
accepted: std.atomic.Value(u32) = .init(0),
/// Requests answered.
requests: std.atomic.Value(u32) = .init(0),
mutex: Io.Mutex = .init,
/// Every request's head and body, as received, one after another.
log: std.ArrayList(u8) = .empty,

/// What to do with one request.
pub const Handler = struct {
    context: ?*anyopaque = null,
    /// The answer to `request`, the head and its body as received.
    answer: *const fn (context: ?*anyopaque, request: Request) Answer,
};

pub const Request = struct {
    head: []const u8,
    body: []const u8,
    /// The request's place on its connection, from 0.
    index: u32,
};

pub const Answer = struct {
    /// Written as given.
    bytes: []const u8 = "",
    /// Read the request and never answer.
    silent: bool = false,
    /// Close the connection after the answer.
    close: bool = false,
    /// Write the answer in pieces this long, flushing each.
    piece: usize = 0,
};

/// An answer that does not depend on the request.
pub fn fixed(comptime bytes: []const u8) Handler {
    return fixedAnswer(.{ .bytes = bytes });
}

/// The same answer to every request.
pub fn fixedAnswer(comptime a: Answer) Handler {
    return .{ .answer = struct {
        fn answer(_: ?*anyopaque, _: Request) Answer {
            return a;
        }
    }.answer };
}

pub fn start(gpa: Allocator, io: Io, handler: Handler) !*Server {
    const s = try gpa.create(Server);
    errdefer gpa.destroy(s);
    var listener = try (try Io.net.IpAddress.parse("127.0.0.1", 0)).listen(io, .{ .reuse_address = true });
    errdefer listener.deinit(io);
    s.* = .{ .io = io, .gpa = gpa, .listener = listener, .port = listener.socket.address.getPort(), .handler = handler };
    s.task = io.concurrent(serve, .{s}) catch return error.SkipZigTest;
    return s;
}

pub fn stop(s: *Server) void {
    const io = s.io;
    s.stopping.store(true, .release);
    const address = Io.net.IpAddress.parse("127.0.0.1", s.port) catch unreachable; // unreachable: a literal address
    if (address.connect(io, .{ .mode = .stream })) |stream| stream.close(io) else |_| {}
    s.task.await(io);
    s.group.cancel(io);
    s.listener.deinit(io);
    s.log.deinit(s.gpa);
    s.gpa.destroy(s);
}

/// `http://127.0.0.1:<port><path>`, in `buffer`.
pub fn url(s: *const Server, buffer: []u8, path: []const u8) []const u8 {
    return std.mem.print(buffer, "http://127.0.0.1:{d}{s}", .{ s.port, path }) catch unreachable; // unreachable: callers pass room for a URL
}

/// A copy of everything received, in `gpa`.
pub fn received(s: *Server, gpa: Allocator) ![]u8 {
    s.mutex.lockUncancelable(s.io);
    defer s.mutex.unlock(s.io);
    return gpa.dupe(u8, s.log.items);
}

fn serve(s: *Server) void {
    while (true) {
        const stream = s.listener.accept(s.io) catch return;
        if (s.stopping.load(.acquire)) return stream.close(s.io);
        _ = s.accepted.fetchAdd(1, .monotonic);
        s.group.concurrent(s.io, handle, .{ s, stream }) catch stream.close(s.io);
    }
}

fn handle(s: *Server, stream: Io.net.Stream) void {
    defer stream.close(s.io);
    var read_buffer: [64 << 10]u8 = undefined;
    var write_buffer: [4096]u8 = undefined;
    var r = stream.reader(s.io, &read_buffer);
    var w = stream.writer(s.io, &write_buffer);
    var index: u32 = 0;
    while (true) : (index += 1) {
        const request = readRequest(&r.interface) catch return;
        s.record(request.head, request.body);
        const answer = s.handler.answer(s.handler.context, .{ .head = request.head, .body = request.body, .index = index });
        r.interface.toss(request.len);
        _ = s.requests.fetchAdd(1, .monotonic);
        if (answer.silent) {
            while (true) r.interface.fillMore() catch return;
        }
        writeAnswer(&w.interface, answer) catch return;
        if (answer.close) return;
    }
}

fn writeAnswer(w: *Io.Writer, answer: Answer) Io.Writer.Error!void {
    if (answer.piece == 0) {
        try w.writeAll(answer.bytes);
        return w.flush();
    }
    var at: usize = 0;
    while (at < answer.bytes.len) {
        const n = @min(answer.piece, answer.bytes.len - at);
        try w.writeAll(answer.bytes[at..][0..n]);
        try w.flush();
        at += n;
    }
}

fn record(s: *Server, head: []const u8, body: []const u8) void {
    s.mutex.lockUncancelable(s.io);
    defer s.mutex.unlock(s.io);
    s.log.appendSlice(s.gpa, head) catch return;
    s.log.appendSlice(s.gpa, body) catch return;
}

const Read = struct { head: []const u8, body: []const u8, len: usize };

/// One whole request in `r`'s buffer, not taken: its head, and its body
/// by `Content-Length` or chunks, decoded here crudely.
fn readRequest(r: *Io.Reader) !Read {
    while (std.mem.find(u8, r.buffered(), "\r\n\r\n") == null) try r.fillMore();
    const head_len = std.mem.find(u8, r.buffered(), "\r\n\r\n").? + 4;
    const head = r.buffered()[0..head_len];
    if (headerValue(head, "content-length")) |text| {
        const n = try std.fmt.parseUnsigned(usize, text, 10);
        while (r.bufferedLen() < head_len + n) try r.fillMore();
        return .{ .head = r.buffered()[0..head_len], .body = r.buffered()[head_len..][0..n], .len = head_len + n };
    }
    if (headerValue(head, "transfer-encoding") != null) {
        while (std.mem.find(u8, r.buffered()[head_len..], "\r\n0\r\n\r\n") == null and !std.mem.startsWith(u8, r.buffered()[head_len..], "0\r\n\r\n")) try r.fillMore();
        const rest = r.buffered()[head_len..];
        const end = if (std.mem.startsWith(u8, rest, "0\r\n\r\n")) 5 else std.mem.find(u8, rest, "\r\n0\r\n\r\n").? + 7;
        return .{ .head = r.buffered()[0..head_len], .body = rest[0..end], .len = head_len + end };
    }
    return .{ .head = head, .body = "", .len = head_len };
}

/// The value of field `name` in `head`, compared without case.
pub fn headerValue(head: []const u8, name: []const u8) ?[]const u8 {
    var lines = std.mem.splitSequence(u8, head, "\r\n");
    _ = lines.next();
    while (lines.next()) |line| {
        const colon = std.mem.findScalar(u8, line, ':') orelse continue;
        if (std.ascii.eqlIgnoreCase(line[0..colon], name)) return std.mem.trim(u8, line[colon + 1 ..], " \t");
    }
    return null;
}
