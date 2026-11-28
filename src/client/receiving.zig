//! What a response is read with: its head from an HTTP/1 connection, parsed
//! in a pooled buffer, and the decoder its body is read through. The client's
//! own machinery, which `Run` drives; not part of uplink's API.

const std = @import("std");
const aegis = @import("aegis");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const wire = @import("uplink.wire");
const h1 = wire.h1;
const fields = wire.fields;
const coding = wire.coding;
const Method = wire.Method;
const BufferPool = @import("../transport/BufferPool.zig");
const Connection = @import("../transport/Connection.zig");
const Context = @import("../transport/Context.zig");
const Diagnostics = @import("../transport/Diagnostics.zig");
const Head = @import("../transport/Head.zig");
const Decoder = @import("../coding/Decoder.zig");

/// Errors from reading a response.
pub const ReceiveError = error{
    ConnectionFailed,
    TimedOut,
    /// No task and no bound of the `Io`'s own could keep a wait's timeout:
    /// the read did not run.
    ConcurrencyUnavailable,
    TlsFailed,
    ClientCertificateRejected,
    Canceled,
    HttpProtocolError,
    OutOfMemory,
};

/// What reading a response needs besides the connection.
pub const ReceiveOptions = struct {
    method: Method,
    limits: h1.Limits,
    decompress: bool,
    diagnostics: ?*Diagnostics,
    /// Set once a byte of the response has arrived.
    progress: *bool,
    /// Return a `100 Continue` rather than skipping it: the request waits
    /// for one before its body.
    want_continue: bool = false,
};

/// The decoder for a body whose codings are all gzip, deflate, zstd or
/// Brotli. Null for a body already `done`, and for one under any other
/// coding or under codings uplink cannot read: it is handed over as it came,
/// `Content-Encoding` and all.
pub fn decoderFor(io: Io, ctx: *Context, headers: *const fields.Headers, done: bool) Allocator.Error!?Decoder {
    if (done) return null;
    const codings = (coding.Codings.of(headers) catch null) orelse return null;
    if (codings.len == 0 or !Decoder.decodes(codings.slice())) return null;
    return try .init(io, ctx.gpa, &ctx.buffers, &ctx.windows, codings.slice());
}

/// A response head, parsed in its pooled buffer.
pub const Received = struct {
    buffer: BufferPool.Buffer,
    head: h1.ResponseHead,
    body_buffer: []u8,
};

/// Read one head from `conn` into a pooled buffer and parse it there.
pub fn receiveHead(io: Io, ctx: *Context, conn: *Connection, options: ReceiveOptions) ReceiveError!Received {
    var head = Head.gather(io, &ctx.buffers, conn.reader(), options.limits, options.progress) catch |err| return switch (err) {
        error.HeadTooLarge, error.StartLineTooLong, error.NoStartLine => error.HttpProtocolError,
        error.EndOfStream => if (conn.failed() == .none) error.ConnectionFailed else conn.readError(),
        error.ReadFailed => conn.readError(),
        error.OutOfMemory => error.OutOfMemory,
    };
    errdefer head.release(io, &ctx.buffers);
    const parsed = (h1.parseResponse(head.bytes(), head.fields(), options.limits) catch return error.HttpProtocolError) orelse
        return error.HttpProtocolError;
    aegis.assert.invariant(parsed.len == head.len, "parsed.len == head.len");
    return .{ .buffer = head.buffer, .head = parsed.head, .body_buffer = head.bodyBuffer() };
}
