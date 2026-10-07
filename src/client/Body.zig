//! A response's body as its framing delimits it: a length, chunks, or the
//! connection's end. The body's bytes pass from the connection's reader to
//! the caller's writer without a copy of the body reader's own; chunk
//! framing is consumed where it lies in the connection's buffer.

const std = @import("std");
const Io = std.Io;
const h1 = @import("../wire/h1.zig");

const Body = @This();

interface: Io.Reader,
/// Private: the connection's reader.
in: *Io.Reader,
/// Private: how the body is delimited.
framing: h1.Framing,
/// Private: bytes left of a body of known length.
remaining: u64,
/// Private: the chunk framing's state.
chunked: h1.ChunkedDecoder = .{},
/// Where reading stands.
state: State = .reading,

pub const State = enum {
    reading,
    /// The body was read to its end.
    done,
    /// The connection failed under the body; it says why.
    read_failed,
    /// The connection ended before the body did.
    incomplete,
    /// The chunk framing was malformed.
    malformed,
};

/// A body read from `in` as `framing` says, with `buffer` for the reader's
/// own buffering.
pub fn init(in: *Io.Reader, framing: h1.Framing, buffer: []u8) Body {
    return .{
        .interface = .{ .vtable = &.{ .stream = stream }, .buffer = buffer, .seek = 0, .end = 0 },
        .in = in,
        .framing = framing,
        .remaining = switch (framing) {
            .length => |n| n,
            else => 0,
        },
        .state = switch (framing) {
            .none => .done,
            .length => |n| if (n == 0) .done else .reading,
            .chunked, .until_close => .reading,
        },
    };
}

/// Whether the whole body has been read, its own buffer included: what the
/// connection needs to carry another exchange.
pub fn complete(b: *const Body) bool {
    return b.state == .done and b.interface.seek == b.interface.end;
}

fn stream(r: *Io.Reader, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
    const b: *Body = @alignCast(@fieldParentPtr("interface", r)); // safe: this vtable is installed only on a Body's interface
    switch (b.state) {
        .reading => {},
        .done => return error.EndOfStream,
        .read_failed, .incomplete, .malformed => return error.ReadFailed,
    }
    if (limit == .nothing) return 0;
    return switch (b.framing) {
        .none => unreachable, // unreachable: a body with no framing starts done
        .length => b.streamLength(w, limit),
        .until_close => b.in.stream(w, limit) catch |err| switch (err) {
            error.EndOfStream => {
                b.state = .done;
                return error.EndOfStream;
            },
            error.ReadFailed => b.failed(.read_failed),
            error.WriteFailed => error.WriteFailed,
        },
        .chunked => b.streamChunked(w, limit),
    };
}

fn streamLength(b: *Body, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
    const n = b.in.stream(w, limit.min(.limited64(b.remaining))) catch |err| return switch (err) {
        error.EndOfStream => b.failed(.incomplete),
        error.ReadFailed => b.failed(.read_failed),
        error.WriteFailed => error.WriteFailed,
    };
    b.remaining -= n;
    if (b.remaining == 0) b.state = .done;
    return n;
}

fn streamChunked(b: *Body, w: *Io.Writer, limit: Io.Limit) Io.Reader.StreamError!usize {
    const d = &b.chunked;
    while (true) {
        const pending = d.pending();
        if (pending != 0) {
            const n = b.in.stream(w, limit.min(.limited64(pending))) catch |err| return switch (err) {
                error.EndOfStream => b.failed(.incomplete),
                error.ReadFailed => b.failed(.read_failed),
                error.WriteFailed => error.WriteFailed,
            };
            d.take(n);
            return n;
        }
        if (d.done()) {
            b.state = .done;
            return error.EndOfStream;
        }
        if (b.in.bufferedLen() == 0) b.in.fillMore() catch |err| return switch (err) {
            error.EndOfStream => b.failed(.incomplete),
            error.ReadFailed => b.failed(.read_failed),
        };
        const step = d.feed(b.in.buffered()) catch return b.failed(.malformed);
        b.in.toss(step.consumed);
    }
}

fn failed(b: *Body, state: State) error{ReadFailed} {
    b.state = state;
    return error.ReadFailed;
}

const testing = std.testing;

fn readAll(b: *Body) ![]u8 {
    return b.interface.allocRemaining(testing.allocator, .unlimited);
}

test "a body of known length stops at its length, and one cut short says so" {
    var in: Io.Reader = .fixed("helloNEXT");
    var buf: [4]u8 = undefined;
    var b: Body = .init(&in, .{ .length = 5 }, &buf);
    const got = try readAll(&b);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("hello", got);
    try testing.expect(b.complete());
    try testing.expectEqualStrings("NEXT", in.buffered());
    var short: Io.Reader = .fixed("hel");
    var cut: Body = .init(&short, .{ .length = 5 }, &buf);
    try testing.expectError(error.ReadFailed, readAll(&cut));
    try testing.expectEqual(State.incomplete, cut.state);
    try testing.expect(!cut.complete());
}

test "a chunked body is decoded where it lies, and what follows it is left" {
    var in: Io.Reader = .fixed("4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\nNEXT");
    var buf: [3]u8 = undefined;
    var b: Body = .init(&in, .chunked, &buf);
    const got = try readAll(&b);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("Wikipedia", got);
    try testing.expect(b.complete());
    try testing.expectEqualStrings("NEXT", in.buffered());
    var bad: Io.Reader = .fixed("4\r\nWikiXX");
    var malformed: Body = .init(&bad, .chunked, &buf);
    try testing.expectError(error.ReadFailed, readAll(&malformed));
    try testing.expectEqual(State.malformed, malformed.state);
}

test "a body to the connection's end, and one with none, end as framed" {
    var in: Io.Reader = .fixed("all of it");
    var buf: [2]u8 = undefined;
    var b: Body = .init(&in, .until_close, &buf);
    const got = try readAll(&b);
    defer testing.allocator.free(got);
    try testing.expectEqualStrings("all of it", got);
    var empty: Io.Reader = .fixed("NEXT");
    var none: Body = .init(&empty, .none, &buf);
    try testing.expect(none.complete());
    const nothing = try readAll(&none);
    defer testing.allocator.free(nothing);
    try testing.expectEqual(@as(usize, 0), nothing.len);
}
