//! How a client answers its proxy, once the proxy has asked: one answer,
//! shared by every connection, as curl keeps one for git. A Digest answer
//! counts its uses of the nonce across them; a stale nonce is answered once
//! more with the fresh one.

const std = @import("std");
const aegis = @import("aegis");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const auth = @import("../wire/auth.zig");
const fields = @import("../wire/fields.zig");
const Proxy = @import("Proxy.zig");

const ProxyAuth = @This();

/// Private: the scheme chosen, once the proxy asked or Basic was asked for
/// from the start, reached only through the lock beside it.
answer: aegis.BlockingGuarded(?Answer),

const Answer = union(enum) {
    basic,
    digest: auth.Digest,
};

pub const init: ProxyAuth = .{ .answer = .init(null) };

pub fn deinit(pa: *ProxyAuth, io: Io) void {
    var held = pa.answer.acquireUncancelable(io);
    if (held.value().*) |*a| switch (a.*) {
        .basic => {},
        .digest => |*d| d.deinit(),
    };
    held.deinit(io);
    pa.* = undefined;
}

/// Write `Proxy-Authorization: …` and its line end for a request `method`
/// to `uri` — the request target, `host:port` for a `CONNECT` — when the
/// proxy is answered. Returns whether a field was written.
pub fn writeField(pa: *ProxyAuth, io: Io, w: *Io.Writer, credential: ?Proxy.Credential, method: []const u8, uri: []const u8) Io.Writer.Error!bool {
    const c = credential orelse return false;
    var held = pa.answer.acquireUncancelable(io);
    defer held.deinit(io);
    const current = held.value();
    if (current.* == null and c.method == .basic) current.* = .basic;
    const answer = &(current.* orelse return false);
    try w.writeAll("Proxy-Authorization: ");
    switch (answer.*) {
        .basic => try auth.writeBasic(w, c.user, c.password),
        .digest => |*d| try d.writeAnswer(w, c.user, c.password, method, uri),
    }
    try w.writeAll("\r\n");
    return true;
}

/// Errors from `challenged`.
pub const ChallengeError = error{
    /// The proxy offers only schemes not spoken here, or none the
    /// credential's method allows; `offered` names them.
    ProxyAuthMethodUnsupported,
    OutOfMemory,
};

/// Take a 407's challenges: whether the request is to be made again with
/// an answer. False when there is no credential to answer with, or when the
/// answer given was refused — a Digest nonce gone stale is answered again.
/// When nothing can answer, the offered schemes go to `offered`.
pub fn challenged(pa: *ProxyAuth, gpa: Allocator, io: Io, credential: ?Proxy.Credential, headers: *const fields.Headers, offered: *Io.Writer) ChallengeError!bool {
    const c = credential orelse return false;
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var challenges: std.ArrayList(auth.Challenge) = .empty;
    var it = headers.iterator();
    while (it.next()) |f| {
        if (!std.ascii.eqlIgnoreCase(f.name, "proxy-authenticate")) continue;
        const list = auth.parse(arena, f.value) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.MalformedChallenge => continue,
        };
        try challenges.appendSlice(arena, list);
    }
    var held = pa.answer.acquireUncancelable(io);
    defer held.deinit(io);
    const current = held.value();
    if (current.*) |*previous| {
        // Answered and refused, unless the nonce only went stale.
        if (previous.* != .digest) return false;
        const fresh = for (challenges.items) |ch| {
            if (ch.scheme != .digest) continue;
            const stale = ch.param("stale") orelse continue;
            if (std.ascii.eqlIgnoreCase(stale, "true") and auth.Digest.speaks(ch)) break ch;
        } else return false;
        const next: auth.Digest = try .init(gpa, fresh, &cnonce(io));
        previous.digest.deinit();
        current.* = .{ .digest = next };
        return true;
    }
    switch (auth.pick(challenges.items, c.method, offered)) {
        .digest => |ch| {
            // Made apart and then stored: `answer` keeps its old value when
            // the copies cannot be made.
            const digest: auth.Digest = try .init(gpa, ch, &cnonce(io));
            current.* = .{ .digest = digest };
        },
        .basic => current.* = .basic,
        .unsupported => return error.ProxyAuthMethodUnsupported,
    }
    return true;
}

/// A client nonce for Digest as curl makes one: thirty-two random hex
/// digits, in base64.
fn cnonce(io: Io) [44]u8 {
    var raw: [16]u8 = undefined;
    io.random(&raw);
    const hex = std.fmt.bytesToHex(raw, .lower);
    var out: [44]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&out, &hex);
    return out;
}

const testing = std.testing;

fn headersOf(comptime challenge: []const u8) fields.Headers {
    const list = [_]fields.Field{.{ .name = "Proxy-Authenticate", .value = challenge }};
    return .init(&list);
}

test "Basic is sent from the start when asked for, else only once the proxy asks" {
    const io = testing.io;
    var buf: [256]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    var pa: ProxyAuth = .init;
    defer pa.deinit(io);
    try testing.expect(!try pa.writeField(io, &w, .{ .user = "a", .password = "b" }, "GET", "/"));
    try testing.expect(try pa.writeField(io, &w, .{ .user = "a", .password = "b", .method = .basic }, "GET", "/"));
    try testing.expectEqualStrings("Proxy-Authorization: Basic YTpi\r\n", w.buffered());
}

test "a Digest challenge is answered, a stale nonce answered again, and a refusal not" {
    const io = testing.io;
    var pa: ProxyAuth = .init;
    defer pa.deinit(io);
    var offered_buf: [64]u8 = undefined;
    var offered: Io.Writer = .fixed(&offered_buf);
    const credential: Proxy.Credential = .{ .user = "a", .password = "b" };
    try testing.expect(try pa.challenged(testing.allocator, io, credential, &headersOf("Digest realm=\"p\", nonce=\"n1\", qop=\"auth\""), &offered));
    var buf: [512]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try testing.expect(try pa.writeField(io, &w, credential, "CONNECT", "h:443"));
    try testing.expect(std.mem.find(u8, w.buffered(), "nonce=\"n1\"") != null);
    try testing.expect(try pa.challenged(testing.allocator, io, credential, &headersOf("Digest realm=\"p\", nonce=\"n2\", stale=true"), &offered));
    w = .fixed(&buf);
    _ = try pa.writeField(io, &w, credential, "CONNECT", "h:443");
    try testing.expect(std.mem.find(u8, w.buffered(), "nonce=\"n2\"") != null);
    try testing.expect(!try pa.challenged(testing.allocator, io, credential, &headersOf("Digest realm=\"p\", nonce=\"n3\""), &offered));
    var unanswered: ProxyAuth = .init;
    defer unanswered.deinit(io);
    try testing.expectError(error.ProxyAuthMethodUnsupported, unanswered.challenged(testing.allocator, io, credential, &headersOf("Negotiate"), &offered));
    try testing.expectEqualStrings("Negotiate", offered.buffered());
    try testing.expect(!try unanswered.challenged(testing.allocator, io, null, &headersOf("Basic"), &offered));
}

test "a challenge leaves nothing allocated when allocation stops" {
    const shakedown = @import("shakedown");
    const Check = struct {
        fn run(gpa: Allocator) !void {
            var pa: ProxyAuth = .init;
            defer pa.deinit(testing.io);
            var offered_buf: [64]u8 = undefined;
            var offered: Io.Writer = .fixed(&offered_buf);
            _ = try pa.challenged(gpa, testing.io, .{ .user = "a", .password = "b" }, &headersOf("Negotiate, Digest realm=\"r\", nonce=\"n\", opaque=\"o\""), &offered);
        }
    };
    var no_resize: shakedown.alloc.NoResize = .init(testing.allocator);
    try testing.checkAllAllocationFailures(no_resize.allocator(), Check.run, .{});
}
