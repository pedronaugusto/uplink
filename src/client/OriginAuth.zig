//! The answers a client gives servers' challenges, per origin: the one
//! owner of them. A secret filled for a 401 is kept, copied, and sent with
//! every later request to the same origin — scheme, host and port — and
//! never to another. A Digest answer counts its uses of the nonce; a stale
//! one is answered again with the fresh nonce.
//!
//! An answer is told to the caller's `Credentials` once: taken, at the
//! first response to it that is not a 401, or refused, at a 401, when it is
//! also forgotten. Entries are counted by the requests that sent them, so
//! one forgotten while another task's request still answers with it lives
//! until that request settles.

const std = @import("std");
const aegis = @import("aegis");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const auth = @import("../wire/auth.zig");
const url_mod = @import("../wire/url.zig");
const Credentials = @import("Credentials.zig");

const OriginAuth = @This();

gpa: Allocator,
/// The listed answers, reached only through the lock beside them. That lock
/// also holds every entry's counts and Digest state.
entries: aegis.BlockingGuarded(std.ArrayList(*Entry)),
/// The number of listed answers, readable without the lock: a client that
/// never answered a challenge pays nothing per request.
live: std.atomic.Value(u32) = .init(0),

/// One origin's answer.
pub const Entry = struct {
    secure: bool,
    port: u16,
    /// Every string below is in `bytes`.
    host: []const u8,
    realm: ?[]const u8,
    url: []const u8,
    secret: Credentials.Secret,
    scheme: auth.Scheme,
    digest: ?auth.Digest = null,
    /// The secret and the strings beside it, wiped before they are freed.
    bytes: aegis.SecretBytes,
    /// Requests that sent it and have not settled, plus one while listed.
    refs: u32 = 1,
    listed: bool = true,
    /// Whether the caller was told how it went.
    reported: bool = false,

    fn query(e: *const Entry) Credentials.Query {
        return .{ .url = e.url, .secure = e.secure, .host = e.host, .port = e.port, .realm = e.realm, .scheme = e.scheme };
    }
};

pub fn init(gpa: Allocator) OriginAuth {
    return .{ .gpa = gpa, .entries = .init(.empty) };
}

/// Forget every answer. No request may still hold one.
pub fn deinit(oa: *OriginAuth, io: Io) void {
    var held = oa.entries.acquireUncancelable(io);
    const entries = held.value();
    for (entries.items) |e| {
        aegis.assert.pre(e.refs == 1, "no request holds an answer being freed");
        oa.free(e);
    }
    entries.deinit(oa.gpa);
    held.deinit(io);
    oa.* = undefined;
}

fn free(oa: *OriginAuth, e: *Entry) void {
    if (e.digest) |*d| d.deinit();
    e.bytes.deinit();
    oa.gpa.destroy(e);
}

fn find(entries: *const std.ArrayList(*Entry), url: url_mod.Url) ?*Entry {
    for (entries.items) |e| {
        if (e.secure == url.secure and e.port == url.port and std.ascii.eqlIgnoreCase(e.host, url.host)) return e;
    }
    return null;
}

/// Write `Authorization: …` and its line end for a request `method` to
/// `target` at `url`, when the origin has an answer, and hold the answer
/// for the request, which must `settle` it. Returns the answer held.
pub fn writeField(oa: *OriginAuth, io: Io, w: *Io.Writer, url: url_mod.Url, method: []const u8, target: []const u8) Io.Writer.Error!?*Entry {
    if (oa.live.load(.acquire) == 0) return null;
    var held = oa.entries.acquireUncancelable(io);
    defer held.deinit(io);
    const e = find(held.value(), url) orelse return null;
    try w.writeAll("Authorization: ");
    switch (e.secret) {
        .token => |t| try auth.writeBearer(w, t),
        .password => |p| if (e.digest) |*d| try d.writeAnswer(w, p.user, p.password, method, target) else try auth.writeBasic(w, p.user, p.password),
    }
    try w.writeAll("\r\n");
    e.refs += 1;
    return e;
}

/// Why a challenge could not be answered.
pub const AnswerError = error{
    OutOfMemory,
    CredentialsUnavailable,
    Canceled,
};

/// Answer `challenges`, a 401's, for `url` (its text `url_text`): fill a
/// secret from `credentials` and keep it for the origin, in place of any
/// answer it had. False when nothing can answer: no challenge a secret can
/// take, or no secret given.
pub fn answer(oa: *OriginAuth, io: Io, credentials: Credentials, url: url_mod.Url, url_text: []const u8, challenges: []const auth.Challenge) AnswerError!bool {
    const best = strongest(challenges) orelse return false;
    const query: Credentials.Query = .{
        .url = url_text,
        .secure = url.secure,
        .host = url.host,
        .port = url.port,
        .realm = best.param("realm"),
        .scheme = best.scheme,
    };
    const filled = try credentials.fill(io, query) orelse return false;
    const e = try oa.copy(query, filled);
    errdefer oa.free(e);
    // The scheme the secret takes: a token is Bearer; a password is Digest
    // when offered, else Basic.
    const chosen: ?auth.Challenge = switch (e.secret) {
        .token => for (challenges) |c| {
            if (c.scheme == .bearer) break c;
        } else null,
        .password => for (challenges) |c| {
            if (c.scheme == .digest and auth.Digest.speaks(c)) break c;
        } else for (challenges) |c| {
            if (c.scheme == .basic) break c;
        } else null,
    };
    const ch = chosen orelse {
        credentials.done(io, e.query(), e.secret, false);
        oa.free(e);
        return false;
    };
    if (ch.scheme == .digest) {
        var raw: [16]u8 = undefined;
        io.random(&raw);
        const hex = std.fmt.bytesToHex(raw, .lower);
        e.digest = try .init(oa.gpa, ch, &hex);
    }
    try oa.list(io, e);
    return true;
}

/// The challenge that names the strongest scheme a secret can answer.
fn strongest(challenges: []const auth.Challenge) ?auth.Challenge {
    for ([_]auth.Scheme{ .digest, .bearer, .basic }) |want| {
        for (challenges) |c| if (c.scheme == want and (want != .digest or auth.Digest.speaks(c))) return c;
    }
    return null;
}

/// A new entry holding copies of `query` and `secret`.
fn copy(oa: *OriginAuth, query: Credentials.Query, secret: Credentials.Secret) Allocator.Error!*Entry {
    const realm = query.realm orelse "";
    var len = query.host.len + realm.len + query.url.len;
    switch (secret) {
        .token => |t| len += t.len,
        .password => |p| len += p.user.len + p.password.len,
    }
    const e = try oa.gpa.create(Entry);
    errdefer oa.gpa.destroy(e);
    e.bytes = try .init(oa.gpa, len);
    errdefer e.bytes.deinit();
    e.bytes.resizeWithinCapacity(len) catch unreachable; // unreachable: `len` is the capacity just made
    const bytes = e.bytes.exposeMut();
    var at: usize = 0;
    const host = put(bytes, &at, query.host);
    const realm_copy = put(bytes, &at, realm);
    const url = put(bytes, &at, query.url);
    const owned: Credentials.Secret = switch (secret) {
        .token => |t| .{ .token = put(bytes, &at, t) },
        .password => |p| .{ .password = .{ .user = put(bytes, &at, p.user), .password = put(bytes, &at, p.password) } },
    };
    e.secure = query.secure;
    e.port = query.port;
    e.host = host;
    e.realm = if (query.realm != null) realm_copy else null;
    e.url = url;
    e.secret = owned;
    e.scheme = query.scheme;
    e.digest = null;
    e.refs = 1;
    e.listed = true;
    e.reported = false;
    return e;
}

fn put(bytes: []u8, at: *usize, text: []const u8) []const u8 {
    @memcpy(bytes[at.*..][0..text.len], text);
    defer at.* += text.len;
    return bytes[at.*..][0..text.len];
}

/// List `e` for its origin, unlisting the answer it replaces.
fn list(oa: *OriginAuth, io: Io, e: *Entry) Allocator.Error!void {
    var held = oa.entries.acquireUncancelable(io);
    defer held.deinit(io);
    const entries = held.value();
    try entries.ensureUnusedCapacity(oa.gpa, 1);
    for (entries.items, 0..) |old, i| {
        if (old.secure == e.secure and old.port == e.port and std.ascii.eqlIgnoreCase(old.host, e.host)) {
            entries.items[i] = e;
            oa.unlist(old);
            return;
        }
    }
    // More answers than a u32 counts are more than memory holds.
    const grown = aegis.int.cast(u32, entries.items.len + 1) catch return error.OutOfMemory;
    entries.appendAssumeCapacity(e);
    oa.live.store(grown, .release);
}

/// Drop the list's reference to `e`, already out of the list.
fn unlist(oa: *OriginAuth, e: *Entry) void {
    e.listed = false;
    e.refs -= 1;
    if (e.refs == 0) oa.free(e);
}

/// A request that sent `e` has its response: a 401 refuses the answer,
/// which is forgotten, and anything else takes it. The caller's store is
/// told, once per answer.
pub fn settle(oa: *OriginAuth, io: Io, e: *Entry, credentials: ?Credentials, accepted: bool) void {
    var held = oa.entries.acquireUncancelable(io);
    const entries = held.value();
    const tell = !e.reported and credentials != null;
    e.reported = true;
    if (!accepted and e.listed) {
        for (entries.items, 0..) |x, i| if (x == e) {
            _ = entries.swapRemove(i);
            break;
        };
        oa.live.store(aegis.int.cast(u32, entries.items.len) catch unreachable, .release); // unreachable: the list was counted into a u32 when it grew
        oa.unlist(e);
    }
    held.deinit(io);
    // Told outside the lock: a store may itself send requests.
    if (tell) credentials.?.done(io, e.query(), e.secret, accepted);
    oa.release(io, e);
}

/// A request that sent `e` ends without a response to judge it by.
pub fn release(oa: *OriginAuth, io: Io, e: *Entry) void {
    var held = oa.entries.acquireUncancelable(io);
    defer held.deinit(io);
    e.refs -= 1;
    if (e.refs == 0) oa.free(e);
}

/// A 401 to `e`'s Digest answer that says only its nonce went stale:
/// answer again with the fresh one. False when the challenges say no
/// such thing.
pub fn refreshNonce(oa: *OriginAuth, io: Io, e: *Entry, challenges: []const auth.Challenge) Allocator.Error!bool {
    const fresh = for (challenges) |ch| {
        if (ch.scheme != .digest) continue;
        const stale = ch.param("stale") orelse continue;
        if (std.ascii.eqlIgnoreCase(stale, "true") and auth.Digest.speaks(ch)) break ch;
    } else return false;
    var raw: [16]u8 = undefined;
    io.random(&raw);
    const hex = std.fmt.bytesToHex(raw, .lower);
    var next: auth.Digest = try .init(oa.gpa, fresh, &hex);
    var held = oa.entries.acquireUncancelable(io);
    defer held.deinit(io);
    if (e.digest == null) {
        next.deinit();
        return false;
    }
    e.digest.?.deinit();
    e.digest = next;
    return true;
}

const testing = std.testing;
const Unwiped = @import("../testing/Unwiped.zig");

const Store = struct {
    filled: u32 = 0,
    taken: u32 = 0,
    refused: u32 = 0,
    secret: Credentials.Secret = .{ .password = .{ .user = "Mufasa", .password = "Circle of Life" } },

    fn credentials(s: *Store) Credentials {
        return .{ .context = s, .fillFn = fillFn, .doneFn = doneFn };
    }

    fn fillFn(_: Io, context: ?*anyopaque, _: Credentials.Query) Credentials.FillError!?Credentials.Secret {
        const s: *Store = @ptrCast(@alignCast(context.?)); // safe: the tests pass a Store
        s.filled += 1;
        return s.secret;
    }

    fn doneFn(_: Io, context: ?*anyopaque, _: Credentials.Query, _: Credentials.Secret, accepted: bool) void {
        const s: *Store = @ptrCast(@alignCast(context.?)); // safe: the tests pass a Store
        if (accepted) s.taken += 1 else s.refused += 1;
    }
};

fn challengesOf(arena: Allocator, value: []const u8) ![]const auth.Challenge {
    return auth.parse(arena, value);
}

test "an answer is kept per origin, sent only there, and told once" {
    const io = testing.io;
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var oa: OriginAuth = .init(testing.allocator);
    defer oa.deinit(io);
    var store: Store = .{};
    const url = try url_mod.parse("https://git.test/repo");
    try testing.expect(try oa.answer(io, store.credentials(), url, "https://git.test/repo", try challengesOf(arena.allocator(), "Basic realm=\"git\"")));
    var buf: [256]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    const sent = (try oa.writeField(io, &w, url, "GET", "/repo")).?;
    try testing.expectEqualStrings("Authorization: Basic TXVmYXNhOkNpcmNsZSBvZiBMaWZl\r\n", w.buffered());
    w = .fixed(&buf);
    try testing.expectEqual(null, try oa.writeField(io, &w, try url_mod.parse("http://git.test/repo"), "GET", "/"));
    try testing.expectEqual(null, try oa.writeField(io, &w, try url_mod.parse("https://git.test:8443/"), "GET", "/"));
    const again = (try oa.writeField(io, &w, url, "GET", "/other")).?;
    oa.settle(io, sent, store.credentials(), true);
    oa.settle(io, again, store.credentials(), true);
    try testing.expectEqual(@as(u32, 1), store.taken);
    // A 401 to the answer refuses and forgets it.
    w = .fixed(&buf);
    const third = (try oa.writeField(io, &w, url, "GET", "/")).?;
    oa.settle(io, third, store.credentials(), false);
    try testing.expectEqual(@as(u32, 0), store.refused);
    try testing.expectEqual(null, try oa.writeField(io, &w, url, "GET", "/"));
}

test "a password answers Digest when offered, and a stale nonce is answered again" {
    const io = testing.io;
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var oa: OriginAuth = .init(testing.allocator);
    defer oa.deinit(io);
    var store: Store = .{};
    const url = try url_mod.parse("http://h.test/");
    const challenges = try challengesOf(arena.allocator(), "Basic realm=\"r\", Digest realm=\"r\", nonce=\"n1\", qop=\"auth\"");
    try testing.expect(try oa.answer(io, store.credentials(), url, "http://h.test/", challenges));
    var buf: [512]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    const e = (try oa.writeField(io, &w, url, "GET", "/")).?;
    try testing.expect(std.mem.find(u8, w.buffered(), "Digest username=\"Mufasa\"") != null);
    try testing.expect(try oa.refreshNonce(io, e, try challengesOf(arena.allocator(), "Digest realm=\"r\", nonce=\"n2\", stale=true")));
    try testing.expect(!try oa.refreshNonce(io, e, try challengesOf(arena.allocator(), "Digest realm=\"r\", nonce=\"n3\"")));
    w = .fixed(&buf);
    const second = (try oa.writeField(io, &w, url, "GET", "/")).?;
    try testing.expect(std.mem.find(u8, w.buffered(), "nonce=\"n2\"") != null);
    oa.release(io, e);
    oa.settle(io, second, store.credentials(), false);
    try testing.expectEqual(@as(u32, 1), store.refused);
}

test "a token answers Bearer, and nothing answers what no secret can" {
    const io = testing.io;
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var oa: OriginAuth = .init(testing.allocator);
    defer oa.deinit(io);
    var store: Store = .{ .secret = .{ .token = "t0k3n" } };
    const url = try url_mod.parse("https://api.test/");
    try testing.expect(try oa.answer(io, store.credentials(), url, "https://api.test/", try challengesOf(arena.allocator(), "Bearer realm=\"api\"")));
    var buf: [128]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    const e = (try oa.writeField(io, &w, url, "GET", "/")).?;
    try testing.expectEqualStrings("Authorization: Bearer t0k3n\r\n", w.buffered());
    oa.release(io, e);
    try testing.expect(!try oa.answer(io, store.credentials(), url, "https://api.test/", try challengesOf(arena.allocator(), "Negotiate")));
    // A token offered only Basic is refused at once.
    try testing.expect(!try oa.answer(io, store.credentials(), url, "https://api.test/", try challengesOf(arena.allocator(), "Basic realm=\"x\"")));
    try testing.expectEqual(@as(u32, 1), store.refused);
}

test "a forgotten answer is wiped before it is freed" {
    const io = testing.io;
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    var unwiped: Unwiped = .init(testing.allocator, "Circle of Life");
    var oa: OriginAuth = .init(unwiped.allocator());
    var store: Store = .{};
    const url = try url_mod.parse("https://git.test/repo");
    try testing.expect(try oa.answer(io, store.credentials(), url, "https://git.test/repo", try challengesOf(arena.allocator(), "Basic realm=\"git\"")));
    var buf: [256]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    const sent = (try oa.writeField(io, &w, url, "GET", "/repo")).?;
    // A 401 to the answer refuses and forgets it; the last request frees it.
    oa.settle(io, sent, store.credentials(), false);
    try testing.expect(!unwiped.found);
    // One replaced by another answer is wiped as well.
    try testing.expect(try oa.answer(io, store.credentials(), url, "https://git.test/repo", try challengesOf(arena.allocator(), "Basic realm=\"git\"")));
    try testing.expect(try oa.answer(io, store.credentials(), url, "https://git.test/repo", try challengesOf(arena.allocator(), "Basic realm=\"git\"")));
    oa.deinit(io);
    try testing.expect(!unwiped.found);
}

test "an answer leaves nothing allocated when allocation stops" {
    const shakedown = @import("shakedown");
    const Check = struct {
        fn run(gpa: Allocator) !void {
            var arena: std.heap.ArenaAllocator = .init(testing.allocator);
            defer arena.deinit();
            var oa: OriginAuth = .init(gpa);
            defer oa.deinit(testing.io);
            var store: Store = .{};
            const url = try url_mod.parse("http://h.test/");
            _ = try oa.answer(testing.io, store.credentials(), url, "http://h.test/", try challengesOf(arena.allocator(), "Digest realm=\"r\", nonce=\"n\", opaque=\"o\""));
        }
    };
    var no_resize: shakedown.alloc.NoResize = .init(testing.allocator);
    try testing.checkAllAllocationFailures(no_resize.allocator(), Check.run, .{});
}
