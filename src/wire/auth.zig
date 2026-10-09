//! HTTP authentication challenges and their answers (RFC 9110 §11): the
//! `Proxy-Authenticate` and `WWW-Authenticate` values read, and the
//! `Authorization` or `Proxy-Authorization` value that answers one, written
//! straight into a request head.
//!
//! A challenge names a scheme and its parameters — `Digest realm="proxy",
//! nonce="…", qop="auth", algorithm=SHA-256` — and one header may carry
//! several. Basic answers with the user and password as they are. Digest
//! (RFC 7616) answers with a hash of them, the nonce the server gave, the
//! request's method and target, and a count and a nonce of the client's
//! own, with MD5, SHA-256 and SHA-512-256 and their `-sess` forms, `qop=auth`
//! or none, and a hashed user name when the server asks for one. `auth-int`,
//! which hashes the body too, is not answered; curl does not offer it for a
//! proxy either. Bearer (RFC 6750) answers with a token the caller holds.
//! Negotiate and NTLM need a security library of the system's and are not
//! spoken: `pick` names them unsupported.

const std = @import("std");
const aegis = @import("aegis");
const Allocator = std.mem.Allocator;
const Writer = std.Io.Writer;
const fields = @import("fields.zig");

/// A scheme a challenge names.
pub const Scheme = enum { basic, digest, bearer, other };

/// One challenge: its scheme, and its parameters as written, quoted strings
/// unescaped.
pub const Challenge = struct {
    scheme: Scheme,
    /// The scheme's name as the server wrote it.
    name: []const u8,
    params: []const Param,

    /// The value of the parameter `key`, compared without case.
    pub fn param(c: Challenge, key: []const u8) ?[]const u8 {
        for (c.params) |p| {
            if (std.ascii.eqlIgnoreCase(p.key, key)) return p.value;
        }
        return null;
    }
};

/// A parameter of a challenge. A token68 in place of parameters
/// (`Negotiate abc==`) is one with an empty key.
pub const Param = struct { key: []const u8, value: []const u8 };

/// Errors from `parse`.
pub const ParseError = error{
    /// A value that is not a list of challenges.
    MalformedChallenge,
    OutOfMemory,
};

/// Every challenge in one challenge header value, into `arena`.
pub fn parse(arena: Allocator, value: []const u8) ParseError![]const Challenge {
    var out: std.ArrayList(Challenge) = .empty;
    var params: std.ArrayList(Param) = .empty;
    var name: ?[]const u8 = null;
    var i: usize = 0;
    while (true) {
        i = skip(value, i, " \t,");
        if (i >= value.len) break;
        const start = i;
        while (i < value.len and fields.isTokenChar(value[i])) i += 1;
        if (i == start) return error.MalformedChallenge;
        const token = value[start..i];
        const after = skip(value, i, " \t");
        if (after < value.len and value[after] == '=' and name != null) {
            // A parameter of the scheme before it.
            i = skip(value, after + 1, " \t");
            const val, i = try paramValue(arena, value, i);
            try params.append(arena, .{ .key = token, .value = val });
        } else {
            // A new scheme. A token68 after it, in place of parameters, is
            // kept as one with no name.
            if (name) |n| try out.append(arena, try finish(arena, n, &params));
            name = token;
            if (after < value.len and value[after] != ',') {
                var j = after;
                while (j < value.len and value[j] != ',') j += 1;
                const rest = std.mem.trim(u8, value[after..j], " \t");
                if (rest.len != 0 and !looksLikeParam(rest)) {
                    try params.append(arena, .{ .key = "", .value = rest });
                    i = j;
                }
            }
        }
    }
    if (name) |n| try out.append(arena, try finish(arena, n, &params));
    return out.items;
}

/// A parameter's value at `at`: a quoted string, unescaped into `arena`,
/// or a token. Returns it and where parsing goes on.
fn paramValue(arena: Allocator, value: []const u8, at: usize) ParseError!struct { []const u8, usize } {
    var i = at;
    if (i < value.len and value[i] == '"') {
        var text: std.ArrayList(u8) = .empty;
        i += 1;
        while (true) {
            if (i >= value.len) return error.MalformedChallenge;
            const c = value[i];
            i += 1;
            if (c == '"') break;
            if (c == '\\') {
                if (i >= value.len) return error.MalformedChallenge;
                try text.append(arena, value[i]);
                i += 1;
            } else try text.append(arena, c);
        }
        return .{ text.items, i };
    }
    const start = i;
    while (i < value.len and value[i] != ',' and value[i] != ' ' and value[i] != '\t') i += 1;
    return .{ value[start..i], i };
}

fn looksLikeParam(text: []const u8) bool {
    const eq = std.mem.findScalar(u8, text, '=') orelse return false;
    if (eq == 0) return false;
    for (text[0..eq]) |c| if (!fields.isTokenChar(c)) return false;
    return eq + 1 < text.len and text[eq + 1] != '=';
}

fn finish(arena: Allocator, name: []const u8, params: *std.ArrayList(Param)) Allocator.Error!Challenge {
    const scheme: Scheme = if (std.ascii.eqlIgnoreCase(name, "basic"))
        .basic
    else if (std.ascii.eqlIgnoreCase(name, "digest"))
        .digest
    else if (std.ascii.eqlIgnoreCase(name, "bearer"))
        .bearer
    else
        .other;
    const owned = try arena.dupe(Param, params.items);
    params.clearRetainingCapacity();
    return .{ .scheme = scheme, .name = name, .params = owned };
}

fn skip(text: []const u8, from: usize, set: []const u8) usize {
    var i = from;
    while (i < text.len and std.mem.findScalar(u8, set, text[i]) != null) i += 1;
    return i;
}

/// Which schemes may answer: `any` answers the strongest offered that is
/// spoken here, Digest before Basic, as curl's anyauth picks; the others
/// answer only their own.
pub const Method = enum { any, basic, digest };

/// What `pick` chose, or why nothing was.
pub const Pick = union(enum) {
    digest: Challenge,
    basic,
    /// Only schemes not spoken here were offered, or none the method
    /// allows. `pick` writes their names into the caller's buffer.
    unsupported,
};

/// The challenge to answer out of `challenges`, as curl picks it. When none
/// can be, the offered schemes' names, `, `-joined, are written to
/// `offered`, as many as fit.
pub fn pick(challenges: []const Challenge, method: Method, offered: *Writer) Pick {
    if (method != .basic) {
        for (challenges) |c| {
            if (c.scheme == .digest and Digest.speaks(c)) return .{ .digest = c };
        }
    }
    if (method != .digest) {
        for (challenges) |c| if (c.scheme == .basic) return .basic;
    }
    for (challenges, 0..) |c, n| {
        if (n != 0) offered.writeAll(", ") catch break;
        offered.writeAll(c.name) catch break;
    }
    return .unsupported;
}

/// Write `Basic <base64 of user:password>`.
pub fn writeBasic(w: *Writer, user: []const u8, password: []const u8) Writer.Error!void {
    try w.writeAll("Basic ");
    const encoder = std.base64.standard.Encoder;
    // In pieces of three bytes, so nothing is gathered first. The piece
    // in hand holds credential bytes, wiped when the answer is written.
    var held: aegis.Secret([3]u8) = .init(undefined);
    defer held.deinit();
    const carry = held.exposeMut();
    var carried: usize = 0;
    for ([_][]const u8{ user, ":", password }) |part| for (part) |c| {
        carry[carried] = c;
        carried += 1;
        if (carried == 3) {
            var out: [4]u8 = undefined;
            try w.writeAll(encoder.encode(&out, carry));
            carried = 0;
        }
    };
    if (carried != 0) {
        var out: [4]u8 = undefined;
        try w.writeAll(encoder.encode(&out, carry[0..carried]));
    }
}

/// Write `Bearer <token>`. The token must be a field value; a caller's
/// token is checked before it gets here.
pub fn writeBearer(w: *Writer, token: []const u8) Writer.Error!void {
    try w.writeAll("Bearer ");
    try w.writeAll(token);
}

/// A Digest answer's state, across the requests that use one nonce.
pub const Digest = struct {
    gpa: Allocator,
    algorithm: Algorithm,
    /// Whether the server named the algorithm, which the answer then names.
    algorithm_named: bool,
    session: bool,
    realm: []const u8,
    nonce: []const u8,
    opaque_value: ?[]const u8,
    qop_auth: bool,
    userhash: bool,
    /// How many requests have used the nonce.
    nc: u32 = 0,
    cnonce: []const u8,

    /// The hash a Digest challenge names.
    pub const Algorithm = enum {
        md5,
        sha256,
        sha512_256,

        fn name(a: Algorithm) []const u8 {
            return switch (a) {
                .md5 => "MD5",
                .sha256 => "SHA-256",
                .sha512_256 => "SHA-512-256",
            };
        }
    };

    /// The longest hex digest an algorithm here makes.
    const max_hex = 64;

    /// Whether `c` is a Digest challenge that can be answered: a known
    /// algorithm, and `auth` among its qop values when it gives any.
    pub fn speaks(c: Challenge) bool {
        if (c.param("nonce") == null) return false;
        _ = algorithmOf(c) orelse return false;
        if (c.param("qop")) |qop| return qopHasAuth(qop);
        return true;
    }

    fn algorithmOf(c: Challenge) ?struct { alg: Algorithm, sess: bool } {
        const text = c.param("algorithm") orelse return .{ .alg = .md5, .sess = false };
        const table = [_]struct { []const u8, Algorithm, bool }{
            .{ "MD5", .md5, false },                .{ "MD5-sess", .md5, true },
            .{ "SHA-256", .sha256, false },         .{ "SHA-256-sess", .sha256, true },
            .{ "SHA-512-256", .sha512_256, false }, .{ "SHA-512-256-sess", .sha512_256, true },
        };
        for (table) |t| if (std.ascii.eqlIgnoreCase(text, t[0])) return .{ .alg = t[1], .sess = t[2] };
        return null;
    }

    fn qopHasAuth(qop: []const u8) bool {
        var it = std.mem.tokenizeAny(u8, qop, ", \t");
        while (it.next()) |q| if (std.ascii.eqlIgnoreCase(q, "auth")) return true;
        return false;
    }

    /// The state for answering `c`, which `speaks` must accept, with
    /// `cnonce` the client's own nonce. Everything is copied into `gpa`;
    /// `deinit` frees it.
    pub fn init(gpa: Allocator, c: Challenge, cnonce: []const u8) Allocator.Error!Digest {
        const alg = algorithmOf(c).?;
        const realm = try gpa.dupe(u8, c.param("realm") orelse "");
        errdefer gpa.free(realm);
        const nonce = try gpa.dupe(u8, c.param("nonce").?);
        errdefer gpa.free(nonce);
        const opaque_value = if (c.param("opaque")) |o| try gpa.dupe(u8, o) else null;
        errdefer if (opaque_value) |o| gpa.free(o);
        const own = try gpa.dupe(u8, cnonce);
        return .{
            .gpa = gpa,
            .algorithm = alg.alg,
            .algorithm_named = c.param("algorithm") != null,
            .session = alg.sess,
            .realm = realm,
            .nonce = nonce,
            .opaque_value = opaque_value,
            .qop_auth = if (c.param("qop")) |q| qopHasAuth(q) else false,
            .userhash = if (c.param("userhash")) |u| std.ascii.eqlIgnoreCase(u, "true") else false,
            .cnonce = own,
        };
    }

    /// Release the copies.
    pub fn deinit(d: *Digest) void {
        d.gpa.free(d.realm);
        d.gpa.free(d.nonce);
        if (d.opaque_value) |o| d.gpa.free(o);
        d.gpa.free(d.cnonce);
        d.* = undefined;
    }

    /// Write the answer for one request, `method` to `uri` — the request
    /// target, `host:port` for a `CONNECT` — counting it. Nothing is
    /// allocated.
    pub fn writeAnswer(d: *Digest, w: *Writer, user: []const u8, password: []const u8, method: []const u8, uri: []const u8) Writer.Error!void {
        d.nc += 1;
        var nc_buf: [8]u8 = undefined;
        // unreachable: a u32 is at most eight hex digits
        const nc = std.mem.print(&nc_buf, "{x:0>8}", .{d.nc}) catch unreachable;

        // HA1 stands for the password to a server that knows it: wiped.
        var ha1_buf: aegis.Secret([max_hex]u8) = .init(undefined);
        defer ha1_buf.deinit();
        var ha1 = d.hash(ha1_buf.exposeMut(), &.{ user, ":", d.realm, ":", password });
        var outer_buf: aegis.Secret([max_hex]u8) = .init(undefined);
        defer outer_buf.deinit();
        if (d.session) ha1 = d.hash(outer_buf.exposeMut(), &.{ ha1, ":", d.nonce, ":", d.cnonce });
        var ha2_buf: [max_hex]u8 = undefined;
        const ha2 = d.hash(&ha2_buf, &.{ method, ":", uri });
        var response_buf: [max_hex]u8 = undefined;
        const response = if (d.qop_auth)
            d.hash(&response_buf, &.{ ha1, ":", d.nonce, ":", nc, ":", d.cnonce, ":", "auth", ":", ha2 })
        else
            d.hash(&response_buf, &.{ ha1, ":", d.nonce, ":", ha2 });
        var user_buf: [max_hex]u8 = undefined;
        const shown_user = if (d.userhash) d.hash(&user_buf, &.{ user, ":", d.realm }) else user;

        // curl's order.
        try w.writeAll("Digest username=\"");
        try writeQuoted(w, shown_user);
        try w.writeAll("\", realm=\"");
        try writeQuoted(w, d.realm);
        try w.writeAll("\", nonce=\"");
        try writeQuoted(w, d.nonce);
        try w.writeAll("\", uri=\"");
        try writeQuoted(w, uri);
        try w.writeByte('"');
        if (d.qop_auth) try w.print(", cnonce=\"{s}\", nc={s}, qop=auth", .{ d.cnonce, nc });
        try w.print(", response=\"{s}\"", .{response});
        if (d.opaque_value) |o| {
            try w.writeAll(", opaque=\"");
            try writeQuoted(w, o);
            try w.writeByte('"');
        }
        if (d.algorithm_named) try w.print(", algorithm={s}{s}", .{ d.algorithm.name(), if (d.session) "-sess" else "" });
        if (d.userhash) try w.writeAll(", userhash=true");
    }

    fn writeQuoted(w: *Writer, text: []const u8) Writer.Error!void {
        for (text) |c| {
            if (c == '"' or c == '\\') try w.writeByte('\\');
            try w.writeByte(c);
        }
    }

    /// The lower-case hex of the algorithm's hash of `parts` joined, in `out`.
    fn hash(d: *const Digest, out: *[max_hex]u8, parts: []const []const u8) []const u8 {
        return switch (d.algorithm) {
            .md5 => hexOf(std.crypto.hash.Md5, out, parts),
            .sha256 => hexOf(std.crypto.hash.sha2.Sha256, out, parts),
            .sha512_256 => hexOf(std.crypto.hash.sha2.Sha512_256, out, parts),
        };
    }

    fn hexOf(comptime H: type, out: *[max_hex]u8, parts: []const []const u8) []const u8 {
        // The hash state holds `parts`, the password among them for HA1, and
        // the digest stands for it: all three are wiped.
        var state: aegis.Secret(H) = .init(.init(.{}));
        defer state.deinit();
        const h = state.exposeMut();
        for (parts) |p| h.update(p);
        var digest: aegis.Secret([H.digest_length]u8) = .init(undefined);
        defer digest.deinit();
        h.final(digest.exposeMut());
        var hex: aegis.Secret([H.digest_length * 2]u8) = .init(std.fmt.bytesToHex(digest.expose().*, .lower));
        defer hex.deinit();
        @memcpy(out[0..hex.expose().len], hex.expose());
        return out[0..hex.expose().len];
    }
};

const testing = std.testing;

test "challenges are read as a server writes them, several to a header" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const list = try parse(a, "Digest realm=\"a \\\"b\\\"\", nonce=\"n1\", qop=\"auth,auth-int\", algorithm=SHA-256, stale=false, Basic realm=\"proxy\"");
    try testing.expectEqual(@as(usize, 2), list.len);
    try testing.expectEqual(Scheme.digest, list[0].scheme);
    try testing.expectEqualStrings("a \"b\"", list[0].param("realm").?);
    try testing.expectEqualStrings("SHA-256", list[0].param("ALGORITHM").?);
    try testing.expectEqual(Scheme.basic, list[1].scheme);
    try testing.expectEqualStrings("proxy", list[1].param("realm").?);
    const neg = try parse(a, "Negotiate, NTLM");
    try testing.expectEqual(@as(usize, 2), neg.len);
    var offered_buf: [64]u8 = undefined;
    var offered: Writer = .fixed(&offered_buf);
    try testing.expect(pick(neg, .any, &offered) == .unsupported);
    try testing.expectEqualStrings("Negotiate, NTLM", offered.buffered());
    try testing.expect(pick(list, .any, &offered) == .digest);
    try testing.expect(pick(list, .basic, &offered) == .basic);
    try testing.expectError(error.MalformedChallenge, parse(a, "Digest realm=\"open"));
    const token68 = try parse(a, "Negotiate abc==");
    try testing.expectEqualStrings("abc==", token68[0].param("").?);
}

test "a long list of offered schemes is cut at the buffer, never past it" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const list = try parse(arena.allocator(), "Negotiate, NTLM, Kerberos, Mutual");
    var offered_buf: [12]u8 = undefined;
    var offered: Writer = .fixed(&offered_buf);
    try testing.expect(pick(list, .any, &offered) == .unsupported);
    try testing.expectEqualStrings("Negotiate, N", offered.buffered());
}

test "a Basic answer is the base64 of user:password, written in pieces" {
    var buf: [128]u8 = undefined;
    for ([_][3][]const u8{
        .{ "a", "b", "Basic YTpi" },
        .{ "Aladdin", "open sesame", "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==" },
        .{ "", "", "Basic Og==" },
        .{ "ab", "", "Basic YWI6" },
    }) |case| {
        var w: Writer = .fixed(&buf);
        try writeBasic(&w, case[0], case[1]);
        try testing.expectEqualStrings(case[2], w.buffered());
    }
}

test "a Digest answer is RFC 7616's, for its worked examples" {
    const gpa = testing.allocator;
    var arena: std.heap.ArenaAllocator = .init(gpa);
    defer arena.deinit();
    // RFC 7616, section 3.9.1: Mufasa, both algorithms.
    for ([_]struct { alg: []const u8, response: []const u8 }{
        .{ .alg = "MD5", .response = "8ca523f5e9506fed4657c9700eebdbec" },
        .{ .alg = "SHA-256", .response = "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1" },
    }) |case| {
        const header = try arena.allocator().print("Digest realm=\"http-auth@example.org\", qop=\"auth, auth-int\", algorithm={s}, nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"", .{case.alg});
        const list = try parse(arena.allocator(), header);
        var d: Digest = try .init(gpa, list[0], "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ");
        defer d.deinit();
        var buf: [512]u8 = undefined;
        var w: Writer = .fixed(&buf);
        try d.writeAnswer(&w, "Mufasa", "Circle of Life", "GET", "/dir/index.html");
        const value = w.buffered();
        const want = try arena.allocator().print("response=\"{s}\"", .{case.response});
        testing.expect(std.mem.find(u8, value, want) != null) catch |err| {
            std.debug.print("{s}\n", .{value});
            return err;
        };
        try testing.expect(std.mem.find(u8, value, "nc=00000001, qop=auth") != null);
        try testing.expect(fields.isFieldValue(value));
    }
}

test "a Bearer challenge is named, and answered with the token as it is" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const list = try parse(arena.allocator(), "Bearer realm=\"api\", error=\"invalid_token\"");
    try testing.expectEqual(Scheme.bearer, list[0].scheme);
    try testing.expectEqualStrings("invalid_token", list[0].param("error").?);
    var buf: [64]u8 = undefined;
    var w: Writer = .fixed(&buf);
    try writeBearer(&w, "mF_9.B5f-4.1JqM");
    try testing.expectEqualStrings("Bearer mF_9.B5f-4.1JqM", w.buffered());
}

test "Digest state releases what it copied when allocation stops" {
    const shakedown = @import("shakedown");
    const Check = struct {
        fn run(gpa: Allocator) !void {
            var arena: std.heap.ArenaAllocator = .init(gpa);
            defer arena.deinit();
            const challenges = try parse(arena.allocator(), "Digest realm=\"proxy\", nonce=\"nonce\", opaque=\"o\", qop=\"auth\", algorithm=SHA-256-sess, userhash=true");
            var digest = try Digest.init(gpa, challenges[0], "client");
            defer digest.deinit();
            var buf: [512]u8 = undefined;
            var w: Writer = .fixed(&buf);
            try digest.writeAnswer(&w, "a", "b", "CONNECT", "git.example.com:443");
            try testing.expect(std.mem.find(u8, w.buffered(), "algorithm=SHA-256-sess, userhash=true") != null);
        }
    };
    var no_resize: shakedown.alloc.NoResize = .init(testing.allocator);
    try testing.checkAllAllocationFailures(no_resize.allocator(), Check.run, .{});
}

test "fuzz: any challenge value is read or refused by name" {
    try testing.fuzz({}, struct {
        fn one(_: void, smith: *testing.Smith) anyerror!void {
            var buf: [256]u8 = undefined;
            const text = buf[0..smith.slice(&buf)];
            var arena: std.heap.ArenaAllocator = .init(testing.allocator);
            defer arena.deinit();
            const list = parse(arena.allocator(), text) catch |err| switch (err) {
                error.MalformedChallenge => return,
                else => return err,
            };
            var offered_buf: [64]u8 = undefined;
            var offered: Writer = .fixed(&offered_buf);
            _ = pick(list, .any, &offered);
        }
    }.one, .{ .corpus = &.{ "Digest realm=\"r\", nonce=\"n\"", "Basic realm=\"p\"", "Negotiate abc==" } });
}
