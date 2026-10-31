//! AWS Signature Version 4: the signature S3 and S3-compatible object
//! storage (and every other AWS service) authenticate a request by, made
//! from an access key's secret, the request's method, path, query and
//! chosen fields, a scope of date, region and service, and the time.
//!
//! Two forms. `Signer.sign` makes the fields a request carries: `X-Amz-Date`,
//! `X-Amz-Content-Sha256`, `X-Amz-Security-Token` for a session's key, and
//! `Authorization`; the client's `SigV4` adds them before each attempt.
//! `Signer.presign` writes a URL whose query carries the signature, which
//! anyone holding it can use, without the key, until it expires: what a
//! server hands a client to upload or download an object straight from the
//! storage.
//!
//! The canonical request is hashed as it is made, with no buffer of its
//! own: the path's segments encoded once as S3 wants them (twice for any
//! other service, `Signer.path`), the query's names and values encoded and
//! sorted, the signed fields' names lowercased and their values trimmed,
//! inner runs of spaces made one. The time is the caller's.

const std = @import("std");
const Writer = std.Io.Writer;
const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const url_mod = @import("url.zig");
const fields = @import("fields.zig");

/// The algorithm a signature names.
pub const algorithm = "AWS4-HMAC-SHA256";
/// The payload hash of a request whose body is not signed: every presigned
/// URL's, and a streamed upload's.
pub const unsigned_payload = "UNSIGNED-PAYLOAD";
/// The SHA-256 of an empty body.
pub const empty_payload = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// The most query parameters and signed fields a request may have.
pub const max_params = 64;
pub const max_fields = 32;
/// The most bytes a request's query and signed fields' names take, encoded.
const scratch_len = 16 * 1024;

/// Why a request could not be signed.
pub const Error = error{
    /// More query parameters or fields than `max_params` or `max_fields`,
    /// or a query longer than the signer holds.
    RequestTooLarge,
    /// A field that cannot be sent, or `expires` past a week, which AWS
    /// refuses.
    InvalidRequest,
} || Writer.Error;

/// An access key: its id, its secret, and the token a temporary one comes
/// with.
pub const Key = struct {
    access_key: []const u8,
    secret_key: []const u8,
    session_token: ?[]const u8 = null,
};

/// How a request's path is encoded in the canonical request.
pub const PathEncoding = enum {
    /// As S3 signs it: each byte that is not unreserved, `/` aside, once.
    once,
    /// As every other AWS service signs it: the once-encoded path encoded
    /// again.
    twice,
};

/// What is signed: the request as it will be sent.
pub const Request = struct {
    method: []const u8,
    url: url_mod.Url,
    /// Fields signed beside `Host` (and the `X-Amz-*` ones `sign` adds).
    /// Those a proxy may change are best left out.
    headers: []const std.http.Header = &.{},
    /// The body's SHA-256 in hex, or `unsigned_payload`.
    payload: []const u8 = unsigned_payload,
};

/// The fields `sign` makes, to send with the request.
pub const Signed = struct {
    date: [16]u8 = undefined,
    authorization_buffer: [512 + 64 * max_fields]u8 = undefined,
    authorization_len: usize = 0,
    payload: []const u8 = unsigned_payload,
    session_token: ?[]const u8 = null,

    pub fn authorization(s: *const Signed) []const u8 {
        return s.authorization_buffer[0..s.authorization_len];
    }

    /// The fields, in the order they are sent; borrowed from `s`.
    pub fn headers(s: *const Signed, out: *[4]std.http.Header) []const std.http.Header {
        out[0] = .{ .name = "X-Amz-Date", .value = &s.date };
        out[1] = .{ .name = "X-Amz-Content-Sha256", .value = s.payload };
        out[2] = .{ .name = "Authorization", .value = s.authorization() };
        if (s.session_token) |token| {
            out[3] = .{ .name = "X-Amz-Security-Token", .value = token };
            return out[0..4];
        }
        return out[0..3];
    }
};

/// A key, and the scope its signatures are for.
pub const Signer = struct {
    key: Key,
    /// `us-east-1`, or what the storage names its region (`auto`, or any
    /// name an S3-compatible server takes).
    region: []const u8,
    service: []const u8 = "s3",
    path: PathEncoding = .once,

    /// The fields that sign `request` at `time`, seconds since the Unix
    /// epoch.
    pub fn sign(s: Signer, request: Request, time: i64, out: *Signed) Error!void {
        out.* = .{ .payload = request.payload, .session_token = s.key.session_token };
        _ = formatDate(time, &out.date) orelse return error.InvalidRequest;
        var extra: [3]std.http.Header = undefined;
        var n: usize = 0;
        extra[n] = .{ .name = "x-amz-content-sha256", .value = request.payload };
        n += 1;
        extra[n] = .{ .name = "x-amz-date", .value = &out.date };
        n += 1;
        if (s.key.session_token) |token| {
            extra[n] = .{ .name = "x-amz-security-token", .value = token };
            n += 1;
        }
        var canonical: Canonical = .{};
        try canonical.addFields(request, extra[0..n]);
        try canonical.addQuery(request.url.target, &.{});
        const hash = canonical.hash(request.method, request.url.target, s.path, request.payload);
        var sig_hex: [64]u8 = undefined;
        s.signature(&out.date, &hash, &sig_hex);
        var w: Writer = .fixed(&out.authorization_buffer);
        w.print("{s} Credential={s}/", .{ algorithm, s.key.access_key }) catch return error.RequestTooLarge;
        s.writeScope(&w, &out.date) catch return error.RequestTooLarge;
        w.writeAll(", SignedHeaders=") catch return error.RequestTooLarge;
        canonical.writeSignedNames(&w) catch return error.RequestTooLarge;
        w.print(", Signature={s}", .{&sig_hex}) catch return error.RequestTooLarge;
        out.authorization_len = w.end;
    }

    /// Write `url`, the URL `request` goes to, with a query that signs it
    /// for `expires` seconds from `time`: `X-Amz-Algorithm`,
    /// `X-Amz-Credential`, `X-Amz-Date`, `X-Amz-Expires`,
    /// `X-Amz-Security-Token` for a session's key, `X-Amz-SignedHeaders`
    /// and `X-Amz-Signature` after whatever query it had. `request.url`
    /// must be `text` parsed.
    pub fn presign(s: Signer, w: *Writer, text: []const u8, request: Request, time: i64, expires: u32) Error!void {
        if (expires == 0 or expires > 7 * 24 * 3600) return error.InvalidRequest;
        var date: [16]u8 = undefined;
        _ = formatDate(time, &date) orelse return error.InvalidRequest;
        var credential_buffer: [256]u8 = undefined;
        var cw: Writer = .fixed(&credential_buffer);
        cw.print("{s}/", .{s.key.access_key}) catch return error.RequestTooLarge;
        s.writeScope(&cw, &date) catch return error.RequestTooLarge;
        var expires_buffer: [16]u8 = undefined;
        const expires_text = std.mem.print(&expires_buffer, "{d}", .{expires}) catch unreachable; // unreachable: a u32 is ten digits

        var canonical: Canonical = .{};
        try canonical.addFields(request, &.{});
        var names_buffer: [64 * max_fields]u8 = undefined;
        var nw: Writer = .fixed(&names_buffer);
        canonical.writeSignedNames(&nw) catch return error.RequestTooLarge;
        var added: [6]Param = undefined;
        var n: usize = 0;
        added[n] = .{ .key = "X-Amz-Algorithm", .value = algorithm };
        n += 1;
        added[n] = .{ .key = "X-Amz-Credential", .value = cw.buffered() };
        n += 1;
        added[n] = .{ .key = "X-Amz-Date", .value = &date };
        n += 1;
        added[n] = .{ .key = "X-Amz-Expires", .value = expires_text };
        n += 1;
        if (s.key.session_token) |token| {
            added[n] = .{ .key = "X-Amz-Security-Token", .value = token };
            n += 1;
        }
        added[n] = .{ .key = "X-Amz-SignedHeaders", .value = nw.buffered() };
        n += 1;
        try canonical.addQuery(request.url.target, added[0..n]);
        const hash = canonical.hash(request.method, request.url.target, s.path, unsigned_payload);
        var sig_hex: [64]u8 = undefined;
        s.signature(&date, &hash, &sig_hex);

        const fragment = std.mem.findScalar(u8, text, '#') orelse text.len;
        try w.writeAll(text[0..fragment]);
        var first = std.mem.findScalar(u8, text[0..fragment], '?') == null;
        for (added[0..n]) |p| {
            try w.writeByte(if (first) '?' else '&');
            first = false;
            try encode(w, p.key, .query);
            try w.writeByte('=');
            try encode(w, p.value, .query);
        }
        try w.print("&X-Amz-Signature={s}", .{&sig_hex});
    }

    fn writeScope(s: Signer, w: *Writer, date: *const [16]u8) Writer.Error!void {
        try w.print("{s}/{s}/{s}/aws4_request", .{ date[0..8], s.region, s.service });
    }

    /// The signature of a canonical request's hash, in hex.
    fn signature(s: Signer, date: *const [16]u8, canonical_hash: *const [32]u8, out: *[64]u8) void {
        var k: [HmacSha256.mac_length]u8 = undefined;
        var secret: HmacSha256 = .init(&.{});
        // The first key is `AWS4` and the secret, which is hashed as a key
        // of any length is.
        {
            var prefixed: [4 + 256]u8 = undefined;
            const key = if (s.key.secret_key.len <= 256) blk: {
                @memcpy(prefixed[0..4], "AWS4");
                @memcpy(prefixed[4..][0..s.key.secret_key.len], s.key.secret_key);
                break :blk prefixed[0 .. 4 + s.key.secret_key.len];
            } else blk: {
                // A secret longer than any AWS issues: hashed as HMAC hashes
                // a long key, `AWS4` included.
                var h: Sha256 = .init(.{});
                h.update("AWS4");
                h.update(s.key.secret_key);
                h.final(prefixed[0..32]);
                break :blk prefixed[0..32];
            };
            secret = .init(key);
        }
        secret.update(date[0..8]);
        secret.final(&k);
        HmacSha256.create(&k, s.region, &k);
        HmacSha256.create(&k, s.service, &k);
        HmacSha256.create(&k, "aws4_request", &k);

        var mac: HmacSha256 = .init(&k);
        mac.update(algorithm ++ "\n");
        mac.update(date);
        mac.update("\n");
        mac.update(date[0..8]);
        mac.update("/");
        mac.update(s.region);
        mac.update("/");
        mac.update(s.service);
        mac.update("/aws4_request\n");
        var hex: [64]u8 = undefined;
        mac.update(hexOf(canonical_hash, &hex));
        var sig: [HmacSha256.mac_length]u8 = undefined;
        mac.final(&sig);
        _ = hexOf(&sig, out);
    }
};

const Param = struct { key: []const u8, value: []const u8 };

/// The canonical request's parts that are sorted, and so held until hashed.
const Canonical = struct {
    scratch: [scratch_len]u8 = undefined,
    used: usize = 0,
    params: [max_params]Param = undefined,
    param_count: usize = 0,
    names: [max_fields]Field = undefined,
    field_count: usize = 0,

    const Field = struct { name: []const u8, value: []const u8 };

    /// `Host` from the URL, the request's fields and `extra`, their names
    /// lowercased, sorted by name.
    fn addFields(c: *Canonical, request: Request, extra: []const std.http.Header) Error!void {
        // The host is kept in the scratch, which outlives this call.
        var hw: Writer = .fixed(c.scratch[c.used..]);
        request.url.writeAuthority(&hw, false) catch return error.RequestTooLarge;
        c.used += hw.end;
        try c.addField("host", hw.buffered());
        for (request.headers) |h| {
            if (fields.hasControl(h.name) or fields.hasControl(h.value)) return error.InvalidRequest;
            try c.addField(h.name, h.value);
        }
        for (extra) |h| try c.addField(h.name, h.value);
        std.mem.sort(Field, c.names[0..c.field_count], {}, struct {
            fn less(_: void, a: Field, b: Field) bool {
                return std.mem.lessThan(u8, a.name, b.name);
            }
        }.less);
    }

    fn addField(c: *Canonical, name: []const u8, value: []const u8) Error!void {
        if (c.field_count == max_fields) return error.RequestTooLarge;
        const lower = try c.take(name.len);
        _ = std.ascii.lowerString(lower, name);
        c.names[c.field_count] = .{ .name = lower, .value = value };
        c.field_count += 1;
    }

    /// The query `target` has, and `added`, each name and value encoded,
    /// sorted by name and then value.
    fn addQuery(c: *Canonical, target: []const u8, added: []const Param) Error!void {
        if (std.mem.findScalar(u8, target, '?')) |q| {
            var it = std.mem.splitScalar(u8, target[q + 1 ..], '&');
            while (it.next()) |pair| {
                if (pair.len == 0) continue;
                const eq = std.mem.findScalar(u8, pair, '=') orelse pair.len;
                try c.addParam(pair[0..eq], if (eq < pair.len) pair[eq + 1 ..] else "", true);
            }
        }
        for (added) |p| try c.addParam(p.key, p.value, false);
        std.mem.sort(Param, c.params[0..c.param_count], {}, struct {
            fn less(_: void, a: Param, b: Param) bool {
                return switch (std.mem.order(u8, a.key, b.key)) {
                    .lt => true,
                    .gt => false,
                    .eq => std.mem.lessThan(u8, a.value, b.value),
                };
            }
        }.less);
    }

    fn addParam(c: *Canonical, key: []const u8, value: []const u8, escaped: bool) Error!void {
        if (c.param_count == max_params) return error.RequestTooLarge;
        c.params[c.param_count] = .{ .key = try c.encoded(key, escaped), .value = try c.encoded(value, escaped) };
        c.param_count += 1;
    }

    /// `text` encoded as AWS encodes a query's names and values, after
    /// undoing the escapes it has when `escaped`.
    fn encoded(c: *Canonical, text: []const u8, escaped: bool) Error![]const u8 {
        var w: Writer = .fixed(c.scratch[c.used..]);
        if (escaped) {
            var i: usize = 0;
            while (i < text.len) : (i += 1) {
                var byte = text[i];
                if (byte == '%' and i + 2 < text.len) {
                    if (std.fmt.parseInt(u8, text[i + 1 .. i + 3], 16)) |b| {
                        byte = b;
                        i += 2;
                    } else |_| {}
                }
                encodeByte(&w, byte, .query) catch return error.RequestTooLarge;
            }
        } else encode(&w, text, .query) catch return error.RequestTooLarge;
        const out = w.buffered();
        c.used += out.len;
        return out;
    }

    fn take(c: *Canonical, len: usize) Error![]u8 {
        if (scratch_len - c.used < len) return error.RequestTooLarge;
        defer c.used += len;
        return c.scratch[c.used..][0..len];
    }

    fn writeSignedNames(c: *const Canonical, w: *Writer) Writer.Error!void {
        for (c.names[0..c.field_count], 0..) |f, i| {
            if (i != 0) try w.writeByte(';');
            try w.writeAll(f.name);
        }
    }

    /// The canonical request's SHA-256.
    fn hash(c: *const Canonical, method: []const u8, target: []const u8, path: PathEncoding, payload: []const u8) [32]u8 {
        var buffer: [256]u8 = undefined;
        var hashing: Writer.Hashing(Sha256) = .init(&buffer);
        // unreachable: a hashing writer does not fail
        c.writeCanonical(&hashing.writer, method, target, path, payload) catch unreachable;
        hashing.writer.flush() catch unreachable; // unreachable: as above
        var out: [32]u8 = undefined;
        hashing.hasher.final(&out);
        return out;
    }

    fn writeCanonical(c: *const Canonical, w: *Writer, method: []const u8, target: []const u8, path: PathEncoding, payload: []const u8) Writer.Error!void {
        try w.writeAll(method);
        try w.writeByte('\n');
        const end = std.mem.findAny(u8, target, "?#") orelse target.len;
        const raw_path = if (end == 0) "/" else target[0..end];
        var i: usize = 0;
        while (i < raw_path.len) : (i += 1) {
            var byte = raw_path[i];
            if (byte == '%' and i + 2 < raw_path.len) {
                if (std.fmt.parseInt(u8, raw_path[i + 1 .. i + 3], 16)) |b| {
                    byte = b;
                    i += 2;
                } else |_| {}
            }
            switch (path) {
                .once => try encodeByte(w, byte, .path),
                .twice => {
                    var once: [3]u8 = undefined;
                    var ow: Writer = .fixed(&once);
                    encodeByte(&ow, byte, .path) catch unreachable; // unreachable: one byte encodes to three at most
                    try encode(w, ow.buffered(), .path);
                },
            }
        }
        try w.writeByte('\n');
        for (c.params[0..c.param_count], 0..) |p, k| {
            if (k != 0) try w.writeByte('&');
            try w.writeAll(p.key);
            try w.writeByte('=');
            try w.writeAll(p.value);
        }
        try w.writeByte('\n');
        for (c.names[0..c.field_count]) |f| {
            try w.writeAll(f.name);
            try w.writeByte(':');
            try writeTrimmed(w, f.value);
            try w.writeByte('\n');
        }
        try w.writeByte('\n');
        try c.writeSignedNames(w);
        try w.writeByte('\n');
        try w.writeAll(payload);
    }
};

/// A field's value as signed: trimmed, each inner run of spaces one.
fn writeTrimmed(w: *Writer, value: []const u8) Writer.Error!void {
    const trimmed = std.mem.trim(u8, value, " \t");
    var space = false;
    for (trimmed) |ch| {
        if (ch == ' ' or ch == '\t') {
            space = true;
            continue;
        }
        if (space) try w.writeByte(' ');
        space = false;
        try w.writeByte(ch);
    }
}

const Part = enum { path, query };

fn encode(w: *Writer, text: []const u8, part: Part) Writer.Error!void {
    for (text) |byte| try encodeByte(w, byte, part);
}

/// One byte as AWS encodes it: unreserved bytes as they are, `/` too in a
/// path, every other byte `%XX` in capitals.
fn encodeByte(w: *Writer, byte: u8, part: Part) Writer.Error!void {
    switch (byte) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '_', '.', '~' => try w.writeByte(byte),
        '/' => if (part == .path) try w.writeByte('/') else try w.writeAll("%2F"),
        else => try w.print("%{X:0>2}", .{byte}),
    }
}

fn hexOf(bytes: []const u8, out: []u8) []const u8 {
    const digits = "0123456789abcdef";
    for (bytes, 0..) |b, i| {
        out[2 * i] = digits[b >> 4];
        out[2 * i + 1] = digits[b & 15];
    }
    return out[0 .. 2 * bytes.len];
}

/// The last time SigV4's date holds, 9999-12-31T23:59:59Z: its year has
/// four digits.
pub const max_time: i64 = 253402300799;

/// `time`, seconds since the Unix epoch, as SigV4 writes it:
/// `YYYYMMDDTHHMMSSZ`. Null past `max_time`.
pub fn formatDate(time: i64, out: *[16]u8) ?[]const u8 {
    if (time > max_time) return null;
    const secs: u64 = @intCast(@max(time, 0)); // safe: a time before 1970 is written as 1970's start
    const epoch: std.time.epoch.EpochSeconds = .{ .secs = secs };
    const day = epoch.getEpochDay().calculateYearDay();
    const month_day = day.calculateMonthDay();
    const clock = epoch.getDaySeconds();
    const parts = .{ day.year, month_day.month.numeric(), month_day.day_index + 1, clock.getHoursIntoDay(), clock.getMinutesIntoHour(), clock.getSecondsIntoMinute() };
    // unreachable: sixteen bytes hold the date while the year has four digits, as it has up to `max_time`
    return std.mem.print(out, "{d:0>4}{d:0>2}{d:0>2}T{d:0>2}{d:0>2}{d:0>2}Z", parts) catch unreachable;
}

// AWS's own examples (the S3 API reference, "Signature Calculations for
// the Authorization Header" and "Authenticating Requests: Using Query
// Parameters"): the example key, bucket and time.
const example: Signer = .{
    .key = .{ .access_key = "AKIAIOSFODNN7EXAMPLE", .secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" },
    .region = "us-east-1",
};
const example_time = 1369353600; // 2013-05-24T00:00:00Z

test "the date is written as SigV4 writes it" {
    var buf: [16]u8 = undefined;
    try std.testing.expectEqualStrings("20130524T000000Z", formatDate(example_time, &buf).?);
    try std.testing.expectEqualStrings("99991231T235959Z", formatDate(max_time, &buf).?);
}

test "a time past the year 9999 is no request to sign" {
    var buf: [16]u8 = undefined;
    try std.testing.expectEqual(null, formatDate(max_time + 1, &buf));
    try std.testing.expectEqual(null, formatDate(std.math.maxInt(i64), &buf));
    const text = "https://examplebucket.s3.amazonaws.com/test.txt";
    var signed: Signed = undefined;
    try std.testing.expectError(error.InvalidRequest, example.sign(.{ .method = "GET", .url = try url_mod.parse(text) }, max_time + 1, &signed));
    var out: [512]u8 = undefined;
    var w: Writer = .fixed(&out);
    try std.testing.expectError(error.InvalidRequest, example.presign(&w, text, .{ .method = "GET", .url = try url_mod.parse(text) }, max_time + 1, 60));
}

test "a GET is signed as AWS's example signs it" {
    var signed: Signed = undefined;
    try example.sign(.{
        .method = "GET",
        .url = try url_mod.parse("https://examplebucket.s3.amazonaws.com/test.txt"),
        .headers = &.{.{ .name = "Range", .value = "bytes=0-9" }},
        .payload = empty_payload,
    }, example_time, &signed);
    try std.testing.expectEqualStrings(
        "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, " ++
            "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, " ++
            "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
        signed.authorization(),
    );
}

test "a GET with a query is signed as AWS's example signs it" {
    var signed: Signed = undefined;
    try example.sign(.{
        .method = "GET",
        .url = try url_mod.parse("https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J"),
        .payload = empty_payload,
    }, example_time, &signed);
    try std.testing.expect(std.mem.endsWith(u8, signed.authorization(), "Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"));
    try example.sign(.{
        .method = "GET",
        .url = try url_mod.parse("https://examplebucket.s3.amazonaws.com/?lifecycle"),
        .payload = empty_payload,
    }, example_time, &signed);
    try std.testing.expect(std.mem.endsWith(u8, signed.authorization(), "Signature=fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"));
}

test "a URL is presigned as AWS's example presigns it" {
    var buf: [1024]u8 = undefined;
    var w: Writer = .fixed(&buf);
    const text = "https://examplebucket.s3.amazonaws.com/test.txt";
    try example.presign(&w, text, .{ .method = "GET", .url = try url_mod.parse(text) }, example_time, 86400);
    try std.testing.expectEqualStrings(
        "https://examplebucket.s3.amazonaws.com/test.txt?X-Amz-Algorithm=AWS4-HMAC-SHA256" ++
            "&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request" ++
            "&X-Amz-Date=20130524T000000Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host" ++
            "&X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404",
        w.buffered(),
    );
}

test "a session's token is signed and sent" {
    var signer = example;
    signer.key.session_token = "token/with+chars";
    var buf: [1024]u8 = undefined;
    var w: Writer = .fixed(&buf);
    const text = "http://127.0.0.1:9000/bucket/key%20one";
    try signer.presign(&w, text, .{ .method = "PUT", .url = try url_mod.parse(text) }, example_time, 60);
    try std.testing.expect(std.mem.find(u8, w.buffered(), "&X-Amz-Security-Token=token%2Fwith%2Bchars&") != null);
    var signed: Signed = undefined;
    try signer.sign(.{ .method = "HEAD", .url = try url_mod.parse(text) }, example_time, &signed);
    var fields_out: [4]std.http.Header = undefined;
    const sent = signed.headers(&fields_out);
    try std.testing.expectEqual(@as(usize, 4), sent.len);
    try std.testing.expect(std.mem.find(u8, signed.authorization(), "SignedHeaders=host;x-amz-content-sha256;x-amz-date;x-amz-security-token,") != null);
    try std.testing.expectError(error.InvalidRequest, signer.presign(&w, text, .{ .method = "GET", .url = try url_mod.parse(text) }, example_time, 8 * 24 * 3600));
}
