//! RSA signing: the private operation, constant-time, over `std.crypto.ff`,
//! and the two encodings TLS signs with — PKCS #1 v1.5 (RFC 8017, 9.2) and
//! PSS with MGF1 and a salt as long as the hash (RFC 8017, 9.1; RFC 8446,
//! 4.2.3).

const std = @import("std");

/// The widest modulus signed with.
pub const max_bits = 4096;
const Modulus = std.crypto.ff.Modulus(max_bits);

/// Errors from signing.
pub const Error = error{
    /// A key whose numbers do not make an RSA key, or one wider than
    /// `max_bits`.
    InvalidRsaKey,
    /// A signature the key's public half does not verify: a fault, not a
    /// signature to send.
    RsaSignatureFault,
};

/// An RSA private key, as big-endian bytes without leading zeroes.
pub const Key = struct {
    n: []const u8,
    e: []const u8,
    d: []const u8,

    /// The modulus's length in bytes: every signature's length.
    pub fn size(k: Key) usize {
        return k.n.len;
    }

    fn bitLength(k: Key) usize {
        return (k.n.len - 1) * 8 + (8 - @clz(k.n[0]));
    }
};

/// `em^d mod n`, checked against `e` before it is handed out. `out` is the
/// modulus's length.
fn private(k: Key, em: []const u8, out: []u8) Error!void {
    if (k.n.len == 0 or k.n.len * 8 > max_bits) return error.InvalidRsaKey;
    const m = Modulus.fromBytes(k.n, .big) catch return error.InvalidRsaKey;
    const x = Modulus.Fe.fromBytes(m, em, .big) catch return error.InvalidRsaKey;
    const s = m.powWithEncodedExponent(x, k.d, .big) catch return error.InvalidRsaKey;
    const back = m.powWithEncodedPublicExponent(s, k.e, .big) catch return error.InvalidRsaKey;
    if (!back.eql(x)) return error.RsaSignatureFault;
    s.toBytes(out, .big) catch return error.InvalidRsaKey;
}

fn digestInfo(comptime Hash: type) []const u8 {
    return switch (Hash) {
        std.crypto.hash.Sha1 => &.{ 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14 },
        std.crypto.hash.sha2.Sha256 => &.{ 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 },
        std.crypto.hash.sha2.Sha384 => &.{ 0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30 },
        std.crypto.hash.sha2.Sha512 => &.{ 0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40 },
        else => @compileError("no DigestInfo for this hash"),
    };
}

/// RSASSA-PKCS1-v1_5: `msg` hashed with `Hash`, into `out`, which is the
/// modulus's length.
pub fn signPkcs1(comptime Hash: type, k: Key, msg: []const u8, out: []u8) Error!void {
    var digest: [Hash.digest_length]u8 = undefined;
    Hash.hash(msg, &digest, .{});
    const info = digestInfo(Hash);
    const em = out;
    const t_len = info.len + digest.len;
    if (em.len < t_len + 11) return error.InvalidRsaKey;
    em[0] = 0x00;
    em[1] = 0x01;
    @memset(em[2 .. em.len - t_len - 1], 0xff);
    em[em.len - t_len - 1] = 0x00;
    @memcpy(em[em.len - t_len ..][0..info.len], info);
    @memcpy(em[em.len - digest.len ..], &digest);
    var buf: [max_bits / 8]u8 = undefined;
    @memcpy(buf[0..em.len], em);
    try private(k, buf[0..em.len], out);
}

/// RSASSA-PSS with MGF1 over `Hash` and a salt of `Hash`'s length taken
/// from `salt`, into `out`, which is the modulus's length.
pub fn signPss(comptime Hash: type, k: Key, msg: []const u8, salt: *const [Hash.digest_length]u8, out: []u8) Error!void {
    const h_len = Hash.digest_length;
    const mod_bits = k.bitLength();
    const em_bits = mod_bits - 1;
    const em_len = (em_bits + 7) / 8;
    if (em_len < h_len * 2 + 2) return error.InvalidRsaKey;
    var m_hash: [h_len]u8 = undefined;
    Hash.hash(msg, &m_hash, .{});
    // H = Hash(0x00 * 8 || mHash || salt)
    var h: [h_len]u8 = undefined;
    {
        var hasher = Hash.init(.{});
        hasher.update(&(@as([8]u8, @splat(0))));
        hasher.update(&m_hash);
        hasher.update(salt);
        hasher.final(&h);
    }
    var em_buf: [max_bits / 8]u8 = undefined;
    const em = em_buf[0..em_len];
    const db_len = em_len - h_len - 1;
    const db = em[0..db_len];
    @memset(db, 0);
    db[db_len - h_len - 1] = 0x01;
    @memcpy(db[db_len - h_len ..], salt);
    // DB ^= MGF1(H, dbLen)
    var counter: u32 = 0;
    var at: usize = 0;
    while (at < db_len) : (counter += 1) {
        var block: [h_len]u8 = undefined;
        var hasher = Hash.init(.{});
        hasher.update(&h);
        var c: [4]u8 = undefined;
        std.mem.writeInt(u32, &c, counter, .big);
        hasher.update(&c);
        hasher.final(&block);
        const n = @min(h_len, db_len - at);
        for (db[at..][0..n], block[0..n]) |*d, b| d.* ^= b;
        at += n;
    }
    const unused_bits: u3 = @intCast(8 * em_len - em_bits);
    db[0] &= @as(u8, 0xff) >> unused_bits;
    @memcpy(em[db_len..][0..h_len], &h);
    em[em_len - 1] = 0xbc;
    // The integer is the modulus's length, EM right-aligned.
    var full: [max_bits / 8]u8 = undefined;
    const size = k.size();
    @memset(full[0 .. size - em_len], 0);
    @memcpy(full[size - em_len .. size], em);
    try private(k, full[0..size], out);
}
