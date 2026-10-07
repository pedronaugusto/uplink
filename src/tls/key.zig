//! A client's private key and certificates, read from the files OpenSSL
//! writes: PEM or DER; PKCS #8 (`PRIVATE KEY`), PKCS #1 (`RSA PRIVATE KEY`)
//! and SEC 1 (`EC PRIVATE KEY`) keys; encrypted PKCS #8 (`ENCRYPTED PRIVATE
//! KEY`) with PBES2 — PBKDF2 over HMAC-SHA-1, -SHA-256, -SHA-384 or
//! -SHA-512, and AES-128 or AES-256 in CBC mode — and OpenSSL's older
//! encrypted PEM (`Proc-Type: 4,ENCRYPTED`) with AES-128-CBC or
//! AES-256-CBC. RSA up to 4096 bits, ECDSA on P-256 and P-384, and Ed25519.
//! A key another way — DES or AES-192, scrypt, RSA-PSS keys, other curves —
//! is refused by name.
//!
//! A key signs for TLS through `sign`, with the schemes `schemes` offers.

const std = @import("std");
const Allocator = std.mem.Allocator;
const der = @import("der.zig");
const rsa = @import("rsa.zig");

const EcdsaP256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const EcdsaP384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const Ed25519 = std.crypto.sign.Ed25519;

/// Errors from reading a key or a certificate.
pub const ParseError = error{
    /// Not the PEM or DER it claims to be.
    MalformedKey,
    /// A key of a kind uplink does not sign with: another curve, DSA,
    /// RSA-PSS keys, a modulus wider than 4096 bits.
    KeyAlgorithmUnsupported,
    /// An encrypted key, and no passphrase to open it with.
    KeyPassphraseRequired,
    /// The passphrase does not open the key.
    KeyPassphraseWrong,
    /// Encrypted in a way uplink does not decrypt: OpenSSL's older PEM
    /// encryption, DES, a key derivation other than PBKDF2.
    KeyEncryptionUnsupported,
    /// No certificate in the file.
    CertificateMissing,
    OutOfMemory,
};

/// A private key.
pub const PrivateKey = union(enum) {
    rsa: rsa.Key,
    ecdsa_p256: EcdsaP256.KeyPair,
    ecdsa_p384: EcdsaP384.KeyPair,
    ed25519: Ed25519.KeyPair,

    /// Read a key from `bytes` — PEM, or DER — opening it with
    /// `passphrase` when it is encrypted. Slices of the result are
    /// `arena`'s.
    pub fn parse(arena: Allocator, bytes: []const u8, passphrase: ?[]const u8) ParseError!PrivateKey {
        if (std.mem.find(u8, bytes, "-----BEGIN ")) |_| {
            var blocks = pemBlocks(bytes);
            while (try blocks.next(arena)) |block| {
                if (std.mem.eql(u8, block.label, "PRIVATE KEY")) return fromPkcs8(arena, block.der);
                if (std.mem.eql(u8, block.label, "RSA PRIVATE KEY")) {
                    return fromPkcs1(arena, try openLegacy(arena, block, passphrase)) catch |err| switch (err) {
                        error.MalformedKey => if (block.legacy_encrypted) error.KeyPassphraseWrong else err,
                        else => err,
                    };
                }
                if (std.mem.eql(u8, block.label, "EC PRIVATE KEY")) {
                    return fromSec1(try openLegacy(arena, block, passphrase), null) catch |err| switch (err) {
                        error.MalformedKey => if (block.legacy_encrypted) error.KeyPassphraseWrong else err,
                        else => err,
                    };
                }
                if (std.mem.eql(u8, block.label, "ENCRYPTED PRIVATE KEY")) {
                    const password = passphrase orelse return error.KeyPassphraseRequired;
                    // What a wrong passphrase leaves can pass for padding
                    // and a sequence, rarely; it does not pass for a key.
                    return fromPkcs8(arena, try decryptPkcs8(arena, block.der, password)) catch |err| switch (err) {
                        error.MalformedKey => error.KeyPassphraseWrong,
                        else => err,
                    };
                }
            }
            return error.MalformedKey;
        }
        // DER: PKCS #8, then PKCS #1, then SEC 1.
        if (fromPkcs8(arena, bytes)) |k| return k else |err| if (err == error.KeyAlgorithmUnsupported) return err;
        if (fromPkcs1(arena, bytes)) |k| return k else |_| {}
        return fromSec1(bytes, null);
    }

    /// Whether `bytes` holds an encrypted key.
    pub fn isEncrypted(bytes: []const u8) bool {
        return std.mem.find(u8, bytes, "-----BEGIN ENCRYPTED PRIVATE KEY-----") != null or
            std.mem.find(u8, bytes, "Proc-Type: 4,ENCRYPTED") != null;
    }

    /// Whether this key is the one `cert`'s public key belongs to.
    pub fn matches(k: PrivateKey, cert: []const u8) bool {
        const parsed = (std.crypto.Certificate{ .buffer = cert, .index = 0 }).parse() catch return false;
        const public = parsed.pubKey();
        switch (k) {
            .rsa => |r| {
                if (parsed.pub_key_algo != .rsaEncryption) return false;
                const components = std.crypto.Certificate.rsa.PublicKey.parseDer(public) catch return false;
                const n = der.unsigned(components.modulus) catch return false;
                return std.mem.eql(u8, n, r.n);
            },
            .ecdsa_p256 => |kp| {
                const encoded = kp.public_key.toUncompressedSec1();
                return std.mem.eql(u8, public, &encoded);
            },
            .ecdsa_p384 => |kp| {
                const encoded = kp.public_key.toUncompressedSec1();
                return std.mem.eql(u8, public, &encoded);
            },
            .ed25519 => |kp| return std.mem.eql(u8, public, &kp.public_key.toBytes()),
        }
    }

    /// The TLS signature schemes this key signs with, in the order uplink
    /// prefers them; `tls12` adds those TLS 1.3 does not allow.
    pub fn schemes(k: PrivateKey, tls12: bool) []const std.crypto.tls.SignatureScheme {
        return switch (k) {
            .rsa => if (tls12)
                &.{ .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512, .rsa_pkcs1_sha256, .rsa_pkcs1_sha384, .rsa_pkcs1_sha512 }
            else
                &.{ .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512 },
            .ecdsa_p256 => &.{.ecdsa_secp256r1_sha256},
            .ecdsa_p384 => &.{.ecdsa_secp384r1_sha384},
            .ed25519 => &.{.ed25519},
        };
    }

    /// The most bytes a signature takes.
    pub const max_signature_len = rsa.max_bits / 8;

    /// Sign `msg` with `scheme`, into `out`: the signature's bytes, as TLS
    /// sends them. `entropy` is fresh randomness for a PSS salt or ECDSA's
    /// hedge.
    pub fn sign(k: PrivateKey, scheme: std.crypto.tls.SignatureScheme, msg: []const u8, entropy: *const [64]u8, out: *[max_signature_len]u8) error{ InvalidRsaKey, RsaSignatureFault, SignatureSchemeMismatch, SigningFailed }![]const u8 {
        const Sha256 = std.crypto.hash.sha2.Sha256;
        const Sha384 = std.crypto.hash.sha2.Sha384;
        const Sha512 = std.crypto.hash.sha2.Sha512;
        switch (k) {
            .rsa => |r| {
                const sig = out[0..r.size()];
                switch (scheme) {
                    .rsa_pss_rsae_sha256 => try rsa.signPss(Sha256, r, msg, entropy[0..32], sig),
                    .rsa_pss_rsae_sha384 => try rsa.signPss(Sha384, r, msg, entropy[0..48], sig),
                    .rsa_pss_rsae_sha512 => try rsa.signPss(Sha512, r, msg, entropy[0..64], sig),
                    .rsa_pkcs1_sha256 => try rsa.signPkcs1(Sha256, r, msg, sig),
                    .rsa_pkcs1_sha384 => try rsa.signPkcs1(Sha384, r, msg, sig),
                    .rsa_pkcs1_sha512 => try rsa.signPkcs1(Sha512, r, msg, sig),
                    else => return error.SignatureSchemeMismatch,
                }
                return sig;
            },
            .ecdsa_p256 => |kp| {
                if (scheme != .ecdsa_secp256r1_sha256) return error.SignatureSchemeMismatch;
                const s = kp.sign(msg, entropy[0..32].*) catch return error.SigningFailed;
                var buf: [EcdsaP256.Signature.der_encoded_length_max]u8 = undefined;
                const d = s.toDer(&buf);
                @memcpy(out[0..d.len], d);
                return out[0..d.len];
            },
            .ecdsa_p384 => |kp| {
                if (scheme != .ecdsa_secp384r1_sha384) return error.SignatureSchemeMismatch;
                const s = kp.sign(msg, entropy[0..48].*) catch return error.SigningFailed;
                var buf: [EcdsaP384.Signature.der_encoded_length_max]u8 = undefined;
                const d = s.toDer(&buf);
                @memcpy(out[0..d.len], d);
                return out[0..d.len];
            },
            .ed25519 => |kp| {
                if (scheme != .ed25519) return error.SignatureSchemeMismatch;
                const s = kp.sign(msg, null) catch return error.SigningFailed;
                const bytes = s.toBytes();
                @memcpy(out[0..bytes.len], &bytes);
                return out[0..bytes.len];
            },
        }
    }
};

/// The certificates in `bytes`, PEM — every `CERTIFICATE` block, leaf
/// first as the file has them — or one in DER. Slices are `arena`'s or
/// `bytes`'.
pub fn certificates(arena: Allocator, bytes: []const u8) ParseError![]const []const u8 {
    if (std.mem.find(u8, bytes, "-----BEGIN ") == null) {
        // DER: one certificate, which must read as one.
        var r: der.Reader = .{ .bytes = bytes };
        _ = try r.expect(der.Tag.sequence);
        return arena.dupe([]const u8, &.{bytes[0..r.at]});
    }
    var out: std.ArrayList([]const u8) = .empty;
    var blocks = pemBlocks(bytes);
    while (try blocks.next(arena)) |block| {
        if (std.mem.eql(u8, block.label, "CERTIFICATE")) try out.append(arena, block.der);
    }
    if (out.items.len == 0) return error.CertificateMissing;
    return out.items;
}

const Pem = struct {
    label: []const u8,
    der: []const u8,
    /// OpenSSL's older encrypted PEM, with `Proc-Type` headers.
    legacy_encrypted: bool,
    /// Its `DEK-Info` header's value: the cipher, a comma, the IV in hex.
    dek_info: ?[]const u8 = null,
};

/// The DER inside `block`, decrypted first when it is OpenSSL's older
/// encrypted PEM: the key from `passphrase` and the IV's first eight bytes
/// by OpenSSL's `EVP_BytesToKey` over MD5, once.
fn openLegacy(arena: Allocator, block: Pem, passphrase: ?[]const u8) ParseError![]const u8 {
    if (!block.legacy_encrypted) return block.der;
    const info = block.dek_info orelse return error.MalformedKey;
    const comma = std.mem.findScalar(u8, info, ',') orelse return error.MalformedKey;
    const cipher = std.mem.trim(u8, info[0..comma], " \t");
    const key_len: usize = if (std.ascii.eqlIgnoreCase(cipher, "AES-128-CBC"))
        16
    else if (std.ascii.eqlIgnoreCase(cipher, "AES-256-CBC"))
        32
    else
        return error.KeyEncryptionUnsupported;
    const password = passphrase orelse return error.KeyPassphraseRequired;
    var iv: [16]u8 = undefined;
    const hex = std.mem.trim(u8, info[comma + 1 ..], " \t");
    if (hex.len != 32) return error.MalformedKey;
    _ = std.fmt.hexToBytes(&iv, hex) catch return error.MalformedKey;
    if (block.der.len == 0 or block.der.len % 16 != 0) return error.MalformedKey;
    var key: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &key);
    const Md5 = std.crypto.hash.Md5;
    var previous: [Md5.digest_length]u8 = undefined;
    var filled: usize = 0;
    while (filled < key_len) {
        var h = Md5.init(.{});
        if (filled != 0) h.update(&previous);
        h.update(password);
        h.update(iv[0..8]);
        h.final(&previous);
        const n = @min(previous.len, key_len - filled);
        @memcpy(key[filled..][0..n], previous[0..n]);
        filled += n;
    }
    const plain = try arena.alloc(u8, block.der.len);
    switch (key_len) {
        16 => cbcDecrypt(std.crypto.core.aes.Aes128, key[0..16].*, iv, block.der, plain),
        32 => cbcDecrypt(std.crypto.core.aes.Aes256, key[0..32].*, iv, block.der, plain),
        else => unreachable,
    }
    return unpad(plain);
}

/// `plain` without its PKCS #7 padding, which must read as a DER sequence:
/// a wrong passphrase leaves neither.
fn unpad(plain: []const u8) ParseError![]const u8 {
    const pad = plain[plain.len - 1];
    if (pad == 0 or pad > 16 or pad > plain.len) return error.KeyPassphraseWrong;
    for (plain[plain.len - pad ..]) |b| if (b != pad) return error.KeyPassphraseWrong;
    const inner = plain[0 .. plain.len - pad];
    var check: der.Reader = .{ .bytes = inner };
    _ = check.expect(der.Tag.sequence) catch return error.KeyPassphraseWrong;
    if (!check.done()) return error.KeyPassphraseWrong;
    return inner;
}

fn pemBlocks(text: []const u8) PemIterator {
    return .{ .text = text };
}

const PemIterator = struct {
    text: []const u8,
    at: usize = 0,

    fn next(it: *PemIterator, arena: Allocator) ParseError!?Pem {
        const begin_mark = "-----BEGIN ";
        const start = std.mem.findPos(u8, it.text, it.at, begin_mark) orelse return null;
        const label_start = start + begin_mark.len;
        const label_end = std.mem.findPos(u8, it.text, label_start, "-----") orelse return error.MalformedKey;
        const label = it.text[label_start..label_end];
        const end_mark = try arena.print("-----END {s}-----", .{label});
        const body_start = label_end + 5;
        const end = std.mem.findPos(u8, it.text, body_start, end_mark) orelse return error.MalformedKey;
        it.at = end + end_mark.len;
        const body = it.text[body_start..end];
        var legacy = false;
        var dek_info: ?[]const u8 = null;
        var b64: std.ArrayList(u8) = .empty;
        var lines = std.mem.splitScalar(u8, body, '\n');
        while (lines.next()) |raw| {
            const line = std.mem.trim(u8, raw, " \t\r");
            if (line.len == 0) continue;
            if (std.mem.findScalar(u8, line, ':')) |_| {
                if (std.mem.startsWith(u8, line, "Proc-Type:") and std.mem.find(u8, line, "ENCRYPTED") != null) legacy = true;
                if (std.mem.startsWith(u8, line, "DEK-Info:")) dek_info = std.mem.trim(u8, line["DEK-Info:".len..], " \t");
                continue;
            }
            try b64.appendSlice(arena, line);
        }
        const decoder = std.base64.standard.Decoder;
        const size = decoder.calcSizeForSlice(b64.items) catch return error.MalformedKey;
        const out = try arena.alloc(u8, size);
        decoder.decode(out, b64.items) catch return error.MalformedKey;
        return .{ .label = label, .der = out, .legacy_encrypted = legacy, .dek_info = dek_info };
    }
};

const oid = struct {
    const rsa_encryption = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
    const ec_public_key = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
    const prime256v1 = [_]u8{ 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
    const secp384r1 = [_]u8{ 0x2b, 0x81, 0x04, 0x00, 0x22 };
    const ed25519 = [_]u8{ 0x2b, 0x65, 0x70 };
    const pbes2 = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d };
    const pbkdf2 = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c };
    const hmac_sha1 = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x07 };
    const hmac_sha256 = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09 };
    const hmac_sha384 = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0a };
    const hmac_sha512 = [_]u8{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x0b };
    const aes128_cbc = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02 };
    const aes256_cbc = [_]u8{ 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x2a };
};

/// PKCS #8 PrivateKeyInfo.
fn fromPkcs8(arena: Allocator, bytes: []const u8) ParseError!PrivateKey {
    var outer: der.Reader = .{ .bytes = bytes };
    var info: der.Reader = .{ .bytes = try outer.expect(der.Tag.sequence) };
    _ = try info.expect(der.Tag.integer);
    var algorithm: der.Reader = .{ .bytes = try info.expect(der.Tag.sequence) };
    const algo = try algorithm.expect(der.Tag.oid);
    const key = try info.expect(der.Tag.octet_string);
    if (std.mem.eql(u8, algo, &oid.rsa_encryption)) return fromPkcs1(arena, key);
    if (std.mem.eql(u8, algo, &oid.ec_public_key)) {
        const curve = try algorithm.expect(der.Tag.oid);
        return fromSec1(key, curve);
    }
    if (std.mem.eql(u8, algo, &oid.ed25519)) {
        var inner: der.Reader = .{ .bytes = key };
        const seed = try inner.expect(der.Tag.octet_string);
        if (seed.len != 32) return error.MalformedKey;
        const kp = Ed25519.KeyPair.generateDeterministic(seed[0..32].*) catch return error.MalformedKey;
        return .{ .ed25519 = kp };
    }
    return error.KeyAlgorithmUnsupported;
}

/// PKCS #1 RSAPrivateKey.
fn fromPkcs1(arena: Allocator, bytes: []const u8) ParseError!PrivateKey {
    var outer: der.Reader = .{ .bytes = bytes };
    var seq: der.Reader = .{ .bytes = try outer.expect(der.Tag.sequence) };
    _ = try seq.expect(der.Tag.integer);
    const n = try der.unsigned(try seq.expect(der.Tag.integer));
    const e = try der.unsigned(try seq.expect(der.Tag.integer));
    const d = try der.unsigned(try seq.expect(der.Tag.integer));
    if (n.len * 8 > rsa.max_bits) return error.KeyAlgorithmUnsupported;
    if (n.len < 64 or n[n.len - 1] & 1 == 0) return error.MalformedKey;
    return .{ .rsa = .{ .n = try arena.dupe(u8, n), .e = try arena.dupe(u8, e), .d = try arena.dupe(u8, d) } };
}

/// SEC 1 ECPrivateKey, its curve named inside or by `curve` from PKCS #8.
fn fromSec1(bytes: []const u8, curve_outside: ?[]const u8) ParseError!PrivateKey {
    var outer: der.Reader = .{ .bytes = bytes };
    var seq: der.Reader = .{ .bytes = try outer.expect(der.Tag.sequence) };
    if (try der.small(try seq.expect(der.Tag.integer)) != 1) return error.MalformedKey;
    const scalar = try seq.expect(der.Tag.octet_string);
    var curve = curve_outside;
    if (try seq.optional(der.Tag.context0)) |params| {
        var p: der.Reader = .{ .bytes = params };
        curve = try p.expect(der.Tag.oid);
    }
    const named = curve orelse return error.MalformedKey;
    if (std.mem.eql(u8, named, &oid.prime256v1)) {
        if (scalar.len != 32) return error.MalformedKey;
        const sk = EcdsaP256.SecretKey.fromBytes(scalar[0..32].*) catch return error.MalformedKey;
        return .{ .ecdsa_p256 = EcdsaP256.KeyPair.fromSecretKey(sk) catch return error.MalformedKey };
    }
    if (std.mem.eql(u8, named, &oid.secp384r1)) {
        if (scalar.len != 48) return error.MalformedKey;
        const sk = EcdsaP384.SecretKey.fromBytes(scalar[0..48].*) catch return error.MalformedKey;
        return .{ .ecdsa_p384 = EcdsaP384.KeyPair.fromSecretKey(sk) catch return error.MalformedKey };
    }
    return error.KeyAlgorithmUnsupported;
}

/// EncryptedPrivateKeyInfo with PBES2: the PrivateKeyInfo inside.
fn decryptPkcs8(arena: Allocator, bytes: []const u8, password: []const u8) ParseError![]const u8 {
    var outer: der.Reader = .{ .bytes = bytes };
    var info: der.Reader = .{ .bytes = try outer.expect(der.Tag.sequence) };
    var algorithm: der.Reader = .{ .bytes = try info.expect(der.Tag.sequence) };
    if (!std.mem.eql(u8, try algorithm.expect(der.Tag.oid), &oid.pbes2)) return error.KeyEncryptionUnsupported;
    var params: der.Reader = .{ .bytes = try algorithm.expect(der.Tag.sequence) };
    var kdf: der.Reader = .{ .bytes = try params.expect(der.Tag.sequence) };
    if (!std.mem.eql(u8, try kdf.expect(der.Tag.oid), &oid.pbkdf2)) return error.KeyEncryptionUnsupported;
    var kdf_params: der.Reader = .{ .bytes = try kdf.expect(der.Tag.sequence) };
    const salt = try kdf_params.expect(der.Tag.octet_string);
    const rounds = try der.small(try kdf_params.expect(der.Tag.integer));
    if (rounds == 0 or rounds > 10_000_000) return error.MalformedKey;
    var key_length: ?u64 = null;
    if (try kdf_params.optional(der.Tag.integer)) |kl| key_length = try der.small(kl);
    var prf: []const u8 = &oid.hmac_sha1;
    if (try kdf_params.optional(der.Tag.sequence)) |p| {
        var pr: der.Reader = .{ .bytes = p };
        prf = try pr.expect(der.Tag.oid);
    }
    var scheme: der.Reader = .{ .bytes = try params.expect(der.Tag.sequence) };
    const cipher = try scheme.expect(der.Tag.oid);
    // AES-192 is not among the standard library's ciphers.
    const key_len: usize = if (std.mem.eql(u8, cipher, &oid.aes128_cbc))
        16
    else if (std.mem.eql(u8, cipher, &oid.aes256_cbc))
        32
    else
        return error.KeyEncryptionUnsupported;
    const iv = try scheme.expect(der.Tag.octet_string);
    if (iv.len != 16) return error.MalformedKey;
    const encrypted = try info.expect(der.Tag.octet_string);
    if (encrypted.len == 0 or encrypted.len % 16 != 0) return error.MalformedKey;
    if (key_length) |kl| if (kl != key_len) return error.MalformedKey;
    var key: [32]u8 = undefined;
    const HmacSha1 = std.crypto.auth.hmac.HmacSha1;
    const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
    const HmacSha384 = std.crypto.auth.hmac.sha2.HmacSha384;
    const HmacSha512 = std.crypto.auth.hmac.sha2.HmacSha512;
    const derived = key[0..key_len];
    const r: u32 = @intCast(rounds);
    (if (std.mem.eql(u8, prf, &oid.hmac_sha1))
        std.crypto.pwhash.pbkdf2(derived, password, salt, r, HmacSha1)
    else if (std.mem.eql(u8, prf, &oid.hmac_sha256))
        std.crypto.pwhash.pbkdf2(derived, password, salt, r, HmacSha256)
    else if (std.mem.eql(u8, prf, &oid.hmac_sha384))
        std.crypto.pwhash.pbkdf2(derived, password, salt, r, HmacSha384)
    else if (std.mem.eql(u8, prf, &oid.hmac_sha512))
        std.crypto.pwhash.pbkdf2(derived, password, salt, r, HmacSha512)
    else
        return error.KeyEncryptionUnsupported) catch return error.MalformedKey;

    const plain = try arena.alloc(u8, encrypted.len);
    switch (key_len) {
        16 => cbcDecrypt(std.crypto.core.aes.Aes128, key[0..16].*, iv[0..16].*, encrypted, plain),
        32 => cbcDecrypt(std.crypto.core.aes.Aes256, key[0..32].*, iv[0..16].*, encrypted, plain),
        else => unreachable,
    }
    std.crypto.secureZero(u8, &key);
    return unpad(plain);
}

fn cbcDecrypt(comptime Aes: type, key: [Aes.key_bits / 8]u8, iv: [16]u8, in: []const u8, out: []u8) void {
    const ctx = Aes.initDec(key);
    var prev = iv;
    var i: usize = 0;
    while (i < in.len) : (i += 16) {
        var block: [16]u8 = undefined;
        ctx.decrypt(&block, in[i..][0..16]);
        for (&block, prev) |*b, p| b.* ^= p;
        prev = in[i..][0..16].*;
        @memcpy(out[i..][0..16], &block);
    }
}

test "fuzz: any key file is a key or a named refusal" {
    try std.testing.fuzz({}, struct {
        fn one(_: void, smith: *std.testing.Smith) anyerror!void {
            var buf: [512]u8 = undefined;
            const bytes = buf[0..smith.slice(&buf)];
            var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
            defer arena.deinit();
            _ = PrivateKey.parse(arena.allocator(), bytes, "pass") catch return;
            _ = certificates(arena.allocator(), bytes) catch return;
        }
    }.one, .{ .corpus = &.{
        "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----\n",
        "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIGbMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAgAAAAAAAAAAAICCAAw\n-----END ENCRYPTED PRIVATE KEY-----\n",
    } });
}

const testing = std.testing;

/// Sign `msg` in every scheme `k` offers and check each signature with the
/// standard library's verification against `cert`'s public key.
fn expectSignsFor(k: PrivateKey, cert_pem: []const u8, tls12: bool) !void {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const chain = try certificates(arena.allocator(), cert_pem);
    try testing.expect(k.matches(chain[0]));
    const parsed = try (std.crypto.Certificate{ .buffer = chain[0], .index = 0 }).parse();
    const msg = "a handshake's transcript";
    var entropy: [64]u8 = undefined;
    for (&entropy, 0..) |*b, i| b.* = @intCast(i * 7 % 251);
    for (k.schemes(tls12)) |scheme| {
        var out: [PrivateKey.max_signature_len]u8 = undefined;
        const sig = try k.sign(scheme, msg, &entropy, &out);
        const Cert = std.crypto.Certificate;
        switch (k) {
            .rsa => {
                const parts = try Cert.rsa.PublicKey.parseDer(parsed.pubKey());
                const public = try Cert.rsa.PublicKey.fromBytes(parts.exponent, parts.modulus);
                try testing.expectEqual(@as(usize, 256), sig.len);
                const Sha256 = std.crypto.hash.sha2.Sha256;
                const Sha384 = std.crypto.hash.sha2.Sha384;
                const Sha512 = std.crypto.hash.sha2.Sha512;
                const s = sig[0..256];
                switch (scheme) {
                    .rsa_pss_rsae_sha256 => try Cert.rsa.PSSSignature.verify(256, s, msg, public, Sha256),
                    .rsa_pss_rsae_sha384 => try Cert.rsa.PSSSignature.verify(256, s, msg, public, Sha384),
                    .rsa_pss_rsae_sha512 => try Cert.rsa.PSSSignature.verify(256, s, msg, public, Sha512),
                    .rsa_pkcs1_sha256 => try Cert.rsa.PKCS1v1_5Signature.verify(256, s, msg, public, Sha256),
                    .rsa_pkcs1_sha384 => try Cert.rsa.PKCS1v1_5Signature.verify(256, s, msg, public, Sha384),
                    .rsa_pkcs1_sha512 => try Cert.rsa.PKCS1v1_5Signature.verify(256, s, msg, public, Sha512),
                    else => unreachable,
                }
            },
            .ecdsa_p256 => {
                const public = try EcdsaP256.PublicKey.fromSec1(parsed.pubKey());
                try (try EcdsaP256.Signature.fromDer(sig)).verify(msg, public);
            },
            .ecdsa_p384 => {
                const public = try EcdsaP384.PublicKey.fromSec1(parsed.pubKey());
                try (try EcdsaP384.Signature.fromDer(sig)).verify(msg, public);
            },
            .ed25519 => {
                const public = try Ed25519.PublicKey.fromBytes(parsed.pubKey()[0..32].*);
                try Ed25519.Signature.fromBytes(sig[0..64].*).verify(msg, public);
            },
        }
    }
}

test "every key OpenSSL writes signs what its certificate's key verifies, in every scheme offered" {
    const Case = struct { key: []const u8, cert: []const u8, passphrase: ?[]const u8 = null };
    for ([_]Case{
        .{ .key = @embedFile("testdata/rsa.pkcs8.pem"), .cert = @embedFile("testdata/rsa.cert.pem") },
        .{ .key = @embedFile("testdata/rsa.pkcs1.pem"), .cert = @embedFile("testdata/rsa.cert.pem") },
        .{ .key = @embedFile("testdata/rsa.enc-aes256-sha256.pem"), .cert = @embedFile("testdata/rsa.cert.pem"), .passphrase = "correct-horse" },
        .{ .key = @embedFile("testdata/rsa.legacy-aes256.pem"), .cert = @embedFile("testdata/rsa.cert.pem"), .passphrase = "correct-horse" },
        .{ .key = @embedFile("testdata/p256.pkcs8.pem"), .cert = @embedFile("testdata/p256.cert.pem") },
        .{ .key = @embedFile("testdata/p256.sec1.pem"), .cert = @embedFile("testdata/p256.cert.pem") },
        .{ .key = @embedFile("testdata/p256.pkcs8.der"), .cert = @embedFile("testdata/p256.cert.der") },
        .{ .key = @embedFile("testdata/p256.enc-aes128-sha1.pem"), .cert = @embedFile("testdata/p256.cert.pem"), .passphrase = "correct-horse" },
        .{ .key = @embedFile("testdata/p256.legacy-aes128.pem"), .cert = @embedFile("testdata/p256.cert.pem"), .passphrase = "correct-horse" },
        .{ .key = @embedFile("testdata/p384.pkcs8.pem"), .cert = @embedFile("testdata/p384.cert.pem") },
        .{ .key = @embedFile("testdata/ed25519.pkcs8.pem"), .cert = @embedFile("testdata/ed25519.cert.pem") },
        .{ .key = @embedFile("testdata/ed25519.enc-aes256-sha512.pem"), .cert = @embedFile("testdata/ed25519.cert.pem"), .passphrase = "correct-horse" },
    }) |case| {
        var arena: std.heap.ArenaAllocator = .init(testing.allocator);
        defer arena.deinit();
        const k = try PrivateKey.parse(arena.allocator(), case.key, case.passphrase);
        try testing.expectEqual(case.passphrase != null, PrivateKey.isEncrypted(case.key));
        try expectSignsFor(k, case.cert, true);
        try expectSignsFor(k, case.cert, false);
    }
}

test "a key is refused by name: no passphrase, a wrong one, a cipher not read, another certificate's" {
    var arena: std.heap.ArenaAllocator = .init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectError(error.KeyPassphraseRequired, PrivateKey.parse(a, @embedFile("testdata/rsa.enc-aes256-sha256.pem"), null));
    try testing.expectError(error.KeyPassphraseRequired, PrivateKey.parse(a, @embedFile("testdata/rsa.legacy-aes256.pem"), null));
    try testing.expectError(error.KeyPassphraseWrong, PrivateKey.parse(a, @embedFile("testdata/rsa.enc-aes256-sha256.pem"), "battery-staple"));
    try testing.expectError(error.KeyPassphraseWrong, PrivateKey.parse(a, @embedFile("testdata/p256.legacy-aes128.pem"), "battery-staple"));
    try testing.expectError(error.KeyPassphraseWrong, PrivateKey.parse(a, @embedFile("testdata/ed25519.enc-aes256-sha512.pem"), "battery-staple"));
    try testing.expectError(error.KeyEncryptionUnsupported, PrivateKey.parse(a, @embedFile("testdata/p384.enc-aes192.pem"), "correct-horse"));
    try testing.expectError(error.KeyEncryptionUnsupported, PrivateKey.parse(a, @embedFile("testdata/p384.enc-des3.pem"), "correct-horse"));
    try testing.expectError(error.KeyEncryptionUnsupported, PrivateKey.parse(a, @embedFile("testdata/rsa.legacy-des3.pem"), "correct-horse"));
    try testing.expectError(error.MalformedKey, PrivateKey.parse(a, "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", null));
    try testing.expectError(error.CertificateMissing, certificates(a, @embedFile("testdata/p256.pkcs8.pem")));
    const p256 = try PrivateKey.parse(a, @embedFile("testdata/p256.pkcs8.pem"), null);
    const others = try certificates(a, @embedFile("testdata/p384.cert.pem"));
    try testing.expect(!p256.matches(others[0]));
    const rsa_key = try PrivateKey.parse(a, @embedFile("testdata/rsa.pkcs1.pem"), null);
    try testing.expect(!rsa_key.matches(others[0]));
    // A key and its certificate in one file, as curl reads `http.sslCert`.
    const both = try std.mem.concat(a, u8, &.{ @embedFile("testdata/p256.cert.pem"), @embedFile("testdata/p256.sec1.pem") });
    const from_both = try PrivateKey.parse(a, both, null);
    try testing.expect(from_both.matches((try certificates(a, both))[0]));
}
