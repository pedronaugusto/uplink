//! The client's half of certificate authentication in a TLS handshake: a
//! server's CertificateRequest read, the handshake kept and signed for a
//! CertificateVerify, and the client's own flight written, sealed under
//! TLS 1.3's handshake keys or in the clear before TLS 1.2's
//! ChangeCipherSpec.
//!
//! This is what `Client.zig` adds to the standard library's client, kept out
//! of it so that the copy of std there differs from std only at the places
//! the handshake has to call these. See `Client.zig` for why there is a copy
//! at all, and how it is kept level with std.

const std = @import("std");
const tls = std.crypto.tls;
const mem = std.mem;
const Writer = std.Io.Writer;
const ClientAuth = @import("ClientAuth.zig");
const PrivateKey = @import("key.zig").PrivateKey;

/// A server's CertificateRequest, as far as the answer needs it.
pub const CertificateRequest = struct {
    /// TLS 1.3's certificate_request_context, echoed in the Certificate.
    context: []const u8,
    /// The signature schemes the server takes, two bytes each.
    schemes: []const u8,

    /// TLS 1.3 (RFC 8446, 4.3.2): the context, then extensions, of which
    /// signature_algorithms must be one.
    pub fn parse13(body: []u8) error{TlsDecodeError}!CertificateRequest {
        var d: tls.Decoder = .fromTheirSlice(body);
        try d.ensure(1);
        const context_len = d.decode(u8);
        try d.ensure(context_len + 2);
        const context = d.slice(context_len);
        const extensions_len = d.decode(u16);
        var extensions = try d.sub(extensions_len);
        if (!d.eof()) return error.TlsDecodeError;
        var schemes: ?[]const u8 = null;
        while (!extensions.eof()) {
            try extensions.ensure(4);
            const et = extensions.decode(tls.ExtensionType);
            const size = extensions.decode(u16);
            var ext = try extensions.sub(size);
            if (et != .signature_algorithms) continue;
            if (schemes != null) return error.TlsDecodeError;
            schemes = try schemeList(&ext);
        }
        return .{ .context = context, .schemes = schemes orelse return error.TlsDecodeError };
    }

    /// TLS 1.2 (RFC 5246, 7.4.4): certificate types, signature schemes,
    /// the authorities the server names.
    pub fn parse12(body: []u8) error{TlsDecodeError}!CertificateRequest {
        var d: tls.Decoder = .fromTheirSlice(body);
        try d.ensure(1);
        const types_len = d.decode(u8);
        try d.ensure(types_len);
        d.skip(types_len);
        const schemes = try schemeList(&d);
        try d.ensure(2);
        const authorities_len = d.decode(u16);
        _ = try d.sub(authorities_len);
        if (!d.eof()) return error.TlsDecodeError;
        return .{ .context = &.{}, .schemes = schemes };
    }

    fn schemeList(d: *tls.Decoder) error{TlsDecodeError}![]const u8 {
        try d.ensure(2);
        const len = d.decode(u16);
        if (len == 0 or len % 2 != 0) return error.TlsDecodeError;
        try d.ensure(len);
        return d.slice(len);
    }

    /// The first of `mine` the server takes.
    pub fn choose(r: CertificateRequest, mine: []const tls.SignatureScheme) ?tls.SignatureScheme {
        for (mine) |want| {
            var i: usize = 0;
            while (i + 2 <= r.schemes.len) : (i += 2) {
                if (mem.readInt(u16, r.schemes[i..][0..2], .big) == @backingInt(want)) return want;
            }
        }
        return null;
    }
};

/// Keep `parts` of the handshake for TLS 1.2's CertificateVerify, when
/// there is a key to sign them with.
pub fn keepRaw(raw: *std.ArrayList(u8), auth: ?*const ClientAuth, parts: []const []const u8) error{OutOfMemory}!void {
    const a = auth orelse return;
    for (parts) |part| try raw.appendSlice(a.gpa, part);
}

pub fn signWith(
    key: PrivateKey,
    scheme: tls.SignatureScheme,
    msg: []const u8,
    entropy: *const [64]u8,
    out: *[PrivateKey.max_signature_len]u8,
) error{ ClientCertificateSchemeUnsupported, ClientKeyInvalid, ClientSignatureFault }![]const u8 {
    return key.sign(scheme, msg, entropy, out) catch |err| switch (err) {
        error.SignatureSchemeMismatch => error.ClientCertificateSchemeUnsupported,
        error.InvalidRsaKey => error.ClientKeyInvalid,
        error.RsaSignatureFault, error.SigningFailed => error.ClientSignatureFault,
    };
}

/// The nonce for record `seq` under `iv` (RFC 8446, 5.3).
pub fn sequenceNonce(comptime P: type, iv: [P.AEAD.nonce_length]u8, seq: u64) [P.AEAD.nonce_length]u8 {
    const pad = @as([P.AEAD.nonce_length - 8]u8, @splat(0));
    const operand: NonceVector(P) = pad ++ @as([8]u8, @bitCast(mem.nativeToBig(u64, seq)));
    return @as(NonceVector(P), iv) ^ operand;
}

fn NonceVector(comptime P: type) type {
    return @Vector(P.AEAD.nonce_length, u8);
}

/// The most handshake bytes put in one record the client writes.
pub const client_fragment_len = 4096;

/// Handshake messages the client sends under TLS 1.3's handshake keys,
/// gathered into records of `client_fragment_len`.
pub fn Sealer13(comptime P: type) type {
    return struct {
        const Self = @This();

        output: *Writer,
        key: [P.AEAD.key_length]u8,
        iv: [P.AEAD.nonce_length]u8,
        seq: *u64,
        buf: [client_fragment_len + 1]u8 = undefined,
        len: usize = 0,

        pub fn add(s: *Self, bytes: []const u8) Writer.Error!void {
            var rest = bytes;
            while (rest.len > 0) {
                const n = @min(rest.len, client_fragment_len - s.len);
                @memcpy(s.buf[s.len..][0..n], rest[0..n]);
                s.len += n;
                rest = rest[n..];
                if (s.len == client_fragment_len) try s.seal();
            }
        }

        pub fn seal(s: *Self) Writer.Error!void {
            if (s.len == 0) return;
            s.buf[s.len] = @backingInt(tls.ContentType.handshake);
            const inner = s.buf[0 .. s.len + 1];
            var record: [tls.record_header_len + client_fragment_len + 1 + @as(usize, P.AEAD.tag_length)]u8 = undefined;
            const total = inner.len + P.AEAD.tag_length;
            record[0] = @backingInt(tls.ContentType.application_data);
            mem.writeInt(u16, record[1..3], @backingInt(tls.ProtocolVersion.tls_1_2), .big);
            mem.writeInt(u16, record[3..5], @intCast(total), .big);
            const header = record[0..tls.record_header_len];
            P.AEAD.encrypt(
                record[tls.record_header_len..][0..inner.len],
                record[tls.record_header_len + inner.len ..][0..P.AEAD.tag_length],
                inner,
                header,
                sequenceNonce(P, s.iv, s.seq.*),
                s.key,
            );
            try s.output.writeAll(record[0 .. tls.record_header_len + total]);
            s.seq.* += 1;
            s.len = 0;
        }
    };
}

/// Handshake messages the client sends in the clear, before TLS 1.2's
/// ChangeCipherSpec, in records of `client_fragment_len`.
pub fn writePlainHandshake(output: *Writer, parts: []const []const u8) Writer.Error!void {
    var total: usize = 0;
    for (parts) |part| total += part.len;
    var part_index: usize = 0;
    var at: usize = 0;
    while (total > 0) {
        const n = @min(total, client_fragment_len);
        var header: [tls.record_header_len]u8 = undefined;
        header[0] = @backingInt(tls.ContentType.handshake);
        mem.writeInt(u16, header[1..3], @backingInt(tls.ProtocolVersion.tls_1_2), .big);
        mem.writeInt(u16, header[3..5], @intCast(n), .big);
        try output.writeAll(&header);
        var left = n;
        while (left > 0) {
            const part = parts[part_index];
            const take = @min(left, part.len - at);
            try output.writeAll(part[at..][0..take]);
            at += take;
            left -= take;
            if (at == part.len) {
                part_index += 1;
                at = 0;
            }
        }
        total -= n;
    }
}

test "a CertificateRequest is read as each version writes it, and anything else is refused" {
    var tls13 = [_]u8{ 2, 0xaa, 0xbb, 0, 10, 0, 13, 0, 6, 0, 4, 0x08, 0x04, 0x04, 0x03 };
    const r13 = try CertificateRequest.parse13(&tls13);
    try std.testing.expectEqualSlices(u8, &.{ 0xaa, 0xbb }, r13.context);
    try std.testing.expectEqual(tls.SignatureScheme.ecdsa_secp256r1_sha256, r13.choose(&.{ .ed25519, .ecdsa_secp256r1_sha256 }).?);
    try std.testing.expectEqual(null, r13.choose(&.{.ed25519}));
    var no_schemes = [_]u8{ 0, 0, 0 };
    try std.testing.expectError(error.TlsDecodeError, CertificateRequest.parse13(&no_schemes));
    var tls12 = [_]u8{ 2, 1, 64, 0, 2, 0x04, 0x01, 0, 0 };
    const r12 = try CertificateRequest.parse12(&tls12);
    try std.testing.expectEqual(tls.SignatureScheme.rsa_pkcs1_sha256, r12.choose(&.{ .rsa_pss_rsae_sha256, .rsa_pkcs1_sha256 }).?);
    var odd = [_]u8{ 0, 0, 3, 0x04, 0x01, 0x05, 0, 0 };
    try std.testing.expectError(error.TlsDecodeError, CertificateRequest.parse12(&odd));
}

test "fuzz: any CertificateRequest is read or refused as undecodable" {
    try std.testing.fuzz({}, struct {
        fn one(_: void, smith: *std.testing.Smith) anyerror!void {
            var buf: [300]u8 = undefined;
            const body = buf[0..smith.slice(&buf)];
            if (CertificateRequest.parse13(body)) |r| {
                _ = r.choose(&.{ .rsa_pss_rsae_sha256, .ed25519 });
            } else |err| try std.testing.expectEqual(error.TlsDecodeError, err);
            if (CertificateRequest.parse12(body)) |r| {
                _ = r.choose(&.{.rsa_pkcs1_sha256});
            } else |err| try std.testing.expectEqual(error.TlsDecodeError, err);
        }
    }.one, .{ .corpus = &.{
        &.{ 0, 0, 8, 0, 13, 0, 4, 0, 2, 0x08, 0x07 },
        &.{ 1, 64, 0, 2, 0x04, 0x03, 0, 0 },
    } });
}
