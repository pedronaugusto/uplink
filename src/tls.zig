//! How uplink's connections use TLS. The engine, the authorities and the
//! certificates and keys a client or a server answers with are cloak's; this
//! file is the HTTP side of them: the options a client and a server take,
//! what an alert says about a client certificate, the certificate decoders
//! a client offers, and the shape of a connection's buffers.

const std = @import("std");
const aegis = @import("aegis");
const warp = @import("warp");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const cloak = @import("cloak");
const Duration = @import("span.zig").Duration;
/// A certificate codec (RFC 8879), cloak's: an algorithm and its decoder.
pub const Codec = cloak.tls.certificate_compression.Codec;

/// How a client's TLS connections are made.
pub const ClientOptions = struct {
    /// The authorities servers are checked against, a snapshot the caller
    /// keeps alive for as long as the client uses it; null is the system's,
    /// read once per client at its first verifying handshake.
    trust: ?cloak.Trust.Snapshot = null,
    /// `none` checks neither a server's certificate nor its name.
    verify: Verify = .full,
    /// The lowest and highest TLS versions spoken with a server: a `min`
    /// of `.tls13` refuses one that speaks only TLS 1.2, as curl's
    /// `CURLOPT_SSLVERSION` (git's `http.sslVersion`) does. A proxy's
    /// own TLS keeps both versions.
    min_version: cloak.tls.Version = .tls12,
    max_version: cloak.tls.Version = .tls13,
    /// The SHA-256 of each SubjectPublicKeyInfo a server's own certificate
    /// may hold, as curl's `CURLOPT_PINNEDPUBLICKEY` (git's
    /// `http.pinnedPubkey`); empty pins nothing. Checked beside the
    /// authorities; with `verify = .none` the leaf's key is checked against
    /// them alone, no path, name or validity (curl's pinned public key with
    /// peer verification off, git's `http.sslVerify=false`), a mismatch
    /// failing the handshake (`Diagnostics.tls_error` `PinMismatch`).
    /// Borrowed for as long as the client uses it.
    pins: []const [32]u8 = &.{},
    /// The certificate and key a server that asks for one is answered with,
    /// which the caller keeps alive for as long as the client uses it.
    client_auth: ?cloak.ClientAuth = null,
    /// Where every session's secrets are written in the NSS key log format,
    /// for a capture to be decrypted with. Never read from the environment.
    /// Every session writes to it; when connections run on several tasks,
    /// the writer must take writes from several tasks.
    key_log: ?*Io.Writer = null,
    /// Session resumption (TLS 1.3, with a fresh key exchange each time)
    /// from the client's own ticket cache, bounded so; null resumes
    /// nothing. A connection through a proxy keeps its tickets apart from
    /// one made directly, so a server cannot link the two by a ticket.
    resumption: ?Resumption = .{},
    /// The certificate compression offered (RFC 8879, TLS 1.3).
    certificate_compression: CertificateCompression = .zstd_zlib,
    /// Encrypted Client Hello (RFC 9849), which hides the server's name
    /// from the network.
    ech: Ech = .published,

    pub const Verify = enum { full, none };

    /// The bounds of the ticket cache, and how long a session lives.
    pub const Resumption = struct {
        /// Tickets kept across every server.
        max_tickets: u32 = 256,
        /// The bytes tickets and their records take across every server.
        max_bytes: aegis.units.Bytes(u32) = .literal("1MiB"),
        /// Tickets kept for one server, at most 16; the oldest goes first.
        per_server: u8 = 4,
        /// The longest a session is resumed after the full handshake that
        /// authenticated it. Under the system's verifier (macOS, Windows)
        /// cloak resumes for an hour at most, whatever this says.
        max_age: Duration = .literal("7d"),
        /// TLS 1.2 session tickets too (RFC 5077). An abbreviated TLS 1.2
        /// handshake reuses the session's master secret with no new key
        /// exchange, giving up forward secrecy between its connections.
        tls12: bool = false,
    };

    /// Which certificate decoders a client offers.
    pub const CertificateCompression = union(enum) {
        /// zstd and zlib, decoded by warp, zstd preferred.
        zstd_zlib,
        none,
        /// The caller's decoders, its preference first; borrowed for as long
        /// as the client is used. `decoder` makes warp's, so a caller can
        /// offer them beside one of its own (brotli, which uplink does not
        /// decode).
        codecs: []const Codec,
    };

    /// When a client offers Encrypted Client Hello.
    pub const Ech = enum {
        /// Never.
        off,
        /// To a server whose HTTPS record publishes a config, when the
        /// client's resolver reads such records (`Dns`); then the
        /// connection is TLS 1.3 only, and a server that refuses it and
        /// sends new configs is tried once more with them.
        published,
        /// As `published`, and a GREASE extension to every other server, as
        /// browsers send, so a hidden name does not stand out.
        grease,
    };
};

/// How a server's TLS connections are accepted.
pub const ServerOptions = struct {
    /// The certificate chains presented, each with the names it answers
    /// for; the first answers a name none lists. The caller keeps them
    /// alive for as long as the server uses them.
    credentials: []const cloak.tls.Credential,
    /// Whether a client is asked for a certificate, and whether it must
    /// present one. The one it proves is each request's `peer_certificate`.
    client_certificate: cloak.tls.ClientCertificate = .none,
    /// The authorities a client's certificate is checked against; null
    /// takes any chain the client presents, unchecked.
    client_trust: ?cloak.Trust.Snapshot = null,
    /// Where every session's secrets are written in the NSS key log format;
    /// never read from the environment.
    key_log: ?*Io.Writer = null,
    /// Session tickets the server issues and resumes from (TLS 1.3, with a
    /// fresh key exchange each time).
    tickets: Tickets = .{ .own = .{} },
    /// TLS 1.2 session tickets too, from the same keys (RFC 5077). An
    /// abbreviated TLS 1.2 handshake reuses the session's master secret
    /// with no new key exchange, giving up forward secrecy between its
    /// connections.
    tls12_tickets: bool = false,
    /// Encrypted Client Hello keys (RFC 9849): each a published config and
    /// the secret of its key, borrowed for as long as the server uses them.
    ech_keys: []const cloak.tls.ech.Key = &.{},

    /// Whose keys seal a server's tickets.
    pub const Tickets = union(enum) {
        /// None: every handshake is a full one.
        none,
        /// The server's own, a fresh key drawn whenever none issues: its
        /// tickets do not outlive the server, nor open at another.
        own: Rotation,
        /// The caller's ring, which it rotates and may share between
        /// servers and processes; borrowed for as long as the server is.
        keys: *cloak.tls.TicketKeys,
    };

    /// How long a server's own keys last.
    pub const Rotation = struct {
        /// How long a ticket opens, from the full handshake its session
        /// began with: at most seven days (RFC 8446).
        lifetime: Duration = .literal("24h"),
        /// How long a key issues tickets before the next is drawn: at most
        /// seven days.
        rotation: Duration = .literal("6h"),
    };
};

/// The protocols a client offers by ALPN when it may speak HTTP/2, its
/// preference first; and when it speaks HTTP/1.1 alone.
pub const client_protocols: []const []const u8 = &.{ "h2", "http/1.1" };
pub const client_protocols_h1: []const []const u8 = &.{"http/1.1"};
/// HTTP/2 alone, for an endpoint whose HTTPS record leaves HTTP/1.1 out.
pub const client_protocols_h2: []const []const u8 = &.{"h2"};

/// The protocols a server offers by ALPN, its preference first: HTTP/2,
/// then HTTP/1.1.
pub const server_protocols: []const []const u8 = &.{ "h2", "http/1.1" };
/// The same, for a server that speaks HTTP/1.1 only.
pub const server_protocols_h1: []const []const u8 = &.{"http/1.1"};

/// The buffers a TLS session reads and writes through: one whole TLS record
/// of ciphertext (16 KiB of plaintext, its header, type and tag), which is
/// also what a socket under TLS reads and writes in.
pub const record_buffer_len = 16 * 1024 + 5 + 256;

/// Which of warp's decoders `decoder` makes.
pub const Decoding = enum { zstd, zlib };

/// warp's decoder for `algorithm` as a certificate codec. Its working state
/// (a zstd decoder's tables, under 96 KiB; a zlib one's, about 11 KiB) is
/// allocated from `gpa` for each certificate and freed after it; `gpa` must
/// outlive the handshakes the codec serves.
pub fn decoder(algorithm: Decoding, gpa: *const Allocator) Codec {
    return switch (algorithm) {
        .zstd => .{ .algorithm = .zstd, .context = @ptrCast(@constCast(gpa)), .decompress = decodeZstd }, // aegis: boundary(A019): cloak's Codec carries its context as *anyopaque; decodeZstd reads it back as the allocator, never writing it
        .zlib => .{ .algorithm = .zlib, .context = @ptrCast(@constCast(gpa)), .decompress = decodeZlib }, // aegis: boundary(A019): cloak's Codec carries its context as *anyopaque; decodeZlib reads it back as the allocator, never writing it
    };
}

fn decodeZstd(context: ?*anyopaque, input: []const u8, out: []u8) cloak.tls.certificate_compression.Error!void {
    const gpa: *const Allocator = @ptrCast(@alignCast(context.?)); // aegis: boundary(A019): cloak gives back the context `decoder` registered, an allocator
    const d = gpa.create(warp.zstd.Decompressor) catch return error.Failed;
    defer gpa.destroy(d);
    d.* = .init;
    const r = d.decompress(input, out, .{ .frames = .one }) catch return error.Failed;
    // The certificate is exactly what the frame holds, and nothing follows it.
    if (r.in_len != input.len or r.out_len != out.len) return error.Failed;
}

fn decodeZlib(context: ?*anyopaque, input: []const u8, out: []u8) cloak.tls.certificate_compression.Error!void {
    const gpa: *const Allocator = @ptrCast(@alignCast(context.?)); // aegis: boundary(A019): cloak gives back the context `decoder` registered, an allocator
    const d = gpa.create(warp.Decompressor) catch return error.Failed;
    defer gpa.destroy(d);
    d.* = .init;
    const r = d.inflate(input, out, .{ .accept = .zlib }) catch return error.Failed;
    if (r.in_len != input.len or r.out_len != out.len) return error.Failed;
}

/// Whether an alert is a server's refusal of a client certificate, or of none,
/// once it has asked for one. OpenSSL answers a missing one in TLS 1.2 with
/// `handshake_failure`.
pub fn refusesCertificate(alert: cloak.tls.Alert) bool {
    return switch (alert) {
        .bad_certificate,
        .unsupported_certificate,
        .certificate_revoked,
        .certificate_expired,
        .certificate_unknown,
        .unknown_ca,
        .access_denied,
        .certificate_required,
        .handshake_failure,
        .decrypt_error,
        => true,
        else => false,
    };
}

/// What a server's certificate must name: the host as an address when it is
/// one, a DNS name otherwise.
pub fn reference(host: []const u8) cloak.certificates.types.Identity {
    const address = Io.net.IpAddress.parse(host, 0) catch return .{ .dns = host };
    return switch (address) {
        .ip4 => |ip| .{ .ipv4 = ip.bytes },
        .ip6 => |ip| .{ .ipv6 = ip.bytes },
    };
}

/// A key log sink that writes each line to `writer`.
pub fn keyLog(writer: *Io.Writer) cloak.tls.Connection.KeyLog {
    return .{ .context = writer, .write = writeKeyLog };
}

fn writeKeyLog(context: ?*anyopaque, line: []const u8) void {
    const writer: *Io.Writer = @ptrCast(@alignCast(context.?)); // aegis: boundary(A019): cloak's KeyLog gives back the context `keyLog` registered, a writer
    // A capture that cannot be written is the caller's to notice; it must not fail the handshake it describes.
    writer.writeAll(line) catch return;
}

test "an alert is a refusal of a client certificate when it says so" {
    try std.testing.expect(refusesCertificate(.certificate_required));
    try std.testing.expect(refusesCertificate(.bad_certificate));
    try std.testing.expect(!refusesCertificate(.protocol_version));
}

test "a host is named as the address it is or the name it is" {
    try std.testing.expectEqualSlices(u8, &.{ 127, 0, 0, 1 }, &reference("127.0.0.1").ipv4);
    try std.testing.expectEqual(@as(u8, 1), reference("::1").ipv6[15]);
    try std.testing.expectEqualStrings("example.com", reference("example.com").dns);
}

test "the key log writes the lines it is given" {
    var out: Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    const sink = keyLog(&out.writer);
    sink.write(sink.context, "CLIENT_RANDOM x\n");
    try std.testing.expectEqualStrings("CLIENT_RANDOM x\n", out.written());
}

/// `in` compressed whole by warp, as a server's encoder would.
fn compressed(gpa: Allocator, algorithm: Decoding, in: []const u8) ![]u8 {
    switch (algorithm) {
        .zstd => {
            var c = try warp.zstd.Compressor.init(gpa, .{ .max_input = .fromRaw(in.len) });
            defer c.deinit();
            const out = try gpa.alloc(u8, warp.zstd.Compressor.bound(in.len));
            errdefer gpa.free(out);
            return gpa.realloc(out, try c.compress(in, out, .{}));
        },
        .zlib => {
            var c = try warp.Compressor.init(gpa, .{ .max_input = .fromRaw(in.len) });
            defer c.deinit();
            const out = try gpa.alloc(u8, warp.Compressor.bound(in.len, .{}));
            errdefer gpa.free(out);
            return gpa.realloc(out, try c.compress(in, out, .{}));
        },
    }
}

test "warp's decoders give back a compressed certificate exactly, and refuse any other length" {
    const gpa = std.testing.allocator;
    var certificate: [3000]u8 = undefined;
    for (&certificate, 0..) |*b, i| b.* = @truncate((i *% 7) ^ (i >> 5));
    for ([_]Decoding{ .zstd, .zlib }) |algorithm| {
        const codec = decoder(algorithm, &gpa);
        const packed_bytes = try compressed(gpa, algorithm, &certificate);
        defer gpa.free(packed_bytes);
        var out: [certificate.len]u8 = undefined;
        try codec.decompress.?(codec.context, packed_bytes, &out);
        try std.testing.expectEqualSlices(u8, &certificate, &out);
        // A declared length the stream does not fill, or overruns.
        var short: [certificate.len - 1]u8 = undefined;
        try std.testing.expectError(error.Failed, codec.decompress.?(codec.context, packed_bytes, &short));
        var long: [certificate.len + 1]u8 = undefined;
        try std.testing.expectError(error.Failed, codec.decompress.?(codec.context, packed_bytes, &long));
        // Bytes after the stream, and a stream cut short.
        const trailing = try std.mem.concat(gpa, u8, &.{ packed_bytes, "x" });
        defer gpa.free(trailing);
        try std.testing.expectError(error.Failed, codec.decompress.?(codec.context, trailing, &out));
        try std.testing.expectError(error.Failed, codec.decompress.?(codec.context, packed_bytes[0 .. packed_bytes.len - 1], &out));
    }
}

test "a decoder that cannot allocate its state fails the certificate" {
    const codec = decoder(.zstd, &std.testing.failing_allocator);
    var out: [4]u8 = undefined;
    try std.testing.expectError(error.Failed, codec.decompress.?(codec.context, "abcd", &out));
}
