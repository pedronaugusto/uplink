//! How uplink's connections use TLS. The engine, the authorities and the
//! certificates and keys a client answers with are cloak's; this file is the
//! HTTP side of them: the options a client takes, what an alert says about
//! a client certificate, and the shape of a connection's buffers.

const std = @import("std");
const Io = std.Io;
const cloak = @import("cloak");

/// How a client's TLS connections are made.
pub const ClientOptions = struct {
    /// The authorities servers are checked against, a snapshot the caller
    /// keeps alive for as long as the client uses it; null is the system's,
    /// read once per client at its first verifying handshake.
    trust: ?cloak.Trust.Snapshot = null,
    /// `none` checks neither a server's certificate nor its name.
    verify: Verify = .full,
    /// The certificate and key a server that asks for one is answered with,
    /// which the caller keeps alive for as long as the client uses it. A key
    /// cloak does not sign with yet (RSA) is refused when a handshake starts
    /// with `ClientCertificateSchemeUnsupported`.
    client_auth: ?cloak.ClientAuth = null,
    /// Where every session's secrets are written in the NSS key log format,
    /// for a capture to be decrypted with. Never read from the environment.
    /// Every session writes to it; when connections run on several tasks,
    /// the writer must take writes from several tasks.
    key_log: ?*Io.Writer = null,

    pub const Verify = enum { full, none };
};

/// The buffers a TLS session reads and writes through: one whole TLS record
/// of ciphertext (16 KiB of plaintext, its header, type and tag), which is
/// also what a socket under TLS reads and writes in.
pub const record_buffer_len = 16 * 1024 + 5 + 256;

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
    const writer: *Io.Writer = @ptrCast(@alignCast(context.?)); // safe: `keyLog` is the only way to make this sink, and it passes a writer
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
