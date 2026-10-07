//! One TLS client session over a byte stream: the handshake, then the
//! decrypted reader and the encrypting writer. Every TLS layer a connection
//! stacks is one of these, so the client underneath can change — the
//! standard library's fork today, uplink's own engine later — without the
//! connection above it changing.
//!
//! A session must not move once `start` has been called: the client keeps
//! pointers into it.

const std = @import("std");
const Io = std.Io;
const tls = std.crypto.tls;
const Client = @import("Client.zig");
const ClientAuth = @import("ClientAuth.zig");
const Trust = @import("Trust.zig");

const Session = @This();

/// Private: the TLS client.
client: Client = undefined,
/// Whether the server asked for a client certificate.
certificate_requested: bool = false,
/// The alert that ended the handshake, when one did.
handshake_alert: ?tls.Alert = null,
/// Private: the key log's state, when there is a key log.
key_log: Client.SslKeyLog = undefined,

/// The smallest buffers `start` takes: one whole TLS record.
pub const min_buffer_len = Client.min_buffer_len;

/// How a session checks and answers its server.
pub const Options = struct {
    /// The server's name, checked against its certificate when verifying.
    host: []const u8,
    /// The authorities the server's certificate must chain to; null checks
    /// neither the chain nor the name.
    trust: ?*Trust,
    /// The certificate and key a server that asks for one is answered
    /// with; without one, the server is sent none and decides.
    client_auth: ?*const ClientAuth = null,
    /// Where the session's secrets are written in the NSS key log format,
    /// for a packet capture to be decrypted with.
    key_log: ?*Io.Writer = null,
};

/// Errors from `start`.
pub const StartError = Client.InitError;

/// Run the handshake over `input` and `output`, which must stay where they
/// are while the session lives. `read_buffer` and `write_buffer` hold at
/// least `min_buffer_len` bytes each and are the session's until it ends.
pub fn start(s: *Session, io: Io, input: *Io.Reader, output: *Io.Writer, read_buffer: []u8, write_buffer: []u8, options: Options) StartError!void {
    s.* = .{};
    var entropy: [Client.Options.entropy_len]u8 = undefined;
    io.random(&entropy);
    var alert: tls.Alert = .{ .level = .fatal, .description = .close_notify };
    if (options.key_log) |w| s.key_log = .{ .client_key_seq = 0, .server_key_seq = 0, .client_random = undefined, .writer = w };
    s.client = Client.init(input, output, .{
        .host = if (options.trust != null) .{ .explicit = options.host } else .no_verification,
        .ca = if (options.trust) |t| .{ .bundle = .{
            .gpa = t.gpa,
            .io = io,
            .lock = &t.lock,
            .bundle = &t.bundle,
        } } else .no_verification,
        .read_buffer = read_buffer,
        .write_buffer = write_buffer,
        .entropy = &entropy,
        .realtime_now = Io.Clock.real.now(io),
        // HTTP says where a body ends, so an end without close_notify is
        // not a truncation it cannot see.
        .allow_truncation_attacks = true,
        .ssl_key_log = if (options.key_log != null) &s.key_log else null,
        .client_auth = options.client_auth,
        .certificate_requested = &s.certificate_requested,
        .alert = &alert,
    }) catch |err| {
        if (err == error.TlsAlert) s.handshake_alert = alert;
        return err;
    };
}

/// The decrypted bytes from the server.
pub fn reader(s: *Session) *Io.Reader {
    return &s.client.reader;
}

/// The bytes to the server, encrypted when flushed.
pub fn writer(s: *Session) *Io.Writer {
    return &s.client.writer;
}

/// Send close_notify into the output, which the caller then flushes.
pub fn end(s: *Session) Io.Writer.Error!void {
    return s.client.end();
}

/// Why the last read failed, when TLS failed it.
pub fn readError(s: *const Session) ?Client.ReadError {
    return s.client.read_err;
}

/// The alert the server sent, when a read failed on one.
pub fn readAlert(s: *const Session) ?tls.Alert {
    return s.client.alert;
}

/// A TLS alert's description as an error: `TlsAlertBadCertificate` and the
/// like.
pub fn alertError(description: tls.Alert.Description) anyerror {
    if (description.toError()) |_| return error.TlsAlert else |err| return err;
}

/// Whether an alert is a server's refusal of a client certificate — or of
/// none — once it has asked for one. OpenSSL answers a missing one in TLS
/// 1.2 with `handshake_failure`.
pub fn refusesCertificate(description: tls.Alert.Description) bool {
    return switch (description) {
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

test "an alert is named, and a certificate refusal told from other alerts" {
    try std.testing.expectEqual(error.TlsAlertBadCertificate, alertError(.bad_certificate));
    try std.testing.expect(refusesCertificate(.certificate_required));
    try std.testing.expect(!refusesCertificate(.protocol_version));
}
