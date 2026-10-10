//! TLS through the client, proved against `openssl s_server`: the versions,
//! the authorities, client certificates of every kind, certificate time,
//! and TLS inside a proxy's tunnel.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const testing = std.testing;
const test_io = @import("../testing/io.zig");
const shakedown = @import("shakedown");
const Client = @import("Client.zig");
const cloak = @import("cloak");
const Diagnostics = @import("../transport/Diagnostics.zig");
const Proxy = @import("../transport/Proxy.zig");
const openssl = @import("../testing/openssl.zig");
const TestProxy = @import("../testing/Proxy.zig");
const Server = @import("../testing/Server.zig");

/// `GET /` over TLS to `port`: the status page, in `gpa`.
fn fetch(gpa: Allocator, io: Io, client: *Client, port: u16, diagnostics: ?*Diagnostics) ![]u8 {
    var url_buf: [64]u8 = undefined;
    const url = try std.mem.print(&url_buf, "https://127.0.0.1:{d}/", .{port});
    var response = try client.send(io, .{ .url = url, .diagnostics = diagnostics });
    defer response.deinit(io);
    return response.collect(gpa, io, .limited(1 << 20));
}

/// The authority in the test PKI's file `name`, as a snapshot a client takes.
fn trusting(io: Io, pki: *openssl.Pki, name: []const u8) !cloak.Trust.Snapshot {
    const pem = try pki.read(io, name);
    defer pki.gpa.free(pem);
    var builder: cloak.Trust = .init(pki.gpa);
    defer builder.deinit();
    try builder.addPem(pem, .{});
    return builder.freeze();
}

test "a server is checked against the authorities given" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const pki = try openssl.Pki.make(gpa, io);
    defer pki.destroy();
    const trust = try trusting(io, pki, "server.pem");
    defer trust.deinit();
    var server = try openssl.SServer.start(gpa, io, pki, .{ .version = "-tls1_3" });
    defer server.stop(io);
    var client: Client = .init(gpa, .{ .tls = .{ .trust = trust } });
    defer client.deinit(io);
    const page = try fetch(gpa, io, &client, server.port, null);
    defer gpa.free(page);
    try testing.expect(std.mem.find(u8, page, "TLSv1.3") != null);

    // An authority that did not sign the server's certificate.
    const stranger = try trusting(io, pki, "stranger.pem");
    defer stranger.deinit();
    var refusing: Client = .init(gpa, .{ .tls = .{ .trust = stranger } });
    defer refusing.deinit(io);
    var diagnostics: Diagnostics = .{};
    try testing.expectError(error.TlsFailed, fetch(gpa, io, &refusing, server.port, &diagnostics));
    try testing.expectEqual(Diagnostics.Stage.tls, diagnostics.stage);
    try testing.expectEqual(error.VerificationRejected, diagnostics.tls_error.?);
    try testing.expectEqual(cloak.tls.Alert.unknown_ca, diagnostics.tls_alert.?);

    // Checking nothing, anything is taken.
    var trusting_all: Client = .init(gpa, .{ .tls = .{ .verify = .none } });
    defer trusting_all.deinit(io);
    const any = try fetch(gpa, io, &trusting_all, server.port, null);
    gpa.free(any);
}

test "a server that speaks only TLS 1.2 is refused, and the alert says why" {
    // cloak speaks TLS 1.3; TLS 1.2 comes with its C4. Until then a server
    // that does not also speak 1.3 is turned away by name.
    const gpa = testing.allocator;
    const io = test_io.io();
    const pki = try openssl.Pki.make(gpa, io);
    defer pki.destroy();
    var server = try openssl.SServer.start(gpa, io, pki, .{ .version = "-tls1_2" });
    defer server.stop(io);
    var client: Client = .init(gpa, .{ .tls = .{ .verify = .none } });
    defer client.deinit(io);
    var diagnostics: Diagnostics = .{};
    try testing.expectError(error.TlsFailed, fetch(gpa, io, &client, server.port, &diagnostics));
    try testing.expectEqual(Diagnostics.Stage.tls, diagnostics.stage);
    try testing.expectEqual(cloak.tls.Alert.protocol_version, diagnostics.tls_alert.?);
}

/// How `openssl s_server -www` says the client signed: the scheme's name
/// from OpenSSL 3.2 on, and a type and a digest before it.
const SignedWith = struct {
    scheme: []const u8,
    type: []const u8,
    digest: ?[]const u8,

    fn of(kind: []const u8) SignedWith {
        if (std.mem.eql(u8, kind, "rsa")) return .{ .scheme = "rsa_pss_rsae_sha256", .type = "RSA-PSS", .digest = "SHA256" };
        if (std.mem.eql(u8, kind, "p256")) return .{ .scheme = "ecdsa_secp256r1_sha256", .type = "ECDSA", .digest = "SHA256" };
        if (std.mem.eql(u8, kind, "p384")) return .{ .scheme = "ecdsa_secp384r1_sha384", .type = "ECDSA", .digest = "SHA384" };
        return .{ .scheme = "ed25519", .type = "Ed25519", .digest = null };
    }

    fn on(s: SignedWith, page: []const u8) bool {
        if (hasLine(page, "Peer signature type: ", s.scheme)) return true;
        if (!hasLine(page, "Peer signature type: ", s.type)) return false;
        const digest = s.digest orelse return true;
        return hasLine(page, "Peer signing digest: ", digest);
    }

    fn hasLine(page: []const u8, label: []const u8, value: []const u8) bool {
        var lines = std.mem.splitScalar(u8, page, '\n');
        while (lines.next()) |line| {
            const rest = std.mem.trimEnd(u8, line, "\r");
            if (std.mem.startsWith(u8, rest, label) and std.mem.eql(u8, rest[label.len..], value)) return true;
        }
        return false;
    }
};

/// A client certificate and key from the test authority's files.
fn loadAuth(gpa: Allocator, io: Io, pki: *openssl.Pki, cert_name: []const u8, key_name: []const u8, pass: ?[]const u8) !cloak.ClientAuth {
    const cert_pem = try pki.read(io, cert_name);
    defer gpa.free(cert_pem);
    const key_pem = try pki.read(io, key_name);
    defer gpa.free(key_pem);
    const key = try cloak.PrivateKey.parse(gpa, key_pem, .{ .passphrase = pass, .entropy = cloak.PrivateKey.Entropy.fromIo(&io) });
    defer key.deinit();
    return cloak.ClientAuth.initPem(gpa, cert_pem, key, .{});
}

test "a server's demand for a client certificate is answered with ECDSA and Ed25519 keys, plain and encrypted" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const pki = try openssl.Pki.make(gpa, io);
    defer pki.destroy();
    const trust = try trusting(io, pki, "server.pem");
    defer trust.deinit();
    var server = try openssl.SServer.start(gpa, io, pki, .{ .version = "-tls1_3", .verify_client = true });
    defer server.stop(io);
    for (openssl.kinds) |kind| for ([_]bool{ false, true }) |encrypted| {
        var arena_state: std.heap.ArenaAllocator = .init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const key_name = try arena.print("{s}.{s}", .{ kind, if (encrypted) "enc.key" else "key" });
        const auth = try loadAuth(gpa, io, pki, try arena.print("{s}.pem", .{kind}), key_name, if (encrypted) openssl.passphrase else null);
        defer auth.deinit();
        var client: Client = .init(gpa, .{ .tls = .{ .trust = trust, .client_auth = auth } });
        defer client.deinit(io);
        if (std.mem.eql(u8, kind, "rsa")) {
            // cloak parses an RSA key but signs only with ECDSA and Ed25519
            // until RSA-PSS signing comes with TLS 1.2.
            var diagnostics: Diagnostics = .{};
            try testing.expectError(error.ClientCertificateSchemeUnsupported, fetch(gpa, io, &client, server.port, &diagnostics));
            continue;
        }
        const page = try fetch(gpa, io, &client, server.port, null);
        defer gpa.free(page);
        try testing.expect(SignedWith.of(kind).on(page));
        try testing.expect(std.mem.find(u8, page, "Verify return code: 0 (ok)") != null);
    };
    // No certificate, and one from an authority the server does not
    // trust, are refused, and named for what they are.
    var bare: Client = .init(gpa, .{ .tls = .{ .trust = trust } });
    defer bare.deinit(io);
    try testing.expectError(error.ClientCertificateRejected, fetch(gpa, io, &bare, server.port, null));
    const stranger = try loadAuth(gpa, io, pki, "p256.stranger.pem", "p256.key", null);
    defer stranger.deinit();
    var refused: Client = .init(gpa, .{ .tls = .{ .trust = trust, .client_auth = stranger } });
    defer refused.deinit(io);
    var diagnostics: Diagnostics = .{};
    try testing.expectError(error.ClientCertificateRejected, fetch(gpa, io, &refused, server.port, &diagnostics));
    try testing.expect(diagnostics.tls_error != null);
}

test "each handshake checks the server's certificate at the time it is made" {
    const gpa = testing.allocator;
    const pki = try openssl.Pki.make(gpa, test_io.io());
    defer pki.destroy();
    var server = try openssl.SServer.start(gpa, test_io.io(), pki, .{});
    defer server.stop(test_io.io());
    var clock: shakedown.Clock = .init(test_io.io(), .{ .real = Io.Clock.real.now(test_io.io()) });
    const io = clock.io();
    const trust = try trusting(io, pki, "server.pem");
    defer trust.deinit();
    const pem = try pki.read(io, "server.pem");
    defer gpa.free(pem);
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const der = try firstCertificate(arena_state.allocator(), pem);
    const validity = (try std.crypto.Certificate.parse(.{ .buffer = der, .index = 0 })).validity;
    var client: Client = .init(gpa, .{ .tls = .{ .trust = trust } });
    defer client.deinit(io);
    var diagnostics: Diagnostics = .{};
    // TLS says `certificate_expired` for a certificate that has expired and
    // for one that is not yet valid.
    clock.stepReal(.fromNanoseconds(@as(i96, validity.not_after + 1) * std.time.ns_per_s));
    try testing.expectError(error.TlsFailed, fetch(gpa, io, &client, server.port, &diagnostics));
    try testing.expectEqual(error.VerificationRejected, diagnostics.tls_error.?);
    try testing.expectEqual(cloak.tls.Alert.certificate_expired, diagnostics.tls_alert.?);
    diagnostics = .{};
    clock.stepReal(.fromNanoseconds(@as(i96, validity.not_before - 1) * std.time.ns_per_s));
    try testing.expectError(error.TlsFailed, fetch(gpa, io, &client, server.port, &diagnostics));
    try testing.expectEqual(cloak.tls.Alert.certificate_expired, diagnostics.tls_alert.?);
    clock.stepReal(.fromNanoseconds(@as(i96, validity.not_before + 1) * std.time.ns_per_s));
    const page = try fetch(gpa, io, &client, server.port, null);
    gpa.free(page);
}

/// The first certificate of a PEM file, as DER.
fn firstCertificate(arena: Allocator, pem: []const u8) ![]u8 {
    const begin = "-----BEGIN CERTIFICATE-----";
    const end = "-----END CERTIFICATE-----";
    const start = (std.mem.find(u8, pem, begin) orelse return error.TestUnexpectedResult) + begin.len;
    const stop = std.mem.findPos(u8, pem, start, end) orelse return error.TestUnexpectedResult;
    var base64: std.ArrayList(u8) = .empty;
    for (pem[start..stop]) |c| if (!std.ascii.isWhitespace(c)) try base64.append(arena, c);
    const der = try arena.alloc(u8, try std.base64.standard.Decoder.calcSizeForSlice(base64.items));
    try std.base64.standard.Decoder.decode(der, base64.items);
    return der;
}

test "TLS to the server runs inside a CONNECT tunnel and inside SOCKS" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const pki = try openssl.Pki.make(gpa, io);
    defer pki.destroy();
    var server = try openssl.SServer.start(gpa, io, pki, .{});
    defer server.stop(io);
    const trust = try trusting(io, pki, "server.pem");
    defer trust.deinit();
    for ([_]TestProxy.Kind{ .http, .socks }) |kind| {
        const proxy = try TestProxy.start(gpa, io, .{ .kind = kind, .credential = "user:secret" });
        defer proxy.stop();
        var proxy_url_buf: [96]u8 = undefined;
        var arena_state: std.heap.ArenaAllocator = .init(gpa);
        defer arena_state.deinit();
        const proxy_url = try std.mem.print(&proxy_url_buf, "{s}://user:secret@127.0.0.1:{d}", .{ if (kind == .http) "http" else "socks5h", proxy.port });
        var client: Client = .init(gpa, .{
            .tls = .{ .trust = trust },
            .proxy = .{ .fixed = try Proxy.parse(arena_state.allocator(), proxy_url, .lowercase) },
        });
        defer client.deinit(io);
        const page = try fetch(gpa, io, &client, server.port, null);
        defer gpa.free(page);
        try testing.expect(std.mem.find(u8, page, "Protocol") != null);
        const log = try proxy.lines(gpa);
        defer gpa.free(log);
        try testing.expect(std.mem.find(u8, log, "127.0.0.1:") != null);
    }
}

test "a handshake that does not come is given up on at the handshake timeout" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const server = try Server.start(gpa, io, Server.fixedAnswer(.{ .silent = true }));
    defer server.stop();
    var client: Client = .init(gpa, .{ .tls = .{ .verify = .none }, .timeouts = .{ .handshake = .fromMilliseconds(100) } });
    defer client.deinit(io);
    var diagnostics: Diagnostics = .{};
    try testing.expectError(error.TimedOut, fetch(gpa, io, &client, server.port, &diagnostics));
    try testing.expectEqual(Diagnostics.Timeout.handshake, diagnostics.timeout.?);
    try testing.expectEqual(Diagnostics.Stage.tls, diagnostics.stage);
    try testing.expectEqual(@as(u32, 0), client.stats().idle);
}

test "a session's secrets go to the key log the client was given, and nowhere else" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const pki = try openssl.Pki.make(gpa, io);
    defer pki.destroy();
    var server = try openssl.SServer.start(gpa, io, pki, .{ .version = "-tls1_3" });
    defer server.stop(io);
    var log: Io.Writer.Allocating = .init(gpa);
    defer log.deinit();
    var client: Client = .init(gpa, .{ .tls = .{ .verify = .none, .key_log = &log.writer } });
    defer client.deinit(io);
    const page = try fetch(gpa, io, &client, server.port, null);
    gpa.free(page);
    try testing.expect(std.mem.find(u8, log.written(), "CLIENT_HANDSHAKE_TRAFFIC_SECRET ") != null);
    try testing.expect(std.mem.find(u8, log.written(), "CLIENT_TRAFFIC_SECRET_0 ") != null);
}
