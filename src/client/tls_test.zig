//! TLS through the client, proved against `openssl s_server`: the versions,
//! the authorities, client certificates of every kind, certificate time,
//! and TLS inside a proxy's tunnel.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const testing = std.testing;
const shakedown = @import("shakedown");
const Client = @import("Client.zig");
const tls = @import("../tls.zig");
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

fn trustServer(io: Io, pki: *openssl.Pki, trust: *tls.Trust) !void {
    const pem = try pki.read(io, "server.pem");
    defer pki.gpa.free(pem);
    try trust.addPem(io, pem);
}

test "a server is checked against the authorities given, in TLS 1.3 and 1.2" {
    const gpa = testing.allocator;
    const io = testing.io;
    const pki = try openssl.Pki.make(gpa, io);
    defer pki.destroy();
    var trust: tls.Trust = .init(gpa);
    defer trust.deinit();
    try trustServer(io, pki, &trust);
    for ([_][]const u8{ "-tls1_3", "-tls1_2" }) |version| {
        var server = try openssl.SServer.start(gpa, io, pki, .{ .version = version });
        defer server.stop(io);
        var client: Client = .init(gpa, .{ .tls = .{ .trust = &trust } });
        defer client.deinit(io);
        const page = try fetch(gpa, io, &client, server.port, null);
        defer gpa.free(page);
        const protocol = if (std.mem.eql(u8, version, "-tls1_3")) "TLSv1.3" else "TLSv1.2";
        try testing.expect(std.mem.find(u8, page, protocol) != null);

        // An authority that did not sign the server's certificate.
        var stranger: tls.Trust = .init(gpa);
        defer stranger.deinit();
        const pem = try pki.read(io, "stranger.pem");
        defer gpa.free(pem);
        try stranger.addPem(io, pem);
        var refusing: Client = .init(gpa, .{ .tls = .{ .trust = &stranger } });
        defer refusing.deinit(io);
        var diagnostics: Diagnostics = .{};
        try testing.expectError(error.TlsFailed, fetch(gpa, io, &refusing, server.port, &diagnostics));
        try testing.expectEqual(Diagnostics.Stage.tls, diagnostics.stage);
        try testing.expect(diagnostics.tls_error != null);

        // Checking nothing, anything is taken.
        var trusting: Client = .init(gpa, .{ .tls = .{ .verify = .none } });
        defer trusting.deinit(io);
        const any = try fetch(gpa, io, &trusting, server.port, null);
        gpa.free(any);
    }
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
fn loadAuth(gpa: Allocator, arena: Allocator, io: Io, pki: *openssl.Pki, cert_name: []const u8, key_name: []const u8, pass: ?[]const u8) !tls.ClientAuth {
    const cert_pem = try pki.read(io, cert_name);
    defer gpa.free(cert_pem);
    const key_pem = try pki.read(io, key_name);
    defer gpa.free(key_pem);
    const chain = try tls.key.certificates(arena, cert_pem);
    const key = try tls.PrivateKey.parse(arena, key_pem, pass);
    return tls.ClientAuth.init(gpa, chain, key);
}

test "a server's demand for a client certificate is answered in TLS 1.3 and 1.2, with RSA, ECDSA and Ed25519 keys, plain and encrypted" {
    const gpa = testing.allocator;
    const io = testing.io;
    const pki = try openssl.Pki.make(gpa, io);
    defer pki.destroy();
    var trust: tls.Trust = .init(gpa);
    defer trust.deinit();
    try trustServer(io, pki, &trust);
    for ([_][]const u8{ "-tls1_3", "-tls1_2" }) |version| {
        var server = try openssl.SServer.start(gpa, io, pki, .{ .version = version, .verify_client = true });
        defer server.stop(io);
        for (openssl.kinds) |kind| for ([_]bool{ false, true }) |encrypted| {
            var arena_state: std.heap.ArenaAllocator = .init(gpa);
            defer arena_state.deinit();
            const arena = arena_state.allocator();
            const key_name = try arena.print("{s}.{s}", .{ kind, if (encrypted) "enc.key" else "key" });
            var auth = try loadAuth(gpa, arena, io, pki, try arena.print("{s}.pem", .{kind}), key_name, if (encrypted) openssl.passphrase else null);
            defer auth.deinit();
            var client: Client = .init(gpa, .{ .tls = .{ .trust = &trust, .client_auth = &auth } });
            defer client.deinit(io);
            const page = try fetch(gpa, io, &client, server.port, null);
            defer gpa.free(page);
            try testing.expect(SignedWith.of(kind).on(page));
            try testing.expect(std.mem.find(u8, page, "Verify return code: 0 (ok)") != null);
        };
        // No certificate, and one from an authority the server does not
        // trust, are refused, and named for what they are.
        var bare: Client = .init(gpa, .{ .tls = .{ .trust = &trust } });
        defer bare.deinit(io);
        try testing.expectError(error.ClientCertificateRejected, fetch(gpa, io, &bare, server.port, null));
        var arena_state: std.heap.ArenaAllocator = .init(gpa);
        defer arena_state.deinit();
        var stranger = try loadAuth(gpa, arena_state.allocator(), io, pki, "p256.stranger.pem", "p256.key", null);
        defer stranger.deinit();
        var refused: Client = .init(gpa, .{ .tls = .{ .trust = &trust, .client_auth = &stranger } });
        defer refused.deinit(io);
        var diagnostics: Diagnostics = .{};
        try testing.expectError(error.ClientCertificateRejected, fetch(gpa, io, &refused, server.port, &diagnostics));
        try testing.expect(diagnostics.tls_error != null);
    }
}

test "each handshake checks the server's certificate at the time it is made" {
    const gpa = testing.allocator;
    const pki = try openssl.Pki.make(gpa, testing.io);
    defer pki.destroy();
    var server = try openssl.SServer.start(gpa, testing.io, pki, .{});
    defer server.stop(testing.io);
    var clock: shakedown.Clock = .init(testing.io, .{ .real = Io.Clock.real.now(testing.io) });
    const io = clock.io();
    var trust: tls.Trust = .init(gpa);
    defer trust.deinit();
    try trustServer(io, pki, &trust);
    const pem = try pki.read(io, "server.pem");
    defer gpa.free(pem);
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const der = (try tls.key.certificates(arena_state.allocator(), pem))[0];
    const validity = (try std.crypto.Certificate.parse(.{ .buffer = der, .index = 0 })).validity;
    var client: Client = .init(gpa, .{ .tls = .{ .trust = &trust } });
    defer client.deinit(io);
    var diagnostics: Diagnostics = .{};
    clock.stepReal(.fromNanoseconds(@as(i96, validity.not_after + 1) * std.time.ns_per_s));
    try testing.expectError(error.TlsFailed, fetch(gpa, io, &client, server.port, &diagnostics));
    try testing.expectEqual(error.CertificateExpired, diagnostics.tls_error.?);
    clock.stepReal(.fromNanoseconds(@as(i96, validity.not_before - 1) * std.time.ns_per_s));
    try testing.expectError(error.TlsFailed, fetch(gpa, io, &client, server.port, &diagnostics));
    try testing.expectEqual(error.CertificateNotYetValid, diagnostics.tls_error.?);
    clock.stepReal(.fromNanoseconds(@as(i96, validity.not_before + 1) * std.time.ns_per_s));
    const page = try fetch(gpa, io, &client, server.port, null);
    gpa.free(page);
}

test "TLS to the server runs inside a CONNECT tunnel and inside SOCKS" {
    const gpa = testing.allocator;
    const io = testing.io;
    const pki = try openssl.Pki.make(gpa, io);
    defer pki.destroy();
    var server = try openssl.SServer.start(gpa, io, pki, .{});
    defer server.stop(io);
    var trust: tls.Trust = .init(gpa);
    defer trust.deinit();
    try trustServer(io, pki, &trust);
    for ([_]TestProxy.Kind{ .http, .socks }) |kind| {
        const proxy = try TestProxy.start(gpa, io, .{ .kind = kind, .credential = "user:secret" });
        defer proxy.stop();
        var proxy_url_buf: [96]u8 = undefined;
        var arena_state: std.heap.ArenaAllocator = .init(gpa);
        defer arena_state.deinit();
        const proxy_url = try std.mem.print(&proxy_url_buf, "{s}://user:secret@127.0.0.1:{d}", .{ if (kind == .http) "http" else "socks5h", proxy.port });
        var client: Client = .init(gpa, .{
            .tls = .{ .trust = &trust },
            .proxy = try Proxy.parse(arena_state.allocator(), proxy_url, .curl),
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
    const io = testing.io;
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
    const io = testing.io;
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
