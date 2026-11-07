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
const serving = struct {
    const Server = @import("../server/Server.zig");
    const Request = @import("../server/Request.zig");
    const Response = @import("../server/Response.zig");
};

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

test "a server that speaks only TLS 1.2 is answered in TLS 1.2" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const pki = try openssl.Pki.make(gpa, io);
    defer pki.destroy();
    var server = try openssl.SServer.start(gpa, io, pki, .{ .version = "-tls1_2" });
    defer server.stop(io);
    var client: Client = .init(gpa, .{ .tls = .{ .verify = .none } });
    defer client.deinit(io);
    const page = try fetch(gpa, io, &client, server.port, null);
    defer gpa.free(page);
    try testing.expect(std.mem.find(u8, page, "TLSv1.2") != null);
}

test "a server is held to the lowest version and to a pinned key, as curl holds it for git" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const pki = try openssl.Pki.make(gpa, io);
    defer pki.destroy();
    const trust = try trusting(io, pki, "server.pem");
    defer trust.deinit();
    var old = try openssl.SServer.start(gpa, io, pki, .{ .version = "-tls1_2" });
    defer old.stop(io);
    var tls13_only: Client = .init(gpa, .{ .tls = .{ .trust = trust, .min_version = .tls13 } });
    defer tls13_only.deinit(io);
    var diagnostics: Diagnostics = .{};
    try testing.expectError(error.TlsFailed, fetch(gpa, io, &tls13_only, old.port, &diagnostics));

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const pem = try pki.read(io, "server.pem");
    defer gpa.free(pem);
    const cert = try cloak.certificates.certificate.parse(try firstCertificate(arena_state.allocator(), pem), .{});
    var pin: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(cert.spki, &pin, .{});
    var server = try openssl.SServer.start(gpa, io, pki, .{ .version = "-tls1_3" });
    defer server.stop(io);
    var pinned: Client = .init(gpa, .{ .tls = .{ .trust = trust, .pins = &.{ @splat(0), pin } } });
    defer pinned.deinit(io);
    const page = try fetch(gpa, io, &pinned, server.port, null);
    gpa.free(page);

    var other: Client = .init(gpa, .{ .tls = .{ .trust = trust, .pins = &.{@splat(0)} } });
    defer other.deinit(io);
    try testing.expectError(error.TlsFailed, fetch(gpa, io, &other, server.port, &diagnostics));
    try testing.expectEqual(error.VerificationRejected, diagnostics.tls_error.?);
    try testing.expectEqual(error.PinMismatch, diagnostics.tls_verification.?);

    // With nothing else checked the leaf's key is checked against the pins
    // alone (git's `http.pinnedPubkey` under `http.sslVerify=false`).
    var leaf: Client = .init(gpa, .{ .tls = .{ .verify = .none, .pins = &.{ @splat(0), pin } } });
    defer leaf.deinit(io);
    const unverified = try fetch(gpa, io, &leaf, server.port, null);
    gpa.free(unverified);
    var mismatched: Client = .init(gpa, .{ .tls = .{ .verify = .none, .pins = &.{@splat(0)} } });
    defer mismatched.deinit(io);
    try testing.expectError(error.TlsFailed, fetch(gpa, io, &mismatched, server.port, &diagnostics));
    try testing.expectEqual(error.PinMismatch, diagnostics.tls_error.?);
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
    const key = try cloak.PrivateKey.parse(gpa, key_pem, .{ .passphrase = pass });
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

/// A proxy that speaks HTTP/2: each `CONNECT` is answered by connecting to its
/// authority and passing bytes both ways until either end ends.
const H2Proxy = struct {
    /// The `CONNECT`s it was asked, and the `proxy-authorization` it was shown.
    connects: std.atomic.Value(u32) = .init(0),
    authorized: std.atomic.Value(u32) = .init(0),
    require: ?[]const u8 = null,
    handler: serving.Server.Handler = .{ .handleFn = handle },

    fn handle(handler: *serving.Server.Handler, io: Io, request: *serving.Request, response: *serving.Response) anyerror!void {
        const p: *H2Proxy = @alignCast(@fieldParentPtr("handler", handler));
        if (!request.method.eql(.CONNECT)) {
            response.status = .method_not_allowed;
            return response.end(io);
        }
        _ = p.connects.fetchAdd(1, .monotonic);
        if (p.require) |want| {
            const shown = request.headers.get("proxy-authorization") orelse "";
            if (!std.mem.eql(u8, shown, want)) {
                response.status = .proxy_auth_required;
                try response.header("Proxy-Authenticate", "Basic realm=\"tunnel\"");
                return response.end(io);
            }
            _ = p.authorized.fetchAdd(1, .monotonic);
        }
        const colon = std.mem.findScalarLast(u8, request.target, ':').?;
        const port = try std.fmt.parseInt(u16, request.target[colon + 1 ..], 10);
        const address = try Io.net.IpAddress.parse(request.target[0..colon], port);
        const stream = try address.connect(io, .{ .mode = .stream });
        defer stream.close(io);
        var taken = try response.hijack(io);
        var up: Io.Future(void) = try io.concurrent(pass, .{ io, taken.reader, stream });
        defer up.cancel(io);
        var from_buffer: [16 << 10]u8 = undefined;
        var from = stream.reader(io, &from_buffer);
        while (true) {
            const n = from.interface.stream(taken.writer, .unlimited) catch break;
            if (n == 0) continue;
            taken.flush() catch break;
        }
    }

    fn pass(io: Io, from: *Io.Reader, stream: Io.net.Stream) void {
        var to_buffer: [16 << 10]u8 = undefined;
        var to = stream.writer(io, &to_buffer);
        while (true) {
            _ = from.stream(&to.interface, .unlimited) catch return;
            to.interface.flush() catch return;
        }
    }

    const Running = struct {
        server: serving.Server,
        listener: Io.net.Server,
        task: Io.Future(serving.Server.ServeError!void),
        port: u16,

        fn start(gpa: Allocator, io: Io, p: *H2Proxy, r: *Running) !void {
            return r.startOn(gpa, io, .{ .h2c = .only }, &p.handler);
        }

        fn startOn(r: *Running, gpa: Allocator, io: Io, options: serving.Server.Options, handler: *serving.Server.Handler) !void {
            r.listener = try (try Io.net.IpAddress.parse("127.0.0.1", 0)).listen(io, .{ .reuse_address = true });
            r.port = r.listener.socket.address.getPort();
            r.server = .init(gpa, options, handler);
            r.task = io.concurrent(serving.Server.serve, .{ &r.server, io, &r.listener }) catch return error.SkipZigTest;
        }

        fn stop(r: *Running, io: Io) void {
            r.server.shutdown(io);
            r.task.await(io) catch |err| std.debug.print("the proxy's serve ended with {t}\n", .{err});
            r.server.deinit(io);
            r.listener.deinit(io);
        }
    };
};

fn throughH2Proxy(gpa: Allocator, io: Io, proxy_url: []const u8, trust: cloak.Trust.Snapshot, target_port: u16, diagnostics: ?*Diagnostics) ![]u8 {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var proxy = try Proxy.parse(arena_state.allocator(), proxy_url, .lowercase);
    proxy.http2 = true;
    var client: Client = .init(gpa, .{ .tls = .{ .trust = trust }, .proxy = .{ .fixed = proxy } });
    defer client.deinit(io);
    return fetch(gpa, io, &client, target_port, diagnostics);
}

test "TLS to the server runs inside a CONNECT stream of an HTTP/2 proxy" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const pki = try openssl.Pki.make(gpa, io);
    defer pki.destroy();
    var target = try openssl.SServer.start(gpa, io, pki, .{});
    defer target.stop(io);
    const trust = try trusting(io, pki, "server.pem");
    defer trust.deinit();
    var h2_proxy: H2Proxy = .{};
    var running: H2Proxy.Running = undefined;
    try H2Proxy.Running.start(gpa, io, &h2_proxy, &running);
    defer running.stop(io);
    var url_buf: [64]u8 = undefined;
    const url = try std.mem.print(&url_buf, "http://127.0.0.1:{d}", .{running.port});
    const page = try throughH2Proxy(gpa, io, url, trust, target.port, null);
    defer gpa.free(page);
    try testing.expect(std.mem.find(u8, page, "Protocol") != null);
    try testing.expectEqual(@as(u32, 1), h2_proxy.connects.load(.monotonic));
}

test "an HTTP/2 proxy that asks is answered on a new connection, and one that refuses says so" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const pki = try openssl.Pki.make(gpa, io);
    defer pki.destroy();
    var target = try openssl.SServer.start(gpa, io, pki, .{});
    defer target.stop(io);
    const trust = try trusting(io, pki, "server.pem");
    defer trust.deinit();
    var h2_proxy: H2Proxy = .{ .require = "Basic dXNlcjpzZWNyZXQ=" };
    var running: H2Proxy.Running = undefined;
    try H2Proxy.Running.start(gpa, io, &h2_proxy, &running);
    defer running.stop(io);
    var url_buf: [96]u8 = undefined;
    const answered = try std.mem.print(&url_buf, "http://user:secret@127.0.0.1:{d}", .{running.port});
    const page = try throughH2Proxy(gpa, io, answered, trust, target.port, null);
    defer gpa.free(page);
    try testing.expectEqual(@as(u32, 1), h2_proxy.authorized.load(.monotonic));
    // No credential to answer with: the proxy's 407 is the failure.
    var bare_buf: [64]u8 = undefined;
    const bare = try std.mem.print(&bare_buf, "http://127.0.0.1:{d}", .{running.port});
    var diagnostics: Diagnostics = .{};
    try testing.expectError(error.ProxyAuthenticationRequired, throughH2Proxy(gpa, io, bare, trust, target.port, &diagnostics));
    try testing.expectEqual(@as(?u16, 407), diagnostics.proxy_status);
}

test "a proxy named http2 that does not speak it fails, and is not asked again over HTTP/1.1" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const pki = try openssl.Pki.make(gpa, io);
    defer pki.destroy();
    const trust = try trusting(io, pki, "server.pem");
    defer trust.deinit();
    // An HTTP/1.1 proxy given HTTP/2's preface: it never answers a CONNECT.
    const http1 = try TestProxy.start(gpa, io, .{});
    defer http1.stop();
    var url_buf: [64]u8 = undefined;
    const url = try std.mem.print(&url_buf, "http://127.0.0.1:{d}", .{http1.port});
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var proxy = try Proxy.parse(arena_state.allocator(), url, .lowercase);
    proxy.http2 = true;
    var client: Client = .init(gpa, .{
        .tls = .{ .trust = trust },
        .proxy = .{ .fixed = proxy },
        .timeouts = .{ .handshake = .literal("500ms") },
    });
    defer client.deinit(io);
    var page_url_buf: [64]u8 = undefined;
    const page_url = try std.mem.print(&page_url_buf, "https://127.0.0.1:{d}/", .{http1.port});
    if (client.send(io, .{ .url = page_url })) |response| {
        var unexpected = response;
        unexpected.deinit(io);
        return error.TestUnexpectedResult;
    } else |_| {}
    const log = try http1.lines(gpa);
    defer gpa.free(log);
    try testing.expectEqual(@as(?usize, null), std.mem.find(u8, log, "CONNECT"));
}

fn echoBody(io: Io, request: *serving.Request, response: *serving.Response) anyerror!void {
    const body = try request.collect(testing.allocator, io, .limited(4 << 20));
    defer testing.allocator.free(body);
    const w = try response.writer(io);
    try w.writeAll(body);
    try response.end(io);
}

test "an https HTTP/2 proxy carries a body past the flow-control windows, both ways" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const pki = try openssl.Pki.make(gpa, io);
    defer pki.destroy();
    const cert = try pki.read(io, "server-ec.pem");
    defer gpa.free(cert);
    const key_pem = try pki.read(io, "server-ec.key");
    defer gpa.free(key_pem);
    const key = try cloak.PrivateKey.parse(gpa, key_pem, .{});
    defer key.deinit();
    var identity = try cloak.Identity.initPem(gpa, cert, key, .{});
    defer identity.deinit();
    var builder: cloak.Trust = .init(gpa);
    defer builder.deinit();
    try builder.addPem(cert, .{});
    var trust = try builder.freeze();
    defer trust.deinit();
    const credentials = [_]cloak.tls.Credential{.{ .identity = identity }};

    var target: H2Proxy.Running = undefined;
    try target.startOn(gpa, io, .{ .tls = .{ .credentials = &credentials } }, serving.Server.Handler.of(echoBody));
    defer target.stop(io);
    var h2_proxy: H2Proxy = .{};
    var proxying: H2Proxy.Running = undefined;
    try proxying.startOn(gpa, io, .{ .tls = .{ .credentials = &credentials } }, &h2_proxy.handler);
    defer proxying.stop(io);

    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    var proxy_url_buf: [64]u8 = undefined;
    var proxy = try Proxy.parse(arena_state.allocator(), try std.mem.print(&proxy_url_buf, "https://127.0.0.1:{d}", .{proxying.port}), .lowercase);
    proxy.http2 = true;
    var client: Client = .init(gpa, .{ .tls = .{ .trust = trust }, .proxy = .{ .fixed = proxy } });
    defer client.deinit(io);

    const sent = try gpa.alloc(u8, 1 << 20);
    defer gpa.free(sent);
    for (sent, 0..) |*b, i| b.* = @truncate(i *% 31);
    var url_buf: [64]u8 = undefined;
    const url = try std.mem.print(&url_buf, "https://127.0.0.1:{d}/", .{target.port});
    // A second round reuses the tunnel the first left in the pool.
    for (0..2) |_| {
        var response = try client.send(io, .{ .url = url, .method = .POST, .body = .{ .bytes = sent } });
        defer response.deinit(io);
        const back = try response.collect(gpa, io, .limited(2 << 20));
        defer gpa.free(back);
        try testing.expectEqualSlices(u8, sent, back);
    }
    try testing.expectEqual(@as(u32, 1), h2_proxy.connects.load(.monotonic));
}

test "an https proxy named http2 that does not agree h2 by ALPN is refused by name" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const pki = try openssl.Pki.make(gpa, io);
    defer pki.destroy();
    // `openssl s_server` given no `-alpn` agrees nothing.
    var no_alpn = try openssl.SServer.start(gpa, io, pki, .{});
    defer no_alpn.stop(io);
    const trust = try trusting(io, pki, "server.pem");
    defer trust.deinit();
    var url_buf: [64]u8 = undefined;
    const url = try std.mem.print(&url_buf, "https://127.0.0.1:{d}", .{no_alpn.port});
    try testing.expectError(error.ProxyProtocolError, throughH2Proxy(gpa, io, url, trust, no_alpn.port, null));
}

test "a handshake that does not come is given up on at the handshake timeout" {
    const gpa = testing.allocator;
    const io = test_io.io();
    const server = try Server.start(gpa, io, Server.fixedAnswer(.{ .silent = true }));
    defer server.stop();
    var client: Client = .init(gpa, .{ .tls = .{ .verify = .none }, .timeouts = .{ .handshake = .literal("100ms") } });
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
