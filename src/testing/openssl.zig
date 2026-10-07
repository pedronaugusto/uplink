//! Test-only: certificates made for one test by `openssl`, and
//! `openssl s_server` to prove TLS against. Nothing reads the user's own
//! configuration: OpenSSL runs with a scratch `HOME` and only `PATH` and
//! what Windows needs to start a process.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const Io = std.Io;

/// What every encrypted key opens with.
pub const passphrase = "correct-horse";
/// The kinds of client key: RSA, ECDSA on P-256 and P-384, Ed25519.
pub const kinds = [_][]const u8{ "rsa", "p256", "p384", "ed25519" };

/// Whether the tests must find `openssl` rather than skip: on a hosted CI
/// job, where it is always installed.
fn required() bool {
    const value = std.testing.environ.getAlloc(std.testing.allocator, "GITHUB_ACTIONS") catch return false;
    std.testing.allocator.free(value);
    return true;
}

/// A directory of certificates: an authority for clients and a stranger
/// one, a server certificate for 127.0.0.1, and each kind of client key
/// with its certificate from each authority, plain and encrypted.
pub const Pki = struct {
    gpa: Allocator,
    dir: std.testing.TmpDir,
    base: [:0]u8,
    env: std.process.Environ.Map,

    /// Make them all. `error.SkipZigTest` without `openssl`, except on CI.
    pub fn make(gpa: Allocator, io: Io) !*Pki {
        const p = try gpa.create(Pki);
        errdefer gpa.destroy(p);
        var env = try environ(gpa);
        errdefer env.deinit();
        var dir = std.testing.tmpDir(.{ .iterate = true });
        errdefer dir.cleanup();
        const base = try dir.dir.realPathFileAlloc(io, ".", gpa);
        errdefer gpa.free(base);
        p.* = .{ .gpa = gpa, .dir = dir, .base = base, .env = env };
        try p.env.put("HOME", base);
        try p.openssl(io, &.{ "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "2", "-subj", "/CN=uplink-test-ca" });
        try p.openssl(io, &.{ "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", "stranger.key", "-out", "stranger.pem", "-days", "2", "-subj", "/CN=uplink-test-stranger" });
        try p.openssl(io, &.{ "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "server.key", "-out", "server.pem", "-days", "2", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1,DNS:127.0.0.1,DNS:localhost" });
        for (kinds) |kind| try p.clientKey(io, kind);
        return p;
    }

    fn clientKey(p: *Pki, io: Io, kind: []const u8) !void {
        var arena_state: std.heap.ArenaAllocator = .init(p.gpa);
        defer arena_state.deinit();
        const a = arena_state.allocator();
        const key = try a.print("{s}.key", .{kind});
        const csr = try a.print("{s}.csr", .{kind});
        const algorithm: []const []const u8 = if (std.mem.eql(u8, kind, "rsa"))
            &.{ "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048" }
        else if (std.mem.eql(u8, kind, "p256"))
            &.{ "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256" }
        else if (std.mem.eql(u8, kind, "p384"))
            &.{ "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-384" }
        else
            &.{ "-algorithm", "ED25519" };
        var genpkey: std.ArrayList([]const u8) = .empty;
        try genpkey.append(a, "genpkey");
        try genpkey.appendSlice(a, algorithm);
        try genpkey.appendSlice(a, &.{ "-out", key });
        try p.openssl(io, genpkey.items);
        try p.openssl(io, &.{ "req", "-new", "-key", key, "-subj", try a.print("/CN=client-{s}", .{kind}), "-out", csr });
        try p.openssl(io, &.{ "x509", "-req", "-in", csr, "-CA", "ca.pem", "-CAkey", "ca.key", "-set_serial", "7", "-days", "2", "-out", try a.print("{s}.pem", .{kind}) });
        try p.openssl(io, &.{ "x509", "-req", "-in", csr, "-CA", "stranger.pem", "-CAkey", "stranger.key", "-set_serial", "8", "-days", "2", "-out", try a.print("{s}.stranger.pem", .{kind}) });
        try p.openssl(io, &.{ "pkcs8", "-topk8", "-in", key, "-v2", "aes-256-cbc", "-passout", "pass:" ++ passphrase, "-out", try a.print("{s}.enc.key", .{kind}) });
    }

    fn openssl(p: *Pki, io: Io, args: []const []const u8) !void {
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(p.gpa);
        try argv.append(p.gpa, "openssl");
        try argv.appendSlice(p.gpa, args);
        const result = std.process.run(p.gpa, io, .{
            .argv = argv.items,
            .cwd = .{ .dir = p.dir.dir },
            .environ_map = &p.env,
        }) catch |err| {
            if (required()) return err;
            return error.SkipZigTest;
        };
        defer p.gpa.free(result.stdout);
        defer p.gpa.free(result.stderr);
        if (result.term != .exited or result.term.exited != 0) {
            std.debug.print("openssl {s} failed:\n{s}\n", .{ args[0], result.stderr });
            return error.OpensslFailed;
        }
    }

    /// The bytes of `name`, in `gpa`.
    pub fn read(p: *const Pki, io: Io, name: []const u8) ![]u8 {
        return p.dir.dir.readFileAlloc(io, name, p.gpa, .limited(1 << 20));
    }

    pub fn destroy(p: *Pki) void {
        p.env.deinit();
        p.dir.cleanup();
        p.gpa.free(p.base);
        p.gpa.destroy(p);
    }
};

/// `PATH`, with OpenSSL 3's own directory first where a package manager
/// keeps it apart from the system's LibreSSL (macOS), and on Windows what a
/// process needs to start and where Git for Windows keeps its
/// `openssl.exe`.
fn environ(gpa: Allocator) !std.process.Environ.Map {
    var map: std.process.Environ.Map = .init(gpa);
    errdefer map.deinit();
    const path = std.testing.environ.getAlloc(gpa, "PATH") catch return error.SkipZigTest;
    defer gpa.free(path);
    if (builtin.target.os.tag == .windows) {
        const with_git = try std.mem.concat(gpa, u8, &.{ "C:\\Program Files\\Git\\usr\\bin;", path });
        defer gpa.free(with_git);
        try map.put("PATH", with_git);
        for ([_][]const u8{ "SystemRoot", "WINDIR", "TEMP", "TMP" }) |name| {
            const value = std.testing.environ.getAlloc(gpa, name) catch continue;
            defer gpa.free(value);
            try map.put(name, value);
        }
    } else if (builtin.target.os.tag == .macos) {
        const with_brew = try std.mem.concat(gpa, u8, &.{ "/opt/homebrew/opt/openssl@3/bin:/usr/local/opt/openssl@3/bin:", path });
        defer gpa.free(with_brew);
        try map.put("PATH", with_brew);
    } else try map.put("PATH", path);
    return map;
}

/// `openssl s_server` on 127.0.0.1, answering each request with its status
/// page (`-www`): the protocol, the cipher, and the client's certificate.
pub const SServer = struct {
    child: std.process.Child,
    port: u16,

    pub const Options = struct {
        /// `-tls1_3` or `-tls1_2`, or neither.
        version: ?[]const u8 = null,
        /// Require a client certificate from the test authority.
        verify_client: bool = false,
        cert: []const u8 = "server.pem",
        key: []const u8 = "server.key",
    };

    pub fn start(gpa: Allocator, io: Io, pki: *Pki, options: Options) !SServer {
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(gpa);
        try argv.appendSlice(gpa, &.{ "openssl", "s_server", "-accept", "127.0.0.1:0", "-cert", options.cert, "-key", options.key, "-www" });
        if (options.verify_client) try argv.appendSlice(gpa, &.{ "-Verify", "1", "-verify_return_error", "-CAfile", "ca.pem" });
        if (options.version) |v| try argv.append(gpa, v);
        var child = std.process.spawn(io, .{
            .argv = argv.items,
            .cwd = .{ .dir = pki.dir.dir },
            .environ_map = &pki.env,
            .stdin = .ignore,
            .stdout = .pipe,
            .stderr = .ignore,
        }) catch |err| {
            if (required()) return err;
            return error.SkipZigTest;
        };
        errdefer child.kill(io);
        var line_buf: [256]u8 = undefined;
        var reader = child.stdout.?.readerStreaming(io, &line_buf);
        while (true) {
            const line = reader.interface.takeDelimiterExclusive('\n') catch return error.SServerDidNotStart;
            reader.interface.toss(1);
            const prefix = "ACCEPT 127.0.0.1:";
            if (!std.mem.startsWith(u8, line, prefix)) continue;
            const port = std.fmt.parseUnsigned(u16, std.mem.trim(u8, line[prefix.len..], " \r"), 10) catch return error.SServerDidNotStart;
            return .{ .child = child, .port = port };
        }
    }

    pub fn stop(s: *SServer, io: Io) void {
        s.child.kill(io);
    }
};
