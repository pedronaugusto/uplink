//! The certificate authorities a TLS client checks a server against. A
//! `Trust` is meant to be shared: several clients may point at one, so a
//! process reads the system's authorities once, not once per client. It is
//! locked inside; adding while handshakes read it is safe.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Certificate = std.crypto.Certificate;
const key = @import("key.zig");

const Trust = @This();

/// Private: what the certificates' bytes live in.
gpa: Allocator,
// The lock and the bundle are separate fields, not an `aegis.RwGuarded`:
// the TLS client is std's, held byte for byte to std, and takes the lock and
// the bundle it verifies against as two pointers (a boundary with code that
// is not ours to change).
/// Private: held for reading by every verifying handshake, for writing by
/// every `add`.
lock: Io.RwLock = .init,
/// Private: the certificates, as the TLS client reads them.
bundle: Certificate.Bundle = .empty,

/// Errors from the `add` functions.
pub const AddError = error{
    /// The file or directory could not be opened or read.
    CertificateFileUnreadable,
    /// The system's certificate store could not be read.
    CertificateBundleUnreadable,
    /// PEM that is not certificates, or a certificate that does not parse.
    MalformedCertificate,
    OutOfMemory,
    Canceled,
};

/// No authority at all: add some before a verifying handshake uses it.
pub fn init(gpa: Allocator) Trust {
    return .{ .gpa = gpa };
}

pub fn deinit(t: *Trust) void {
    t.bundle.deinit(t.gpa);
    t.* = undefined;
}

/// Add the system's authorities: the macOS keychains, the Windows ROOT
/// store, the bundle files of the Linux distributions and BSDs.
pub fn addSystem(t: *Trust, io: Io) AddError!void {
    var system: Certificate.Bundle = .empty;
    defer system.deinit(t.gpa);
    system.rescan(t.gpa, io, Io.Clock.real.now(io)) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.Canceled => error.Canceled,
        else => error.CertificateBundleUnreadable,
    };
    t.lock.lockUncancelable(io);
    defer t.lock.unlock(io);
    try merge(t, &system, Io.Clock.real.now(io).toSeconds());
}

/// Add every certificate in the PEM file at `path` in `dir`.
pub fn addFile(t: *Trust, io: Io, dir: Io.Dir, path: []const u8) AddError!void {
    t.lock.lockUncancelable(io);
    defer t.lock.unlock(io);
    t.bundle.addCertsFromFilePath(t.gpa, io, Io.Clock.real.now(io), dir, path) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.Canceled => error.Canceled,
        else => error.CertificateFileUnreadable,
    };
}

/// Add every certificate file in the directory at `path` in `dir`.
pub fn addDir(t: *Trust, io: Io, dir: Io.Dir, path: []const u8) AddError!void {
    var sub = dir.openDir(io, path, .{ .iterate = true }) catch |err| return switch (err) {
        error.Canceled => error.Canceled,
        else => error.CertificateFileUnreadable,
    };
    defer sub.close(io);
    t.lock.lockUncancelable(io);
    defer t.lock.unlock(io);
    t.bundle.addCertsFromDir(t.gpa, io, Io.Clock.real.now(io), sub) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.Canceled => error.Canceled,
        else => error.CertificateFileUnreadable,
    };
}

/// Add every certificate in `pem`. One that has expired is left out, as the
/// file and system forms leave it out.
pub fn addPem(t: *Trust, io: Io, pem: []const u8) AddError!void {
    var arena_state: std.heap.ArenaAllocator = .init(t.gpa);
    defer arena_state.deinit();
    const certs = key.certificates(arena_state.allocator(), pem) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.MalformedCertificate,
    };
    t.lock.lockUncancelable(io);
    defer t.lock.unlock(io);
    const now = Io.Clock.real.now(io).toSeconds();
    for (certs) |der| try addDer(t, der, now);
}

/// How many authorities are trusted.
pub fn count(t: *Trust, io: Io) usize {
    t.lock.lockSharedUncancelable(io);
    defer t.lock.unlockShared(io);
    return t.bundle.map.count();
}

fn addDer(t: *Trust, der: []const u8, now_sec: i64) AddError!void {
    const start: u32 = @intCast(t.bundle.bytes.items.len);
    try t.bundle.bytes.appendSlice(t.gpa, der);
    t.bundle.parseCert(t.gpa, start, now_sec) catch |err| {
        t.bundle.bytes.items.len = start;
        return switch (err) {
            error.OutOfMemory => error.OutOfMemory,
            else => error.MalformedCertificate,
        };
    };
}

/// Every certificate of `from` added to `t`, which is locked.
fn merge(t: *Trust, from: *Certificate.Bundle, now_sec: i64) AddError!void {
    if (t.bundle.map.count() == 0) {
        // The common case, the system's alone: take it whole.
        std.mem.swap(Certificate.Bundle, &t.bundle, from);
        return;
    }
    var it = from.map.valueIterator();
    while (it.next()) |start| {
        const cert: Certificate = .{ .buffer = from.bytes.items, .index = start.* };
        const element = std.crypto.Certificate.der.Element.parse(cert.buffer, cert.index) catch continue;
        try addDer(t, cert.buffer[cert.index..element.slice.end], now_sec);
    }
}

const testing = std.testing;

test "PEM certificates are added, a key file is refused, and the count says what is trusted" {
    const io = testing.io;
    var t: Trust = .init(testing.allocator);
    defer t.deinit();
    try testing.expectEqual(@as(usize, 0), t.count(io));
    try t.addPem(io, @embedFile("testdata/p256.cert.pem"));
    try t.addPem(io, @embedFile("testdata/rsa.cert.pem") ++ @embedFile("testdata/p384.cert.pem"));
    try testing.expectEqual(@as(usize, 3), t.count(io));
    // The same certificate twice is one authority.
    try t.addPem(io, @embedFile("testdata/p256.cert.pem"));
    try testing.expectEqual(@as(usize, 3), t.count(io));
    try testing.expectError(error.MalformedCertificate, t.addPem(io, @embedFile("testdata/p256.pkcs8.pem")));
    try testing.expectError(error.CertificateFileUnreadable, t.addFile(io, Io.Dir.cwd(), "does/not/exist.pem"));
    try testing.expectError(error.CertificateFileUnreadable, t.addDir(io, Io.Dir.cwd(), "does/not/exist"));
}

test "the system's authorities join the ones already trusted" {
    const io = testing.io;
    var t: Trust = .init(testing.allocator);
    defer t.deinit();
    try t.addPem(io, @embedFile("testdata/p256.cert.pem"));
    t.addSystem(io) catch |err| switch (err) {
        // A host without a store of its own.
        error.CertificateBundleUnreadable => return error.SkipZigTest,
        else => return err,
    };
    try testing.expect(t.count(io) >= 1);
    var alone: Trust = .init(testing.allocator);
    defer alone.deinit();
    try alone.addSystem(io);
    try testing.expectEqual(alone.count(io) + 1, t.count(io));
}
