//! A client's certificate chain and private key, encoded once for every
//! handshake that answers a server's request for them.

const std = @import("std");
const Allocator = std.mem.Allocator;
const PrivateKey = @import("key.zig").PrivateKey;
const ClientAuth = @This();

/// What keeps the TLS 1.2 handshake's messages until the client signs them.
gpa: Allocator,
/// The key the chain's first certificate is for.
key: PrivateKey,
/// The chain's entries as TLS 1.3 sends them, each with no extensions.
list13: []u8,
/// The chain's entries as TLS 1.2 sends them.
list12: []u8,

/// Errors from `init`.
pub const Error = error{
    /// No certificate at all.
    CertificateMissing,
    /// The key is not the one the first certificate is for.
    KeyCertificateMismatch,
    /// A chain longer than a handshake message holds.
    CertificateChainTooLong,
} || Allocator.Error;

/// Encode `chain` — DER certificates, the client's own first — for `key`,
/// which must be the first certificate's.
pub fn init(gpa: Allocator, chain: []const []const u8, key: PrivateKey) ClientAuth.Error!ClientAuth {
    if (chain.len == 0) return error.CertificateMissing;
    if (!key.matches(chain[0])) return error.KeyCertificateMismatch;
    var total12: usize = 0;
    for (chain) |cert| total12 += 3 + cert.len;
    const total13 = total12 + 2 * chain.len;
    // One handshake message's length is 24 bits, with room for its header.
    if (total13 > (1 << 24) - 512) return error.CertificateChainTooLong;
    const list12 = try gpa.alloc(u8, total12);
    errdefer gpa.free(list12);
    const list13 = try gpa.alloc(u8, total13);
    var at12: usize = 0;
    var at13: usize = 0;
    for (chain) |cert| {
        std.mem.writeInt(u24, list12[at12..][0..3], @intCast(cert.len), .big);
        @memcpy(list12[at12 + 3 ..][0..cert.len], cert);
        at12 += 3 + cert.len;
        std.mem.writeInt(u24, list13[at13..][0..3], @intCast(cert.len), .big);
        @memcpy(list13[at13 + 3 ..][0..cert.len], cert);
        std.mem.writeInt(u16, list13[at13 + 3 + cert.len ..][0..2], 0, .big);
        at13 += 3 + cert.len + 2;
    }
    return .{ .gpa = gpa, .key = key, .list13 = list13, .list12 = list12 };
}

/// Free the encoded chain.
pub fn deinit(a: *ClientAuth) void {
    a.gpa.free(a.list13);
    a.gpa.free(a.list12);
    a.* = undefined;
}
