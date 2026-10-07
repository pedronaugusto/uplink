//! Why an exchange failed, in more detail than its error says. A caller
//! passes one in a request's options and reads it after a failure; it holds
//! no allocator and owns no memory, so it is safe to leave on the stack and
//! to drop at any time.

const std = @import("std");
const Io = std.Io;

const Diagnostics = @This();

/// What the exchange was doing when it failed.
stage: Stage = .none,
/// The address the failing connection went to, once it had one.
peer: ?Io.net.IpAddress = null,
/// Why a TLS handshake failed, or the server's refusal of a client
/// certificate: `CertificateExpired`, `TlsAlertBadCertificate`, and the like.
tls_error: ?anyerror = null,
/// The TLS alert that ended a handshake, when one did.
tls_alert: ?std.crypto.tls.Alert.Description = null,
/// A proxy's refusal: its HTTP status, or its SOCKS reply code.
proxy_status: ?u16 = null,
/// The authentication schemes a proxy offered that could not be answered.
proxy_offered: Offered = .{},
/// Which timeout ran out.
timeout: ?Timeout = null,

/// `connect` covers the name's lookup too: the two run as one race.
/// `connect` covers the name's lookup too: the two run as one race.
pub const Stage = enum { none, connect, proxy_tls, tunnel, tls, write, head, body };

pub const Timeout = enum { connect, handshake, activity };

/// Scheme names, `, `-joined, in a fixed buffer: cut, and `truncated` set,
/// when they do not fit.
pub const Offered = struct {
    buffer: [256]u8 = undefined,
    len: u16 = 0,
    truncated: bool = false,

    /// The names written.
    pub fn slice(o: *const Offered) []const u8 {
        return o.buffer[0..o.len];
    }

    /// Set the names to those `write` writes into a writer over the buffer.
    pub fn set(o: *Offered, names: []const u8, truncated: bool) void {
        const n = @min(names.len, o.buffer.len);
        @memmove(o.buffer[0..n], names[0..n]);
        o.len = @intCast(n);
        o.truncated = truncated or n < names.len;
    }
};

/// Clear every detail, for a new exchange.
pub fn reset(d: *Diagnostics) void {
    d.* = .{};
}

test "offered schemes are cut to the buffer and say so" {
    var d: Diagnostics = .{};
    d.proxy_offered.set("Negotiate, NTLM", false);
    try std.testing.expectEqualStrings("Negotiate, NTLM", d.proxy_offered.slice());
    try std.testing.expect(!d.proxy_offered.truncated);
    const long: [300]u8 = @splat('a');
    d.proxy_offered.set(&long, false);
    try std.testing.expectEqual(@as(usize, 256), d.proxy_offered.slice().len);
    try std.testing.expect(d.proxy_offered.truncated);
    d.reset();
    try std.testing.expectEqual(@as(usize, 0), d.proxy_offered.slice().len);
}
