//! TLS for uplink's connections: the standard library's client with client
//! certificates added, the authorities a server is checked against, and the
//! reading of the keys and certificates a client answers with. Nothing here
//! imports anything but the standard library.

const std = @import("std");
const Io = std.Io;

/// The certificate authorities servers are checked against; shareable.
pub const Trust = @import("tls/Trust.zig");
/// A certificate chain and key, ready for handshakes.
pub const ClientAuth = @import("tls/ClientAuth.zig");
/// Keys and certificates from PEM and DER files.
pub const key = @import("tls/key.zig");
/// A client's private key.
pub const PrivateKey = key.PrivateKey;
/// One TLS client session over a byte stream.
pub const Session = @import("tls/Session.zig");

/// How a client's TLS connections are made.
pub const ClientOptions = struct {
    /// The authorities servers are checked against; null is the system's,
    /// read once per client at its first verifying handshake.
    trust: ?*Trust = null,
    /// `none` checks neither a server's certificate nor its name.
    verify: Verify = .full,
    /// The certificate and key a server that asks for one is answered with.
    client_auth: ?*const ClientAuth = null,
    /// Where every session's secrets are written in the NSS key log format,
    /// for a capture to be decrypted with. Never read from the environment.
    /// Every session writes to it; when connections run on several tasks,
    /// the writer must take writes from several tasks.
    key_log: ?*Io.Writer = null,

    pub const Verify = enum { full, none };
};

test "nothing in tls/ imports anything but the standard library and its own files" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var dir = Io.Dir.cwd().openDir(io, "src/tls", .{ .iterate = true }) catch return error.SkipZigTest;
    defer dir.close(io);
    var it = dir.iterate();
    var files: usize = 0;
    while (try it.next(io)) |entry| {
        if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".zig")) continue;
        files += 1;
        const text = try dir.readFileAlloc(io, entry.name, gpa, .limited(1 << 20));
        defer gpa.free(text);
        var at: usize = 0;
        while (std.mem.findPos(u8, text, at, "@import(\"")) |start| {
            const name_start = start + "@import(\"".len;
            const end = std.mem.findScalarPos(u8, text, name_start, '"') orelse return error.TestUnexpectedResult;
            const name = text[name_start..end];
            at = end;
            if (std.mem.eql(u8, name, "std") or std.mem.eql(u8, name, "builtin")) continue;
            if (std.mem.findScalar(u8, name, '/') == null and std.mem.endsWith(u8, name, ".zig")) {
                dir.access(io, name, .{}) catch return error.TestUnexpectedResult;
                continue;
            }
            std.debug.print("{s} imports {s}\n", .{ entry.name, name });
            return error.TestUnexpectedResult;
        }
    }
    try std.testing.expect(files >= 8);
}

test {
    _ = Trust;
    _ = ClientAuth;
    _ = key;
    _ = Session;
    _ = @import("tls/Client.zig");
    _ = @import("tls/der.zig");
    _ = @import("tls/rsa.zig");
    _ = @import("tls/auth_wire.zig");
}
