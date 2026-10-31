//! The one call on a socket that neither `std.Io` nor reactor makes: a look
//! that neither waits nor takes anything. Everything else uplink does to a
//! socket goes through the caller's `Io`, or reactor's networking over it,
//! its options among them.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;

const os = builtin.target.os.tag;

/// What a look at an idle socket finds.
pub const Peek = enum {
    /// Nothing waiting: the peer has said nothing.
    idle,
    /// Bytes waiting.
    readable,
    /// The peer closed it, or it failed.
    closed,
};

/// Look at a socket without waiting and without taking anything from it:
/// one `recv` with `MSG_PEEK` and `MSG_DONTWAIT`, a few times cheaper than
/// a readiness check through the `Io`. Null where the system has no such
/// call: Windows and WASI.
pub fn peek(handle: Io.net.Socket.Handle) ?Peek {
    if (os == .windows or os == .wasi) return null;
    var byte: [1]u8 = undefined;
    while (true) {
        // aegis: boundary(A019): recvfrom(2) writes the peeked byte; only its count is read
        const rc = std.posix.system.recvfrom(handle, &byte, byte.len, std.posix.MSG.PEEK | std.posix.MSG.DONTWAIT, null, null);
        switch (std.posix.errno(rc)) {
            .SUCCESS => return if (rc == 0) .closed else .readable,
            .AGAIN => return .idle,
            .INTR => continue,
            else => return .closed,
        }
    }
}
