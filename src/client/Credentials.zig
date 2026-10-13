//! Where a client gets the answer to a server's 401: the caller's store of
//! secrets, such as git's credential helpers. The client asks once per
//! origin, sends the answer with every later request there, and says
//! whether it was taken, so a store can keep a good secret and drop a bad
//! one, as git's `approve` and `reject` do.

const std = @import("std");
const Io = std.Io;
const wire = @import("uplink.wire");
const auth = wire.auth;

const Credentials = @This();

context: ?*anyopaque,
/// The secret for `query`, or null to answer nothing: the 401 is then the
/// caller's. The slices returned need only last until this returns; the
/// client copies them.
fillFn: *const fn (io: Io, context: ?*anyopaque, query: Query) FillError!?Secret,
/// Whether the secret filled for `query` was taken (a response that is not
/// 401) or refused. Called once per filled secret; null when the store
/// does not care. The slices are the client's copies, valid during the
/// call.
doneFn: ?*const fn (io: Io, context: ?*anyopaque, query: Query, secret: Secret, accepted: bool) void = null,

/// What is asked for.
pub const Query = struct {
    /// The URL the 401 answered.
    url: []const u8,
    /// `https`.
    secure: bool,
    host: []const u8,
    port: u16,
    /// The realm the challenge named, when it named one.
    realm: ?[]const u8,
    /// The strongest scheme the server offered that a secret can answer:
    /// `digest` or `basic` for a password, `bearer` for a token.
    scheme: auth.Scheme,
};

/// A secret.
pub const Secret = union(enum) {
    /// Answered by Digest when the server offers it, else Basic.
    password: struct { user: []const u8, password: []const u8 },
    /// Answered by Bearer.
    token: []const u8,
};

/// Why no secret could be had.
pub const FillError = error{
    /// The store could not be asked: a helper that failed, say.
    CredentialsUnavailable,
    Canceled,
};

/// Ask for the secret.
pub fn fill(c: Credentials, io: Io, query: Query) FillError!?Secret {
    return c.fillFn(io, c.context, query);
}

/// Say whether the secret was taken.
pub fn done(c: Credentials, io: Io, query: Query, secret: Secret, accepted: bool) void {
    if (c.doneFn) |f| f(io, c.context, query, secret, accepted);
}

/// Secrets from a `.netrc`'s text, which the caller reads and keeps: the
/// entry for the host that asks, or the file's `default`, answers with its
/// login and password; an entry without both answers nothing.
pub const Netrc = struct {
    text: []const u8,

    /// The store, reading `n`, which must outlive the client.
    pub fn credentials(n: *const Netrc) Credentials {
        return .{ .context = @constCast(n), .fillFn = fillNetrc }; // safe: a fill only reads through the pointer
    }

    fn fillNetrc(_: Io, context: ?*anyopaque, query: Query) FillError!?Secret {
        const n: *const Netrc = @ptrCast(@alignCast(context.?)); // safe: `credentials` passes its Netrc
        if (query.scheme == .bearer) return null;
        // The client copies the secret before this returns, so a quoted
        // value may be unescaped into a buffer on the stack.
        var buffer: [1024]u8 = undefined;
        const entry = wire.netrc.find(n.text, query.host, &buffer) catch return error.CredentialsUnavailable;
        const e = entry orelse return null;
        return .{ .password = .{ .user = e.login orelse return null, .password = e.password orelse return null } };
    }
};

test "a .netrc answers for its machine, and for no other without a default" {
    const netrc: Netrc = .{ .text = "machine example.com login alice password \"pa ss\"\n" };
    const c = netrc.credentials();
    const io = std.testing.io;
    const asked: Query = .{ .url = "https://example.com/", .secure = true, .host = "EXAMPLE.com", .port = 443, .realm = null, .scheme = .basic };
    const secret = (try c.fill(io, asked)).?;
    try std.testing.expectEqualStrings("alice", secret.password.user);
    try std.testing.expectEqualStrings("pa ss", secret.password.password);
    var other = asked;
    other.host = "example.org";
    try std.testing.expectEqual(null, try c.fill(io, other));
}
