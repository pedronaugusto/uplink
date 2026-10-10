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
