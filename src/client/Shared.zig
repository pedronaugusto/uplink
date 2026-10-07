//! What every request of a client shares: the connections' context, the
//! pool of idle connections, the answers to servers' challenges, and the
//! options. A client is one of these; each request's run points at it.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const h1 = @import("../wire/h1.zig");
const tls = @import("../tls.zig");
const Resolver = @import("../net/Resolver.zig");
const Context = @import("../transport/Context.zig");
const Observer = @import("../transport/Observer.zig");
const Proxy = @import("../transport/Proxy.zig");
const Pool = @import("../pool/Pool.zig");
const CookieJar = @import("CookieJar.zig");
const Credentials = @import("Credentials.zig");
const OriginAuth = @import("OriginAuth.zig");
const Prepare = @import("Prepare.zig");
const policy = @import("policy.zig");

const Shared = @This();

context: Context,
pool: Pool,
origin_auth: OriginAuth,
options: Options,

/// How a client connects and what it does with what comes back.
pub const Options = struct {
    /// The proxy requests go through: none, one, or the one the
    /// environment names per request, by curl's rules or Go's.
    proxy: Proxy.Choice = .none,
    tls: tls.ClientOptions = .{},
    timeouts: Context.Timeouts = .{},
    pool: Pool.Options = .{},
    dial: Context.Dial = .{},
    /// What looks names up; null is the system's.
    resolver: ?Resolver = null,
    /// Keep the resolver's answers for a while; null keeps none.
    dns_cache: ?Resolver.Cache.Options = .{},
    /// Send `Accept-Encoding: gzip, deflate, zstd` unless a request names
    /// its own, and decode such bodies. A request with a `Range`, or a
    /// `HEAD`, is sent without it, as Go sends them: a range of coded bytes
    /// cannot be decoded from its middle, and a `HEAD` would report the
    /// coded length.
    decompress: bool = true,
    /// The largest zstd window decoded: a body asking for more is refused
    /// as it is read. A client keeps one window of this size, plus a
    /// block, once it has decoded zstd.
    max_zstd_window: u32 = 8 << 20,
    redirects: policy.Redirects = .default,
    retries: policy.Retries = .{},
    /// Where cookies are kept and sent from; null keeps none.
    cookies: ?*CookieJar = null,
    /// Where an answer to a server's 401 comes from; null answers none.
    credentials: ?Credentials = null,
    /// Sent as `User-Agent` unless a request names its own.
    user_agent: ?[]const u8 = null,
    /// Told every step of every request, with its timing.
    observer: ?Observer = null,
    /// Called before every attempt is written.
    prepare: ?Prepare = null,
    /// How long a request with `expect_continue` waits for the server's
    /// go-ahead before sending its body anyway: Go's default.
    expect_continue_timeout: Io.Duration = .fromSeconds(1),
    /// The largest response head, and the most fields in one.
    limits: h1.Limits = .{},
};

/// Why a request failed.
pub const SendError = error{
    /// Not an `http` or `https` URL, or one with a byte a request line
    /// cannot carry.
    InvalidUrl,
    UnsupportedScheme,
    /// A field name or value that cannot be sent, or a field uplink writes
    /// itself.
    InvalidHeader,
    NameNotResolved,
    ConnectionFailed,
    /// A timeout ran out: `Diagnostics.timeout` says which.
    TimedOut,
    /// The TLS handshake failed: `Diagnostics.tls_error` says why.
    TlsFailed,
    ClientCertificateRejected,
    ClientCertificateSchemeUnsupported,
    CertificateBundleUnreadable,
    /// The environment names a proxy that cannot be read.
    InvalidProxy,
    ProxyRefused,
    ProxyAuthenticationRequired,
    ProxyAuthMethodUnsupported,
    ProxyAddressUnsupported,
    ProxyHostUnreachable,
    /// A proxy's answer that is neither SOCKS nor HTTP.
    ProxyProtocolError,
    /// A response that is not HTTP/1.x.
    HttpProtocolError,
    /// A body reader that ended before its declared length.
    BodyIncomplete,
    /// A body kind the call does not take: `.streamed` to `send`, bytes or
    /// a reader to `begin`.
    InvalidBody,
    /// The request body's reader failed.
    BodyReadFailed,
    /// A 307 or 308 asks for a body sent again that was read once.
    BodyNotReplayable,
    /// More redirects in a row than the policy's `max`.
    TooManyRedirects,
    /// A redirect from `https` to `http`, which the policy refuses.
    InsecureRedirect,
    /// A `Location` that is no URL, or names a scheme other than `http`
    /// or `https`.
    InvalidRedirect,
    /// The credentials store could not be asked.
    CredentialsUnavailable,
    /// The prepare hook failed.
    PrepareFailed,
    /// A host name with no task to look it up beside the caller's, on a
    /// target with no lookup of its own.
    ConcurrencyUnavailable,
    OutOfMemory,
    Canceled,
};
