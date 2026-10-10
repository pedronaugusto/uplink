# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Breaking: TLS is [cloak](https://github.com/pedronaugusto/cloak)'s. The copy of std's TLS client with client authentication, its recorded diff and check, `tls.Trust`, `tls.ClientAuth`, `tls.PrivateKey`, `tls.key` and `tls.Session` are gone; `tls.ClientOptions` takes a `cloak.Trust.Snapshot` for `trust` and a `cloak.ClientAuth` for `client_auth` (build them with cloak's `Trust.addPem`, `PrivateKey.parse` and `ClientAuth.initPem`), `Proxy.Tls` the same, and `Diagnostics.tls_alert` is a `cloak.tls.Alert`, the server's or the one the client sent for a failure of its own. `Diagnostics.tls_error` names what cloak reports (`PeerAlert`, `VerificationRejected`) instead of `TlsAlert...` and `Certificate...` errors.
- Breaking: TLS 1.3 only, until cloak adds TLS 1.2, which the std client's fork spoke: a server that speaks only TLS 1.2 is turned away with a `protocol_version` alert. A client key that is RSA fails a handshake with `ClientCertificateSchemeUnsupported` until cloak signs with RSA-PSS; ECDSA on P-256 and P-384 and Ed25519 keys are answered. A server's request for a certificate a client has no usable scheme for is no longer an error of its own: the client sends none and the server decides.
- cloak is a lazy dependency like reactor, fetched only for the client; `uplink.wire` still imports `std` and aegis alone. On macOS and Windows cloak links the platform's trust store.
- The family's newest aegis, preflight, shakedown and reactor; the exception files and `ci/glint.json` give way to glint's rules in `ci/preflight.json` (Z026 gates) and `glint-ignore` comments at the sites.

### Added

- `check-cold-consumer`: a project that depends on uplink as a client is built from an empty package cache, so the module is declared before the lazy dependencies are fetched.

- `Client`: HTTP/1.1 requests over kept connections, shared by tasks, with
  `send` for a body given whole or from a reader and `begin` for one the caller
  writes. A kept connection is checked before reuse, and a request that fails
  on a stale one before any response byte is sent once more when it had no body
  or its method is idempotent. `stats` reads the client's counters without a
  lock.
- `Response`: the head, read through a pooled buffer, and the body by its
  framing, decoded for the codings the client offers, which it offers on
  every request but a `HEAD` or a range. `readerBuffered` reads the body through
  the caller's buffer, for one that peeks further at once. `collect`,
  `failure` and `deinit`, which keeps the connection when the body was read
  to its end.
- Proxies: HTTP (absolute form, or a `CONNECT` tunnel with TLS to the server
  inside it), HTTPS, and SOCKS 4, 4a, 5 and 5h; Basic and Digest (MD5,
  SHA-256, SHA-512-256, `-sess`, userhash) answers to a proxy's challenge.
  `Proxy.parse`, `Proxy.fromEnvironment` and `Proxy.bypassed` by either of
  two sets of rules, `Proxy.Rules`.
- Timeouts for connecting, each handshake, and each read or write, kept in the
  kernel on a reactor runtime, by one task per client on any other `Io`, by the
  `Io` itself where it has no task to spare, and counted where neither can.
- `tls`: the options a client takes for cloak's TLS (authorities, a client
  certificate and key, a key log through a writer), and what an alert says about
  a client certificate.
- `net`: connections raced over a name's addresses within one deadline.
- `uplink.wire`: the codecs as a module of their own, on `std` and aegis alone,
  for a server, a proxy or a test tool that reads and writes HTTP messages and
  has no use for a client. `.client = false` on the dependency leaves it the
  only module and fetches no reactor; the default, `.client = true`, builds the
  `uplink` module, which still exposes everything, `uplink.wire` as `wire`. A check builds such a
  project with reactor absent.
- `wire`: HTTP/1.1 heads parsed in place, strict on requests and lenient on
  responses; framing by RFC 9112 §6.3; a chunked decoder and writers; header
  fields and lists; content codings; authentication challenges; SOCKS; URLs.
- `Diagnostics`: why an exchange failed, with no allocation, and how many
  redirects and retries it took.
- Redirects: `Redirects.follow` up to ten by default, the method and body
  changed or kept by status as RFC 9110 has it, `https` to `http` refused
  unless allowed, the caller's credentials and cookies dropped when the
  origin changes; `Response.url` is where they led.
- Retries: a connection that failed before any answer, when the request can
  go again, and the statuses `Retries.statuses` names, after `Retry-After` or
  a full-jitter backoff, within the request's deadline.
- `Credentials`: answers to a server's 401, filled once per origin and sent
  with every later request there as Basic, Digest or Bearer, with the store
  told whether each was taken; `Request.auth` for credentials sent from the
  first request.
- `CookieJar`: cookies kept and sent by RFC 6265bis, with a public suffix
  seam, and read from and written to the Netscape cookie file.
- `Prepare`, a hook called before every attempt is written, and `Observer`,
  told every step of every request with its timing.
- Timeouts: `Request.timeout` over the whole request, its retries, redirects
  and body reads included, and `Timeouts.low_speed`, a low speed limit as
  git has it.
- Pool: `max_per_route` with first-come waiters bounded by the request's
  deadline, `idle_timeout`, and `drain_limit`, the unread body read so its
  connection is kept.
- `Proxy.Choice.environment`: the environment's proxy chosen per request.
- `net.Resolver`: the system's lookup, `Resolver.Static` (chosen names
  with chosen addresses) and `Resolver.Cache`, which a client keeps by default;
  addresses raced by Happy Eyeballs; `Dial.unix_socket`; TCP keepalive.
- `Expect: 100-continue` for a body given or written; `Response.upgrade` for
  a 101 or a `CONNECT`'s tunnel; `Response.trailers`; zstd bodies, with the
  window capped by `max_zstd_window`.
- `wire`: HTTP dates, `Set-Cookie` values and cookie dates, Server-Sent
  Events read and written, form and multipart bodies, references resolved
  against a URL, Bearer.

### Changed

- reactor is a lazy dependency, fetched only for the client: a project that
  sets `.client = false` does not fetch it.
- Depends on [reactor](https://github.com/pedronaugusto/reactor), the family's
  evented `std.Io`, which now owns what uplink kept for itself: the task that
  keeps socket deadlines (`net.Deadlines`), name lookup (`net.resolve`) and
  connecting with a timeout (`net.connect`). uplink runs on any `Io` and is
  evented on reactor's runtime, where a deadline is the kernel's and a single
  address is dialed with no task beside the caller's; std 0.17's own evented
  `Io`s cannot open a TCP connection (`Uring`, `Dispatch`) or panic on a
  connect timeout (`Kqueue`). The test suite runs twice, on `Io.Threaded` and
  on a reactor runtime, and the benchmarks run on a runtime unless asked for
  `--io threaded`.
- Pins the newest aegis, preflight, shakedown and reactor.
- Depends on aegis, the family's std-only safety library. Locks sit beside the
  data they guard (`BlockingGuarded`) in the pool, the buffer pool, the
  cookie jar, the answers kept per origin and for the proxy, the name cache,
  the timer and the proxies. Waiters are granted and queued as before.
- Credentials are held in aegis secret owners and wiped before they are
  freed: an answer kept for an origin, the user and password of a proxy the
  environment names (parsed in wiped scratch, no longer left in the arena
  the proxies free), and the Digest and Basic intermediates of an answer.
- A timeout deadline too far off for an `i64` of nanoseconds is the latest
  instant instead of an integer overflow.
- Breaking: `Proxy.Rules` is `lowercase` and `uppercase`, which were named for
  the programs whose environment conventions they follow.
- Breaking: `net.resolve`, `net.sys.abort` and `net.sys.getaddrinfo` are gone,
  reactor's `net.resolve` and `net.abort` being their owners; `Resolver.LookupError`
  is reactor's `net.ResolveError`.
- Breaking: `CookieJar.deinit`, `Resolver.Cache.deinit` take the `Io`, as
  `Client.deinit` does.
- Breaking: `Pool.Options.max_per_route` is `?u16`, null for no limit; zero,
  which was no limit, is refused.
- Breaking: `Pool.Options.drain_limit`, `Client.Options.max_zstd_window` and
  `Timeouts.lowSpeedNeed` are aegis byte counts (`units.Bytes`): construct
  with `.fromRaw(n)`, read with `.raw()`.
