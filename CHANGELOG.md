# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking

- `Dns.https` returns the name's usable HTTPS records owned by an allocator, as a `net.Resolver.Binding`, the most preferred first and each with its effective target (the record's own name for "."); `Dns.ServiceCopy` is gone.

### Added

- HTTPS records when dialing (RFC 9460): with a resolver that reads them (`Dns`, over the stub or DoH), a client dials an `https` origin as its records say, each endpoint that speaks a protocol the client offers in turn, at its target and port, the target's addresses or else its hints, offering by ALPN only the protocols both speak; when every endpoint fails, the origin as it is, unless one publishes ECH. Records live under `_port._https.host` off port 443. `Resolver` has `serviceFn` and `service`; the cache keeps records, none included, beside the addresses; a `Static` name has none.
- Encrypted Client Hello (RFC 9849), `tls.ClientOptions.ech`: from the config an endpoint's HTTPS record publishes, the connection then TLS 1.3 only; a server that refuses a stale config with new ones is tried once more with them, one with ECH off once more without it. `.grease` sends GREASE to every other server. A server takes `tls.ServerOptions.ech_keys`.
- TLS session resumption, on by default: a client resumes TLS 1.3 sessions from a ticket cache of its own (`tls.ClientOptions.resumption`: its bounds, the longest a session lives, TLS 1.2 tickets when asked), keeping the tickets of connections through a proxy apart from direct ones; a server issues tickets from keys of its own, a fresh one drawn whenever none issues, or from a ring the caller rotates (`tls.ServerOptions.tickets`, `tls12_tickets`).
- Certificate compression (RFC 8879), `tls.ClientOptions.certificate_compression`: a client offers zstd and zlib, decoded by warp (`tls.decoder`), or the caller's codecs.
- `Observer.Event.tls` says whether a handshake `resumed` and whether it used `ech`; `dial.Dialed.peer`.
- `wire.h2.Lifecycle`, an HTTP/2 stream's states and the edges between them (RFC 9113 §5.1) as an aegis typestate machine, validated whole when analyzed, with `wire.h2.StreamEvent`; a stream receives where its end can still come and sends where its own can, read off the one table.

### Fixed

- `Diagnostics.peer` and `Observer.Event.connected.peer` name the address connected to, where they named the connection's own local end.

### Changed

- Pins cloak 0.10.1 and warp 0.4.0.

## [0.6.0] - 2026-10-14

### Breaking

- `wire.h2.Connection.Limits`: `max_header_block`, `max_header_list` and `connection_window` are aegis sizes (`.literal("64KiB")`), and `stream_window`, which nothing read, is gone: a stream's receive window is the local SETTINGS' `initial_window_size`.
- `wire.dns.Config.timeout_seconds` is `timeout`, an aegis duration.
- `wire.cookie.SetCookie.max_age` is a `wire.cookie.MaxAge`, whole seconds, zero for an age of zero or less.
- `ws.Conn.Transport` has `canceledFn`, which tells a cancelation from a broken stream; `server.Response.Hijacked` has the response it came from.
- `server.Response.Error` and `ws.AcceptError` have `Canceled`.

### Fixed

- Cancelation is returned as `error.Canceled` where it was taken for something else, and no socket operation follows it: a server response's write canceled says so (`Response.failure` names it after the body writer's `error.WriteFailed`), and a canceled handler gets no 500 written after it; a connection waiting idle for its next request whose task is canceled ends, where the wait was taken for a request coming; a file whose stat or open is canceled is no 404; a canceled HTTP/2 `100 Continue` fails the body's read at once; a WebSocket's read or write on a canceled stream returns `Canceled`, a ping or close answer's failure is not `ConnectionFailed` when it was a cancelation, and a message writer keeps why a frame it drained failed for `end`; the DNS stub's socket canceled at its bind or send ends the query instead of moving to the next server. A lookup or Unix-socket dial with no task to spare for its time limit is waited for, where it was canceled and returned `Canceled` to a caller no one canceled. Setting a socket option on Windows is no cancelation point.

### Changed

- glint's A001 and A002 gated (glint 0.2.7 decides every site); pins preflight 0.5.4 for development.

## [0.5.0] - 2026-10-14

### Breaking

- `tls.h2_over_tls` is gone: over TLS both ends offer `h2` first by ALPN (`tls.client_protocols`, `tls.server_protocols`), as cloak's `tls.Session` reads in one task while others write (cloak 0.5.0).

### Changed

- HTTP/2 over TLS, both ends: the client speaks it to a server that agrees it by ALPN, its requests streams of one connection, and the server serves it to a client that asks (WebSocket over HTTP/2, RFC 8441, with it). h2spec 2.6.0 `--strict` passes over TLS as over plain TCP: 146 of 147, 1 skipped, none failed. `bay h2spec` takes `--tls <cert.pem> <key.pem>`.
- Pins cloak 0.6.0.

## [0.4.2] - 2026-10-14

### Changed

- A URL's host, the request's and a `Location`'s, goes as IDNA's ASCII form (xenoglyph's `idna`: UTS #46 ToASCII with the URL Standard's options): a name in Unicode or upper case is looked up, sent in `Host` and the request line, given as SNI and matched for cookies and proxies as `xn--bcher-kva.de` and `example.com`; a host IDNA refuses (a disallowed code point, a joiner out of context, Punycode that does not decode, a Bidi label that breaks RFC 5893) is `InvalidUrl` (`InvalidRedirect` for a `Location`).
- Pins xenoglyph 0.3.2, a new dependency fetched only with the client.

## [0.4.1] - 2026-10-14

### Changed

- Pins reactor 0.4.3 (shuttle 0.2.1: one aegis in a plain `zig build` consumer's graph; a task's file calls on Windows on a lane, where the file server's handler overflowed its stack), shakedown 0.4.2 and preflight 0.5.0.

### Fixed

- HTTP/2 reads in one task while the streams write in others, and ThreadSanitizer found what they shared without a lock; each now has one owner or a lock. A socket keeps a read's deadline apart from a write's, so a write no longer replaced the deadline of a read under way, or left it unarmed once done (on any `Io` but reactor's runtime, an idle HTTP/2 connection's read could then wait past its timeout). The server's HTTP/2 writes keep the activity timeout whatever the reading task waits for; a stream never moves its connection's `Io`, and reads its state (the body's end, its trailers, a reset) under the session's lock; a connection's failure is recorded atomically. The client's shared connection keeps the `Io` it was opened on, and only its reads, which one request makes at a time, count toward the low-speed window.

## [0.4.0] - 2026-10-14

### Breaking

- `pool.Pool.Kind` has an `h2` arm and `Pool.Acquired` a `shared` one, for HTTP/2 connections; `client.Run.Lease` holds a `Pool.Kind`.
- `transport.Head.Error` names a start line past `max_head` apart from a head past it: `StartLineTooLong` and `NoStartLine`.
- `server.Router` answers `OPTIONS *` and a `CONNECT` to a host and port itself, and routes an extended `CONNECT` by its path, where all three were 404s.
- `wire.Version.h2` is a version messages are exchanged in.

### Notes

- HTTP/2 goes over plain TCP alone for now: over TLS both ends agree HTTP/1.1 by ALPN until cloak's `tls.Session` reads and writes from two tasks at once, which an HTTP/2 connection does.

### Changed

- The server reads a request strictly where Http11Probe found it lenient: a chunked body's line ends and extensions as RFC 9112 writes them, a target with a raw byte past 0x7f or a `#` refused, a `Host` that is empty or not a URI's host refused; a body the client got wrong is answered 400 (or 413 past `max_body`) rather than 500, and a request line past `max_head` 414 or 400 rather than 431.
- Pins aegis 0.1.6, reactor 0.3.1, cloak 0.4.0, shakedown 0.4.1, warp 0.3.1 and preflight 0.4.5.
- `Router` answers `OPTIONS *` 200 and a `CONNECT` to a host and port 405, and routes an extended `CONNECT` by its path.

### Added

- `Server`: an HTTP/1.1 server on any `std.Io`, evented on reactor's runtime. Requests are read strictly (bare LF, folded fields, request smuggling, `Host`, limits), pipelined requests answered in order, every wait bounded (head, idle, activity, handshake), `100 Continue` sent when the body is first read, TLS terminated by cloak with client certificates, request bodies decoded and responses compressed through warp, `Response.hijack` after a 101, trailers both ways, a connection limit, an observer, and a graceful `shutdown`.
- `server.Router`: Go 1.22's patterns and precedence on a tree of segments, conflicts refused at `add`, 405 with `Allow`, clean-path and subtree redirects, captures unescaped; `server.Routes`: the same at compile time, conflicts a compile error and captures a struct.
- `server.Files`: a directory served with `Content-Type`, `ETag` and `Last-Modified`, conditional requests, byte ranges one or several, and index files.
- `ws`: WebSocket (RFC 6455) on the client (`ws.connect`, through the `Client`'s proxies, TLS, cookies and credentials) and the server (`ws.accept`): subprotocols, messages streamed across fragments with pings, pongs and closes answered between them, text checked as UTF-8 as it arrives, limits, keepalive pings with no task, and permessage-deflate (RFC 7692) through warp with or without context takeover.
- HTTP/2 on the server (RFC 9113): by ALPN over TLS, or by prior knowledge over plain TCP (`Options.h2c`), each stream answered by the handler on a task of its own through the same `Request` and `Response`, flow control both ways, HPACK, and the limits against Rapid Reset, CONTINUATION floods, the HPACK bomb and SETTINGS, PING and empty-frame floods. `wire.h2` holds the frames and a sans-I/O connection, `wire.hpack` HPACK with its Huffman code decoded four bits at a time.
- HTTP/2 on the client: `Options.http2` (`.negotiate` by default, `.prior_knowledge` for plain TCP, `.off`). Requests to one route share one connection, each a stream; no task reads on its own, a request waiting for its answer reads the frames for all of them in turn, and no request's deadline ends the connection the others share. A request the server refused unprocessed goes again on another connection. `CONNECT`, an `Upgrade` and a request sent whole to an HTTP proxy go in HTTP/1.1. `wire.h2.message` checks request, response and trailer blocks for both ends.
- WebSocket over HTTP/2 on the server (RFC 8441): `ws.accept` takes an extended `CONNECT`, and `Response.hijack` after a 2xx to one hands over the stream; `Request.protocol` names what it asks for.
- `Dns`: a resolver that speaks DNS itself: the stub over UDP and TCP from `resolv.conf` or Windows' adapters (`Dns.System`), or DNS over HTTPS through `Doh` (RFC 8484); AAAA and A at once, CNAMEs followed, search domains, and HTTPS records (RFC 9460) through `Dns.https`. `wire.dns` writes queries and reads answers, names and SVCB/HTTPS parameters with every length and pointer bounded, and `resolv.conf`.
- HTTP/2 connections idle past the pool's `idle_timeout` are closed, as HTTP/1.1 ones are.
- `Credentials.Netrc` and `wire.netrc`: a 401 answered from a `.netrc`, read as curl reads one, quoted values and `macdef` included.
- `Request.cookie` and `wire.cookie.Pairs`: a `Cookie` field's pairs as a server reads them.
- `conformance/h1.zig` (`zig build h1`): an HTTP/1.1 conformance tool run against the server, as h1spec and Http11Probe are.
- Fuzz properties for HPACK blocks, HTTP/2 frame sequences, WebSocket frame heads and `--resolve` entries.
- `wire.range` (`Range` and `Content-Range`), `wire.ws` (frames, masking, keys, close codes, incremental UTF-8, extension parameters), `wire.multipart.Reader` (parts read as they arrive), `wire.coding.negotiate` (`Accept-Encoding`), `wire.h1.writeStatusLine`, `wire.fields.ListIterator.contains`.

## [0.3.1] - 2026-10-13

### Added

- TLS 1.2 through cloak for servers that speak nothing newer: ECDHE with AEAD suites and the extended master secret. TLS 1.2 with RSA key exchange, CBC or without the extended master secret is refused.
- A client answers a server's request for a certificate with an RSA key too, signed by cloak (RSA-PSS in TLS 1.3, PSS or PKCS#1 v1.5 in TLS 1.2).

### Changed

- Pins cloak 0.4.0 and aegis 0.1.6.

## [0.3.0] - 2026-10-13

### Breaking

- Every timeout, delay, keepalive and lifetime is an aegis `Duration` (`uplink.Duration`, nanoseconds), and every duration the observer reports: `Timeouts`, `Dial`, `Pool.Options.idle_timeout`, `Retries`, `Resolver.Cache.Options.ttl`, `expect_continue_timeout`. Write one as `.literal("30s")`, or read it with `Duration.parse`; log one with `{f}`. `h1.Limits.max_head` is an aegis `Bytes(u32)`.
- A coded body that does not decode is `error.BadContentEncoding`, not `HttpProtocolError`, and `Response.decodingFailure` says why: not a stream of its coding, a checksum that is not the data's, a zstd window past the cap, or a stream cut short.

### Changed

- gzip, deflate and zstd bodies are decoded by warp, with every checksum verified: gzip's CRC-32 and length and zlib's Adler-32, which std's decoders read without comparing, and zstd's content checksum, which they did not read. A gzip body of several members is read whole, a raw DEFLATE stream sent as `deflate` is read, and a body under several codings is undone, the last applied first.
- A route holds its host by value, so a copy of one cannot point at a freed connection.
- Pins aegis 0.1.5, reactor 0.3.0, preflight 0.4.4 and shakedown 0.4.0, and adds warp 0.2.3 (lazy, with the client).
- The release tier fuzzes the codecs and runs the threaded suite under ThreadSanitizer; glint's A003, A005 and Z013 gate.

## [0.2.5] - 2026-10-13

### Changed

- Pins aegis 0.1.3, reactor 0.2.3, cloak 0.3.0, preflight 0.4.1 and shakedown 0.3.2.

## [0.2.4] - 2026-10-13

### Changed

- The tests take shakedown as bay gives it, with no `.aegis = .consumer` or `useAegis` binding: bay gives a graph one aegis, so shakedown's is this package's.

## [0.2.3] - 2026-10-12

### Changed

- Pins aegis 0.1.1, reactor 0.2.2, cloak 0.2.1, preflight 0.3.4 and shakedown 0.2.6.

## [0.2.2] - 2026-10-12

### Fixed

- Pins reactor 0.2.1, whose context switch keeps the vector registers on x86_64: on Windows, in optimized builds, a request read values a task held in them across a switch after another task had overwritten them, and crashed or hung.

## [0.2.1] - 2026-10-12

### Fixed

- A closed connection gives its room on a limited route back. Closing it read its route's host from the connection after freeing it, so the pool could miss the route: a request waiting for the route then waited forever, and a read of the freed bytes could crash, as it did on Windows in ReleaseSafe. The pool closes a connection itself now, its route read first, and a route it does not know is an assertion, not a silent miss.

## [0.2.0] - 2026-10-12

### Breaking

- uplink is developed with [bay](https://github.com/pedronaugusto/bay): preflight and shakedown are dev dependencies, and the tests, example, checks and benchmarks are the development build's (`bay test`, `bay check`, `bay bench`). uplink ships with aegis and, for the client, the lazy reactor and cloak, and the option `-Dclient`; what a project that depends on it builds is unchanged.

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

- The Smith fuzz tests are shakedown `check` properties.
- Breaking: TLS is [cloak](https://github.com/pedronaugusto/cloak)'s. The copy of std's TLS client with client authentication, its recorded diff and check, `tls.Trust`, `tls.ClientAuth`, `tls.PrivateKey`, `tls.key` and `tls.Session` are gone; `tls.ClientOptions` takes a `cloak.Trust.Snapshot` for `trust` and a `cloak.ClientAuth` for `client_auth` (build them with cloak's `Trust.addPem`, `PrivateKey.parse` and `ClientAuth.initPem`), `Proxy.Tls` the same, and `Diagnostics.tls_alert` is a `cloak.tls.Alert`, the server's or the one the client sent for a failure of its own. `Diagnostics.tls_error` names what cloak reports (`PeerAlert`, `VerificationRejected`) instead of `TlsAlert...` and `Certificate...` errors.
- Breaking: TLS 1.3 only, until cloak adds TLS 1.2, which the std client's fork spoke: a server that speaks only TLS 1.2 is turned away with a `protocol_version` alert. A client key that is RSA fails a handshake with `ClientCertificateSchemeUnsupported` until cloak signs with RSA-PSS; ECDSA on P-256 and P-384 and Ed25519 keys are answered. A server's request for a certificate a client has no usable scheme for is no longer an error of its own: the client sends none and the server decides.
- cloak is a lazy dependency like reactor, fetched only for the client; `uplink.wire` still imports `std` and aegis alone. On macOS and Windows cloak links the platform's trust store.
- The family's newest aegis, preflight, shakedown and reactor; the exception files and `ci/glint.json` give way to glint's rules in `ci/preflight.json` (Z026 gates) and `glint-ignore` comments at the sites.
- Pins aegis 0.1.0, reactor 0.2.0 and cloak 0.2.0.
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

### Fixed

- A client checks a server against the system's authorities on macOS and Windows: cloak verifies a snapshot of the system's policy with the system's own verifier, where it handed it, rootless, to the portable verifier, so no public server verified there. A host written with its trailing dot (`example.com.`) is opened; a CA file with comments before its certificates, as common CA bundles and the Fedora and RHEL bundles have, is read.

[Unreleased]: https://github.com/pedronaugusto/uplink/commits/main
