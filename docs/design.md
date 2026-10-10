# uplink design

uplink is an HTTP/1.1 client with the codecs it is built from. This page says
how it is put together and why: the layers, who owns which state, what always
holds, and the decisions that shaped it. The README says what it does and how
to use it.

## Layers

```
 client     Client, Request, Response, Outgoing; the policy: redirects, retries,
            origin authentication, cookies, decoding, hooks
 pool       which connection serves which exchange: idle sets, route limits, waiters
 transport  one connection: TCP, then TLS to a proxy, a CONNECT or SOCKS tunnel,
            TLS to the server; deadlines; the buffers connections borrow
 net        names and sockets: lookup, resolvers, Happy Eyeballs, socket options
 tls        the TLS client with client certificates, trust, keys
 wire       sans-I/O codecs: HTTP/1.1 heads and bodies, fields, dates, cookies,
            auth challenges, SOCKS, SSE, form, multipart, URLs
```

Each layer imports only the ones below it. `wire` imports `std` and aegis;
`tls` imports `std` alone, and a test reads its sources to hold it to that.
`net` and `tls` are siblings: neither knows the other. The rule is not a
convention: `ci/layers.zig` gives every production source one place in an
ordered list of finer layers, and gantry's lint fails a source that imports
upward or has no place. A second rule bans the spelling of `io.async` and
`Group.async` from `src/` (see "What always holds").

`wire` is public. A program that wants HTTP's syntax without a client, or a
stack of its own, takes the codecs; none of them takes an `Io`, opens a socket
or allocates per message.

## One owner per state

| State | Owner |
|---|---|
| A socket, its layers, its buffers while busy | `transport.Connection`, held by an exchange while busy and by the pool while idle |
| Which connection serves which request; idle sets; per-route counts and waiters | `pool.Pool`, and nothing else |
| The I/O buffers connections and exchanges borrow | `transport.BufferPool` |
| Read and write deadlines | `transport.Timer`: connections store a deadline, the timer enforces it |
| The proxies, and their answers to challenges | `transport.Context` (the proxies), `transport.ProxyAuth` (one answer per proxy, shared by its connections) |
| Answers to servers' 401s | `client.OriginAuth`: per origin, counted by the requests using them, told to `Credentials` once |
| Trusted authorities | `tls.Trust`, shareable between clients, locked inside |
| Cookies | `CookieJar`, the caller's, shareable between clients |
| Name answers | `net.Resolver.Cache` (a client's own) around the caller's or the system's resolver |
| Body framing state | the exchange's `client.Body` |
| Everything a request of one client shares | `client.Shared` |

A lock sits beside the data it guards, in aegis's `BlockingGuarded`, so the
state cannot be reached without it. The few counters read without the lock
(`Pool.count`, the number of kept answers, `Client.stats`) are atomics beside
the lock, and say so where they are declared.

## What always holds

- **`Io` is never stored.** Every call that can block takes `io` right after
  `self`; a `Client`, a pool, a jar or a cache keeps an allocator at most. The
  two readers and writers a connection hands out are std's own adapters.
- **No uplink task waits on work started with `io.async`.** Zig 0.17 no
  longer promises `io.async` runs beside its caller, so a wait on it can be a
  wait on nothing. Work another task waits on is started with `io.concurrent`
  or done inline.
- **No task per connection.** Deadlines, idle expiry and waiting use one timer
  task per client at most, and park when nothing is armed.
- **A warm exchange allocates nothing.** On a kept HTTP/1.1 connection,
  cookies and a kept answer to a challenge included, a small exchange takes
  buffers from the client's pool, writes with one `writev`, reads once and
  looks at the socket once. Two tests count it; neither is timed.
- **A fired deadline poisons its connection.** It reports `TimedOut` and is
  never reused. A cancel during a head leaves nothing in the pool, and a
  cancel during a body closes the connection.
- **Nothing a caller passes can add a line to a request.** Every method,
  target, name and value is checked before a byte is written.
- **Credentials do not leave their origin.** A kept answer is sent to the
  origin it was given for and no other; a redirect that crosses origins drops
  `Authorization`, `Cookie` and `Proxy-Authorization`. Secrets live in aegis
  secret owners and are wiped before they are freed.
- **A client does not move once it has made a request, nor a response once
  its reader has been asked for.** Connections, the timer and the resolver
  point into them. The doc comment of each says so.
- **Every function has a named error set**, and a failable end leaves its
  value valid; `deinit` never fails.

## Decisions

### Messages

- **The HTTP/1.1 parser and the chunked codec are uplink's own.** Framing is
  where request smuggling lives, so the grammar is held to the RFC in one
  place: a status is three digits, a `Content-Length` is digits only, `Connection`
  and `Transfer-Encoding` are read as the lists RFC 9110 defines, a chunk size is
  hex digits and overflow-checked, a chunk extension is skipped under a cap
  (4 KiB), and a head is capped (64 KiB). Heads are parsed in place, lines found
  thirty-two bytes at a time, values checked for control characters sixteen at
  a time, and the twenty names the client reads indexed once, so a lookup of
  `content-length` is a field read. The response parser is held, on fixed and
  random heads, to a reference written from the RFC's grammar.
- **Strict in what it writes, lenient in what it reads.** Requests are
  validated whole before they are sent. Responses accept a bare LF and unfold
  an obsolete folded value, which RFC 9112 permits a recipient and which real
  servers send. `h1.Lenience` names the two modes, `response` and `request`.
- **Framing follows RFC 9112 §6.3 in its order**, and a response whose framing
  is ambiguous (`Transfer-Encoding` beside `Content-Length`, differing lengths)
  is never trusted with another exchange: its connection is closed.
- **Interim 1xx responses are skipped, except 101**, which is the caller's.
- **The wire layer is public and sans-I/O** so the same grammar serves the
  client, tests (including a reference parser and differential tests) and
  anyone building another stack.

### Connections and the pool

- **A route is where a connection goes**: TLS or not, host (compared without
  case), port, and the proxy it goes through. TLS settings are the client's,
  the same for every route, so they are not part of the key. Connections with
  equal routes are interchangeable.
- **The most recently used idle connection is taken first.** It is the one most
  likely still open at the server. An idle list is allocated once, at its cap;
  keeping and taking a connection allocate nothing after that. One idle longer
  than `idle_timeout` is closed instead of used.
- **A kept connection is looked at before it is used**: one `recv` that peeks
  and does not wait, so an end or stray bytes close a plain connection (a TLS
  one leaves its bytes to the session). On Windows the look is a read through
  the `Io` that does not wait. The old way, noticing a stale connection at the
  write and sending again, misses the streaming `begin`, and costs a failed
  write; the look is the fast path and a single resend stays for the race
  between the look and the write, allowed only when no response byte arrived.
- **A route may be limited**, and past its limit a request waits first come
  first served, until a connection comes back or closes, its deadline passes or
  its task is canceled. A connection given back goes straight to the first
  waiter.
- **A response released with a little of its body unread reads it**, up to
  `drain_limit` (64 KiB), within the activity timeout, so the connection can be
  kept instead of closed.
- **An idle connection holds no I/O buffer of its own.** Buffers come from the
  client's `BufferPool` in three sizes (4 KiB, one TLS record, 72 KiB) and go
  back when the connection is put away; a response's head, its fields and its
  body reader share one buffer, and a decoder with its window another. The
  pool keeps a bounded number of each size, threaded through the free buffers
  themselves.
- **`Pool.Kind` is a union** that has an arm for HTTP/1.1 only. Another
  protocol joins as an arm of its own, and the pool's rules (routes, limits,
  waiters) stay as they are. `wire.Version` carries `h2` and `h3` so a
  `switch` written now stays exhaustive.
- **Layers on a connection are what the route needs, in order**: TLS to an
  `https` proxy, a `CONNECT` tunnel or a SOCKS negotiation, TLS to the server.
  A request to an `http` server through an HTTP proxy goes in absolute form
  instead. SOCKS4 refuses an IPv6 host; 4a and 5h leave resolving to the proxy.

### Time

- **Deadlines are per operation, not a task per connection.** `connect` covers
  the lookup and every attempt, `handshake` each TLS handshake, `CONNECT`
  exchange and SOCKS negotiation, `activity` any read or write that moves
  nothing, `low_speed` a connection that moves too little over a window, and a
  request's own `timeout` everything from waiting for a connection to the last
  read of its body, retries and redirects included. The nearest deadline of an
  operation is an atomic store on its connection; `transport.Timer` shuts the
  socket of one that is past it. The task ticks at a tenth of the shortest
  timeout while anything is armed and parks otherwise, so an idle client costs
  no wakeups and an operation with no deadline reads no clock.
- **Why a timer at all.** Zig 0.17's `Io.Threaded` cannot bound a socket
  operation everywhere: on Windows a timed read or write is refused, on POSIX
  a timed write waits only for the socket to take bytes and then blocks in
  `sendmsg` while the peer keeps its window shut, and the connect timeout is
  not implemented on any system. An abandoned connect is canceled through the
  task it runs on.
- **Without a task to spare the client degrades and says so**: reads are
  bounded by `Io.operateTimeout` where the `Io` can, connects are not bounded,
  `Dialed.timeout_enforced` is false, and `Client.stats().timeouts_unenforced`
  counts what was not kept. A timeout that cannot be kept is reported, not
  assumed.
- **Instants on the awake clock are a type of their own** (`transport.awake`),
  stored as `i64` nanoseconds in the atomics the timer and pool keep. A time
  from another clock cannot meet one, spans are checked, and a deadline too far
  off to hold is the latest instant instead of an overflow.
- **Every wait is `io.sleep` or a timed wait on the `Io`**, so tests move time
  by hand with shakedown's `Clock`, and a wait is cancelable.

### Names and dialing

- **A lookup runs as a task of its own while the caller drains it.** std's
  lookup puts its answers one at a time into a queue, and run inline with
  nothing draining the queue it waits on itself once a name has more answers
  than the queue holds. `getaddrinfo` puts every result libc gives, and std's
  own DNS client puts one per record and one per line of the hosts file,
  whatever its documented bound. With no task to spare, a libc target calls
  `getaddrinfo` on the caller's task into a bounded slice; any other target
  returns `ConcurrencyUnavailable` for a name (an address needs no lookup).
  It does not hang.
- **Happy Eyeballs is uplink's own** (RFC 8305): the addresses are ordered
  with the families alternating from the first the resolver gave, attempts
  start one at a time, each `attempt_delay` (250 ms) after the last or at once
  when it fails, and the first to connect wins while the rest are canceled. std's
  `HostName.connect` is not used, because it starts its attempts with
  `io.async`. The delay is armed beside an attempt and a delay outrun by a
  failure is recognised as stale by the count of attempts it was armed at.
  Without a task to spare the addresses are tried in turn. A broken IPv6 path
  costs a quarter second, not a timeout, and a healthy host is not hit with a
  connection per address.
- **The test for the delay runs on a manual clock**, so its bound is exact: the
  second attempt starts exactly one delay after the first, one millisecond
  short of it starts nothing, and a refusal starts the next attempt with the
  clock not having moved.
- **Resolvers stack.** A `Resolver` is a context and a function; `Static`
  answers chosen names, as a pinned address does, and passes the rest on;
  `Cache` keeps answers for a minute and wraps another. A client keeps a cache by
  default.
- **Sockets are tuned in one place** (`net.sys`): `TCP_NODELAY` on by default,
  keepalive when asked, `SO_NOSIGPIPE` where the system has it, because a
  library cannot count on its program having ignored the signal. Everything
  else uplink does to a socket goes through the caller's `Io`.

### Policy

- **Redirects are followed, up to ten, and the default is the safe one.**
  301 and 302 turn a POST into a GET, 303 turns anything but HEAD into one,
  307 and 308 keep the method and send the body again, or fail with
  `BodyNotReplayable` when it came from a reader. `https` to `http` fails
  with `InsecureRedirect` unless allowed. A hop that leaves the origin drops
  the credentials and cookies, and the jar judges the cookies again for each
  hop.
- **Retries are opt-out for connections and opt-in for statuses.** A failure
  before any byte of a response is retried (three attempts, full-jitter
  backoff) when nothing of the request was sent or its method is idempotent
  and its body replayable. A status is retried only when `Retries.statuses`
  names it, after `Retry-After` when there is one; a wait that does not fit
  the request's deadline returns the response instead. The resend on a stale
  kept connection is outside the attempt count.
- **A 401 is answered once per origin and the answer kept.** `Credentials`
  fills it; Basic, Digest or Bearer goes with every later request to that
  origin and no other. The store is told once whether the answer was taken (the
  first response that is not a 401) or refused, which is what a credential
  helper needs to approve or reject it.
- **One interception point, not a middleware chain.** `Prepare` sees every
  attempt after redirects and before the write, so a signature is made again
  for each. `Observer` is told every step with its timing. Neither can change
  what the client owns.
- **Compression is not uplink's.** gzip, deflate and zstd are decoded by std's
  decoders, with the zstd window capped by an option (one buffer is kept for
  the next zstd body, taken and given back with one atomic swap).
  `Accept-Encoding` is set from what is enabled. Brotli is not decoded: such a
  body is handed over as it came, with its `Content-Encoding`.
- **Cookies follow RFC 6265bis** and the Netscape cookie file. The public
  suffix list is a seam (`Options.public_suffix`), not a table in the package;
  without one a cookie for a domain of one label is refused.

### TLS

- **TLS is std's client with client authentication added.** `tls/Client.zig`
  is a copy of std's, held byte for byte to std plus a recorded diff by a
  test (`zig build check-tls-fork`; `tls-fork` records it again), so each Zig
  release's fixes are brought across and cannot be missed. It answers a
  server's request for a certificate with RSA (PKCS #1 v1.5 and PSS), ECDSA on
  P-256 and P-384, or Ed25519, from PKCS #8, PKCS #1, SEC 1, encrypted PKCS #8
  and OpenSSL's older encrypted PEM.
- **Every TLS layer a connection stacks is a `tls.Session`.** What is above it
  does not know whose client is underneath, so the client can change without
  the connection changing.
- **`Trust` is shared.** Several clients may point at one, so a process reads
  the system's authorities once, not once per client; without one a client
  reads them at its first verifying handshake. Each handshake checks
  certificates at the current real time.
- **Key logs are explicit.** A writer in the options, never the environment.
  Tests, and users, are not subject to a stray variable.
- **The environment is never read by uplink.** `Proxy.fromEnvironment` takes the
  environment it is given. Programs differ in variables, default port and what
  `no_proxy` can name, so the rules are a parameter.

## Tests

The suite proves behaviour with fakes first and a peer where a peer is the
point. The shape is in the README; what the design depends on is:

- **Counts are tests, timing is not.** Allocations per warm exchange and the
  syscalls of a small one are asserted on shakedown's counting allocator and
  layered `Io`; benchmarks are compiled by CI and timed by hand.
- **Time is moved by the test.** Timeouts, the delay between attempts and the
  stepped clock a certificate is checked at all run on shakedown's `Clock`.
- **Concurrency is varied.** Every timeout runs with a task to spare and
  without, and the lookup is run against a resolver that answers one address at
  a time.
- **Peers are real where they are the proof**: `openssl s_server` for TLS 1.3
  and 1.2 and every key kind and format, with certificates made per run in a
  scratch `HOME`; a proxy and a server of the test tree for the rest.
- **Hostile input is a table**, not luck: framing smuggling cases, oversized
  heads, chunk sizes that overflow, folded and bare-LF heads in both modes.

## Left out, and why

- **HTTP/2, a server, WebSocket and a TLS engine of uplink's own** are not in
  the package. The seams above (the pool's `Kind`, `Version`, the `Session`
  layer) are where they join.
- **HTTP/3** belongs to a QUIC package of its own: QUIC is a transport, as large
  as this package, with users that have no HTTP.
- **NTLM, Negotiate and SOCKS5 GSSAPI** need the system's SSPI or GSSAPI. **PAC
  files** need a JavaScript engine. **OCSP** is gone from the ecosystem in favour of
  short-lived certificates. **0-RTT** carries replay risk.
- **No client pipelining.** Head-of-line blocking and broken intermediaries.
- **No HTTP cache, no JSON.** A store is a different concern, a layer above the
  client; JSON belongs to the JSON library, and uplink hands over readers and
  bytes.
- **No local address to bind**: Zig 0.17's `Io` has no bind before connect.
- **No `.netrc`**, no bandwidth limit (the caller throttles its reader or
  writer), no IDNA (callers pass punycode).
- **No event loop of its own.** uplink makes only `Io` calls on sockets, apart
  from the socket options and the inline `getaddrinfo`, and runs on the `Io` it
  is given. Zig 0.17's evented `Io`s on Linux and macOS cannot open a TCP
  connection yet, so it runs on `Io.Threaded` there.
