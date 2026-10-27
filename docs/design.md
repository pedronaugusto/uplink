# uplink design

uplink is an HTTP/1.1 client and server with the codecs they are built from. This page says
how it is put together and why: the layers, who owns which state, what always
holds, and the decisions that shaped it. The README says what it does and how
to use it.

## Layers

```
 server     Server, its connections, Request, Response, Handler; Router and the
            comptime routes; Files
 client     Client, Request, Response, Outgoing; the policy: redirects, retries,
            origin authentication, cookies, decoding, hooks
 pool       which connection serves which exchange: idle sets, route limits, waiters
 coding     warp's decoders and encoders, a body's codings undone or applied
 transport  one connection: TCP, then TLS to a proxy, a CONNECT or SOCKS tunnel,
            TLS to the server; deadlines; the buffers connections borrow; a
            body as its framing delimits it; a head gathered from a socket
 net        names and sockets: lookup, resolvers, Happy Eyeballs, socket options
 tls        how connections use cloak's TLS: client options, what an alert says
            about a client certificate, the shape of the buffers
 wire       sans-I/O codecs: HTTP/1.1 heads and bodies, fields, dates, cookies,
            auth challenges, SOCKS, SSE, form, multipart, URLs
```

Each layer imports only the ones below it. `wire` imports `std` and aegis;
`tls` imports `std` and cloak, the family's TLS; `net` and `transport` import
reactor, the evented `std.Io`, for the sockets' deadlines, name lookup and
connecting. `net` and `tls` are siblings: neither knows the other. The rule is not a
convention: `ci/layers.zig` gives every production source one place in an
ordered list of finer layers, and gantry's lint fails a source that imports
upward or has no place. A second rule bans the spelling of `io.async` and
`Group.async` from `src/` (see "What always holds").

`wire` is public, and it is a module of its own, `uplink.wire`. A program that
wants HTTP's syntax without a client, or a stack of its own, takes the codecs;
none of them takes an `Io`, opens a socket or allocates per message.

## Modules

Two modules are published. `uplink.wire` is `src/wire.zig` and what it
reaches, on `std` and aegis. `uplink` is everything else on top of it, and
re-exports it as `wire`. The client imports the codecs through the module, never
by path, so a type is one declaration whichever name a program reaches it by,
and the compiler holds `wire` to its two imports.

Why a module and not only the layer: Zig analyses what is used, so a program
that imports `uplink` and calls the codecs compiles none of the client. What
it does not avoid is fetching: a build that reaches `uplink` fetches reactor,
cloak and warp with it. A separate module buys something only where a part's dependencies
should not be fetched by those who do not use it, and the codecs are such a part:
a server or a proxy parsing HTTP/1.1 has no use for the client's runtime or its
TLS. `tls`, `net`, `transport`, `coding`, `pool` and `client` are not modules:
they share reactor, cloak and warp, and no user wants one without the rest.

The build has one option, `client`, true unless a project says otherwise.
reactor, cloak and warp are lazy dependencies, requested only when it is true, so the common
user, who builds the client, writes nothing and gets the whole package, and
a wire-only user writes `.client = false` and fetches aegis and nothing more. With
it false the `uplink` module is not defined: it cannot be built without the
runtime. The default is the client's because that is the package's purpose; a program
that wants less says so.
`zig build check-consumer` builds a project of each kind from the package's
directory with fetching off and only the packages that kind needs in the package
directory; `check-wire-consumer` is the wire-only one, with aegis alone, so a
build script or module that reached for reactor, shakedown or preflight fails
there. `wire`'s own tests run as the root of their own build (`src/wire_test.zig`),
because a module's tests run only from the build that has it as root.

## One owner per state

| State | Owner |
|---|---|
| A socket, its layers, its buffers while busy | `transport.Connection`, held by an exchange while busy and by the pool while idle |
| Which connection serves which request; idle sets; per-route counts and waiters | `pool.Pool`, and nothing else |
| The I/O buffers connections and exchanges borrow | `transport.BufferPool` |
| Read and write deadlines | reactor's `net.Deadlines`, held by `transport.Context`: a connection hands it each operation's nearest deadline |
| The proxies, and their answers to challenges | `transport.Context` (the proxies), `transport.ProxyAuth` (one answer per proxy, shared by its connections) |
| Answers to servers' 401s | `client.OriginAuth`: per origin, counted by the requests using them, told to `Credentials` once |
| Trusted authorities | cloak's `Trust.Snapshot`, immutable and shared between clients; the system's one is `transport.Context.SystemTrust`'s |
| Cookies | `CookieJar`, the caller's, shareable between clients |
| Name answers | `net.Resolver.Cache` (a client's own) around the caller's or the system's resolver |
| Body framing state | the exchange's `client.Body` |
| Everything a request of one client shares | `client.Shared` |
| What a server's connections share: options, buffers, encoders, deadlines, counters, the live list | `server.Context` |
| One served connection's socket, TLS session and wait | `server.Socket` |
| The patterns and their tree | `server.Router` |

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
- **No task per connection.** Deadlines, idle expiry and waiting use at most one
  task per client, and none on a reactor runtime, where the kernel keeps them.
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
  case), port, and the proxy it goes through. It holds its host by value, in
  a bounded array the size of the longest host name, so a copy of a route is
  whole on its own: nothing it names can be freed under it, as a host slice
  into a closed connection once was. TLS settings are the client's,
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
- **`Pool.Kind` is a union** with one arm, HTTP/1.1; the pool's rules (routes,
  limits, waiters) do not depend on the protocol. `wire.Version` names `h2` and
  `h3` so that a `switch` over it is exhaustive.
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
  operation goes to reactor's `Deadlines` with the operation. On a reactor
  runtime it is the kernel's: the operation ends at its deadline and no task
  watches. On any other `Io` it is an atomic store on the connection, and one
  task per client shuts the socket of one that is past it; the task ticks at a
  tenth of the shortest timeout while anything is armed and parks otherwise, so
  an idle client costs no wakeups. Either way an operation with no deadline
  reads no clock.
- **Why a task on other `Io`s.** Zig 0.17's `Io.Threaded` cannot bound a socket
  operation everywhere: on Windows a timed read or write is refused, on POSIX
  a timed write waits only for the socket to take bytes and then blocks in
  `sendmsg` while the peer keeps its window shut, and the connect timeout is
  not implemented on any system. reactor's connect keeps its timeout in the
  kernel on a runtime and, on any other `Io`, abandons the attempt by canceling
  the task it runs on.
- **Without a task to spare the client degrades and says so**: reads are
  bounded by `Io.operateTimeout` where the `Io` can, connects are not bounded,
  `Dialed.timeout_enforced` is false, and `Client.stats().timeouts_unenforced`
  counts what was not kept. A timeout that cannot be kept is reported, not
  assumed.
- **Every span uplink takes or reports is aegis's** (`Duration`, nanoseconds,
  never negative): a timeout, a delay, a keepalive, a lifetime, and what the
  observer is told a step took. It reads and writes the same text a command
  line or a configuration file would (`30s`, `250ms`), a default is written
  so (`.literal("90s")`), and it logs with `{f}`. Sizes are aegis's `Bytes`
  the same way (`max_head`, `drain_limit`, the zstd window). std's
  `Io.Duration` is met only where an `Io` call takes one.
- **Instants on the awake clock are a type of their own** (`transport.awake`),
  stored as `i64` nanoseconds in the pool's idle list. A time
  from another clock cannot meet one, spans are checked, and a deadline too far
  off to hold is the latest instant instead of an overflow.
- **Every wait is `io.sleep` or a timed wait on the `Io`**, so tests move time
  by hand with shakedown's `Clock`, and a wait is cancelable.

### Names and dialing

- **A lookup is reactor's.** std's lookup puts its answers one at a time into a
  queue, and run inline with nothing draining the queue it waits on itself once
  a name has more answers than the queue holds: `getaddrinfo` puts every result
  libc gives, and std's own DNS client puts one per record and one per line of
  the hosts file, whatever its documented bound. reactor's `net.resolve` never
  puts more than its queue holds on a runtime, runs as a task of its own
  elsewhere, and with no task to spare a libc target calls `getaddrinfo` on the
  caller's task into a bounded slice while any other target returns
  `ConcurrencyUnavailable` for a name (an address needs no lookup). It does not
  hang. The limit on a lookup is uplink's: it races the lookup against a sleep
  within the `connect` budget.
- **Happy Eyeballs is uplink's own** (RFC 8305): the addresses are ordered
  with the families alternating from the first the resolver gave, attempts
  start one at a time, each `attempt_delay` (250 ms) after the last or at once
  when it fails, and the first to connect wins while the rest are canceled. std's
  `HostName.connect` is not used, because it starts its attempts with
  `io.async`. Each attempt is reactor's `net.connect` ending at the one
  deadline, so a single address is dialed on the caller's own task, with no
  task beside it on a runtime. The delay is armed beside an attempt and a delay
  outrun by a failure is recognised as stale by the count of attempts it was
  armed at. Without a task to spare the addresses are tried in turn. A broken IPv6 path
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
- **A socket's options are reactor's** (`reactor.net.SocketOptions`): the
  client's are set before its connect (`Dial.socket`), where the buffers fix
  the window scale; a server's on each accepted socket (`setOptions`).
  `TCP_NODELAY` is on by default, `SO_NOSIGPIPE` set where the system has it,
  because a library cannot count on its program having ignored the signal. A
  refused option is named: a dial returns it at once (the same for every
  address), and a server closes that connection and tells its observer
  (`option_refused`). A local address or interface goes to reactor's connect,
  and Happy Eyeballs then tries only the addresses of the local family.
  Everything else uplink does to a socket goes through the caller's `Io`, or
  through reactor's networking over it.

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
- **Compression is warp's, and every check it offers is made.** gzip,
  deflate and zstd are decoded by warp's streaming decoders (`coding`):
  gzip's CRC-32 and length, zlib's Adler-32 and zstd's content checksum are
  verified, a gzip body of several members is read whole, a stream cut short
  is refused, and a body under several codings is undone last first. HTTP's
  `deflate` is zlib, and a raw stream sent under the name is read too. std's
  decoders were not enough: they read gzip's and zlib's checksums without
  comparing them, and zstd's not at all. The zstd window is capped by an
  option; one buffer sized for the cap is kept for the next zstd body, taken
  and given back with one atomic swap. `Accept-Encoding` is set from what is
  enabled. Brotli is not decoded: such a body is handed over as it came, with
  its `Content-Encoding`.
- **Cookies follow RFC 6265bis** and the Netscape cookie file. The public
  suffix list is a seam (`Options.public_suffix`), not a table in the package;
  without one a cookie for a domain of one label is refused.

### The server

- **The server is a DAG of its own.** `Context` holds what connections share
  and knows nothing of requests; `Socket` is one connection's I/O and its
  deadlines; `Request` and `Response` sit on a `Socket`; `Handler` names
  them; `Connection` is the loop that reads requests and calls the handler;
  `Server` accepts. Nothing imports upward, so the response cannot reach the
  accept loop and the context cannot reach a handler.
- **One way to time an operation.** The client's connections and the
  server's share `transport.Timed`: an operation and its deadline, kept by
  reactor's `Deadlines` or the `Io`'s own timeout, or counted as unkept.
  Each side only decides which deadline: the client the nearest of its
  limits, the server the wait it is in (handshake, idle, head, answer).
- **One way to read a head.** `transport.Head` gathers a head into a pooled
  buffer with room for its fields and a body buffer, taking exactly its bytes
  from the connection, for the client's responses and the server's requests
  alike, so a head's fields never point into a buffer the body read refills.
- **A head timeout ends the connection without a 408.** A deadline that
  fires poisons its socket, as on the client, so nothing can be written
  after it: the client of a slowloris gets a closed connection, as nginx and
  Go give it.
- **Nothing goes out before it must.** A response's fields are kept as their
  lines until the head goes, at the first drain of its 4 KiB body buffer or
  at `end`, so a handler sets status and fields in any order and a small
  body gets its `Content-Length` counted. A declared length is held to.
- **A failure is never a short success.** Before the head, a 500; after it,
  what went out is flushed and the connection closed without a chunked
  body's last chunk.
- **A connection ends with a FIN, then a short read** (RFC 9112 §9.6). The
  server shuts its sending side and reads and drops what the client still
  sends until the client ends its side or `timeouts.linger` runs out: closed
  with bytes unread, a socket is reset, and a reset can reach the client
  before the server's last bytes do (on Windows it always takes them).
- **Shutdown knows which connections are idle.** The live list marks a
  connection idle under its lock while it waits for a request; `shutdown`
  ends those sockets at once and gives the rest their grace.
- **Compression is negotiated, not assumed.** The client's weights decide
  between the codings offered, ties going to the server's order; a body
  shorter than `min_size`, of a type not listed, already coded, partial or
  for a `HEAD` goes as it is; a whole body is compressed into a buffer and
  sent with its own length when that is shorter, a streamed one is chunked.
  Encoders live in pooled blocks of their own.
- **No `sendfile`.** `Io.Writer.sendFile` goes through `netWriteFile`, which
  no deadline bounds; a file is read and written through the response's
  writer with the activity timeout kept, until reactor's deadlines cover it.

### Routing

- **Go 1.22's semantics, one implementation.** `Pattern` parses a pattern
  and relates two of them (equivalent, more specific, more general,
  disjoint, overlapping), purely, so the runtime `Router` and the comptime
  `Routes` refuse the same conflicts, one at `add`, the other at compile
  time.
- **A tree of segments.** Literal children are sorted for a binary search;
  one wildcard child serves every name, the names belonging to the pattern;
  the routes that end at a node, take the rest from it or end with `{$}` sit
  on it. A match tries literal before wildcard before the rest and backs out
  of a branch with no route for the method; conflicts having been refused,
  the first route found is the most specific. A match allocates nothing;
  captures are unescaped into the request's scratch buffer.
- **Comptime routes are an ordered list.** The patterns are sorted at compile
  time, the more specific first, and matched in that order with every
  literal comparison unrolled; a handler's captures are a struct made from
  its pattern.
- **Both routers answer alike.** `Router.dispatch` does the cleaning
  redirects, the subtree redirect, the 405 with `Allow` and the 404 for any
  table with `find`, `run` and `notFound`.

### WebSocket

- **Above both, known to neither.** `ws` imports the client and the server;
  they hand over an upgraded stream (`Response.upgrade`, `Response.hijack`)
  and know nothing of WebSocket. The codec (`wire.ws`) is sans-I/O. On
  HTTP/2, `hijack` after a 2xx to an extended `CONNECT` hands over the
  stream instead of the connection, and a WebSocket over it is the same
  `Conn`. The client's side is the same: a request with `protocol` is an
  extended `CONNECT`, and `upgrade` after its 2xx hands over the stream
  (`Upgraded.carrier`), its writes DATA through a buffer of the pool and
  its reads through one, as a connection's are.
- **The client asks HTTP/2 first, as it negotiates anything.** `connect`
  sends an extended `CONNECT` when the client speaks HTTP/2; the client
  waits for the server's first SETTINGS before it does (RFC 8441 §3), and
  a connection in HTTP/1.1 or a server without
  `SETTINGS_ENABLE_CONNECT_PROTOCOL` refuses it with nothing sent
  (`ExtendedConnectUnsupported`), so `connect` asks by `Upgrade` next, on
  the HTTP/1.1 connection kept for it. Not a fallback that hides a
  failure: the two forms are one handshake in two versions, as ALPN picks
  a version.
- **A message is a stream.** The reader yields a message's payload as it
  arrives across its frames, answering control frames between them, so a
  message of any size costs its reader's buffer, and the limits are checked
  as bytes come, never after.
- **No task watches.** A keepalive is the reader's: a wait for a frame with
  `ping_interval` asks the stream whether anything came, without a deadline
  that would end it, pings, and closes after a second silence.
- **A server keeps no compressor between messages by default**
  (`no_context_takeover`): a kept DEFLATE state costs its memory per
  connection.

### Reverse proxy

- **A handler above both, as `ws` is.** `proxy.Proxy` is a server
  `Handler` that sends each request on through a `Client` and writes back
  what came; neither knows it. Go's `httputil.ReverseProxy` is the model,
  without what Go keeps for compatibility (`Director`, `X-Forwarded-*`).
- **One hop, said once.** The fields that belong to a connection are not
  forwarded either way: `Connection` and the fields it names, `Keep-Alive`,
  `Proxy-Connection`, `TE` (except `trailers`), `Trailer`,
  `Transfer-Encoding`, `Upgrade`, `Proxy-Authenticate` and
  `Proxy-Authorization` (RFC 9110 §7.6.1). `Host` and `Content-Length` are
  each side's to write. The proxy appends itself to `Forwarded` (RFC 7239:
  `for`, `host`, `proto`), after any element the request carried.
- **Bytes pass as they came.** The request's body is read with its codings
  on (`Request.rawReader`) and sent with the length the server holds it to
  (`Request.length`), or in chunks; the response's is written back the same way, its length
  declared when the upstream gave one and announced no trailer. Neither
  side decodes: a request names its own `Accept-Encoding`, so the client
  undoes no coding it did not offer (Go's rule), and a request that came
  without one is sent with `identity`, which is what it can read. A body
  streams; nothing is gathered whole.
- **The upstream's answer, unchanged.** No redirect is followed and no
  status tried again (`redirects = .none`, `retries = .none`): the client
  behind the proxy decides. A kept connection found stale is still sent
  once more, as the client always does, for a request that can be. The
  response's trailer goes back as its trailer.
- **A failure has its status.** An upstream that cannot be reached or
  breaks before its head is a 502, one that runs out of time a 504, a
  request whose own body was at fault its 400 or 413. A cancel is the
  handler's `Canceled`, never a status. After the head went out, a failure
  ends the connection, as any handler's does, so the client sees a cut
  body, never a short success.
- **Where to is the caller's, by an embedded hook.** The common case is
  one upstream: its scheme, authority and path prefix, the request's path
  and query joined after it. A `Rewrite`, embedded in the caller's type and
  found by `@fieldParentPtr`, sees the request and changes the outbound
  URL and fields instead.
- **The client is the caller's, and keeps nothing of its own.** A cookie
  jar would add cookies to requests that came without, and credentials
  would answer the upstream's 401s for someone else: `Proxy.init` refuses
  a client with either. A cache is the caller's choice.
- **An upgrade passes through.** A request asking an HTTP/1.1 connection
  to switch is sent with its `Upgrade` (never `h2c`, the hop's own); the
  upstream's 101 to the same protocol is the client's 101, and each
  connection's bytes go to the other (`Response.upgrade`, `hijack`) on a
  task each way, both had before the 101 goes, until either end ends. A
  101 to another protocol is a 502.
- **Not yet:** a request's trailer (the client sends none), a WebSocket
  over HTTP/2's extended `CONNECT`, and `CONNECT` itself, which is a
  forward proxy's (a 501).

### HTTP/2

- **The protocol is sans-I/O.** `wire.h2.Connection` holds the settings,
  streams, windows and HPACK tables in memory its caller gives, takes whole
  frames, answers what the protocol answers by itself onto a writer, and
  returns events. The server's driver is one reading task, one sending task
  and a task per stream; nothing in the codec knows which.
- **A stream's data waits in a buffer no larger than its window.** The
  window is given back as the handler reads, so a slow handler slows its own
  stream and no other.
- **Every limit is a test of the attack it stops.** Streams at once,
  header-block bytes across CONTINUATION frames, the decoded header list,
  resets, SETTINGS, PINGs and empty frames per window of frames.
- **One lock, one condition, no write under the lock.** Frames are encoded
  into an outbox under the session's lock, the protocol state behind it, and
  one task at a time writes the outbox to the socket with the lock let go:
  on the server a sending task of its own, on the client whichever request
  finds no one writing. An end that held its lock across a socket write
  could not read while the write waited, and two such ends stop each other
  once the socket buffers between them fill. A stream waits for room past a
  high-water mark; the reading task never waits. A stream waiting for its
  window, its data or room waits on one condition the reading and sending
  tasks broadcast.
- **The client has no reading task.** A connection shared by requests that
  each run on their caller's task is read by whichever of them waits: it
  takes a token, reads one frame with the lock let go, hands the frame to the
  protocol state under the lock, and gives the token back, waking the rest.
  A frame is read only once the socket has something, waited for without a
  deadline that would end the socket, so a request that gives up gives up its
  turn and nothing else. A connection costs no task while it sits idle.
- **One way to say what HTTP/2 refuses.** `wire.h2.message` checks request,
  response and trailer blocks and turns HTTP/1.1 field lines into fields,
  dropping those of a connection's own; the server and the client both use
  it.
- **HTTP/2 over TLS rests on a full-duplex session.** A connection reads in
  one task while others write; cloak's `tls.Session` (0.5.0 on) keeps the two
  halves apart, so both ends offer `h2` first by ALPN.

### HTTPS records

- **An `https` origin is dialed as its HTTPS records say** (RFC 9460), when the
  resolver reads them: `Resolver.serviceFn`, which `Dns` fills and the
  system's lookup leaves null. The records live under the host on 443 and
  under `_port._https.host` elsewhere; AliasMode is followed, ServiceMode
  records beside an alias are ignored, and those a client can use (every
  mandatory key known) come back most preferred first, a target of "." being
  the record's own name. The dialer (`dial.dialHttps`) takes each endpoint
  that speaks a protocol the connection offers, at its target and port, the
  target's addresses or else its hints, all within the `connect` budget, and
  the connection offers by ALPN only the protocols both speak. When every
  endpoint fails the origin is dialed as it is (SVCB-optional), unless one of
  them publishes ECH: that bare dial would put the hidden name on the wire.
  Records that cannot be had are none (RFC 9460 §3); a failed allocation is
  an error.
- **The cache keeps records beside addresses**, none included, for its TTL,
  so a client asks once per name per minute rather than once per
  connection. A `Static` name is reached at its addresses alone: it has no
  binding to send it elsewhere.
- **Through a proxy no record is asked for**: the proxy finds the target, and
  a local lookup would show the name a SOCKS5h proxy is chosen to hide. An
  `http` URL is not upgraded by a record (§9.5): that would change the
  request's scheme under the caller.

### TLS

- **TLS is cloak's, and uplink owns only its HTTP side.** The engine, the
  certificates, the keys and the authorities live in cloak, which fixes its own
  bugs and measures its own handshake; what is left here is `tls.ClientOptions`
  (what a client takes), the reading of an alert as a client certificate's
  refusal, and the size of a record buffer. A connection opens a
  `cloak.tls.Session` for each TLS layer it stacks, over the reader and writer
  below, so a tunnel inside TLS inside TCP is the same code as TLS alone, and
  a handshake that fails reports its alerts through the session's diagnostics.
  An end of stream without close_notify ends a body cleanly, since HTTP says
  where a body ends.
- **TLS 1.2 is cloak's too.** A server that speaks nothing newer is answered
  in TLS 1.2 with ECDHE, AEAD suites and the extended master secret; RSA key
  exchange, CBC and legacy suites are refused by cloak, not filtered here.
- **Resumption is on by default, both ends.** A client keeps one
  `cloak.tls.SessionCache`, made at its first handshake that can use it and
  keyed as cloak keys it (server name, identity, ALPN, the verification
  policy and trust generation, the client certificate), with a namespace
  naming the proxy a target is reached through, so a ticket never links a
  client's proxied connections to its direct ones. A server's own keys
  (`tickets = .own`) are a `cloak.tls.TicketKeys` ring with a fresh key drawn
  at the first handshake that finds none issuing; a ring the caller rotates
  (`.keys`) serves servers that share tickets. TLS 1.2 tickets give up forward
  secrecy between a session's connections and are off unless asked for.
- **Certificate decoders are warp's**, zstd then zlib, their tables (under
  96 KiB, about 11 KiB) allocated for each compressed certificate, since a
  codec has no allocator of its own and two handshakes may decode at once.
  The certificate must fill exactly the length the server declared.
- **ECH comes from the endpoint's record.** Its config list is the
  handshake's `ech`; a refusal by a server that authenticated as the
  config's public name gives retry configs, and the connection is made once
  more on a new socket with them, or with ECH off when there were none (RFC
  9849 §6.1.6). A second refusal is a failure. `.grease` sends GREASE where
  no record gives a config.
- **Authorities are cloak's snapshots.** An immutable `Trust.Snapshot` is
  shared by any number of clients; a client without one builds the system's
  once, at its first verifying handshake, and keeps it until it is deinitialized.
  A reload is a new snapshot. Each handshake checks certificates at the current
  real time.
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
  without. The whole suite runs twice, on `Io.Threaded` and on a reactor
  runtime with worker threads of its own, so what is proved of the client is
  proved of both. The codecs, which take no `Io`, run once, as the root of
  their own build.
- **Peers are real where they are the proof**: `openssl s_server` for TLS 1.3
  and 1.2 and every key kind and format, with certificates made per run in a
  scratch `HOME`; a proxy and a server of the test tree for the rest.
- **Hostile input is a table**, not luck: framing smuggling cases, oversized
  heads, chunk sizes that overflow, folded and bare-LF heads in both modes.

## Left out, and why

- **A TLS engine of uplink's own** never will be: the `Session` layer
  assumes no one TLS engine.
- **HTTP/3** belongs to a QUIC package of its own: QUIC is a transport, as large
  as this package, with users that have no HTTP.
- **NTLM, Negotiate and SOCKS5 GSSAPI** need the system's SSPI or GSSAPI. **PAC
  files** need a JavaScript engine. **OCSP** is gone from the ecosystem in favour of
  short-lived certificates. **0-RTT** carries replay risk.
- **No client pipelining.** Head-of-line blocking and broken intermediaries.
- **No JSON.** JSON belongs to the JSON library, and uplink hands over
  readers and bytes.
- **The cache sits in the run** (`client/Cache.zig`, RFC 9111): each hop of a
  request asks it, so a redirect's 301 is cached as its target is. A response
  goes into the store as the caller reads it, content-coded as it came (one
  decoder for the network and the store), and is kept only when its body ended
  whole. A store that fails costs the cache, never the request
  (`cache_failed`). No ranges: a 206 is not stored.
- **A store on disk is one file per variant** (`client/CacheDisk.zig`): named by
  the key's hash and the `Vary` values' hash, a header with the times and
  lengths, the key, the values, the head, the body as it came and a trailer
  with the body's length. airlock writes it under a temp name and renames it
  over the variant it replaces, the directory synced after (`Options.level`),
  so a crash leaves the old variant or the whole new one. The index (sizes,
  least recently used order) is held in memory and rebuilt from the
  directory's names at `open`, newest first by write time; a crash's temps go
  then. What a file says is read once, at one boundary (`Framing.parse`), and
  a file that is not a variant of the key asked for is never served: the
  lookup fails by name and the file goes. A holder reads its body from the
  file it opened, so an eviction or a replacement leaves it readable.
- **No `.netrc`**, no bandwidth limit (the caller throttles its reader or
  writer), no IDNA (callers pass punycode).
- **No event loop of its own.** uplink makes only `Io` calls on sockets, apart
  from the socket options, and runs on the `Io` it is given. reactor's runtime
  is the evented one: std 0.17's `Uring` and `Dispatch` cannot open a TCP
  connection, and its `Kqueue` panics on a connect timeout.
