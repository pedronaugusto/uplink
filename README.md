# uplink

uplink is HTTP for Zig: a client and a server. The client keeps connections for reuse and
shares them between tasks, limits them per route when asked, follows
redirects, tries failed requests again where that is safe, answers servers'
and proxies' challenges, keeps cookies, and goes through HTTP, HTTPS and SOCKS
proxies with TLS to the server inside the tunnel. It presents client
certificates, keeps connect, handshake, activity, low-speed and per-request
deadlines without a task per connection, races a name's addresses by Happy
Eyeballs, sends a host in Unicode as IDNA's ASCII form, and decodes gzip, deflate and zstd bodies with
[warp](https://github.com/pedronaugusto/warp), every checksum verified. The
server reads requests strictly, pipelined ones in order, keeps every wait to a
timeout, terminates TLS, compresses responses, serves files with their
validators and ranges, and routes by Go 1.22's patterns at run time or at
compile time, and proxies to an upstream. Both speak WebSocket and HTTP/2. Both run on any `std.Io` and evented on
[reactor](https://github.com/pedronaugusto/reactor)'s runtime, and allocate
nothing per request once warm. The codecs it is built from, HTTP/1.1 heads and
chunked bodies, header fields, dates, cookies, authentication challenges,
AWS Signature Version 4 (a request signed, a URL presigned, for S3 and
S3-compatible storage), Server-Sent Events, form and multipart bodies and SOCKS,
are public and do no I/O.

## Install

Requires Zig 0.17.0. Fetch with `zig fetch --save
git+https://github.com/pedronaugusto/uplink` and add the `uplink` module to
your module's imports. It depends on `std`,
[aegis](https://github.com/pedronaugusto/aegis),
[reactor](https://github.com/pedronaugusto/reactor),
[cloak](https://github.com/pedronaugusto/cloak),
[warp](https://github.com/pedronaugusto/warp) and
[xenoglyph](https://github.com/pedronaugusto/xenoglyph), the last four fetched
only when the client is built.

The codecs are a module of their own. A program that reads and writes HTTP
messages and has no use for the client, a server, a proxy or a test tool, asks
for less in its `build.zig`:

```zig
const uplink = b.dependency("uplink", .{ .target = target, .optimize = optimize, .client = false });
const wire = uplink.module("uplink.wire");
```

and imports `uplink.wire`. It depends on `std` and aegis alone: no reactor is
fetched, nothing of the client is built, and there is no `uplink` module to ask for. Without `.client = false` both
modules are there, and `uplink` exposes the codecs too, as `uplink.wire`; the
two are the same declarations, not copies.

## Usage

[examples/usage.zig](examples/usage.zig) starts a server with a router on
loopback and sends it a request with a body, on a reactor runtime.

<!-- BEGIN GENERATED zig build docs -- usage -->
```zig
const uplink = @import("uplink");

// Any `std.Io`: here a reactor runtime's, the evented one.
const io = runtime.io();

// A server: patterns with Go 1.22's semantics, routed to handlers,
// each given the request, with what the router captured, and the
// response that answers it.
const Echo = struct {
    fn handle(hio: Io, request: *uplink.server.Request, response: *uplink.server.Response) anyerror!void {
        var buffer: [256]u8 = undefined;
        const body = try request.reader(hio).readSliceShort(&buffer);
        try response.header("Content-Type", "text/plain");
        const w = try response.writer(hio);
        try w.print("{s}: {s}", .{ request.param("name").?, buffer[0..body] });
        try response.end(hio);
    }
};
var router: uplink.server.Router = .init(gpa);
defer router.deinit();
try router.add("POST /echo/{name}", .of(Echo.handle));
var server: uplink.Server = .init(gpa, .{ .compression = .{} }, router.handler());
defer server.deinit(io);
var listener = try (try Io.net.IpAddress.parse("127.0.0.1", 0)).listen(io, .{ .reuse_address = true });
defer listener.deinit(io);
var serving = try io.concurrent(uplink.Server.serve, .{ &server, io, &listener });
defer {
    server.shutdown(io);
    serving.await(io) catch |err| std.log.err("serve: {t}", .{err});
}

// A client for the program: it keeps connections for reuse, follows
// redirects, tries failed requests again where that is safe, and may be
// shared by several tasks. Cookies go in a jar of the caller's.
var jar: uplink.CookieJar = .init(gpa, .{});
defer jar.deinit(io);
var client: uplink.Client = .init(gpa, .{
    .timeouts = .{ .connect = .literal("10s"), .activity = .literal("30s") },
    .cookies = &jar,
    .user_agent = "example/1.0",
});
defer client.deinit(io);

var url_buffer: [64]u8 = undefined;
const url = try std.mem.print(&url_buffer, "http://127.0.0.1:{d}/echo/ping", .{listener.socket.address.getPort()});
var diagnostics: uplink.Diagnostics = .{};
var response = client.send(io, .{
    .method = .POST,
    .url = url,
    .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
    .body = .{ .bytes = "hello" },
    // The whole request, retries and redirects included.
    .timeout = .{ .duration = .{ .raw = .fromSeconds(60), .clock = .awake } },
    .diagnostics = &diagnostics,
}) catch |err| {
    std.log.err("{t} while at {t}", .{ err, diagnostics.stage });
    return err;
};
defer response.deinit(io);

std.debug.assert(response.status == .ok);
const body = try response.collect(gpa, io, .limited(1 << 20));
defer gpa.free(body);
std.debug.assert(std.mem.eql(u8, body, "ping: hello"));
```
<!-- END GENERATED -->

A body can also come from a reader, with its length or in chunks, or be
written by the caller: `client.begin` returns an `Outgoing` whose `writer`
takes it and whose `finish` reads the response. `response.reader(io)` streams
a body instead of collecting it; `wire.sse.Reader` reads Server-Sent Events
from it.

## Design

The package is layered, and each layer owns its state alone: `wire` (the
codecs, sans I/O) under `tls` (the HTTP side of cloak's TLS) and `net`, under `transport` (one connection),
under `coding` (warp's codecs, both ways), under `pool` (which connection
serves which request), under `client` (the policy) and `server`. The layer rule is checked in CI. [docs/design.md](docs/design.md)
gives the layers, who owns which state, what always holds, and the reasons
behind the decisions.

**Requests.** `send` carries a request through the client's policy to its
final response. A redirect is followed up to ten times; 301 and 302 turn a
POST into a GET, 303 turns anything but HEAD into one, 307 and 308 keep the
method and send the body again, or fail with `BodyNotReplayable` when it was
read from a reader. A redirect from `https` to `http` fails with
`InsecureRedirect` unless allowed, and one that leaves the origin drops the
caller's `Authorization`, `Cookie` and `Proxy-Authorization`. A connection
that fails before any byte of a response comes back is tried again, up to
three attempts with a random backoff, when nothing of the request went or its
method is idempotent; statuses such as 429 and 503 are tried again when the
retries name them, after `Retry-After`. A 401 is answered from the caller's
`Credentials`, asked once per origin, and the answer, Basic, Digest or
Bearer, is sent with every later request to that origin and no other; the
store is told whether it was taken, as git's credential helpers want. The answer is kept in aegis secret memory and wiped when it is
forgotten. `Credentials.Netrc` is such a store over a `.netrc`'s text, which
the caller reads: the host's machine, or the file's default. A
`CookieJar` keeps cookies by RFC 6265bis and reads and writes the Netscape
cookie file. A `Cache` (`Options.cache`) is an HTTP cache by RFC 9111, private
or shared, in a `Store` (`Cache.Memory`, bounded by bytes, or the caller's):
a fresh stored response is served with its `Age`, a stale one revalidated with
its validators, a 304 bringing its head up to date; `Vary` keeps a variant per
value, an unsafe method's success invalidates, `only-if-cached` and
`stale-if-error` are kept, and a body is stored as it is read, only when
read whole. `Response.cache` says where a response came from. A `Prepare` hook sees every attempt before it is written, so a
signature is made again for each redirect and retry, and an `Observer` is
told every step with its timing. `Response.url` is where the redirects led,
`Response.trailers` a chunked body's trailer fields, and `Response.upgrade`
the raw connection after a 101 or a `CONNECT`.

**Connections.** A connection is a socket and the layers a route needs on it:
TLS to an `https` proxy, a `CONNECT` tunnel or a SOCKS negotiation, TLS to the
server. A request to an `http` server through an HTTP proxy goes in absolute
form instead. The proxy is one, or the one the environment names per
request, read once per scheme. Idle connections are kept per route,
two by default and sixty-four in all, the most recently used taken first; one
idle ninety seconds is closed rather than used. `max_per_route` limits the connections open
to a route; past it a request waits, first come first served, for one to come
back, until its deadline. Before a kept connection is used its socket is looked
at once, a `recv` that peeks and does not wait (on Windows, a read through
the `Io` that does not wait): a plain connection with its end or unexpected
bytes waiting is closed, and a TLS one leaves its bytes for the session to
read. A request that still fails on a kept connection
before a byte of the response arrives is sent again on a new one, once. A
response released with a little of its body unread, 64 KiB by default, has
it read so its connection can be kept.

**Timeouts.** `connect` covers the name's lookup and the connection,
`handshake` each TLS handshake, `CONNECT` exchange and SOCKS negotiation,
`activity` any read or write that moves nothing, and `low_speed` a connection
that moves too little over a window while a request waits on it. A request's
own `timeout` covers everything from waiting for a connection to the last
read of its body, retries and redirects included. The deadlines are
reactor's. On its runtime each socket operation carries its deadline into the
kernel and no task watches. On any other `Io` a connection stores its
operation's nearest deadline in an atomic, and one task per client shuts the
socket of an operation past it; the task ticks at a tenth of the shortest
timeout while operations are armed and parks when none are, so an idle
client costs no wakeups. Either way an operation with no deadline reads no
clock. `Io.Threaded` needs the task because it cannot bound a socket
operation by itself: on Windows it refuses a timed socket read, on POSIX a
timed write waits only for the socket to take bytes, and its connect timeout
is not implemented anywhere. With no task to spare, reads are bounded by
`Io.operateTimeout` where the `Io` can, connects are not bounded, and
`Client.stats().timeouts_unenforced` counts what was not kept.

**Names.** A name is looked up through a `Resolver`: the system's by default,
or `Resolver.Static` for chosen names, as a pinned address does, and a
cache keeps answers for a minute. The system's lookup is reactor's bounded
one, which never waits on itself the way std's does when its queue fills;
with no task to spare, a libc target calls `getaddrinfo` on the caller's task
and other targets return `error.ConcurrencyUnavailable` for a name. `Dns`
speaks DNS itself when a client is given it: a stub that asks the name
servers of `resolv.conf` (the adapters' on Windows, `Dns.System`) over UDP
and over TCP when an answer is truncated, each wait bounded, or DNS over
HTTPS (`Doh`, RFC 8484) through a client of its own. It asks for AAAA and A
at once, follows CNAMEs, tries the search domains in the C library's order,
and reads HTTPS records (RFC 9460). With it a client dials an `https`
origin as its records say: each endpoint that speaks a protocol the client
offers, most preferred first, at its target and port, the target's addresses
or else its hints, offering only the protocols both speak; then the origin
as it is, unless an endpoint publishes ECH, whose name a bare dial would
show. The cache keeps the records beside the addresses, none included; the
system's lookup reads none. The messages are
`wire.dns`'s, read with every name and pointer bounded, and fuzzed. A name's
addresses are raced by Happy Eyeballs (RFC 8305): one at a time, the families
alternating, each a quarter second after the last or at once when it failed,
and each attempt is reactor's connect, which its runtime ends at the deadline
in the kernel.
`Dial.unix_socket` sends every request to a Unix socket instead, and on
Windows `Dial.named_pipe` to a named pipe (Docker's
`\\.\pipe\docker_engine`), which `Server.servePipe` serves on. No uplink
task waits on work started with `io.async`, which Zig 0.17 no longer promises
runs beside it; a source rule refuses the spelling.

**Messages.** Heads are parsed in place: lines are found thirty-two bytes at
a time, values checked for control characters sixteen at a time, and the
twenty names the client reads are indexed once. Responses are read leniently,
as RFC 9112 allows: a bare LF ends a line, and a folded value is unfolded into
spaces. Framing follows RFC 9112 §6.3 in its order, and a response that names
both `Transfer-Encoding` and `Content-Length`, or differing lengths, is never
trusted with another exchange. Every method, target, name and value a request
carries is checked before a byte is written, so nothing a caller passes can
add a line. A response's head goes into a buffer from the client's pool, its
fields beside it and its body reader's buffer after them; a decoder and its
window share one pooled buffer too, so a response stays small. A connection
put away idle gives its socket buffers back. A small exchange on a kept
connection is one `writev`, one read and one look at the socket, and allocates
nothing, cookies and a kept answer to a challenge included.

**TLS** is [cloak](https://github.com/pedronaugusto/cloak)'s: TLS 1.3, and TLS 1.2 with
ECDHE, AEAD suites and the extended master secret for servers that speak nothing newer.
A client answers a server's request for a certificate with ECDSA on P-256 and P-384,
Ed25519 or RSA keys, read by cloak from PKCS #8, SEC 1, PKCS #1, encrypted PKCS #8
and OpenSSL's older encrypted PEM. `tls.ClientOptions` takes a cloak `Trust.Snapshot` for the
authorities, which clients may share; without one the client reads the system's
once, at its first verifying handshake. Each handshake checks certificates at
the current real time, and a handshake that fails says why in
`Diagnostics.tls_error` and `tls_alert`.

Sessions resume (TLS 1.3, a fresh key exchange each time) from a ticket cache
each client keeps, bounded by `tls.ClientOptions.resumption`, with the
tickets of connections through a proxy kept apart from direct ones; TLS 1.2
tickets only when asked. A server issues tickets from keys of its own, drawn
fresh whenever none issues, or from a ring the caller rotates and may share
(`tls.ServerOptions.tickets`). A client offers certificate compression (RFC
8879) with warp's zstd and zlib decoders, or the caller's. Encrypted Client
Hello (RFC 9849) hides the server's name when its HTTPS record publishes a
config: a server that refuses a stale config with new ones is tried once
more with them, one that has ECH off once more without it, and `ech =
.grease` sends GREASE to every other server. A server takes ECH keys.

**The server.** `Server.serve` accepts on a listener until `shutdown`, each
connection a task of its own; on an `Io` with no task to spare it serves one
connection at a time, and never deadlocks. `serveConnection` serves one a
caller accepted. A request is read strictly, as RFC 9112 asks of a server: a
bare LF or a folded field is a 400, a request with both `Transfer-Encoding`
and `Content-Length`, or whose last coding is not `chunked`, is a 400 that
closes its connection (the request-smuggling class), an HTTP/1.1 request
without exactly one `Host` is a 400, a head past `max_head` (16 KiB by
default) a 431, a body past `max_body` a 413, an expectation other than
`100-continue` a 417. Pipelined requests are answered in order. A `Response`
sends nothing until it must: a body that fits its buffer goes out with its
length counted, a longer one is chunked, a `HEAD` gets the head a `GET` would,
and a handler that fails before its head gets a 500 while one that fails after
it has its connection cut, so its client sees a truncation and never a short
success. `100 Continue` goes out when the handler first reads the body.
Request bodies under gzip, deflate or zstd are decoded, their checksums
verified, and responses of a compressible type are compressed when the client
accepts zstd or gzip (`Options.compression`). Every wait is bounded: the whole
of a request's head (10 seconds, however slowly it trickles in), the time
between requests (60), each read and write while answering (30), the TLS
handshake (10), by the same reactor deadlines the client keeps. `shutdown`
stops accepting, ends idle connections at once, lets requests under way finish
with `Connection: close` for up to `Timeouts.shutdown`, then ends the rest. A
connection the server ends goes with its FIN, and what the client still sends
is read and dropped for up to `Timeouts.linger` (2 seconds), so a refusal is
not lost to a reset.
`Response.hijack` hands the connection to the handler after a 101, and
`trailer` writes a chunked body's trailer. TLS termination is cloak's, client
certificates included.

**Routing.** `server.Router` holds patterns with Go 1.22's `ServeMux`
grammar and semantics: `[METHOD ][HOST]/PATH`, `{name}` for a segment,
`{name...}` for the rest, `{$}` for the end, a trailing `/` for a subtree.
The most specific pattern wins whatever the order they were added in, two
that conflict are refused at `add` naming the first, `GET` serves `HEAD`, a
path that matches only under other methods is a 405 with `Allow`, a path that
is not clean or names a subtree without its `/` is redirected, and segments
are matched with their escapes undone. Patterns live in a tree of segments,
and a match allocates nothing. `server.Routes` takes the patterns at compile
time: a conflict is a compile error, and each handler takes its captures as
a struct, so `captures.id` exists or the program does not build.
`OPTIONS *` is answered 200, and a `CONNECT` to a host and port 405. An
extended `CONNECT` (a WebSocket over HTTP/2) is routed by its path as
method `CONNECT`, so a WebSocket route that takes both versions is added
without a method.

**WebSocket.** `ws.accept` answers a server's request and `ws.connect` opens
one through a `Client`, with subprotocols and permessage-deflate negotiated.
A `ws.Conn` reads messages as streams of their own across fragments,
answering pings and closes between them, checks text as UTF-8 as it
arrives and fails at the frame that breaks it (1007), refuses what RFC
6455 forbids (1002) and what passes its limits (1009), and writes messages
whole or in pieces. One task reads and one writes. A keepalive ping needs
no task: a reader that waits `ping_interval` sends one, and closes after
twice that. Compression is warp's; a server keeps no compressor between
messages by default. Over HTTP/2 both ends speak a WebSocket as an
extended `CONNECT` (RFC 8441), a stream of a shared connection carrying its
frames: the client asks so when it speaks HTTP/2 and the server's settings
allow it, and by HTTP/1.1's `Upgrade` otherwise.

**Reverse proxy.** `ReverseProxy` is a server handler that sends each
request on to an upstream through a `Client` and answers with what came
back, as Go's `httputil.ReverseProxy` does. A connection's own fields stay
behind both ways, `Forwarded` gains the proxy's element, and bodies stream
through as they came, coded or not, with their length and trailer. No
redirect is followed and no status tried again. An upstream that cannot be
reached is a 502, one out of time a 504, and a cancel ends the request with
no answer. An upgrade passes through: the upstream's 101, then each side's
bytes to the other. One upstream URL is the common case; a `Rewrite`
changes where each request goes and what it carries.

```zig
var through: uplink.Client = .init(gpa, .{});
var proxy: uplink.ReverseProxy = try .init(gpa, &through, .{ .upstream = "http://127.0.0.1:9000/api" });
var server: uplink.Server = .init(gpa, .{}, &proxy.handler);
```

**HTTP/2.** The server speaks HTTP/2 by ALPN over TLS, and over plain TCP by
prior knowledge when `Options.h2c` says so. Its frames, HPACK and the
protocol state are sans-I/O in `wire.h2` and `wire.hpack`; the connection's
one reading task feeds them, and each stream's handler runs on a task of its
own through the same `Request` and `Response` as HTTP/1.1. Flow control
goes both ways, a stream's received data waits in a buffer no larger than
the window it was given, and a peer is held to limits on streams, header
blocks across CONTINUATION frames (VU#421644), decoded header lists (the
HPACK bomb), resets per window (Rapid Reset, CVE-2023-44487) and SETTINGS,
PING and empty-frame floods. h2spec passes every case it runs, strict mode
included.

The client speaks HTTP/2 when `Options.http2` allows it: by ALPN over TLS,
and over plain TCP by prior knowledge when it says `.prior_knowledge`.
Requests to one route share one connection, each a stream of its own. No
task reads on its own: a request waiting for its head or its data reads the
next frame for whichever stream it carries, and the others wait their turn,
so a request's deadline ends its own wait and never the connection. A
request the server refused before it processed it goes again on another
connection. `CONNECT`, a request with `Upgrade` and one sent whole to an
HTTP proxy go in HTTP/1.1.

Over TLS both ends offer `h2` first by ALPN: one task reads the session
while the streams write it, which cloak's `tls.Session` allows.

**Files.** `server.Files` serves a directory: `Content-Type` by extension,
`Last-Modified` and a strong `ETag`, the conditional requests of RFC 9110 in
their order, one byte range or several as `multipart/byteranges` (a request
for overlapping ranges past the whole is answered whole), the directory's
index, and nothing outside the root.

**Proxies.** `Proxy.parse` reads `host:port` or a URL with scheme `http`,
`https`, `socks4`, `socks4a`, `socks5` or `socks5h`. `Proxy.fromEnvironment`
picks a proxy for a URL from an environment the caller passes, by one of two
sets of rules (`Proxy.Rules`), which differ in their variables, their default
port and what `no_proxy` can name; uplink never reads the process
environment itself.

## Scope

- No server push, which browsers dropped. There is no TLS engine of
  uplink's own (TLS is cloak's), and HTTP/3 belongs to a QUIC package of its
  own.
- No middleware framework, sessions, templating or JSON binding: a handler
  is a function, and the rest is a program's own. The reverse proxy sends
  no request trailer, and takes no WebSocket over HTTP/2 or `CONNECT`.
- A file is sent through the response's writer, read and written with the
  activity timeout kept: no `sendfile`, which no `Io` bounds by a deadline yet.
- No Brotli decoding: such a body is handed over as it came, with its
  `Content-Encoding`, and a client offers no Brotli for certificates unless
  given a decoder of its own. A server compresses no certificates.
- HTTPS records are read for an `https` origin dialed directly: an `http`
  URL is not upgraded by one (RFC 9460 §9.5), and through a proxy, which
  finds the target itself, none is asked for.
- No NTLM, Negotiate, PAC files or OCSP. The HTTP cache serves no ranges:
  a 206 is not stored.
- No public suffix list: a `CookieJar` takes one through
  `Options.public_suffix`, and without one refuses a cookie for a domain of
  one label.
- No event loop of its own: uplink runs on the `Io` it is given, and is evented
  on reactor's runtime.
- A client must not move once it has made a request, a server once it
  serves, and a request or response once its reader or writer has been
  asked for.

## Platforms

Linux, macOS and Windows are tested in CI. A socket's options are reactor's
(`Dial.socket` for the client, `socket` in a server's options): TCP_NODELAY
on by default, keepalive and its timings, the buffers and the traffic class
when asked, set before a client's connect, and SO_NOSIGPIPE where the system
has it. A refused option is returned by name, never passed over. `Dial`
also takes a local address (only the name's addresses of its family are
then tried) and an interface. On
Windows, with no task to spare, a read timeout cannot be kept: `Io.Threaded`
refuses a timed socket read there, and the client counts it in
`timeouts_unenforced`. For the same reason a request with `expect_continue`
sends its body there at once instead of waiting for the go-ahead. On
reactor's runtime both are kept on every system.

## Built with

- [Zig](https://ziglang.org) 0.17.0 and its standard library; nothing else is
  linked into the module, except that cloak links the platform's own trust
  store on macOS and Windows.
- [cloak](https://github.com/pedronaugusto/cloak) is the TLS engine, with the
  certificates, keys and authorities. It is a lazy dependency, fetched only for
  the client.
- [reactor](https://github.com/pedronaugusto/reactor) is the evented `std.Io`,
  and owns the sockets' deadlines, name lookup and connecting. It is a lazy
  dependency, fetched only for the client and the server.
- [warp](https://github.com/pedronaugusto/warp) decodes and encodes gzip,
  deflate and zstd, every checksum verified. It is a lazy dependency too.
- [xenoglyph](https://github.com/pedronaugusto/xenoglyph) maps a URL's host to
  the name DNS has (UTS #46 ToASCII, `Bücher.de` to `xn--bcher-kva.de`). It is
  a lazy dependency, fetched only for the client.
- [preflight](https://github.com/pedronaugusto/preflight) runs the source checks,
  the tests and CI.
- [shakedown](https://github.com/pedronaugusto/shakedown) is the layered `Io`,
  manual clock and counting allocator the tests run on.

preflight and shakedown are dev dependencies, which [bay](https://github.com/pedronaugusto/bay)
gives uplink's own development and a project that depends on uplink never sees.

## Testing

Development runs through bay.

`bay test` runs the unit suite and the example. The suite runs twice,
on `Io.Threaded` and on a reactor runtime; the codecs, which take no `Io`, run
once. They are tested rule by rule and fuzzed: the response parser is held to a reference written
from RFC 9112's grammar on fixed and random heads, references are resolved as
RFC 3986's examples resolve, dates read back as they are written, and events
and chunked bodies decode the same in any pieces. The client runs against a
server and a proxy (HTTP with Basic and Digest, SOCKS 4, 4a, 5 and 5h) in the
test tree, over loopback and a Unix socket: bodies of every framing and
coding, written and streamed requests, connections the server closed idle or
mid-request, every timeout with and without a task to spare, tasks sharing
one client and waiting on a full route, redirects and their method rules,
retries by status and by failure, 401s answered with Basic, Digest and Bearer,
cookies across a redirect, `Expect: 100-continue`, upgrades and tunnels,
trailers, proxies from the environment, and the observer and prepare hook.
Happy Eyeballs is held to its timing against a black-holed address. The
server is driven by the client and by raw bytes: kept and pipelined
connections, every refusal of the smuggling class and every limit, `HEAD`,
handlers failing before and after their head, request bodies decoded and
responses compressed, TLS with a required client certificate, the head,
idle and shutdown timeouts on real sockets, an upgrade, trailers both ways,
the connection limit, the router's precedence, conflicts, 405s and redirects,
comptime routes, and files with every condition and range. Two tests
count what an exchange costs on a warm client: no allocation, with cookies and
a kept answer too, and one write, one read and one look at the socket. TLS is
proved against `openssl s_server` with certificates made for each run in a
scratch `HOME`: TLS 1.3 and a server that speaks only TLS 1.2, authorities given and
refused, client certificates of every key kind cloak signs with, RSA included, a certificate checked at a stepped clock, and TLS inside a `CONNECT`
tunnel and SOCKS. HTTP/2 is driven from both ends: the client against the
server by prior knowledge, bodies past every window both ways, trailers,
`Expect: 100-continue`, sixteen requests at once over one connection, and a
WebSocket opened by an extended `CONNECT`; curl against the server when it
is installed. HPACK blocks, frame sequences, WebSocket heads and resolve
entries are fuzzed.

The protocols' own suites run by hand before a release, each driven by a
Zig program in `conformance/` that starts the peer and reads its report:
`bay h2spec` (with `--tls <cert> <key>` over TLS), `bay autobahn` and `bay h1`. As of 2026-10-14:

| Suite | Against | Result |
|---|---|---|
| h2spec 2.6.0, `--strict` | the HTTP/2 server, by prior knowledge | 146 of 147 passed, 1 skipped, none failed |
| h2spec 2.6.0, `--strict`, built with Go 1.27 | the HTTP/2 server over TLS, agreed by ALPN | 146 of 147 passed, 1 skipped, none failed |
| Autobahn\|Testsuite 0.10.9 | the WebSocket server | 517 cases: 514 OK, 3 informational, none failed |
| Autobahn\|Testsuite 0.10.9 | the WebSocket client | 517 cases: 514 OK, 3 informational, none failed |
| h1spec, `--strict` | the HTTP/1.1 server | 33 of 33 passed |
| Http11Probe | the HTTP/1.1 server | 159 of 159 scored passed, 16 warnings where RFC 9112 allows either answer |

`bay bench` measures head parsing, chunked decoding, Server-Sent Events
and `Set-Cookie` reading, keep-alive requests with their latency percentiles
plain, with cookies and with a kept answer, a redirect, tasks sharing a
client, and downloads plain, chunked and gzip, against a server in the same
process, and writes JSON lines to `zig-out/bench/results.jsonl`. The rows run
on a reactor runtime; `--io threaded` runs them on `Io.Threaded` and
`--workers N` sets the runtime's worker threads. CI compiles the benchmarks
and never times them.

## Licence

MIT. See [LICENSE](LICENSE).
