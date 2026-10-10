# uplink

uplink is an HTTP/1.1 client for Zig. It keeps connections for reuse and
shares them between tasks, limits them per route when asked, follows
redirects, tries failed requests again where that is safe, answers servers'
and proxies' challenges, keeps cookies, and goes through HTTP, HTTPS and SOCKS
proxies with TLS to the server inside the tunnel. It presents client
certificates, keeps connect, handshake, activity, low-speed and per-request
deadlines without a task per connection, races a name's addresses by Happy
Eyeballs, and decodes gzip, deflate and zstd bodies. It runs on any `std.Io`
and evented on [reactor](https://github.com/pedronaugusto/reactor)'s runtime. A warm client makes a
request without allocating. The codecs it is built from, HTTP/1.1 heads and
chunked bodies, header fields, dates, cookies, authentication challenges,
Server-Sent Events, form and multipart bodies and SOCKS, are public and do no
I/O.

## Install

Requires Zig 0.17.0. Fetch with `zig fetch --save
git+https://github.com/pedronaugusto/uplink` and add the `uplink` module to
your module's imports. It depends on `std`,
[aegis](https://github.com/pedronaugusto/aegis) and
[reactor](https://github.com/pedronaugusto/reactor), which is fetched only when the
client is built.

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

[examples/usage.zig](examples/usage.zig) sends a request with a body and
reads the response, against a server it starts on loopback, on a reactor
runtime.

<!-- BEGIN GENERATED zig build docs -- usage -->
```zig
const uplink = @import("uplink");

// Any `std.Io`: here a reactor runtime's, the evented one.
const io = runtime.io();

// One client for the program: it keeps connections for reuse, follows
// redirects, tries failed requests again where that is safe, and may be
// shared by several tasks. Cookies go in a jar of the caller's.
var jar: uplink.CookieJar = .init(gpa, .{});
defer jar.deinit(io);
var client: uplink.Client = .init(gpa, .{
    .timeouts = .{ .connect = .fromSeconds(10), .activity = .fromSeconds(30) },
    .cookies = &jar,
    .user_agent = "example/1.0",
});
defer client.deinit(io);

var diagnostics: uplink.Diagnostics = .{};
var response = client.send(io, .{
    .method = .POST,
    .url = url,
    .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
    .body = .{ .bytes = "ping" },
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
std.debug.assert(std.mem.eql(u8, body, "pong"));
```
<!-- END GENERATED -->

A body can also come from a reader, with its length or in chunks, or be
written by the caller: `client.begin` returns an `Outgoing` whose `writer`
takes it and whose `finish` reads the response. `response.reader(io)` streams
a body instead of collecting it; `wire.sse.Reader` reads Server-Sent Events
from it.

## Design

The package is layered, and each layer owns its state alone: `wire` (the
codecs, sans I/O) under `tls` and `net`, under `transport` (one connection),
under `pool` (which connection serves which request), under `client` (the
policy). The layer rule is checked in CI. [docs/design.md](docs/design.md)
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
forgotten. A
`CookieJar` keeps cookies by RFC 6265bis and reads and writes the Netscape
cookie file. A `Prepare` hook sees every attempt before it is written, so a
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
and other targets return `error.ConcurrencyUnavailable` for a name. A name's
addresses are raced by Happy Eyeballs (RFC 8305): one at a time, the families
alternating, each a quarter second after the last or at once when it failed,
and each attempt is reactor's connect, which its runtime ends at the deadline
in the kernel.
`Dial.unix_socket` sends every request to a Unix socket instead. No uplink
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

**TLS** is the standard library's client with client authentication added: a
copy of std's `Client.zig` held byte for byte to std and a recorded diff by a
test, so a new Zig release's fixes are brought across rather than missed. It
answers a server's request for a certificate with RSA (PKCS #1 v1.5 and PSS),
ECDSA on P-256 and P-384, or Ed25519 keys, read from PKCS #8, PKCS #1, SEC 1,
encrypted PKCS #8 and OpenSSL's older encrypted PEM. A `Trust` holds the
authorities and may be shared by clients; without one the client reads the
system's once, at its first verifying handshake. Each handshake checks
certificates at the current real time.

**Proxies.** `Proxy.parse` reads `host:port` or a URL with scheme `http`,
`https`, `socks4`, `socks4a`, `socks5` or `socks5h`. `Proxy.fromEnvironment`
picks a proxy for a URL from an environment the caller passes, by one of two
sets of rules (`Proxy.Rules`), which differ in their variables, their default
port and what `no_proxy` can name; uplink never reads the process
environment itself.

## Scope

- HTTP/1.1 only, client only. No HTTP/2, server, WebSocket or TLS engine of
  uplink's own; HTTP/3 belongs to a QUIC package of its own.
- No Brotli decoding: such a body is handed over as it came, with its
  `Content-Encoding`.
- No NTLM, Negotiate, PAC files, OCSP or `.netrc`, and no HTTP cache.
- No local address or interface to bind a connection to.
- No public suffix list: a `CookieJar` takes one through
  `Options.public_suffix`, and without one refuses a cookie for a domain of
  one label.
- No event loop of its own: uplink runs on the `Io` it is given, and is evented
  on reactor's runtime.
- A client must not move once it has made a request, and a response once
  its reader has been asked for.

## Platforms

Linux, macOS and Windows are tested in CI. TCP_NODELAY is set on every socket,
SO_NOSIGPIPE where the system has it, and TCP keepalive when asked. On
Windows, with no task to spare, a read timeout cannot be kept: `Io.Threaded`
refuses a timed socket read there, and the client counts it in
`timeouts_unenforced`. For the same reason a request with `expect_continue`
sends its body there at once instead of waiting for the go-ahead. On
reactor's runtime both are kept on every system.

## Built with

- [Zig](https://ziglang.org) 0.17.0 and its standard library; nothing else is
  linked into the module.
- [reactor](https://github.com/pedronaugusto/reactor) is the evented `std.Io`,
  and owns the sockets' deadlines, name lookup and connecting. It is a lazy
  dependency, fetched only for the client.
- [preflight](https://github.com/pedronaugusto/preflight) runs the source checks,
  the tests and CI.
- [shakedown](https://github.com/pedronaugusto/shakedown) is the layered `Io`,
  manual clock and counting allocator the tests run on, fetched only for them.

## Testing

`zig build test` runs the unit suite and the example. The suite runs twice,
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
Happy Eyeballs is held to its timing against a black-holed address. Two tests
count what an exchange costs on a warm client: no allocation, with cookies and
a kept answer too, and one write, one read and one look at the socket. TLS is
proved against `openssl s_server` with certificates made for each run in a
scratch `HOME`: TLS 1.3 and 1.2, authorities given and refused, client
certificates of every key kind and format, a certificate checked at a stepped
clock, and TLS inside a `CONNECT` tunnel and SOCKS.

`zig build bench` measures head parsing, chunked decoding, Server-Sent Events
and `Set-Cookie` reading, keep-alive requests with their latency percentiles
plain, with cookies and with a kept answer, a redirect, tasks sharing a
client, and downloads plain, chunked and gzip, against a server in the same
process, and writes JSON lines to `zig-out/bench/results.jsonl`. The rows run
on a reactor runtime; `--io threaded` runs them on `Io.Threaded` and
`--workers N` sets the runtime's worker threads. CI compiles the benchmarks
and never times them.

## Licence

MIT. See [LICENSE](LICENSE).
