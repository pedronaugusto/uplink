# uplink

uplink is an HTTP/1.1 client for Zig. It keeps connections for reuse and
shares them between tasks, goes through HTTP, HTTPS and SOCKS proxies with TLS
to the server inside the tunnel, answers a proxy's Basic and Digest
challenges, presents client certificates, keeps connect, handshake and
activity timeouts without a task per connection, and decodes gzip and deflate
bodies. A warm client makes a request without allocating. The codecs it is
built from, HTTP/1.1 heads and chunked bodies, header fields, authentication
challenges and SOCKS, are public and do no I/O.

## Install

Requires Zig 0.17.0. Fetch with `zig fetch --save
git+https://github.com/pedronaugusto/uplink` and add the `uplink` module to
your module's imports. It depends on `std` only.

## Usage

[examples/usage.zig](examples/usage.zig) sends a request with a body and
reads the response, against a server it starts on loopback.

<!-- BEGIN GENERATED zig build docs -- usage -->
```zig
const uplink = @import("uplink");

const io = init.io;

// One client for the program: it keeps connections for reuse, and may
// be shared by several tasks.
var client: uplink.Client = .init(gpa, .{
    .timeouts = .{ .connect = .fromSeconds(10), .activity = .fromSeconds(30) },
    .user_agent = "example/1.0",
});
defer client.deinit(io);

var diagnostics: uplink.Diagnostics = .{};
var response = client.send(io, .{
    .method = .POST,
    .url = url,
    .headers = &.{.{ .name = "Content-Type", .value = "text/plain" }},
    .body = .{ .bytes = "ping" },
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
a body instead of collecting it.

## Design

The package is layered, and each layer owns its state alone: `wire` (the
codecs, sans I/O) under `tls` and `net`, under `transport` (one connection),
under `pool` (the idle connections), under `client`. The layer rule is checked
in CI.

**Connections.** A connection is a socket and the layers a route needs on it:
TLS to an `https` proxy, a `CONNECT` tunnel or a SOCKS negotiation, TLS to the
server. A request to an `http` server through an HTTP proxy goes in absolute
form instead, as curl sends it. Idle connections are kept per route, two by
default and sixty-four in all, the most recently used taken first. Before a
kept connection is used it is checked with one read that does not wait: a
plain connection with its end or unexpected bytes waiting is closed, and a TLS
one keeps its bytes for the session to read. A request that still fails on a
kept connection before a byte of the response arrives is sent again on a new
one, once, when it had no body or its method is idempotent.

**Timeouts.** `connect` covers the name's lookup and the connection,
`handshake` each TLS handshake, `CONNECT` exchange and SOCKS negotiation, and
`activity` any read or write that moves nothing. A connection stores its
operation's deadline in an atomic, and one task per client shuts the socket of
an operation past it; the task ticks at a tenth of the shortest timeout while
operations are armed and parks when none are, so an idle client costs no
wakeups. Zig 0.17's `Io.Threaded` cannot do this by itself: on Windows it
refuses a timed socket read, on POSIX a timed write waits only for the socket
to take bytes, and its connect timeout is not implemented anywhere. With no
task to spare, reads are bounded by `Io.operateTimeout` where the `Io` can,
connects are not bounded, and `Client.stats().timeouts_unenforced` counts what
was not kept.

**Names.** A name is looked up by a task of its own while the caller drains its
answers, because std's lookup waits on itself when its queue fills and nothing
else drains it; with no task to spare, a libc target calls `getaddrinfo` on the
caller's task and other targets return `error.ConcurrencyUnavailable` for a
name. No uplink task waits on work started with `io.async`, which Zig 0.17 no
longer promises runs beside it; a source rule refuses the spelling.

**Messages.** Heads are parsed in place: lines are found thirty-two bytes at
a time, values checked for control characters sixteen at a time, and the
twenty names the client reads are indexed once. Responses are read leniently,
as RFC 9112 allows: a bare LF ends a line, and a folded value is unfolded into
spaces. Framing follows RFC 9112 §6.3 in its order, and a response that names
both `Transfer-Encoding` and `Content-Length`, or differing lengths, is never
trusted with another exchange. Every method, target, name and value a request
carries is checked before a byte is written, so nothing a caller passes can
add a line. A response's head goes into a buffer from the client's pool, its
fields beside it and its body reader's buffer after them; a connection put
away idle gives its socket buffers back too. A small exchange on a kept
connection is one `writev`, one read and one readiness check.

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
picks a proxy for a URL from an environment the caller passes, by curl's rules
or Go's, which differ in their variables, their default port and what
`no_proxy` can name; uplink never reads the process environment itself.

## Scope

- HTTP/1.1 only, client only. HTTP/2, a server, WebSocket and a TLS engine of
  uplink's own are planned; HTTP/3 belongs to a QUIC package of its own.
- No redirects, retries of failed responses, cookies or origin
  authentication yet: a 3xx, a 401 or a 503 is the caller's to handle.
- No Brotli or zstd decoding: such a body is handed over as it came, with its
  `Content-Encoding`.
- No NTLM, Negotiate, PAC files or OCSP.
- No event loop of its own: uplink runs on the `Io` it is given.
- A client must not move once it has made a connection, and a response once
  its reader has been asked for.

## Platforms

Linux, macOS and Windows are tested in CI. TCP_NODELAY is set on every socket,
and SO_NOSIGPIPE where the system has it. On Windows, with no task to spare,
a read timeout cannot be kept: `Io.Threaded` refuses a timed socket read there,
and the client counts it in `timeouts_unenforced`. Zig 0.17's evented `Io`s on
Linux and macOS cannot open a TCP connection yet, so uplink runs on
`Io.Threaded` there.

## Built with

- [Zig](https://ziglang.org) 0.17.0 and its standard library; nothing else is
  linked into the module.
- [preflight](https://github.com/pedronaugusto/preflight) runs the source checks,
  the tests and CI.
- [shakedown](https://github.com/pedronaugusto/shakedown) is the layered `Io`,
  manual clock and counting allocator the tests run on, fetched only for them.

## Testing

`zig build test` runs the unit suite and the example. The codecs are tested
rule by rule and fuzzed, and the response parser is held to a reference
written from RFC 9112's grammar on fixed and random heads. The client runs
against a server and a proxy (HTTP with Basic and Digest, SOCKS 4, 4a, 5 and
5h) in the test tree, over loopback: bodies of every framing and coding,
written and streamed requests, connections the server closed idle or
mid-request, every timeout with and without a task to spare, tasks sharing
one client. Two tests count what an exchange costs on a warm client: no
allocation, and one write, one read and one readiness check. TLS is proved
against `openssl s_server` with certificates made for each run in a scratch
`HOME`: TLS 1.3 and 1.2, authorities given and refused, client certificates of
every key kind and format, a certificate checked at a stepped clock, and TLS
inside a `CONNECT` tunnel and SOCKS.

`zig build bench` measures head parsing, chunked decoding, keep-alive
requests with their latency percentiles, tasks sharing a client, and
downloads, against a server in the same process, and writes JSON lines to
`zig-out/bench/results.jsonl`. CI compiles the benchmarks and never times them.

## Licence

MIT. See [LICENSE](LICENSE).
