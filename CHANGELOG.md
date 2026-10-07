# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `Client`: HTTP/1.1 requests over kept connections, shared by tasks, with
  `send` for a body given whole or from a reader and `begin` for one the caller
  writes. A kept connection is checked before reuse, and a request that fails
  on a stale one before any response byte is sent once more when it had no body
  or its method is idempotent. `stats` reads the client's counters without a
  lock.
- `Response`: the head, read through a pooled buffer, and the body by its
  framing, decoded for gzip and deflate, which the client offers on every
  request but a `HEAD` or a range. `collect`, `failure` and `deinit`,
  which keeps the connection when the body was read to its end.
- Proxies: HTTP (absolute form, or a `CONNECT` tunnel with TLS to the server
  inside it), HTTPS, and SOCKS 4, 4a, 5 and 5h; Basic and Digest (MD5,
  SHA-256, SHA-512-256, `-sess`, userhash) answers to a proxy's challenge.
  `Proxy.parse`, `Proxy.fromEnvironment` and `Proxy.bypassed` by curl's rules
  or Go's.
- Timeouts for connecting, each handshake, and each read or write, kept by one
  task per client, by the `Io` where it has no task to spare, and counted where
  neither can.
- `tls`: the standard library's TLS client with client certificates, held to
  std by its recorded diff; `Trust`, shareable authorities; `PrivateKey` and
  `ClientAuth`; a key log through a writer.
- `net`: name lookup that never waits on itself, and connections raced over a
  name's addresses within one deadline.
- `wire`: HTTP/1.1 heads parsed in place, strict on requests and lenient on
  responses; framing by RFC 9112 §6.3; a chunked decoder and writers; header
  fields and lists; content codings; authentication challenges; SOCKS; URLs.
- `Diagnostics`: why an exchange failed, with no allocation.
