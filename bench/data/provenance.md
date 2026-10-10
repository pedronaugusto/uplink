# Benchmark data

`tls-root.der`, `tls-leaf.der` and `tls-leaf.key.pem` are a disposable P-256 test root, a server certificate it signed for
`example.com` and that certificate's key, from cloak's test PKI (generated once with OpenSSL, valid from 2026-10-10 for a
hundred years). They give the TLS rows a server whose chain a client verifies in full. Nothing here is a production credential.
