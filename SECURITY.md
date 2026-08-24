# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately via
[GitHub security advisories](https://github.com/nsalerni/mojo-http2/security/advisories/new)
rather than public issues. You should receive a response within a week.

## Scope notes

mojo-http2 supports h2c, Unix sockets, and HTTP/2 over TLS. Use TLS with
certificate verification when a connection needs confidentiality or peer
authentication. h2c and Unix socket permissions do not provide certificate
authentication.

The HTTP/2 layer limits rapid resets, PING and SETTINGS floods, concurrent
streams, header sizes, compressed header blocks, continuation frames, and
queued control frames. Flow-control accounting applies backpressure. These
limits do not replace request limits in the application that uses the package.

mojo-http2 has not had an independent security review. See
[ROADMAP.md](ROADMAP.md) for supported behavior and deliberate non-goals.
