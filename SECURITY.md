# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately via
[GitHub security advisories](https://github.com/nsalerni/mojo-http2/security/advisories/new)
rather than public issues. You should receive a response within a week.

## Scope

mojo-http2 parses untrusted HTTP/2 frames and HPACK blocks. Use TLS with
certificate verification when a connection needs confidentiality or peer
authentication. The connection layer limits rapid resets, PING and SETTINGS
floods, concurrent streams, header sizes, and queued control frames.
Application request limits still belong in the caller.

The project has not had an independent security review. See
[ROADMAP.md](ROADMAP.md) for supported behavior and non-goals.

## Residual risks

- `SETTINGS_TIMEOUT` is defined as an error code but is not armed. The
  connection is caller-driven and has no timer; a peer that never ACKs
  SETTINGS must be torn down by the application.
- Header values are `String` (UTF-8). Arbitrary octet values are out of
  scope; gRPC `-bin` metadata is base64 at a higher layer.
- Application request-rate limits still belong in the caller. The
  connection layer bounds rapid reset, control-frame floods, header size,
  and queued output.
