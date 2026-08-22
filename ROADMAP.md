# Roadmap

Same rule as the rest of the family: nothing lands without a differential
check against a reference implementation. For this package that means
rerunning the full existing gauntlet (h2spec, hyper-h2 live in both roles,
hyperframe byte comparisons) on every change, and extending it to cover
whatever is new.

## 1. Generalize the connection over a stream trait (shipped)

`Http2Connection` is now generic over mojo-net's `IOStream` trait
(`Http2Connection[S: IOStream = TCPStream]`), so the protocol logic runs
over TCP, Unix sockets, or TLS without protocol changes. Verified
as a pure refactor: h2spec stayed at 146/146 and every differential and
unit suite passed unchanged.

## 2. HTTP/2 over TLS with ALPN (shipped)

`H2TLSContext` builds client and server connections over mojo-tls, offers
or accepts only the `h2` ALPN token, and rejects peers that do not
negotiate it. The existing connection state machine runs over `TLSStream`
through the `IOStream` trait. h2c stays fully supported.

Verified by h2spec in TLS mode and by hyper-h2 over CPython's `ssl` module
in both roles. The same suite checks certificate verification, ALPN
selection, and rejection when `h2` is not negotiated.

## 3. Readiness-driven transport boundary (shipped)

Construction queues client startup bytes without reading or writing the
transport. `feed_input` accepts the server-side client preface and subsequent
frames at arbitrary byte boundaries, while `take_pending_output` exposes every
protocol response. The blocking connection pump remains available as a
compatibility adapter over the same state machine.

Verified against hyper-h2 at every preface and SETTINGS split point, including
one-byte feeds, with hidden transport reads and writes rejected by the probe.

## Deliberate non-goals

These stay out on purpose, not for lack of time:

- PUSH_PROMISE. gRPC never uses it, we advertise `ENABLE_PUSH = 0`, and a
  peer that pushes anyway gets the connection error RFC 9113 prescribes.
- The RFC 7540 priority tree. RFC 9113 deprecated it; we validate PRIORITY
  frames and ignore them, which is exactly what the spec permits. If a
  consumer ever needs prioritization, RFC 9218 (Extensible Priorities) is
  the thing to implement, not the old tree.
