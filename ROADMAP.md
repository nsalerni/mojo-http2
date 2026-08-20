# Roadmap

Same rule as the rest of the family: nothing lands without a differential
check against a reference implementation. For this package that means
rerunning the full existing gauntlet (h2spec, hyper-h2 live in both roles,
hyperframe byte comparisons) on every change, and extending it to cover
whatever is new.

## 1. Generalize the connection over a stream trait (shipped)

`Http2Connection` is now generic over mojo-net's `IOStream` trait
(`Http2Connection[S: IOStream = TCPStream]`), so the protocol logic runs
over TCP, Unix sockets, or the future TLS stream without change. Verified
as a pure refactor: h2spec stayed at 146/146 and every differential and
unit suite passed unchanged.

## 2. HTTP/2 over TLS with ALPN

Depends on the planned `mojo-tls` package (see the mojo-net roadmap).
Client and server constructors over a TLS stream, offering and requiring
the `h2` ALPN token, with mismatches rejected cleanly. h2c stays fully
supported.

Verified by: h2spec run in TLS mode against our server, hyper-h2 over
CPython's `ssl` module in both roles, and a curl `--http2` smoke test.
The compliance report grows a TLS section alongside the existing h2c one.

## Deliberate non-goals

These stay out on purpose, not for lack of time:

- PUSH_PROMISE. gRPC never uses it, we advertise `ENABLE_PUSH = 0`, and a
  peer that pushes anyway gets the connection error RFC 9113 prescribes.
- The RFC 7540 priority tree. RFC 9113 deprecated it; we validate PRIORITY
  frames and ignore them, which is exactly what the spec permits. If a
  consumer ever needs prioritization, RFC 9218 (Extensible Priorities) is
  the thing to implement, not the old tree.
