# Roadmap

Shipped work lives in [CHANGELOG.md](CHANGELOG.md).

## Open

These are not blocked on Mojo 1.0 or another package; they wait on a consumer
or a later protocol choice:

- RFC 9218 extensible prioritization, if a caller needs stream priority
  beyond FIFO. RFC 9113 deprecated the RFC 7540 priority tree, so PRIORITY
  frames stay validated and ignored.

## Blocked

Nothing currently in scope is waiting on a Mojo language feature. HTTP/2
is caller-driven on one thread by design; an async adapter would belong in
the application (or in mojo-net, once Modular ships a public async I/O
runtime).

`Http2Connection(initial_window_size=...)` shipped in 0.2.7. Consumers
such as grpc-mojo can advertise a non-default window once they pin this
tag.

## Non-goals

These stay out on purpose:

- PUSH_PROMISE. gRPC never uses it; `ENABLE_PUSH = 0`. A peer that pushes
  anyway gets the connection error RFC 9113 prescribes.
- The RFC 7540 priority tree. RFC 9113 deprecated it; PRIORITY frames are
  validated and ignored. RFC 9218 is the path if a consumer needs
  prioritization.
- HTTP/3, QUIC, and WebSocket. Those are different protocols with their own
  packages, not extensions of this HTTP/2 state machine.
