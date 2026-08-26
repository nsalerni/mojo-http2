# Roadmap

Shipped work lives in [CHANGELOG.md](CHANGELOG.md).

## Non-goals

These stay out on purpose:

- PUSH_PROMISE. gRPC never uses it; `ENABLE_PUSH = 0`. A peer that pushes
  anyway gets the connection error RFC 9113 prescribes.
- The RFC 7540 priority tree. RFC 9113 deprecated it; PRIORITY frames are
  validated and ignored. RFC 9218 is the path if a consumer needs
  prioritization.
