# mojo-http2

[![CI](https://github.com/nsalerni/mojo-http2/actions/workflows/ci.yml/badge.svg)](https://github.com/nsalerni/mojo-http2/actions/workflows/ci.yml)
[![h2spec results](https://img.shields.io/endpoint?url=https%3A%2F%2Fnsalerni.github.io%2Fmojo-http2%2Fh2spec-badge.json)](https://nsalerni.github.io/mojo-http2/COMPLIANCE.html)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

HPACK ([RFC 7541](https://www.rfc-editor.org/rfc/rfc7541)) and HTTP/2
([RFC 9113](https://www.rfc-editor.org/rfc/rfc9113)) for **Mojo 1.0**.

Two modules version together: **hpack** (standard library only) and **h2**
(depends on hpack, [mojo-net](https://github.com/nsalerni/mojo-net), and
[mojo-tls](https://github.com/nsalerni/mojo-tls)).

**[Compliance report](https://nsalerni.github.io/mojo-http2/COMPLIANCE.html)**
([Markdown](COMPLIANCE.md)) is regenerated on every CI run.

## Install

```sh
curl -fsSL https://pixi.sh/install.sh | sh
git clone https://github.com/nsalerni/mojo-http2.git
cd mojo-http2
pixi install
python3 tools/fetch_deps.py
pixi run test
```

`fetch_deps.py` clones mojo-net and mojo-tls into `.deps/`. A conda recipe
lives in [`recipe/`](recipe/).

## Example

```sh
pixi run example-h2c-loopback
pixi run example-h2-tls-loopback
```

[`examples/h2c_loopback.mojo`](examples/h2c_loopback.mojo) drives a cleartext
client and server through the incremental API.
[`examples/h2_tls_loopback.mojo`](examples/h2_tls_loopback.mojo) makes one
request over TLS with the `h2` ALPN token. See
[examples/README.md](examples/README.md).

## Features

- `hpack`: encoder, decoder, dynamic table, Huffman coding, never-indexed fields
- `h2`: frame codec, stream multiplexing, flow control, and connection errors
- Blocking helpers (`process_next_frame`, `send_*`) and readiness-driven
  `feed_input` / `queue_*` / `take_pending_output`
- `H2TLSContext` requires the `h2` ALPN token
- Rapid-reset, PING/SETTINGS flood, concurrency, and header-size limits

Header names and values are `String` (UTF-8). HTTP/2 allows arbitrary octets
in field values; gRPC uses base64 `-bin` metadata instead.

## Non-goals

PUSH_PROMISE and the deprecated RFC 7540 priority tree. Details:
[ROADMAP.md](ROADMAP.md).

## Compliance

h2spec 2.6.0 (146/146 in cleartext and TLS), RFC 7541 Appendix C vectors, and
differential checks against python-hpack, hyperframe, hyper-h2, and CPython
`ssl`. Current results: [COMPLIANCE.md](COMPLIANCE.md).

```sh
pixi run compliance
```

## Related packages

[mojo-net](https://github.com/nsalerni/mojo-net) ·
[mojo-tls](https://github.com/nsalerni/mojo-tls) ·
[grpc-mojo](https://github.com/nsalerni/grpc-mojo)

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[Apache-2.0](LICENSE). Not affiliated with Modular; "Mojo" is a trademark of
Modular Inc.
