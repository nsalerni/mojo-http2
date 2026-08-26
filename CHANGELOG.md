# Changelog

## Unreleased

- Applies the peer's SETTINGS_HEADER_TABLE_SIZE to the HPACK encoder.
  If the size shrinks and then grows before the next header block, the
  encoder emits the minimum size and then the final size. An empty
  HEADERS block still flushes that update.
- Refuses locally opened streams that would exceed the peer's
  SETTINGS_MAX_CONCURRENT_STREAMS. Half-closed streams still occupy a
  slot; a locally sent RST_STREAM frees it.
- Shortened the README and added contributor, issue, and pull-request
  templates.
- Aligned the weekly HTTP/2 state job timeout with the runner's allowed range.

## 0.2.5 - 2026-08-25

- Verified the source and installed package against mojo-net 0.2.2 and
  mojo-tls 0.3.0, while keeping package compatibility with mojo-tls 0.2
  releases.

## 0.2.4 - 2026-08-22

- Added an optional per-call frame dispatch budget to `feed_input`, with
  ordered empty-input resume and unchanged unlimited behavior by default.

## 0.2.3 - 2026-08-22

- Added safe stream retirement after both directions close or reset and all
  buffered DATA is consumed, with retired IDs preserved as closed per RFC 9113.

## 0.2.2 - 2026-08-22

- Added stateful `process_frame` dispatch for readiness-driven callers while
  preserving the blocking `process_next_frame` API.
- Bounded compressed HEADERS plus CONTINUATION storage and fragment count, and
  verified legal and illegal sequences against hyper-h2.
- Added a bounded outbound frame queue and non-writing `queue_*` APIs, with
  automatic protocol responses and flow-control progress verified against
  hyper-h2.
- Made connection startup nonblocking and added `feed_input` for arbitrarily
  fragmented prefaces and frames, verified against hyper-h2 at every split.
- Corrected SETTINGS_ENABLE_PUSH behavior for client and server roles.
- Added a live h2spec results badge and an incremental h2c loopback example.

## 0.2.1 - 2026-08-20

- Added bounded incremental HTTP/2 frame decoding for split and coalesced
  transport input, differential-tested against hyperframe.
- Made the TLS functional test complete graceful HTTP/2 shutdown before
  closing the transport.
- Expanded the full test and compliance matrix to macOS and Linux.

## 0.2.0 - 2026-08-20

- Added `H2TLSContext` for HTTP/2 over mojo-tls with mandatory `h2` ALPN.
- Added TLS coverage against CPython ssl, hyper-h2, and all 146 h2spec cases.
- Added an installable package containing the compiled `hpack` and `h2`
  modules, verified from clean prefixes on macOS and Linux.

## 0.1.0 - 2026-08-19

Initial release.

- `hpack`: RFC 7541 encoder/decoder with dynamic table, generated
  static/Huffman tables, strict Huffman padding validation, size updates,
  and never-indexed (sensitive) fields. Byte-exact on all Appendix C
  vectors; differential vs python-hpack.
- `h2`: RFC 9113 frame codec and connection state machine over blocking
  TCP: preface/SETTINGS, stream multiplexing, §8 request validation,
  consume-driven flow control, GOAWAY/RST error signaling, and abuse
  guards (rapid reset, control-frame floods, concurrency and header-size
  caps). h2spec 146/146; live differential vs strict hyper-h2 both roles.
