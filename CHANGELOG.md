# Changelog

## Unreleased

- Expanded HTTP/2 state generation with DATA, HEADERS plus CONTINUATION,
  PRIORITY, PUSH_PROMISE, padded DATA, unknown frames, reserved-bit
  WINDOW_UPDATE, and duplicate SETTINGS. HPACK random blocks now cover
  more gRPC header names, Huffman-unfriendly values, and swap/duplicate
  mutations. Connection-state comparison ignores WINDOW_UPDATE output:
  Mojo replenishes the receive window after DATA, and hyper-h2 does not
  until the caller acknowledges the bytes. OPEN now sends the same
  request HEADERS plus END_STREAM as hyper-h2. DATA after RST_STREAM is
  compared against RFC 9113 §5.1 (Mojo connection-errors; hyper-h2
  ignores the DATA).

## 0.2.7 - 2026-08-27

- `Http2Connection` accepts `initial_window_size` to advertise
  SETTINGS_INITIAL_WINDOW_SIZE and size new stream receive windows. Values
  above the 65,535 RFC default also send a connection-level WINDOW_UPDATE
  so the larger stream budget is not capped by the session window. The
  default constructor is unchanged: the identifier is omitted when the
  window is 65,535. Preface SETTINGS and a companion connection
  WINDOW_UPDATE are reserved as one unit so a queue-limit failure cannot
  advertise a larger stream window without raising the session window.
  Servers reserve that startup output before accepting any client preface
  byte, including the blocking `process_next_frame` path, so a short
  first chunk cannot consume bytes that a later retry cannot reconstruct.
  Blocking `process_next_frame` also flushes that startup output before
  reading the first peer frame, so a queue that fits SETTINGS plus
  WINDOW_UPDATE still has room to acknowledge peer SETTINGS.
- Pin source, recipe, and package tests to mojo-net `v0.2.4`. Release
  0.2.6 named `v0.2.3`, but that git tag still built a 0.2.2 conda
  package. The recipe lower bound is now `>=0.2.4` so `write_some` is
  present at the published package version.

## 0.2.6 - 2026-08-26

- `flush_output` writes with `write_some` and drops any prefix the
  transport accepted, so a failed flush can be retried without
  duplicating bytes already on the wire. Requires mojo-net `v0.2.3`.
- Documented that `Http2Connection` is caller-driven on one thread, with no
  background event loop.
- Added caller-driven keepalive helpers: `touch_keepalive` records activity,
  and `maybe_keepalive_ping` queues a PING after an idle interval. The first
  call starts the clock without sending.
- Refuses locally opened streams after this endpoint has sent GOAWAY.
  `begin_graceful_shutdown` queues GOAWAY with NO_ERROR;
  `live_stream_count` reports streams that are still open or half-closed.
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
