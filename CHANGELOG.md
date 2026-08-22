# Changelog

## Unreleased

- Added stateful `process_frame` dispatch for readiness-driven callers while
  preserving the blocking `process_next_frame` API.
- Bounded compressed HEADERS plus CONTINUATION storage and fragment count, and
  verified legal and illegal sequences against hyper-h2.
- Added a bounded outbound frame queue and non-writing `queue_*` APIs, with
  automatic protocol responses and flow-control progress verified against
  hyper-h2.
- Made connection startup nonblocking and added `feed_input` for arbitrarily
  fragmented prefaces and frames, verified against hyper-h2 at every split.

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
