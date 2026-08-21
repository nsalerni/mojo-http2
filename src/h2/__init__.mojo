# ===----------------------------------------------------------------------=== #
# Copyright (c) 2026 the grpc-mojo contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# ===----------------------------------------------------------------------=== #

"""HTTP/2 framing and connection state machine ([RFC 9113](https://www.rfc-editor.org/rfc/rfc9113)).

`frame` defines the wire constants (frame types, flags, error codes), the
frame header codec, `Settings`, and big-endian helpers; `connection`
provides `Http2Connection`, the full connection state machine over a
blocking byte stream, and `StreamState`, the receive-side state of one
stream. `secure` provides `H2TLSContext`, which requires `h2` ALPN and
specializes the same connection over mojo-tls.

Depends on `hpack`, `net`, and `tls`; extractable as a standalone package.
The design is single-threaded and caller-driven: there is no event loop;
callers can dispatch decoded frames with `Http2Connection.process_frame`, or
pump a blocking stream with `process_next_frame` and the `wait_*` helpers.

Conformance is verified with h2spec in cleartext and TLS modes.
"""

from .connection import Http2Connection, StreamState
from .frame import (
    CONNECTION_PREFACE,
    DEFAULT_MAX_FRAME_SIZE,
    DEFAULT_WINDOW_SIZE,
    ERR_CANCEL,
    ERR_COMPRESSION_ERROR,
    ERR_CONNECT_ERROR,
    ERR_ENHANCE_YOUR_CALM,
    ERR_FLOW_CONTROL_ERROR,
    ERR_FRAME_SIZE_ERROR,
    ERR_HTTP_1_1_REQUIRED,
    ERR_INADEQUATE_SECURITY,
    ERR_INTERNAL_ERROR,
    ERR_NO_ERROR,
    ERR_PROTOCOL_ERROR,
    ERR_REFUSED_STREAM,
    ERR_SETTINGS_TIMEOUT,
    ERR_STREAM_CLOSED,
    FLAG_ACK,
    FLAG_END_HEADERS,
    FLAG_END_STREAM,
    FLAG_PADDED,
    FLAG_PRIORITY,
    FRAME_CONTINUATION,
    FRAME_DATA,
    FRAME_GOAWAY,
    FRAME_HEADER_LEN,
    FRAME_HEADERS,
    FRAME_PING,
    FRAME_PRIORITY,
    FRAME_PUSH_PROMISE,
    FRAME_RST_STREAM,
    FRAME_SETTINGS,
    FRAME_WINDOW_UPDATE,
    Frame,
    FrameHeader,
    IncrementalFrameDecoder,
    Settings,
    get_u16_be,
    get_u24_be,
    get_u32_be,
    put_u16_be,
    put_u24_be,
    put_u32_be,
)
from .secure import H2_ALPN, H2TLSContext
