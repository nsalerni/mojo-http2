# ===----------------------------------------------------------------------=== #
# Copyright (c) 2026 the grpc-mojo contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# ===----------------------------------------------------------------------=== #

"""HTTP/2 frame layer ([RFC 9113](https://www.rfc-editor.org/rfc/rfc9113) §4).

Defines the wire-level constants, frame types (§6), frame flags (§6),
error codes (§7), and settings identifiers (§6.5.2), plus the 9-byte
`FrameHeader` codec, the `Frame` header/payload pair, the `Settings`
bookkeeping struct, an incremental frame decoder, and the big-endian
integer helpers the rest of the package builds on.
"""

comptime FRAME_HEADER_LEN = 9
"""Size in bytes of the fixed frame header (RFC 9113 §4.1)."""

# Frame types (§6)
comptime FRAME_DATA: UInt8 = 0x0
"""DATA frame type (§6.1): carries request or response bytes."""
comptime FRAME_HEADERS: UInt8 = 0x1
"""HEADERS frame type (§6.2): opens a stream or carries trailers."""
comptime FRAME_PRIORITY: UInt8 = 0x2
"""PRIORITY frame type (§6.3): deprecated stream priority signal."""
comptime FRAME_RST_STREAM: UInt8 = 0x3
"""RST_STREAM frame type (§6.4): immediately terminates one stream."""
comptime FRAME_SETTINGS: UInt8 = 0x4
"""SETTINGS frame type (§6.5): connection configuration exchange."""
comptime FRAME_PUSH_PROMISE: UInt8 = 0x5
"""PUSH_PROMISE frame type (§6.6): announces a server-pushed stream."""
comptime FRAME_PING: UInt8 = 0x6
"""PING frame type (§6.7): liveness and round-trip measurement."""
comptime FRAME_GOAWAY: UInt8 = 0x7
"""GOAWAY frame type (§6.8): initiates connection shutdown."""
comptime FRAME_WINDOW_UPDATE: UInt8 = 0x8
"""WINDOW_UPDATE frame type (§6.9): replenishes flow-control credit."""
comptime FRAME_CONTINUATION: UInt8 = 0x9
"""CONTINUATION frame type (§6.10): continues a header block."""

# Flags (§6)
comptime FLAG_END_STREAM: UInt8 = 0x1
"""END_STREAM flag on DATA/HEADERS: sender is done with the stream."""
comptime FLAG_ACK: UInt8 = 0x1
"""ACK flag on SETTINGS/PING: acknowledges the peer's frame."""
comptime FLAG_END_HEADERS: UInt8 = 0x4
"""END_HEADERS flag: the header block ends with this frame."""
comptime FLAG_PADDED: UInt8 = 0x8
"""PADDED flag: the payload starts with a pad-length byte."""
comptime FLAG_PRIORITY: UInt8 = 0x20
"""PRIORITY flag on HEADERS: a 5-byte priority field precedes the block."""

# Error codes (§7)
comptime ERR_NO_ERROR: UInt32 = 0x0
"""Graceful shutdown; no error occurred."""
comptime ERR_PROTOCOL_ERROR: UInt32 = 0x1
"""Unspecific protocol violation detected."""
comptime ERR_INTERNAL_ERROR: UInt32 = 0x2
"""Unexpected internal failure in the endpoint."""
comptime ERR_FLOW_CONTROL_ERROR: UInt32 = 0x3
"""Peer violated the flow-control protocol."""
comptime ERR_SETTINGS_TIMEOUT: UInt32 = 0x4
"""SETTINGS frame was not acknowledged in time."""
comptime ERR_STREAM_CLOSED: UInt32 = 0x5
"""Frame received on a half-closed or closed stream."""
comptime ERR_FRAME_SIZE_ERROR: UInt32 = 0x6
"""Frame has an invalid size for its type."""
comptime ERR_REFUSED_STREAM: UInt32 = 0x7
"""Stream refused before any application processing (safe to retry)."""
comptime ERR_CANCEL: UInt32 = 0x8
"""Stream is no longer needed by the endpoint."""
comptime ERR_COMPRESSION_ERROR: UInt32 = 0x9
"""HPACK connection state cannot be maintained (bad header block)."""
comptime ERR_CONNECT_ERROR: UInt32 = 0xA
"""TCP connection behind a CONNECT request was reset or errored."""
comptime ERR_ENHANCE_YOUR_CALM: UInt32 = 0xB
"""Peer is generating excessive load (used by the flood guards)."""
comptime ERR_INADEQUATE_SECURITY: UInt32 = 0xC
"""Transport properties do not meet minimum security requirements."""
comptime ERR_HTTP_1_1_REQUIRED: UInt32 = 0xD
"""Request should be retried over HTTP/1.1."""

# Settings identifiers (§6.5.2)
comptime SETTINGS_HEADER_TABLE_SIZE: UInt16 = 0x1
"""Maximum HPACK dynamic table size the sender's decoder allows."""
comptime SETTINGS_ENABLE_PUSH: UInt16 = 0x2
"""Whether the sender accepts PUSH_PROMISE frames (0 or 1)."""
comptime SETTINGS_MAX_CONCURRENT_STREAMS: UInt16 = 0x3
"""Maximum concurrent streams the sender allows the peer to open."""
comptime SETTINGS_INITIAL_WINDOW_SIZE: UInt16 = 0x4
"""Initial per-stream flow-control window size in bytes."""
comptime SETTINGS_MAX_FRAME_SIZE: UInt16 = 0x5
"""Largest frame payload the sender is willing to receive."""
comptime SETTINGS_MAX_HEADER_LIST_SIZE: UInt16 = 0x6
"""Advisory limit on the uncompressed size of a header list."""

comptime DEFAULT_WINDOW_SIZE = 65535
"""Initial flow-control window size (connection and stream), §6.9.2."""
comptime DEFAULT_MAX_FRAME_SIZE = 16384
"""Default and minimum SETTINGS_MAX_FRAME_SIZE value, §6.5.2."""

comptime CONNECTION_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
"""The 24-byte client connection preface (§3.4)."""


def put_u16_be(mut buf: List[Byte], v: UInt16):
    """Appends a 16-bit unsigned integer in network byte order.

    Args:
        buf: Buffer the two bytes are appended to.
        v: The value to encode.
    """
    buf.append(UInt8((v >> 8) & 0xFF))
    buf.append(UInt8(v & 0xFF))


def put_u24_be(mut buf: List[Byte], v: UInt32):
    """Appends the low 24 bits of an integer in network byte order.

    Used for the frame length field; the high byte of `v` is discarded.

    Args:
        buf: Buffer the three bytes are appended to.
        v: The value to encode; must fit in 24 bits.
    """
    buf.append(UInt8((v >> 16) & 0xFF))
    buf.append(UInt8((v >> 8) & 0xFF))
    buf.append(UInt8(v & 0xFF))


def put_u32_be(mut buf: List[Byte], v: UInt32):
    """Appends a 32-bit unsigned integer in network byte order.

    Args:
        buf: Buffer the four bytes are appended to.
        v: The value to encode.
    """
    buf.append(UInt8((v >> 24) & 0xFF))
    buf.append(UInt8((v >> 16) & 0xFF))
    buf.append(UInt8((v >> 8) & 0xFF))
    buf.append(UInt8(v & 0xFF))


def get_u16_be(data: Span[Byte, _], offset: Int) -> UInt16:
    """Reads a 16-bit unsigned integer in network byte order.

    Args:
        data: Source bytes; must hold at least 2 bytes at `offset`.
        offset: Position of the first (most significant) byte.

    Returns:
        The decoded value.
    """
    return (UInt16(data[offset]) << 8) | UInt16(data[offset + 1])


def get_u24_be(data: Span[Byte, _], offset: Int) -> UInt32:
    """Reads a 24-bit unsigned integer in network byte order.

    Args:
        data: Source bytes; must hold at least 3 bytes at `offset`.
        offset: Position of the first (most significant) byte.

    Returns:
        The decoded value in the low 24 bits.
    """
    return (
        (UInt32(data[offset]) << 16)
        | (UInt32(data[offset + 1]) << 8)
        | UInt32(data[offset + 2])
    )


def get_u32_be(data: Span[Byte, _], offset: Int) -> UInt32:
    """Reads a 32-bit unsigned integer in network byte order.

    Args:
        data: Source bytes; must hold at least 4 bytes at `offset`.
        offset: Position of the first (most significant) byte.

    Returns:
        The decoded value.
    """
    return (
        (UInt32(data[offset]) << 24)
        | (UInt32(data[offset + 1]) << 16)
        | (UInt32(data[offset + 2]) << 8)
        | UInt32(data[offset + 3])
    )


@fieldwise_init
struct FrameHeader(Copyable, ImplicitlyCopyable, Movable, Writable):
    """The fixed 9-byte header that starts every HTTP/2 frame (§4.1)."""

    var length: Int
    """Payload length in bytes (24 bits on the wire; excludes the header)."""
    var frame_type: UInt8
    """Frame type code; one of the FRAME_* constants or an unknown type."""
    var flags: UInt8
    """Type-specific flag bits; see the FLAG_* constants."""
    var stream_id: UInt32
    """Stream identifier (31 bits); 0 addresses the connection itself."""

    @staticmethod
    def parse(data: Span[Byte, _]) raises -> FrameHeader:
        """Parses a frame header from wire bytes.

        The reserved high bit of the stream identifier is masked off, as
        required by [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113) §4.1.

        Args:
            data: Buffer starting with the 9 header bytes.

        Returns:
            The decoded header.

        Raises:
            If fewer than 9 bytes are available.
        """
        if len(data) < FRAME_HEADER_LEN:
            raise Error("h2: short frame header")
        return FrameHeader(
            length=Int(get_u24_be(data, 0)),
            frame_type=data[3],
            flags=data[4],
            stream_id=get_u32_be(data, 5) & 0x7FFFFFFF,
        )

    def serialize(self, mut buf: List[Byte]):
        """Appends the 9-byte wire encoding of this header to a buffer.

        The reserved high bit of the stream identifier is always sent as 0.

        Args:
            buf: Buffer the header bytes are appended to.
        """
        put_u24_be(buf, UInt32(self.length))
        buf.append(self.frame_type)
        buf.append(self.flags)
        put_u32_be(buf, self.stream_id & 0x7FFFFFFF)

    def has_flag(self, flag: UInt8) -> Bool:
        """Reports whether a flag bit is set on this frame.

        Args:
            flag: The flag bit(s) to test; one of the FLAG_* constants.

        Returns:
            True if any of the given bits are set.
        """
        return (self.flags & flag) != 0

    def write_to(self, mut writer: Some[Writer]):
        """Writes a human-readable summary of the header for debugging.

        Args:
            writer: The writer to receive the formatted header.
        """
        writer.write(
            "Frame(type=",
            self.frame_type,
            " flags=",
            self.flags,
            " len=",
            self.length,
            " stream=",
            self.stream_id,
            ")",
        )


@fieldwise_init
struct Frame(Movable, Writable):
    """A complete frame: header plus raw (undecoded) payload bytes."""

    var header: FrameHeader
    """The frame's 9-byte header."""
    var payload: List[Byte]
    """The raw payload, exactly `header.length` bytes."""

    def write_to(self, mut writer: Some[Writer]):
        """Writes the frame's header summary for debugging.

        Args:
            writer: The writer to receive the formatted frame.
        """
        writer.write(self.header)


struct IncrementalFrameDecoder(Movable):
    """Decodes complete HTTP/2 frames from arbitrarily split input.

    `feed` accepts partial headers, partial payloads, multiple coalesced
    frames, and empty input. Complete frames are returned in wire order.
    Only an incomplete frame is retained between calls: at most eight header
    bytes before the header is known, then fewer than `max_frame_size`
    payload bytes. A declared length over the configured limit fails as soon
    as its nine-byte header is complete, before any payload is retained.

    A size-limit error is terminal for the decoder. This keeps the caller
    from treating bytes after a rejected header as a new frame boundary.
    """

    var _max_frame_size: Int
    """Largest accepted frame payload in bytes."""
    var _header_bytes: List[Byte]
    """Incomplete wire header, always shorter than nine bytes."""
    var _pending_header: Optional[FrameHeader]
    """Parsed header for the payload currently being collected."""
    var _payload: List[Byte]
    """Incomplete payload for `_pending_header`."""
    var _failed: Bool
    """True after a terminal size-limit error."""

    def __init__(out self, max_frame_size: Int = DEFAULT_MAX_FRAME_SIZE) raises:
        """Creates a decoder with a payload-size limit.

        Args:
            max_frame_size: Largest frame payload to accept. Must be between
                zero and the 24-bit HTTP/2 frame-length maximum.

        Raises:
            If `max_frame_size` is outside the wire format's range.
        """
        if max_frame_size < 0 or max_frame_size > 0xFFFFFF:
            raise Error("h2: invalid incremental frame size limit")
        self._max_frame_size = max_frame_size
        self._header_bytes = List[Byte](capacity=FRAME_HEADER_LEN)
        self._pending_header = None
        self._payload = List[Byte]()
        self._failed = False

    def _fail_size(mut self) raises:
        """Marks the decoder failed, releases retained bytes, and raises."""
        self._failed = True
        self._header_bytes.clear()
        self._pending_header = None
        self._payload.clear()
        raise Error("h2: frame exceeds incremental decoder limit")

    def feed(mut self, data: Span[Byte, _]) raises -> List[Frame]:
        """Consumes available bytes and returns every completed frame.

        Args:
            data: The next contiguous bytes from the HTTP/2 byte stream.

        Returns:
            Complete frames decoded by this call, in wire order. An empty
            list means more bytes are needed.

        Raises:
            If a frame declares a payload larger than `max_frame_size`, or
            if the decoder was already failed by such a frame.
        """
        if self._failed:
            raise Error("h2: incremental frame decoder is failed")

        var out = List[Frame]()
        var offset = 0
        while offset < len(data):
            if not self._pending_header:
                var needed = FRAME_HEADER_LEN - len(self._header_bytes)
                var take = min(needed, len(data) - offset)
                self._header_bytes.extend(data[offset : offset + take])
                offset += take
                if len(self._header_bytes) < FRAME_HEADER_LEN:
                    break

                var header = FrameHeader.parse(Span(self._header_bytes))
                self._header_bytes.clear()
                if header.length > self._max_frame_size:
                    self._fail_size()
                if header.length == 0:
                    out.append(Frame(header=header, payload=List[Byte]()))
                    continue
                self._pending_header = header

            var header = self._pending_header.value()
            var remaining = header.length - len(self._payload)
            var take = min(remaining, len(data) - offset)
            self._payload.extend(data[offset : offset + take])
            offset += take
            if len(self._payload) < header.length:
                break

            var payload = self._payload^
            self._payload = List[Byte]()
            self._pending_header = None
            out.append(Frame(header=header, payload=payload^))

        return out^

    def buffered_len(self) -> Int:
        """Returns incomplete wire bytes retained for the next call.

        Parsed header fields use fixed storage and are not counted.

        Returns:
            Incomplete header or payload bytes retained by the decoder.
        """
        return len(self._header_bytes) + len(self._payload)


@fieldwise_init
struct Settings(Copyable, ImplicitlyCopyable, Movable):
    """The subset of peer settings we track (RFC 9113 §6.5.2).

    Fields start at the protocol-defined defaults and are overwritten as
    SETTINGS frames arrive.
    """

    var header_table_size: UInt32
    """SETTINGS_HEADER_TABLE_SIZE: HPACK dynamic table ceiling."""
    var enable_push: Bool
    """SETTINGS_ENABLE_PUSH: whether the peer accepts PUSH_PROMISE."""
    var max_concurrent_streams: UInt32
    """SETTINGS_MAX_CONCURRENT_STREAMS: stream limit (default unlimited)."""
    var initial_window_size: UInt32
    """SETTINGS_INITIAL_WINDOW_SIZE: starting per-stream send window."""
    var max_frame_size: UInt32
    """SETTINGS_MAX_FRAME_SIZE: largest payload the peer accepts."""
    var max_header_list_size: UInt32
    """SETTINGS_MAX_HEADER_LIST_SIZE: advisory header list limit."""

    def __init__(out self):
        """Initializes every setting to its RFC 9113 §6.5.2 default."""
        self.header_table_size = 4096
        self.enable_push = True
        self.max_concurrent_streams = 0xFFFFFFFF
        self.initial_window_size = DEFAULT_WINDOW_SIZE
        self.max_frame_size = DEFAULT_MAX_FRAME_SIZE
        self.max_header_list_size = 0xFFFFFFFF

    def apply(mut self, payload: Span[Byte, _]) raises:
        """Applies a SETTINGS frame payload (sequence of 6-byte id/value).

        Known identifiers are validated and stored; unknown identifiers are
        ignored as §6.5.2 requires.

        Args:
            payload: The frame payload; its length must be a multiple of 6.

        Raises:
            If the payload length is not a multiple of 6, ENABLE_PUSH is
            not 0 or 1, INITIAL_WINDOW_SIZE exceeds 2^31 - 1, or
            MAX_FRAME_SIZE is outside [16384, 16777215].
        """
        if len(payload) % 6 != 0:
            raise Error("h2: SETTINGS payload not a multiple of 6")
        var off = 0
        while off < len(payload):
            var ident = get_u16_be(payload, off)
            var value = get_u32_be(payload, off + 2)
            if ident == SETTINGS_HEADER_TABLE_SIZE:
                self.header_table_size = value
            elif ident == SETTINGS_ENABLE_PUSH:
                if value > 1:
                    raise Error("h2: invalid ENABLE_PUSH value")
                self.enable_push = value == 1
            elif ident == SETTINGS_MAX_CONCURRENT_STREAMS:
                self.max_concurrent_streams = value
            elif ident == SETTINGS_INITIAL_WINDOW_SIZE:
                if value > 0x7FFFFFFF:
                    raise Error("h2: INITIAL_WINDOW_SIZE too large")
                self.initial_window_size = value
            elif ident == SETTINGS_MAX_FRAME_SIZE:
                if value < 16384 or value > 16777215:
                    raise Error("h2: invalid MAX_FRAME_SIZE")
                self.max_frame_size = value
            elif ident == SETTINGS_MAX_HEADER_LIST_SIZE:
                self.max_header_list_size = value
            # Unknown identifiers must be ignored (§6.5.2).
            off += 6
