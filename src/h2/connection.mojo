# ===----------------------------------------------------------------------=== #
# Copyright (c) 2026 the grpc-mojo contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# ===----------------------------------------------------------------------=== #

"""HTTP/2 connection state machine ([RFC 9113](https://www.rfc-editor.org/rfc/rfc9113)) over a blocking TCP stream.

Single-threaded design: callers drive the connection by calling
`Http2Connection.process_next_frame` until the state they are waiting for
appears; the `wait_headers`/`wait_data`/`wait_stream_end`/`take_data`
helpers wrap that loop for common cases. This matches the blocking-I/O v0
transport (docs/ARCHITECTURE.md).

Error handling follows RFC 9113 §5.4: connection errors send GOAWAY with
the appropriate error code and then raise, ending the connection; stream
errors send RST_STREAM with the code and the connection continues. Abuse
guards (PING/SETTINGS floods, rapid stream resets, oversized header lists)
answer with ENHANCE_YOUR_CALM.

Flow control is asymmetric by design: the connection-level receive window
is replenished as soon as DATA arrives, while each stream window is
replenished only when the application consumes bytes via `take_data` — so
per-stream buffering is bounded by the window size (backpressure).
"""

from hpack import Decoder as HpackDecoder
from hpack import Encoder as HpackEncoder
from hpack import HeaderField
from net import IOStream, TCPStream

from .frame import (
    CONNECTION_PREFACE,
    DEFAULT_WINDOW_SIZE,
    ERR_COMPRESSION_ERROR,
    ERR_FLOW_CONTROL_ERROR,
    ERR_FRAME_SIZE_ERROR,
    ERR_PROTOCOL_ERROR,
    ERR_STREAM_CLOSED,
    SETTINGS_ENABLE_PUSH,
    SETTINGS_HEADER_TABLE_SIZE,
    SETTINGS_INITIAL_WINDOW_SIZE,
    SETTINGS_MAX_CONCURRENT_STREAMS,
    SETTINGS_MAX_FRAME_SIZE,
    SETTINGS_MAX_HEADER_LIST_SIZE,
    get_u16_be,
    put_u16_be,
    ERR_ENHANCE_YOUR_CALM,
    ERR_REFUSED_STREAM,
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
    Settings,
    get_u32_be,
    put_u32_be,
)


struct StreamState(Movable):
    """Receive-side state of one HTTP/2 stream.

    Populated by `Http2Connection.process_next_frame` as frames arrive;
    callers read it (usually via the connection's `wait_*`/`take_data`
    helpers) to observe headers, body bytes, trailers, and termination.
    """

    var id: UInt32
    """The stream identifier."""
    var headers: List[HeaderField]
    """Decoded initial header block; valid once `headers_done` is True."""
    var trailers: List[HeaderField]
    """Decoded trailer block; valid once `trailers_done` is True."""
    var headers_done: Bool
    """True once the initial header block has been received."""
    var trailers_done: Bool
    """True once a trailer block has been received."""
    var data: List[Byte]
    """Bytes received and not yet consumed by the application."""
    var end_stream: Bool
    """True once the peer sent END_STREAM (its side is done)."""
    var reset_code: Optional[UInt32]
    """Error code if the stream was reset, by either side."""
    var send_window: Int
    """Peer-granted flow-control credit for our DATA on this stream."""
    var recv_window: Int
    """Our flow-control budget for the peer's DATA on this stream."""
    var local_reset: Bool
    """True when we sent RST_STREAM for this stream."""
    var local_end: Bool
    """True when we sent END_STREAM (our side is done)."""
    var expected_content_length: Int
    """From a content-length header; -1 when absent."""
    var received_data_len: Int
    """Total DATA bytes received (after padding removal), for the check
    against `expected_content_length`."""

    def __init__(out self, id: UInt32, send_window: Int):
        """Creates a fresh stream in its initial receive state.

        Args:
            id: The stream identifier.
            send_window: Initial send window, from the peer's
                SETTINGS_INITIAL_WINDOW_SIZE.
        """
        self.id = id
        self.headers = List[HeaderField]()
        self.trailers = List[HeaderField]()
        self.headers_done = False
        self.trailers_done = False
        self.data = List[Byte]()
        self.end_stream = False
        self.reset_code = None
        self.send_window = send_window
        self.recv_window = DEFAULT_WINDOW_SIZE
        self.local_reset = False
        self.local_end = False
        self.expected_content_length = -1
        self.received_data_len = 0

    def closed_by_peer(self) -> Bool:
        """Reports whether the peer has finished or reset this stream.

        Returns:
            True if the peer sent END_STREAM or the stream was reset;
            buffered `data` may still remain to be consumed.
        """
        return self.end_stream or Bool(self.reset_code)


struct Http2Connection[S: IOStream = TCPStream](Movable):
    """HTTP/2 connection state machine over a blocking byte stream.

    Usable as either endpoint: construct with `is_client=True` to send the
    connection preface, or `is_client=False` to expect it. Construction
    also sends the initial SETTINGS frame; the peer's SETTINGS is handled
    by the normal frame loop.

    There is no background thread or event loop. Callers pump the
    connection by calling `process_next_frame` — directly, or via the
    blocking helpers (`wait_headers`, `wait_data`, `wait_stream_end`,
    `take_data`) — and read the per-stream results from `streams`.

    Per [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113) §5.4, protocol
    violations that are connection errors send GOAWAY and then raise;
    stream errors send RST_STREAM and processing continues. In the server
    role, request header blocks are validated per §8.1/§8.2. Flood guards
    (rapid reset, PING/SETTINGS spam, oversized header lists) terminate
    abusive connections with ENHANCE_YOUR_CALM.

    Parameters:
        S: The underlying transport type, which must conform to `IOStream`.
    """

    var stream: Self.S
    """The underlying byte stream (TCP by default; any `IOStream`)."""
    var is_client: Bool
    """True when this endpoint initiated the connection."""
    var hpack_enc: HpackEncoder
    """HPACK encoder for header blocks we send."""
    var hpack_dec: HpackDecoder
    """HPACK decoder for header blocks we receive."""
    var next_stream_id: UInt32
    """Next locally-initiated stream id (odd for clients, even for servers)."""
    var our_settings: Settings
    """The settings we advertised to the peer."""
    var peer_settings: Settings
    """The peer's most recently received settings."""
    var peer_settings_received: Bool
    """True once the peer's initial SETTINGS frame has been processed."""
    var send_window: Int
    """Connection-level flow-control credit for our DATA frames."""
    var streams: Dict[UInt32, StreamState]
    """Per-stream receive state, keyed by stream id."""
    var stream_ids: List[UInt32]
    """Insertion-ordered ids (Dict with move-only values can't iterate)."""
    var goaway_code: Optional[UInt32]
    """Error code from a received GOAWAY, if any."""
    var goaway_last_stream: UInt32
    """Last-stream-id from a received GOAWAY frame."""
    var highest_remote_stream: UInt32
    """Highest peer-initiated stream id seen (for GOAWAY and idle checks)."""
    var recv_window: Int
    """Our connection-level flow-control budget for the peer's DATA."""
    var sent_goaway: Bool
    """True once we have sent a GOAWAY frame."""
    var validate_requests: Bool
    """Server role: validate request header blocks per RFC 9113 §8."""
    var rst_received: Int
    """RST_STREAM frames received (rapid-reset flood guard)."""
    var control_frames: Int
    """PING/SETTINGS received since the last useful frame (flood guard)."""
    var max_concurrent_streams: Int
    """Our advertised limit on concurrent peer-initiated streams."""
    var max_header_list_size: Int
    """Our limit on the uncompressed size of a received header list."""

    def __init__(out self, var stream: Self.S, *, is_client: Bool) raises:
        """Performs the connection preface exchange and sends our SETTINGS.

        As a client, writes the [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113)
        §3.4 preface followed by SETTINGS. As a server, reads and verifies
        the client preface, then sends SETTINGS. Neither side waits for the
        peer's SETTINGS here; `process_next_frame` handles (and ACKs) it.

        Args:
            stream: The connected stream; ownership is taken and the
                no-delay latency hint is applied.
            is_client: True to act as the client endpoint, False as the
                server.

        Raises:
            On transport errors, or (server role) when the client preface
            is malformed — after responding with GOAWAY(PROTOCOL_ERROR)
            per §3.4.
        """
        self.stream = stream^
        self.is_client = is_client
        self.hpack_enc = HpackEncoder()
        self.hpack_dec = HpackDecoder()
        self.next_stream_id = 1 if is_client else 2
        self.our_settings = Settings()
        self.peer_settings = Settings()
        self.peer_settings_received = False
        self.send_window = DEFAULT_WINDOW_SIZE
        self.streams = Dict[UInt32, StreamState]()
        self.stream_ids = List[UInt32]()
        self.goaway_code = None
        self.goaway_last_stream = 0
        self.highest_remote_stream = 0
        self.recv_window = DEFAULT_WINDOW_SIZE
        self.sent_goaway = False
        self.validate_requests = not is_client
        self.rst_received = 0
        self.control_frames = 0
        self.max_concurrent_streams = 256
        self.max_header_list_size = 16384
        self.stream.set_nodelay(True)

        var our = List[Byte]()
        put_u16_be(our, SETTINGS_MAX_CONCURRENT_STREAMS)
        put_u32_be(our, UInt32(self.max_concurrent_streams))
        put_u16_be(our, SETTINGS_MAX_HEADER_LIST_SIZE)
        put_u32_be(our, UInt32(self.max_header_list_size))
        if is_client:
            self.stream.write_all(StaticString(CONNECTION_PREFACE).as_bytes())
            self._write_frame(FRAME_SETTINGS, 0, 0, our.copy())
        else:
            var preface = self.stream.read_exact(
                StaticString(CONNECTION_PREFACE).byte_length()
            )
            if String(from_utf8=preface) != String(
                StaticString(CONNECTION_PREFACE)
            ):
                # §3.4: respond with GOAWAY(PROTOCOL_ERROR) and close.
                try:
                    self.send_goaway(ERR_PROTOCOL_ERROR)
                except:
                    pass
                raise Error("h2: bad client connection preface")
            self._write_frame(FRAME_SETTINGS, 0, 0, our.copy())
        # Both sides: the peer's SETTINGS is processed by the normal frame
        # loop (process_next_frame ACKs it).

    # --- low-level frame I/O ---

    def _write_frame(
        mut self,
        frame_type: UInt8,
        flags: UInt8,
        stream_id: UInt32,
        payload: List[Byte],
    ) raises:
        """Serialize and send one frame."""
        var buf = List[Byte](capacity=FRAME_HEADER_LEN + len(payload))
        var header = FrameHeader(
            length=len(payload),
            frame_type=frame_type,
            flags=flags,
            stream_id=stream_id,
        )
        header.serialize(buf)
        buf.extend(Span(payload))
        self.stream.write_all(Span(buf))

    def _read_frame(mut self) raises -> Frame:
        """Read one frame, enforcing our max frame size."""
        var head = self.stream.read_exact(FRAME_HEADER_LEN)
        var header = FrameHeader.parse(Span(head))
        if header.length > Int(self.our_settings.max_frame_size):
            raise Error("h2: peer frame exceeds our max frame size")
        var payload = List[Byte]()
        if header.length > 0:
            payload = self.stream.read_exact(header.length)
        return Frame(header=header, payload=payload^)

    # --- stream helpers ---

    def _ensure_stream(mut self, id: UInt32):
        """Create the stream's state record if it does not exist yet."""
        if id not in self.streams:
            self.streams[id] = StreamState(
                id, Int(self.peer_settings.initial_window_size)
            )
            self.stream_ids.append(id)

    def open_stream(mut self) raises -> UInt32:
        """Allocates the next locally-initiated stream id.

        Returns:
            The new stream id (odd for clients, even for servers), with its
            state record created.

        Raises:
            If the peer has sent GOAWAY — no new streams may be opened on a
            connection that is shutting down.
        """
        if self.goaway_code:
            raise Error("h2: connection is shutting down (GOAWAY)")
        var id = self.next_stream_id
        self.next_stream_id += 2
        self._ensure_stream(id)
        return id

    # --- sending ---

    def send_headers(
        mut self,
        stream_id: UInt32,
        fields: Span[HeaderField, _],
        *,
        end_stream: Bool,
    ) raises:
        """Sends a header block as HEADERS plus CONTINUATION as needed.

        The block is HPACK-encoded and split into chunks no larger than the
        peer's SETTINGS_MAX_FRAME_SIZE; END_HEADERS is set on the final
        frame.

        Args:
            stream_id: The stream to send on.
            fields: The header fields, in wire order (pseudo-headers first).
            end_stream: True to also set END_STREAM, finishing our side of
                the stream (as in a bodiless request, or gRPC trailers).

        Raises:
            On transport errors.
        """
        var block = List[Byte]()
        for f in fields:
            self.hpack_enc.encode_field(f, block)
        var max_len = Int(self.peer_settings.max_frame_size)
        var flags: UInt8 = 0
        if end_stream:
            flags |= FLAG_END_STREAM
            self._ensure_stream(stream_id)
            self.streams[stream_id].local_end = True
        if len(block) <= max_len:
            self._write_frame(
                FRAME_HEADERS, flags | FLAG_END_HEADERS, stream_id, block
            )
            return
        # Split into HEADERS + CONTINUATION frames.
        var first = List[Byte](Span(block)[0:max_len])
        self._write_frame(FRAME_HEADERS, flags, stream_id, first)
        var off = max_len
        while off < len(block):
            var end = min(off + max_len, len(block))
            var chunk = List[Byte](Span(block)[off:end])
            var cflags: UInt8 = 0
            if end == len(block):
                cflags = FLAG_END_HEADERS
            self._write_frame(FRAME_CONTINUATION, cflags, stream_id, chunk)
            off = end

    def send_data(
        mut self, stream_id: UInt32, data: Span[Byte, _], *, end_stream: Bool
    ) raises:
        """Sends DATA frames, respecting flow control.

        Chunks the payload to the peer's max frame size and to the
        connection and stream send windows. When both windows are
        exhausted, blocks in `process_next_frame` until the peer grants
        credit via WINDOW_UPDATE (incoming frames are processed normally
        while waiting). An empty payload with `end_stream=True` sends an
        empty END_STREAM DATA frame.

        Args:
            stream_id: The stream to send on; must already exist.
            data: The payload bytes.
            end_stream: True to set END_STREAM on the final frame,
                finishing our side of the stream.

        Raises:
            On transport errors, if the stream is unknown, or if a
            connection error occurs while waiting for window credit.
        """
        var off = 0
        while off < len(data):
            if stream_id not in self.streams:
                raise Error("h2: send_data on unknown stream")
            var stream_window = self.streams[stream_id].send_window
            var allowed = min(
                len(data) - off,
                Int(self.peer_settings.max_frame_size),
                self.send_window,
                stream_window,
            )
            if allowed <= 0:
                # Wait for WINDOW_UPDATE (or an error) from the peer.
                self.process_next_frame()
                continue
            var chunk = List[Byte](Span(data)[off : off + allowed])
            var last = off + allowed == len(data)
            var flags: UInt8 = 0
            if end_stream and last:
                flags = FLAG_END_STREAM
            self._write_frame(FRAME_DATA, flags, stream_id, chunk)
            self.send_window -= allowed
            try:
                self.streams[stream_id].send_window -= allowed
            except:
                pass
            off += allowed
        if len(data) == 0 and end_stream:
            self._write_frame(
                FRAME_DATA, FLAG_END_STREAM, stream_id, List[Byte]()
            )
        if end_stream and stream_id in self.streams:
            self.streams[stream_id].local_end = True

    def send_rst_stream(mut self, stream_id: UInt32, code: UInt32) raises:
        """Sends RST_STREAM, terminating one stream with an error code.

        Only writes the frame; callers wanting local bookkeeping updated
        should rely on the connection's own error paths, which mark the
        stream reset before sending.

        Args:
            stream_id: The stream to reset.
            code: One of the ERR_* error codes.

        Raises:
            On transport errors.
        """
        var payload = List[Byte](capacity=4)
        put_u32_be(payload, code)
        self._write_frame(FRAME_RST_STREAM, 0, stream_id, payload)

    def send_goaway(mut self, code: UInt32) raises:
        """Sends GOAWAY, beginning connection shutdown.

        The last-stream-id field is set to the highest peer-initiated
        stream we have processed, telling the peer which streams may have
        had an effect ([RFC 9113](https://www.rfc-editor.org/rfc/rfc9113)
        §6.8).

        Args:
            code: One of the ERR_* error codes (ERR_NO_ERROR for graceful
                shutdown).

        Raises:
            On transport errors.
        """
        self.sent_goaway = True
        var payload = List[Byte](capacity=8)
        put_u32_be(payload, self.highest_remote_stream)
        put_u32_be(payload, code)
        self._write_frame(FRAME_GOAWAY, 0, 0, payload)

    # --- error signaling (RFC 9113 §5.4) ---

    def _conn_error(mut self, code: UInt32, var msg: String) raises:
        """Connection error: GOAWAY with the code, then raise."""
        if not self.sent_goaway:
            try:
                self.send_goaway(code)
            except:
                pass
        raise Error("h2: connection error: " + msg)

    def _stream_error(mut self, sid: UInt32, code: UInt32) raises:
        """Stream error: RST_STREAM with the code; connection continues."""
        self._ensure_stream(sid)
        self.streams[sid].local_reset = True
        self.streams[sid].reset_code = code
        try:
            self.send_rst_stream(sid, code)
        except:
            pass

    def _bump_control(mut self) raises:
        """PING/SETTINGS flood guard: control frames with no useful frames
        in between eventually cost the connection (CVE-2019-9512-style)."""
        self.control_frames += 1
        if self.control_frames > 1024:
            self._conn_error(
                ERR_ENHANCE_YOUR_CALM, String("control frame flood")
            )

    def _is_idle(self, sid: UInt32) -> Bool:
        """True when no frame has created this stream yet."""
        if sid in self.streams:
            return False
        var peer_initiated = (sid % 2 == 1) != self.is_client
        if peer_initiated:
            return sid > self.highest_remote_stream
        return sid >= self.next_stream_id

    def send_ping(mut self, data: UInt64) raises:
        """Sends a PING frame with the given opaque payload.

        The peer must answer with a PING ACK carrying the same 8 bytes;
        the ACK is consumed by `process_next_frame`.

        Args:
            data: Opaque payload, sent big-endian.

        Raises:
            On transport errors.
        """
        var payload = List[Byte](capacity=8)
        for i in range(8):
            payload.append(UInt8((data >> UInt64(56 - 8 * i)) & 0xFF))
        self._write_frame(FRAME_PING, 0, 0, payload)

    # --- receiving / dispatch ---

    def process_next_frame(mut self) raises:
        """Reads one frame, validates it per RFC 9113, and updates state.

        The single dispatch point every receive path goes through. Blocks
        until a frame arrives. Effects by type: SETTINGS is applied and
        ACKed; PING is answered; WINDOW_UPDATE grants send credit; DATA
        and HEADERS (with any inline CONTINUATION frames) update the
        stream's `StreamState`; RST_STREAM and GOAWAY record termination;
        unknown frame types are ignored
        ([RFC 9113](https://www.rfc-editor.org/rfc/rfc9113) §4.1).

        Protocol violations follow §5.4: stream errors send RST_STREAM and
        return normally; connection errors send GOAWAY with the proper
        error code and then raise. Flood guards (PING/SETTINGS spam, rapid
        reset) escalate to ENHANCE_YOUR_CALM connection errors.

        Raises:
            On transport errors and on connection-level protocol errors
            (after GOAWAY has been sent). The connection is unusable
            afterwards.
        """
        var head = self.stream.read_exact(FRAME_HEADER_LEN)
        var h = FrameHeader.parse(Span(head))
        if h.length > Int(self.our_settings.max_frame_size):
            self._conn_error(
                ERR_FRAME_SIZE_ERROR, String("frame exceeds max frame size")
            )
        var frame_payload = List[Byte]()
        if h.length > 0:
            frame_payload = self.stream.read_exact(h.length)

        if h.frame_type == FRAME_DATA or h.frame_type == FRAME_HEADERS:
            self.control_frames = 0
        if h.frame_type == FRAME_SETTINGS:
            self._bump_control()
            self._on_settings(h, Span(frame_payload))
        elif h.frame_type == FRAME_PING:
            self._bump_control()
            if h.stream_id != 0:
                self._conn_error(ERR_PROTOCOL_ERROR, String("PING on stream"))
            if h.length != 8:
                self._conn_error(ERR_FRAME_SIZE_ERROR, String("PING length"))
            if not h.has_flag(FLAG_ACK):
                self._write_frame(FRAME_PING, FLAG_ACK, 0, frame_payload.copy())
        elif h.frame_type == FRAME_WINDOW_UPDATE:
            self._on_window_update(h, Span(frame_payload))
        elif h.frame_type == FRAME_DATA:
            self._on_data(h, frame_payload^)
        elif h.frame_type == FRAME_HEADERS:
            self._on_headers(h, frame_payload^)
        elif h.frame_type == FRAME_RST_STREAM:
            if h.stream_id == 0:
                self._conn_error(
                    ERR_PROTOCOL_ERROR, String("RST_STREAM on stream 0")
                )
            if h.length != 4:
                self._conn_error(
                    ERR_FRAME_SIZE_ERROR, String("RST_STREAM length")
                )
            if self._is_idle(h.stream_id):
                self._conn_error(
                    ERR_PROTOCOL_ERROR, String("RST_STREAM on idle stream")
                )
            var code = get_u32_be(Span(frame_payload), 0)
            self.rst_received += 1
            if self.rst_received > 512 and self.rst_received * 2 > len(
                self.stream_ids
            ):
                # Rapid-reset (CVE-2023-44487)-style churn guard.
                self._conn_error(
                    ERR_ENHANCE_YOUR_CALM, String("stream reset flood")
                )
            self._ensure_stream(h.stream_id)
            self.streams[h.stream_id].reset_code = code
        elif h.frame_type == FRAME_GOAWAY:
            if h.stream_id != 0:
                self._conn_error(ERR_PROTOCOL_ERROR, String("GOAWAY on stream"))
            if h.length < 8:
                self._conn_error(ERR_FRAME_SIZE_ERROR, String("GOAWAY length"))
            self.goaway_last_stream = (
                get_u32_be(Span(frame_payload), 0) & 0x7FFFFFFF
            )
            self.goaway_code = get_u32_be(Span(frame_payload), 4)
        elif h.frame_type == FRAME_PRIORITY:
            if h.stream_id == 0:
                self._conn_error(
                    ERR_PROTOCOL_ERROR, String("PRIORITY on stream 0")
                )
            if h.length != 5:
                self._stream_error(h.stream_id, ERR_FRAME_SIZE_ERROR)
                return
            var dep = get_u32_be(Span(frame_payload), 0) & 0x7FFFFFFF
            if dep == h.stream_id:
                self._stream_error(h.stream_id, ERR_PROTOCOL_ERROR)
        elif h.frame_type == FRAME_PUSH_PROMISE:
            # Servers never receive PUSH_PROMISE; we never enable push.
            self._conn_error(
                ERR_PROTOCOL_ERROR, String("unexpected PUSH_PROMISE")
            )
        elif h.frame_type == FRAME_CONTINUATION:
            # CONTINUATION is only legal directly after HEADERS (handled
            # inside _on_headers).
            self._conn_error(ERR_PROTOCOL_ERROR, String("stray CONTINUATION"))
        else:
            # Unknown frame types must be ignored (§4.1).
            pass

    def _on_settings(mut self, h: FrameHeader, payload: Span[Byte, _]) raises:
        """Validate and apply a SETTINGS frame; ACK non-ACK frames."""
        if h.stream_id != 0:
            self._conn_error(ERR_PROTOCOL_ERROR, String("SETTINGS on stream"))
        if h.has_flag(FLAG_ACK):
            if h.length != 0:
                self._conn_error(
                    ERR_FRAME_SIZE_ERROR, String("SETTINGS ACK with payload")
                )
            return
        if len(payload) % 6 != 0:
            self._conn_error(ERR_FRAME_SIZE_ERROR, String("SETTINGS length"))
        var old_window = Int(self.peer_settings.initial_window_size)
        var off = 0
        while off < len(payload):
            var ident = get_u16_be(payload, off)
            var value = get_u32_be(payload, off + 2)
            if ident == SETTINGS_HEADER_TABLE_SIZE:
                self.peer_settings.header_table_size = value
            elif ident == SETTINGS_ENABLE_PUSH:
                if value > 1:
                    self._conn_error(
                        ERR_PROTOCOL_ERROR, String("invalid ENABLE_PUSH")
                    )
                self.peer_settings.enable_push = value == 1
            elif ident == SETTINGS_MAX_CONCURRENT_STREAMS:
                self.peer_settings.max_concurrent_streams = value
            elif ident == SETTINGS_INITIAL_WINDOW_SIZE:
                if value > 0x7FFFFFFF:
                    self._conn_error(
                        ERR_FLOW_CONTROL_ERROR,
                        String("INITIAL_WINDOW_SIZE too large"),
                    )
                self.peer_settings.initial_window_size = value
            elif ident == SETTINGS_MAX_FRAME_SIZE:
                if value < 16384 or value > 16777215:
                    self._conn_error(
                        ERR_PROTOCOL_ERROR, String("invalid MAX_FRAME_SIZE")
                    )
                self.peer_settings.max_frame_size = value
            elif ident == SETTINGS_MAX_HEADER_LIST_SIZE:
                self.peer_settings.max_header_list_size = value
            # Unknown identifiers must be ignored (§6.5.2).
            off += 6
        self.peer_settings_received = True
        # §6.9.2: a changed INITIAL_WINDOW_SIZE adjusts all stream windows.
        var delta = Int(self.peer_settings.initial_window_size) - old_window
        if delta != 0:
            for id in self.stream_ids:
                self.streams[id].send_window += delta
        self._write_frame(FRAME_SETTINGS, FLAG_ACK, 0, List[Byte]())

    def _on_window_update(
        mut self, h: FrameHeader, payload: Span[Byte, _]
    ) raises:
        """Apply a WINDOW_UPDATE to the connection or a stream window."""
        if h.length != 4:
            self._conn_error(
                ERR_FRAME_SIZE_ERROR, String("WINDOW_UPDATE length")
            )
        var increment = Int(get_u32_be(payload, 0) & 0x7FFFFFFF)
        if h.stream_id == 0:
            if increment == 0:
                self._conn_error(
                    ERR_PROTOCOL_ERROR, String("WINDOW_UPDATE increment 0")
                )
            if self.send_window + increment > 0x7FFFFFFF:
                self._conn_error(
                    ERR_FLOW_CONTROL_ERROR,
                    String("connection window overflow"),
                )
            self.send_window += increment
            return
        if increment == 0:
            self._stream_error(h.stream_id, ERR_PROTOCOL_ERROR)
            return
        if self._is_idle(h.stream_id):
            self._conn_error(
                ERR_PROTOCOL_ERROR, String("WINDOW_UPDATE on idle stream")
            )
        self._ensure_stream(h.stream_id)
        if self.streams[h.stream_id].send_window + increment > 0x7FFFFFFF:
            self._stream_error(h.stream_id, ERR_FLOW_CONTROL_ERROR)
            return
        self.streams[h.stream_id].send_window += increment

    def _on_data(
        mut self, h: FrameHeader, var frame_payload: List[Byte]
    ) raises:
        """Validate a DATA frame, buffer its bytes, manage flow control."""
        if h.stream_id == 0:
            self._conn_error(ERR_PROTOCOL_ERROR, String("DATA on stream 0"))
        if self._is_idle(h.stream_id):
            self._conn_error(ERR_PROTOCOL_ERROR, String("DATA on idle stream"))
        # Flow control counts the whole frame payload, padding included.
        self.recv_window -= h.length
        if self.recv_window < 0:
            self._conn_error(
                ERR_FLOW_CONTROL_ERROR, String("connection window exceeded")
            )
        self._ensure_stream(h.stream_id)
        self.streams[h.stream_id].recv_window -= h.length
        if self.streams[h.stream_id].recv_window < 0:
            self._stream_error(h.stream_id, ERR_FLOW_CONTROL_ERROR)
            return
        if self.streams[h.stream_id].reset_code:
            # Frames on a closed (reset) stream: connection error (§5.1),
            # except for streams we reset ourselves (a natural race).
            if self.streams[h.stream_id].local_reset:
                self._replenish(h)
                return
            self._conn_error(ERR_STREAM_CLOSED, String("DATA on closed stream"))
        if self.streams[h.stream_id].end_stream:
            self._stream_error(h.stream_id, ERR_STREAM_CLOSED)
            return
        var payload = Span(frame_payload)
        var data_len = len(payload)
        if h.has_flag(FLAG_PADDED):
            if data_len < 1:
                self._conn_error(
                    ERR_FRAME_SIZE_ERROR, String("padded DATA too short")
                )
            var pad = Int(payload[0])
            if pad + 1 > data_len:
                self._conn_error(
                    ERR_PROTOCOL_ERROR, String("DATA padding exceeds payload")
                )
            payload = payload[1 : data_len - pad]
        self.streams[h.stream_id].data.extend(payload)
        self.streams[h.stream_id].received_data_len += len(payload)
        if h.has_flag(FLAG_END_STREAM):
            self.streams[h.stream_id].end_stream = True
            self._check_content_length(h.stream_id)
        self._replenish(h)

    def _replenish(mut self, h: FrameHeader) raises:
        """Refill the connection window on receipt; the stream window is
        refilled only when the application consumes (take_data) — bounding
        per-stream buffering at the window size (backpressure)."""
        if h.length <= 0:
            return
        var inc = List[Byte](capacity=4)
        put_u32_be(inc, UInt32(h.length))
        self.recv_window += h.length
        self._write_frame(FRAME_WINDOW_UPDATE, 0, 0, inc)

    def _check_content_length(mut self, sid: UInt32) raises:
        """Reset the stream if actual DATA length contradicts content-length."""
        var expected = self.streams[sid].expected_content_length
        if expected >= 0 and self.streams[sid].received_data_len != expected:
            self._stream_error(sid, ERR_PROTOCOL_ERROR)

    def _on_headers(
        mut self, h: FrameHeader, var frame_payload: List[Byte]
    ) raises:
        """Handle HEADERS: state checks, inline CONTINUATION, HPACK decode,
        MAX_CONCURRENT_STREAMS enforcement, and request validation."""
        if h.stream_id == 0:
            self._conn_error(ERR_PROTOCOL_ERROR, String("HEADERS on stream 0"))
        var peer_initiated = (h.stream_id % 2 == 1) != self.is_client
        var is_new = h.stream_id not in self.streams
        if is_new and peer_initiated:
            if h.stream_id <= self.highest_remote_stream:
                self._conn_error(
                    ERR_PROTOCOL_ERROR,
                    String("new stream id not strictly increasing"),
                )
            self.highest_remote_stream = h.stream_id
        elif is_new and not peer_initiated:
            self._conn_error(
                ERR_PROTOCOL_ERROR, String("HEADERS on our idle stream id")
            )

        var payload = Span(frame_payload)
        var data_len = len(payload)
        if h.has_flag(FLAG_PADDED):
            if data_len < 1:
                self._conn_error(
                    ERR_FRAME_SIZE_ERROR, String("padded HEADERS too short")
                )
            var pad = Int(payload[0])
            if pad + 1 > data_len:
                self._conn_error(
                    ERR_PROTOCOL_ERROR,
                    String("HEADERS padding exceeds payload"),
                )
            payload = payload[1 : data_len - pad]
        var self_dep = False
        if h.has_flag(FLAG_PRIORITY):
            if len(payload) < 5:
                self._conn_error(
                    ERR_FRAME_SIZE_ERROR, String("HEADERS priority too short")
                )
            var dep = get_u32_be(payload, 0) & 0x7FFFFFFF
            if dep == h.stream_id:
                self_dep = True
            payload = payload[5 : len(payload)]
        var block = List[Byte](payload)
        # Accumulate CONTINUATION frames until END_HEADERS.
        var end_headers = h.has_flag(FLAG_END_HEADERS)
        while not end_headers:
            var cont = self._read_frame()
            if (
                cont.header.frame_type != FRAME_CONTINUATION
                or cont.header.stream_id != h.stream_id
            ):
                self._conn_error(
                    ERR_PROTOCOL_ERROR, String("expected CONTINUATION")
                )
            block.extend(Span(cont.payload))
            end_headers = cont.header.has_flag(FLAG_END_HEADERS)

        var fields: List[HeaderField]
        try:
            fields = self.hpack_dec.decode(Span(block))
        except:
            self._conn_error(
                ERR_COMPRESSION_ERROR, String("header block decode failed")
            )
            return
        var list_size = 0
        for f in fields:
            list_size += f.name.byte_length() + f.value.byte_length() + 32
        if list_size > self.max_header_list_size:
            self._conn_error(
                ERR_ENHANCE_YOUR_CALM, String("header list too large")
            )
        if is_new and peer_initiated:
            var active = 0
            for id in self.stream_ids:
                # Open or half-closed(remote) both count (§5.1.2):
                # a stream stops counting only once fully closed.
                if (
                    (id % 2 == 1) != self.is_client
                    and not self.streams[id].local_end
                    and not Bool(self.streams[id].reset_code)
                ):
                    active += 1
            if active >= self.max_concurrent_streams:
                self._ensure_stream(h.stream_id)
                self._stream_error(h.stream_id, ERR_REFUSED_STREAM)
                return
        # HEADERS opens/continues the stream even when we then reset it.
        self._ensure_stream(h.stream_id)
        if self_dep:
            self._stream_error(h.stream_id, ERR_PROTOCOL_ERROR)
            return
        if self.streams[h.stream_id].reset_code:
            if self.streams[h.stream_id].local_reset:
                return
            self._conn_error(
                ERR_STREAM_CLOSED, String("HEADERS on closed stream")
            )
        var is_trailers = self.streams[h.stream_id].headers_done
        if self.streams[h.stream_id].end_stream:
            if self.streams[h.stream_id].local_end:
                # Fully closed stream (§5.1 "closed"): connection error.
                self._conn_error(
                    ERR_STREAM_CLOSED, String("HEADERS on closed stream")
                )
            self._stream_error(h.stream_id, ERR_STREAM_CLOSED)
            return
        if is_trailers and not h.has_flag(FLAG_END_STREAM):
            # Trailers must end the stream (§8.1).
            self._stream_error(h.stream_id, ERR_PROTOCOL_ERROR)
            return
        if self.validate_requests and not self._validate_header_block(
            h.stream_id, Span(fields), is_trailers
        ):
            self._stream_error(h.stream_id, ERR_PROTOCOL_ERROR)
            return
        if not is_trailers:
            self.streams[h.stream_id].headers = fields^
            self.streams[h.stream_id].headers_done = True
        else:
            self.streams[h.stream_id].trailers = fields^
            self.streams[h.stream_id].trailers_done = True
        if h.has_flag(FLAG_END_STREAM):
            self.streams[h.stream_id].end_stream = True
            self._check_content_length(h.stream_id)

    def _validate_header_block(
        mut self,
        sid: UInt32,
        fields: Span[HeaderField, _],
        is_trailers: Bool,
    ) raises -> Bool:
        """RFC 9113 §8.1/§8.3 request validation. False = malformed."""
        var seen_regular = False
        var method_count = 0
        var scheme_count = 0
        var path_count = 0
        for f in fields:
            # Field names must be lowercase (§8.2.1).
            for b in f.name.as_bytes():
                if Int(b) >= ord("A") and Int(b) <= ord("Z"):
                    return False
            if f.name.startswith(":"):
                if seen_regular or is_trailers:
                    return False  # pseudo after regular / in trailers
                if f.name == ":method":
                    method_count += 1
                elif f.name == ":scheme":
                    scheme_count += 1
                elif f.name == ":path":
                    path_count += 1
                    if f.value.byte_length() == 0:
                        return False
                elif f.name == ":authority":
                    pass
                else:
                    return False  # unknown/response pseudo-header in request
            else:
                seen_regular = True
                if (
                    f.name == "connection"
                    or f.name == "keep-alive"
                    or f.name == "proxy-connection"
                    or f.name == "transfer-encoding"
                    or f.name == "upgrade"
                ):
                    return False  # connection-specific (§8.2.2)
                if f.name == "te" and f.value != "trailers":
                    return False
                if f.name == "content-length":
                    try:
                        self.streams[sid].expected_content_length = Int(f.value)
                    except:
                        return False
        if not is_trailers:
            if method_count != 1 or scheme_count != 1 or path_count != 1:
                return False
        return True

    # --- waiting helpers for blocking callers ---

    def _headers_ready(self, stream_id: UInt32) -> Bool:
        """True once headers arrived or the peer closed the stream."""
        try:
            return (
                self.streams[stream_id].headers_done
                or self.streams[stream_id].closed_by_peer()
            )
        except:
            return False

    def wait_headers(mut self, stream_id: UInt32) raises:
        """Blocks until the stream has response/request headers (or closes).

        Pumps `process_next_frame` until `headers_done` is set or the peer
        ends/resets the stream; callers must check which happened.

        Args:
            stream_id: The stream to wait on.

        Raises:
            On transport errors or connection-level protocol errors while
            processing frames.
        """
        while not self._headers_ready(stream_id):
            self.process_next_frame()

    def _stream_ended(self, stream_id: UInt32) -> Bool:
        """True once the peer finished or reset the stream."""
        try:
            return self.streams[stream_id].closed_by_peer()
        except:
            return False

    def wait_stream_end(mut self, stream_id: UInt32) raises:
        """Blocks until the peer ends or resets the stream.

        Args:
            stream_id: The stream to wait on.

        Raises:
            On transport errors or connection-level protocol errors while
            processing frames.
        """
        while not self._stream_ended(stream_id):
            self.process_next_frame()

    def wait_data(mut self, stream_id: UInt32, n: Int) raises -> Bool:
        """Blocks until n bytes are buffered or the stream ends.

        Does not consume anything; pair with `take_data`.

        Args:
            stream_id: The stream to wait on.
            n: Number of buffered bytes to wait for.

        Returns:
            True once at least n bytes are buffered; False if the stream
            ended with fewer than n bytes left.

        Raises:
            On transport errors or connection-level protocol errors while
            processing frames.
        """
        while True:
            self._ensure_stream(stream_id)
            if len(self.streams[stream_id].data) >= n:
                return True
            if self.streams[stream_id].closed_by_peer():
                return False
            self.process_next_frame()

    def take_data(mut self, stream_id: UInt32, n: Int) raises -> List[Byte]:
        """Consumes exactly n buffered bytes, processing frames as needed.

        Consumption drives per-stream flow control: taking bytes sends the
        peer a stream-level WINDOW_UPDATE for the amount consumed, so a
        slow reader bounds the peer's sending (backpressure). The
        connection-level window is replenished on receipt instead.

        Args:
            stream_id: The stream to read from.
            n: Exact number of bytes to consume.

        Returns:
            The first n buffered bytes, removed from the stream's buffer.

        Raises:
            If the stream ends before n bytes are available, on transport
            errors, or on connection-level protocol errors while processing
            frames.
        """
        while True:
            self._ensure_stream(stream_id)
            if len(self.streams[stream_id].data) >= n:
                var out = List[Byte](Span(self.streams[stream_id].data)[0:n])
                var remaining = len(self.streams[stream_id].data)
                var rest = List[Byte](
                    Span(self.streams[stream_id].data)[n:remaining]
                )
                self.streams[stream_id].data = rest^
                # Consume-driven stream window refill (backpressure).
                if n > 0 and not self.streams[stream_id].closed_by_peer():
                    self.streams[stream_id].recv_window += n
                    var inc = List[Byte](capacity=4)
                    put_u32_be(inc, UInt32(n))
                    self._write_frame(FRAME_WINDOW_UPDATE, 0, stream_id, inc)
                return out^
            if self.streams[stream_id].closed_by_peer():
                raise Error("h2: stream ended before enough data")
            self.process_next_frame()

    def buffered_data_len(self, stream_id: UInt32) -> Int:
        """Returns the number of received-but-unconsumed bytes on a stream.

        Args:
            stream_id: The stream to inspect.

        Returns:
            The buffered byte count; 0 for unknown streams.
        """
        try:
            return len(self.streams[stream_id].data)
        except:
            return 0

    def close(mut self):
        """Closes the underlying TCP stream without sending GOAWAY.

        Call `send_goaway` first for a graceful shutdown.
        """
        self.stream.close()
