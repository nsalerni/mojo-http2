# ===----------------------------------------------------------------------=== #
# Copyright (c) 2026 the grpc-mojo contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# ===----------------------------------------------------------------------=== #

"""HTTP/2 connection state machine ([RFC 9113](https://www.rfc-editor.org/rfc/rfc9113)) over an IOStream.

Single-threaded design: readiness-driven callers feed decoded frames through
`Http2Connection.process_frame` and take serialized responses from its bounded
outbound queue. Blocking callers use `process_next_frame`, the `send_*`
methods, and the `wait_headers`/`wait_data`/`wait_stream_end`/`take_data`
helpers.

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
    ERR_NO_ERROR,
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
    IncrementalFrameDecoder,
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

    def __init__(
        out self, id: UInt32, send_window: Int, recv_window: Int = DEFAULT_WINDOW_SIZE
    ):
        """Creates a fresh stream in its initial receive state.

        Args:
            id: The stream identifier.
            send_window: Initial send window, from the peer's
                SETTINGS_INITIAL_WINDOW_SIZE.
            recv_window: Initial receive window, from the SETTINGS we
                advertised as SETTINGS_INITIAL_WINDOW_SIZE.
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
        self.recv_window = recv_window
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
    """HTTP/2 connection state machine over a reliable byte stream.

    Usable as either endpoint: construct with `is_client=True` to queue the
    connection preface, or `is_client=False` to expect it. Construction does
    not read from or write to the transport. The initial SETTINGS and all
    automatic responses enter the bounded outbound queue.

    There is no background thread or event loop. Callers either feed complete
    frames with `process_frame` and take the resulting queued output, or pump
    a blocking stream with `process_next_frame` and the `wait_*` helpers.

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
    """Insertion-ordered live ids (Dict with move-only values can't iterate)."""
    var _streams_opened: Int
    """Total state records created, retained for rapid-reset accounting."""
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
    var max_header_block_size: Int
    """Our limit on compressed bytes retained across a header block."""
    var max_header_continuations: Int
    """Our limit on CONTINUATION frames in one header block."""
    var max_pending_output_size: Int
    """Maximum outbound bytes retained; at least 26 for frame dispatch."""
    var _pending_output: List[Byte]
    """Serialized frames waiting to be taken or flushed in FIFO order."""
    var _pending_header_stream: UInt32
    """Stream whose fragmented header block is awaiting CONTINUATION."""
    var _pending_header_flags: UInt8
    """Flags from the HEADERS frame that opened the pending block."""
    var _pending_header_block: List[Byte]
    """Compressed fragments retained until END_HEADERS arrives."""
    var _pending_header_is_new: Bool
    """Whether the pending block opens a new stream."""
    var _pending_header_peer_initiated: Bool
    """Whether the pending block belongs to a peer-initiated stream."""
    var _pending_header_self_dependency: Bool
    """Whether the pending HEADERS priority depends on its own stream."""
    var _pending_header_continuations: Int
    """CONTINUATION frames received for the pending header block."""
    var _input_decoder: IncrementalFrameDecoder
    """Frame decoder used by the readiness-driven byte-feed path."""
    var _input_frames: List[Frame]
    """Decoded frames awaiting enough outbound response capacity."""
    var _preface_received: Int
    """Validated bytes of the client connection preface."""
    var _input_failed: Bool
    """True after a terminal preface or frame-decoding error."""
    var _last_keepalive_ns: Optional[Int64]
    """Caller-supplied timestamp of the last keepalive activity, if any."""

    def __init__(
        out self,
        var stream: Self.S,
        *,
        is_client: Bool,
        initial_window_size: UInt32 = DEFAULT_WINDOW_SIZE,
        max_concurrent_streams: Int = 256,
        max_header_list_size: Int = 16384,
        max_header_block_size: Int = 65536,
        max_header_continuations: Int = 1024,
        max_pending_output_size: Int = 1048576,
    ) raises:
        """Initializes the connection without transport reads or writes.

        As a client, queues the [RFC 9113](https://www.rfc-editor.org/rfc/rfc9113)
        §3.4 preface followed by SETTINGS. A server queues SETTINGS after
        `feed_input` or `process_next_frame` validates the complete client
        preface. Neither role waits for peer bytes during construction.

        A non-default `initial_window_size` is advertised as
        SETTINGS_INITIAL_WINDOW_SIZE and used as each new stream's receive
        window. When it is larger than the RFC default of 65,535, a
        connection-level WINDOW_UPDATE raises the connection receive window
        to match; the connection window cannot be reduced through SETTINGS.

        Args:
            stream: The connected stream; ownership is taken and the
                no-delay latency hint is applied.
            is_client: True to act as the client endpoint, False as the
                server.
            initial_window_size: Per-stream receive window advertised to
                the peer. Must not exceed 2^31 - 1.
            max_concurrent_streams: Advertised limit on concurrent
                peer-initiated streams. Must be at least 1.
            max_header_list_size: Limit on the uncompressed size of a
                received header list, advertised in SETTINGS. Must be at
                least 1.
            max_header_block_size: Limit on compressed bytes retained
                across a header block. Must be at least 1.
            max_header_continuations: Limit on CONTINUATION frames in one
                header block. Must be at least 1.
            max_pending_output_size: Maximum outbound bytes retained.
                Must be at least 26 so a SETTINGS ACK and PING ACK can
                both fit.

        Raises:
            If a limit is out of range, the latency hint cannot be
            applied, or startup output cannot fit in the output queue.
        """
        if initial_window_size > 0x7FFFFFFF:
            raise Error("h2: INITIAL_WINDOW_SIZE too large")
        if max_concurrent_streams < 1:
            raise Error("h2: max_concurrent_streams must be at least 1")
        if max_header_list_size < 1:
            raise Error("h2: max_header_list_size must be at least 1")
        if max_header_block_size < 1:
            raise Error("h2: max_header_block_size must be at least 1")
        if max_header_continuations < 1:
            raise Error("h2: max_header_continuations must be at least 1")
        if max_pending_output_size < 26:
            raise Error("h2: max_pending_output_size must be at least 26")
        self.stream = stream^
        self.is_client = is_client
        self.hpack_enc = HpackEncoder()
        self.hpack_dec = HpackDecoder()
        self.next_stream_id = 1 if is_client else 2
        self.our_settings = Settings()
        self.our_settings.initial_window_size = initial_window_size
        self.peer_settings = Settings()
        self.peer_settings_received = False
        self.send_window = DEFAULT_WINDOW_SIZE
        self.streams = Dict[UInt32, StreamState]()
        self.stream_ids = List[UInt32]()
        self._streams_opened = 0
        self.goaway_code = None
        self.goaway_last_stream = 0
        self.highest_remote_stream = 0
        self.recv_window = DEFAULT_WINDOW_SIZE
        self.sent_goaway = False
        self.validate_requests = not is_client
        self.rst_received = 0
        self.control_frames = 0
        self.max_concurrent_streams = max_concurrent_streams
        self.max_header_list_size = max_header_list_size
        self.max_header_block_size = max_header_block_size
        self.max_header_continuations = max_header_continuations
        self.max_pending_output_size = max_pending_output_size
        self._pending_output = List[Byte]()
        self._pending_header_stream = 0
        self._pending_header_flags = 0
        self._pending_header_block = List[Byte]()
        self._pending_header_is_new = False
        self._pending_header_peer_initiated = False
        self._pending_header_self_dependency = False
        self._pending_header_continuations = 0
        self._input_decoder = IncrementalFrameDecoder()
        self._input_frames = List[Frame]()
        self._preface_received = (
            StaticString(CONNECTION_PREFACE).byte_length() if is_client else 0
        )
        self._input_failed = False
        self._last_keepalive_ns = None
        self.stream.set_nodelay(True)

        if is_client:
            self.our_settings.enable_push = False
            self._ensure_output_capacity(
                StaticString(CONNECTION_PREFACE).byte_length()
                + self._initial_settings_output_size()
            )
            self._pending_output.extend(
                StaticString(CONNECTION_PREFACE).as_bytes()
            )
            self._queue_initial_settings()

    def _initial_settings_output_size(self) -> Int:
        """Bytes for the preface SETTINGS frame and any companion WINDOW_UPDATE.

        Server SETTINGS is 12 payload bytes (MAX_CONCURRENT_STREAMS and
        MAX_HEADER_LIST_SIZE). Clients add ENABLE_PUSH. A non-default
        INITIAL_WINDOW_SIZE adds 6 more, and a larger-than-default window
        also sends a 4-byte connection WINDOW_UPDATE.
        """
        var payload = 12
        if self.is_client:
            payload += 6
        if self.our_settings.initial_window_size != DEFAULT_WINDOW_SIZE:
            payload += 6
        var total = FRAME_HEADER_LEN + payload
        if Int(self.our_settings.initial_window_size) > DEFAULT_WINDOW_SIZE:
            total += FRAME_HEADER_LEN + 4
        return total

    def _queue_initial_settings(mut self) raises:
        """Queues the local connection preface SETTINGS frame.

        SETTINGS and a companion connection WINDOW_UPDATE are reserved as
        one unit so a queue-limit failure cannot advertise a larger stream
        window without raising the session window.
        """
        var our = List[Byte]()
        if self.is_client:
            # This implementation does not expose server push, so clients
            # explicitly disable it in the initial SETTINGS frame.
            put_u16_be(our, SETTINGS_ENABLE_PUSH)
            put_u32_be(our, 0)
        put_u16_be(our, SETTINGS_MAX_CONCURRENT_STREAMS)
        put_u32_be(our, UInt32(self.max_concurrent_streams))
        put_u16_be(our, SETTINGS_MAX_HEADER_LIST_SIZE)
        put_u32_be(our, UInt32(self.max_header_list_size))
        # The RFC default is 65,535; omit the identifier unless the caller
        # asked for a different stream receive window.
        if self.our_settings.initial_window_size != DEFAULT_WINDOW_SIZE:
            put_u16_be(our, SETTINGS_INITIAL_WINDOW_SIZE)
            put_u32_be(our, self.our_settings.initial_window_size)
        var advertised = Int(self.our_settings.initial_window_size)
        self._ensure_output_capacity(self._initial_settings_output_size())
        self._queue_frame_unchecked(FRAME_SETTINGS, 0, 0, our^)
        if advertised > DEFAULT_WINDOW_SIZE:
            # SETTINGS_INITIAL_WINDOW_SIZE is stream-level only. Raise the
            # connection window with WINDOW_UPDATE so the larger stream
            # budget is not capped at the 65,535 connection default.
            var delta = advertised - DEFAULT_WINDOW_SIZE
            self.recv_window = advertised
            var inc = List[Byte](capacity=4)
            put_u32_be(inc, UInt32(delta))
            self._queue_frame_unchecked(FRAME_WINDOW_UPDATE, 0, 0, inc)

    # --- low-level frame I/O ---

    def _ensure_output_capacity(self, additional: Int) raises:
        """Rejects output that would exceed the configured queue bound."""
        if (
            additional < 0
            or self.max_pending_output_size < len(self._pending_output)
            or additional
            > self.max_pending_output_size - len(self._pending_output)
        ):
            raise Error("h2: outbound frame queue limit exceeded")

    def _queue_frame_unchecked(
        mut self,
        frame_type: UInt8,
        flags: UInt8,
        stream_id: UInt32,
        payload: List[Byte],
    ):
        """Serializes one frame after its queue capacity was reserved."""
        var header = FrameHeader(
            length=len(payload),
            frame_type=frame_type,
            flags=flags,
            stream_id=stream_id,
        )
        header.serialize(self._pending_output)
        self._pending_output.extend(Span(payload))

    def _queue_frame(
        mut self,
        frame_type: UInt8,
        flags: UInt8,
        stream_id: UInt32,
        payload: List[Byte],
    ) raises:
        """Serializes and appends one bounded frame to the output queue."""
        self._ensure_output_capacity(FRAME_HEADER_LEN + len(payload))
        self._queue_frame_unchecked(frame_type, flags, stream_id, payload)

    def _write_frame(
        mut self,
        frame_type: UInt8,
        flags: UInt8,
        stream_id: UInt32,
        payload: List[Byte],
    ) raises:
        """Queues and synchronously flushes one frame."""
        self._queue_frame(frame_type, flags, stream_id, payload)
        self.flush_output()

    def pending_output_len(self) -> Int:
        """Reports how much serialized output is waiting.

        Returns:
            The number of bytes currently held in the outbound queue.
        """
        return len(self._pending_output)

    def take_pending_output(mut self) -> List[Byte]:
        """Takes every queued byte in FIFO order without transport I/O.

        Returns:
            The serialized frames currently ready to write. The connection's
            queue is empty after this call.
        """
        var output = self._pending_output^
        self._pending_output = List[Byte]()
        return output^

    def flush_output(mut self) raises:
        """Writes queued bytes, dropping any prefix the transport accepted.

        Loops `write_some` until the queue is empty. If a call raises after
        accepting some bytes, those bytes are dropped so a retry does not
        duplicate them on the wire. Bytes the transport never accepted stay
        queued.

        Raises:
            On transport write errors, including a zero-length `write_some`
            on a non-empty remainder.
        """
        var offset = 0
        try:
            while offset < len(self._pending_output):
                var n = self.stream.write_some(
                    Span(self._pending_output)[offset:]
                )
                if n <= 0:
                    raise Error("http2: write_some returned 0")
                var remaining = len(self._pending_output) - offset
                if n > remaining:
                    n = remaining
                offset += n
            self._pending_output = List[Byte]()
        except error:
            if offset > 0:
                self._pending_output = List[Byte](
                    Span(self._pending_output)[offset:]
                )
            raise error

    def _read_frame(mut self) raises -> Frame:
        """Read one frame, enforcing our max frame size."""
        var head = self.stream.read_exact(FRAME_HEADER_LEN)
        var header = FrameHeader.parse(Span(head))
        if header.length > Int(self.our_settings.max_frame_size):
            self._conn_error(
                ERR_FRAME_SIZE_ERROR, String("frame exceeds max frame size")
            )
        var payload = List[Byte]()
        if header.length > 0:
            payload = self.stream.read_exact(header.length)
        return Frame(header=header, payload=payload^)

    # --- stream helpers ---

    def _ensure_stream(mut self, id: UInt32):
        """Create the stream's state record if it does not exist yet."""
        if id not in self.streams:
            self.streams[id] = StreamState(
                id,
                Int(self.peer_settings.initial_window_size),
                Int(self.our_settings.initial_window_size),
            )
            self.stream_ids.append(id)
            self._streams_opened += 1

    def retire_stream(mut self, stream_id: UInt32) raises -> Bool:
        """Removes application state for a completed stream when safe.

        A stream is eligible after it was reset, or after both endpoints sent
        END_STREAM, and only once the application consumed all buffered DATA.
        The connection's monotonic local and remote stream-id state remains,
        so later frames on the retired id are classified as closed rather
        than idle under RFC 9113 section 5.1.

        Args:
            stream_id: The completed stream whose state can be discarded.

        Returns:
            True when the state was removed. False when the stream is unknown,
            still open or half-closed, or still has buffered DATA.

        Raises:
            If internal stream bookkeeping is inconsistent.
        """
        if stream_id not in self.streams:
            return False
        if len(self.streams[stream_id].data) != 0:
            return False
        if not (
            Bool(self.streams[stream_id].reset_code)
            or (
                self.streams[stream_id].local_end
                and self.streams[stream_id].end_stream
            )
        ):
            return False

        var remaining = List[UInt32](capacity=len(self.stream_ids))
        var matches = 0
        for id in self.stream_ids:
            if id == stream_id:
                matches += 1
            else:
                remaining.append(id)
        if matches != 1:
            raise Error("h2: inconsistent live stream bookkeeping")

        _ = self.streams.pop(stream_id)
        self.stream_ids = remaining^
        return True

    def _local_concurrent_streams(self) raises -> Int:
        """Counts locally-initiated streams that still occupy a slot.

        Open and half-closed streams both count ([RFC 9113](https://www.rfc-editor.org/rfc/rfc9113)
        §5.1.2). A stream is released only after both sides end, or after
        RST_STREAM.
        """
        var active = 0
        for id in self.stream_ids:
            if (id % 2 == 1) != self.is_client:
                continue
            if self.streams[id].local_end and self.streams[id].end_stream:
                continue
            if Bool(self.streams[id].reset_code):
                continue
            active += 1
        return active

    def live_stream_count(self) raises -> Int:
        """Counts streams that are still open or half-closed.

        Reset streams and streams ended in both directions are omitted.
        After `begin_graceful_shutdown`, callers can wait until this
        returns zero before closing the transport.

        Returns:
            The number of streams that still occupy a connection slot.

        Raises:
            If a live stream id is missing from the stream table.
        """
        var live = 0
        for id in self.stream_ids:
            if Bool(self.streams[id].reset_code):
                continue
            if self.streams[id].local_end and self.streams[id].end_stream:
                continue
            live += 1
        return live

    def open_stream(mut self) raises -> UInt32:
        """Allocates the next locally-initiated stream id.

        Returns:
            The new stream id (odd for clients, even for servers), with its
            state record created.

        Raises:
            If this endpoint has sent GOAWAY or the peer has sent GOAWAY,
            or opening another stream would exceed the peer's
            SETTINGS_MAX_CONCURRENT_STREAMS.
        """
        if self.goaway_code or self.sent_goaway:
            raise Error("h2: connection is shutting down (GOAWAY)")
        var peer_max = Int(self.peer_settings.max_concurrent_streams)
        if self._local_concurrent_streams() >= peer_max:
            raise Error("h2: peer MAX_CONCURRENT_STREAMS exceeded")
        var id = self.next_stream_id
        self.next_stream_id += 2
        self._ensure_stream(id)
        return id

    # --- sending ---

    def queue_headers(
        mut self,
        stream_id: UInt32,
        fields: Span[HeaderField, _],
        *,
        end_stream: Bool,
    ) raises:
        """Queues a header block as HEADERS plus CONTINUATION as needed.

        The block is HPACK-encoded and split into chunks no larger than the
        peer's SETTINGS_MAX_FRAME_SIZE. Fields with `sensitive=True` are
        emitted as never-indexed literals. No transport I/O is performed.

        Args:
            stream_id: The stream to send on.
            fields: The header fields, in wire order (pseudo-headers first).
            end_stream: True to also set END_STREAM, finishing our side of
                the stream (as in a bodiless request, or gRPC trailers).

        Raises:
            If the bounded queue cannot safely admit the whole header block.
        """
        # Preflight a conservative literal representation before mutating the
        # stateful HPACK encoder. Huffman output is never longer than raw input
        # in this encoder; the per-field allowance covers integer prefixes.
        # Two dynamic table size updates (RFC 7541 §4.2) need at most 12 bytes.
        var upper_bound = 12
        for f in fields:
            upper_bound += f.name.byte_length() + f.value.byte_length() + 32
        var max_len = Int(self.peer_settings.max_frame_size)
        var upper_frames = max(1, (upper_bound + max_len - 1) // max_len)
        self._ensure_output_capacity(
            upper_bound + upper_frames * FRAME_HEADER_LEN
        )

        var block = List[Byte]()
        self.hpack_enc.encode(fields, block)
        var frame_count = max(1, (len(block) + max_len - 1) // max_len)
        self._ensure_output_capacity(
            len(block) + frame_count * FRAME_HEADER_LEN
        )
        var flags: UInt8 = 0
        if end_stream:
            flags |= FLAG_END_STREAM
            self._ensure_stream(stream_id)
            self.streams[stream_id].local_end = True
        if len(block) <= max_len:
            self._queue_frame_unchecked(
                FRAME_HEADERS, flags | FLAG_END_HEADERS, stream_id, block
            )
            return
        # Split into HEADERS + CONTINUATION frames.
        var first = List[Byte](Span(block)[0:max_len])
        self._queue_frame_unchecked(FRAME_HEADERS, flags, stream_id, first)
        var off = max_len
        while off < len(block):
            var end = min(off + max_len, len(block))
            var chunk = List[Byte](Span(block)[off:end])
            var cflags: UInt8 = 0
            if end == len(block):
                cflags = FLAG_END_HEADERS
            self._queue_frame_unchecked(
                FRAME_CONTINUATION, cflags, stream_id, chunk
            )
            off = end

    def send_headers(
        mut self,
        stream_id: UInt32,
        fields: Span[HeaderField, _],
        *,
        end_stream: Bool,
    ) raises:
        """Queues and synchronously flushes a complete header block.

        Args:
            stream_id: The stream to send on.
            fields: The header fields, in wire order.
            end_stream: True to finish the local side of the stream.

        Raises:
            On queue capacity or transport write errors.
        """
        self.flush_output()
        self.queue_headers(stream_id, fields, end_stream=end_stream)
        self.flush_output()

    def queue_data(
        mut self, stream_id: UInt32, data: Span[Byte, _], *, end_stream: Bool
    ) raises -> Int:
        """Queues DATA up to the currently available flow-control credit.

        No transport I/O or incoming frame processing is performed. The
        caller can retry the unconsumed suffix after WINDOW_UPDATE arrives.
        END_STREAM is queued only when the entire supplied payload fits. An
        empty payload with `end_stream=True` queues an empty DATA frame.

        Args:
            stream_id: The stream to send on; must already exist.
            data: The payload bytes.
            end_stream: True to finish our side if all supplied bytes fit.

        Returns:
            The number of payload bytes consumed into the queue. Zero means
            flow-control credit or queue capacity must become available.

        Raises:
            If the stream is unknown, or an empty END_STREAM frame would
            exceed the outbound queue bound.
        """
        if stream_id not in self.streams:
            raise Error("h2: queue_data on unknown stream")
        if len(data) == 0:
            if end_stream:
                self._queue_frame(
                    FRAME_DATA, FLAG_END_STREAM, stream_id, List[Byte]()
                )
                self.streams[stream_id].local_end = True
            return 0

        var flow_allowed = min(
            len(data),
            self.send_window,
            self.streams[stream_id].send_window,
        )
        if flow_allowed <= 0:
            return 0
        var max_len = Int(self.peer_settings.max_frame_size)
        var queue_budget = self.max_pending_output_size - len(
            self._pending_output
        )
        var allowed = 0
        while allowed < flow_allowed and queue_budget > FRAME_HEADER_LEN:
            var chunk = min(
                max_len,
                flow_allowed - allowed,
                queue_budget - FRAME_HEADER_LEN,
            )
            if chunk <= 0:
                break
            allowed += chunk
            queue_budget -= FRAME_HEADER_LEN + chunk
        if allowed == 0:
            return 0
        var frame_count = (allowed + max_len - 1) // max_len
        self._ensure_output_capacity(allowed + frame_count * FRAME_HEADER_LEN)

        var off = 0
        while off < allowed:
            var end = min(off + max_len, allowed)
            var chunk = List[Byte](Span(data)[off:end])
            var flags: UInt8 = 0
            if end_stream and end == len(data):
                flags = FLAG_END_STREAM
            self._queue_frame_unchecked(FRAME_DATA, flags, stream_id, chunk)
            off = end
        self.send_window -= allowed
        self.streams[stream_id].send_window -= allowed
        if end_stream and allowed == len(data):
            self.streams[stream_id].local_end = True
        return allowed

    def send_data(
        mut self, stream_id: UInt32, data: Span[Byte, _], *, end_stream: Bool
    ) raises:
        """Synchronously sends DATA, waiting for flow-control credit.

        Args:
            stream_id: The stream to send on; must already exist.
            data: The payload bytes.
            end_stream: True to finish the local side after the payload.

        Raises:
            On queue capacity or transport errors, if the stream is unknown,
            or on protocol errors while waiting for WINDOW_UPDATE.
        """
        self.flush_output()
        if len(data) == 0:
            _ = self.queue_data(stream_id, data, end_stream=end_stream)
            self.flush_output()
            return
        var off = 0
        while off < len(data):
            var consumed = self.queue_data(
                stream_id, data[off : len(data)], end_stream=end_stream
            )
            if consumed == 0:
                if (
                    self.send_window > 0
                    and self.streams[stream_id].send_window > 0
                ):
                    raise Error("h2: outbound queue too small for DATA frame")
                self.process_next_frame()
                continue
            self.flush_output()
            off += consumed

    def queue_rst_stream(mut self, stream_id: UInt32, code: UInt32) raises:
        """Queues RST_STREAM without performing transport I/O.

        Only queues the frame; callers wanting local bookkeeping updated
        should rely on the connection's own error paths, which mark the
        stream reset before sending.

        Args:
            stream_id: The stream to reset.
            code: One of the ERR_* error codes.

        Raises:
            If the frame would exceed the outbound queue bound.
        """
        var payload = List[Byte](capacity=4)
        put_u32_be(payload, code)
        self._queue_frame(FRAME_RST_STREAM, 0, stream_id, payload)

    def send_rst_stream(mut self, stream_id: UInt32, code: UInt32) raises:
        """Queues and synchronously flushes RST_STREAM.

        Marks the stream reset locally after the RST_STREAM frame is
        queued and flushed, so it no longer occupies a
        SETTINGS_MAX_CONCURRENT_STREAMS slot.

        Args:
            stream_id: The stream to reset.
            code: One of the ERR_* error codes.

        Raises:
            On queue capacity or transport write errors.
        """
        self.flush_output()
        self.queue_rst_stream(stream_id, code)
        self.flush_output()
        if stream_id in self.streams:
            self.streams[stream_id].local_reset = True
            self.streams[stream_id].reset_code = code

    def queue_goaway(mut self, code: UInt32) raises:
        """Queues GOAWAY without performing transport I/O.

        The last-stream-id field is set to the highest peer-initiated
        stream we have processed, telling the peer which streams may have
        had an effect ([RFC 9113](https://www.rfc-editor.org/rfc/rfc9113)
        §6.8).

        Args:
            code: One of the ERR_* error codes (ERR_NO_ERROR for graceful
                shutdown).

        Raises:
            If the frame would exceed the outbound queue bound.
        """
        var payload = List[Byte](capacity=8)
        put_u32_be(payload, self.highest_remote_stream)
        put_u32_be(payload, code)
        self._queue_frame(FRAME_GOAWAY, 0, 0, payload)
        self.sent_goaway = True

    def send_goaway(mut self, code: UInt32) raises:
        """Queues and synchronously flushes GOAWAY.

        Args:
            code: One of the ERR_* error codes.

        Raises:
            On queue capacity or transport write errors.
        """
        self.flush_output()
        self.queue_goaway(code)
        self.flush_output()

    def begin_graceful_shutdown(mut self) raises:
        """Queues GOAWAY with NO_ERROR and refuses further local streams.

        Existing streams remain usable. Readiness-driven callers take the
        queued frame with `take_pending_output`; blocking callers flush
        afterwards. A second call is a no-op once GOAWAY has been queued.

        Raises:
            If the frame would exceed the outbound queue bound.
        """
        if self.sent_goaway:
            return
        self.queue_goaway(ERR_NO_ERROR)

    # --- error signaling (RFC 9113 §5.4) ---

    def _conn_error(mut self, code: UInt32, var msg: String) raises:
        """Connection error: GOAWAY with the code, then raise."""
        if not self.sent_goaway:
            try:
                self.queue_goaway(code)
            except:
                pass
        raise Error("h2: connection error: " + msg)

    def _stream_error(mut self, sid: UInt32, code: UInt32) raises:
        """Stream error: RST_STREAM with the code; connection continues."""
        if self._is_closed(sid):
            self.queue_rst_stream(sid, code)
            return
        self._ensure_stream(sid)
        self.streams[sid].local_reset = True
        self.streams[sid].reset_code = code
        self.queue_rst_stream(sid, code)

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

    def _is_closed(self, sid: UInt32) -> Bool:
        """True for a retired or implicitly closed non-idle stream id."""
        return sid not in self.streams and not self._is_idle(sid)

    def queue_ping(mut self, data: UInt64) raises:
        """Queues a PING frame without performing transport I/O.

        The peer must answer with a PING ACK carrying the same 8 bytes;
        the ACK is consumed by `process_next_frame`.

        Args:
            data: Opaque payload, sent big-endian.

        Raises:
            If the frame would exceed the outbound queue bound.
        """
        var payload = List[Byte](capacity=8)
        for i in range(8):
            payload.append(UInt8((data >> UInt64(56 - 8 * i)) & 0xFF))
        self._queue_frame(FRAME_PING, 0, 0, payload)

    def send_ping(mut self, data: UInt64) raises:
        """Queues and synchronously flushes a PING frame.

        Args:
            data: Opaque payload, sent big-endian.

        Raises:
            On queue capacity or transport write errors.
        """
        self.flush_output()
        self.queue_ping(data)
        self.flush_output()

    def touch_keepalive(mut self, now_ns: Int64):
        """Records that the connection was used at `now_ns`.

        Call this after sending or receiving useful frames so idle
        keepalive PINGs are postponed. There is no internal clock;
        the caller supplies the timestamp.

        Args:
            now_ns: Current time in nanoseconds from the caller's clock.
        """
        self._last_keepalive_ns = now_ns

    def maybe_keepalive_ping(
        mut self, now_ns: Int64, interval_ns: Int64
    ) raises -> Bool:
        """Queues a PING if the connection has been idle for `interval_ns`.

        The first call with no prior timestamp starts the idle clock
        without sending. Subsequent calls queue one PING when the idle
        interval has elapsed and then restart the clock. Does not ping
        after GOAWAY has been sent or received. The PING payload is the
        supplied timestamp, truncated to 64 bits.

        Args:
            now_ns: Current time in nanoseconds from the caller's clock.
            interval_ns: Idle duration before a keepalive PING.

        Returns:
            True when a PING frame was queued.

        Raises:
            If `interval_ns` is not positive, or if the PING would exceed
            the outbound queue bound.
        """
        if interval_ns <= 0:
            raise Error("h2: keepalive interval must be positive")
        if self.sent_goaway or Bool(self.goaway_code):
            return False
        if not self._last_keepalive_ns:
            self._last_keepalive_ns = now_ns
            return False
        if now_ns - self._last_keepalive_ns.value() < interval_ns:
            return False
        self.queue_ping(UInt64(now_ns))
        self._last_keepalive_ns = now_ns
        return True

    # --- receiving / dispatch ---

    def input_preface_complete(self) -> Bool:
        """Reports whether the client connection preface is complete.

        Clients do not receive this marker, so this is true immediately for
        a client-role connection. Servers become ready for frames only after
        all 24 bytes from RFC 9113 §3.4 have been validated.

        Returns:
            True when frame bytes may follow the connection preface.
        """
        return self._preface_received == StaticString(
            CONNECTION_PREFACE
        ).byte_length()

    def pending_input_frame_count(self) -> Int:
        """Reports decoded frames waiting for outbound queue capacity.

        Returns:
            The number of complete frames retained for later dispatch.
        """
        return len(self._input_frames)

    def _process_pending_input(mut self, dispatch_budget: Int = -1) raises -> Int:
        """Dispatches decoded frames while worst-case responses can fit."""
        var processed = 0
        var response_bound = 2 * (FRAME_HEADER_LEN + 4)
        while len(self._input_frames) > 0:
            if dispatch_budget >= 0 and processed >= dispatch_budget:
                break
            if (
                self.max_pending_output_size < len(self._pending_output)
                or response_bound
                > self.max_pending_output_size - len(self._pending_output)
            ):
                break
            var frame = self._input_frames.pop()
            try:
                self.process_frame(frame^)
            except error:
                self._input_failed = True
                raise error
            processed += 1
        return processed

    def feed_input(
        mut self, data: Span[Byte, _], dispatch_budget: Int = -1
    ) raises -> Int:
        """Consumes available wire bytes without transport I/O.

        Server input begins with the RFC 9113 §3.4 client preface. The
        preface and subsequent frames may be split at any byte boundary.
        Complete frames are dispatched in wire order, and automatic
        responses are queued for `take_pending_output`.

        If the output queue lacks room for a frame's worst-case automatic
        responses, that decoded frame remains pending. After draining output,
        resume dispatch with an empty span. New wire bytes are accepted only
        after `pending_input_frame_count()` returns zero.

        A dispatch budget can also leave decoded frames pending. While
        `pending_input_frame_count()` is nonzero, callers must resume with an
        empty span before supplying more wire bytes.

        Args:
            data: Newly received contiguous bytes. Bytes are consumed before
                this method returns unless it raises before validating them.
            dispatch_budget: Maximum frames to dispatch during this call, or
                -1 for no per-call limit. Decoded frames beyond the limit stay
                pending and resume when this method is called again.

        Returns:
            The number of complete frames dispatched by this call. A zero
            result can mean that more bytes or more output capacity is needed.

        Raises:
            On a malformed client preface, oversized frame, or protocol
            error. Values below -1 are invalid. Connection errors queue GOAWAY
            without writing it.
        """
        if dispatch_budget < -1:
            raise Error("h2: dispatch budget must be -1 or non-negative")
        if self._input_failed:
            raise Error("h2: incremental input is failed")
        if len(self._input_frames) > 0 and len(data) > 0:
            raise Error("h2: resume pending frames before feeding more input")

        var processed = self._process_pending_input(dispatch_budget)
        if len(self._input_frames) > 0:
            return processed
        if len(data) == 0:
            return processed

        var offset = 0
        var preface_len = StaticString(CONNECTION_PREFACE).byte_length()
        if self._preface_received < preface_len:
            var remaining = preface_len - self._preface_received
            # Reserve the full SETTINGS (and companion WINDOW_UPDATE) before
            # accepting any preface byte. A smaller fallback would let a
            # short first chunk commit bytes that a later retry cannot
            # reconstruct once capacity is raised.
            self._ensure_output_capacity(self._initial_settings_output_size())
            var expected = StaticString(CONNECTION_PREFACE).as_bytes()
            var take = min(remaining, len(data))
            for i in range(take):
                if data[i] != expected[self._preface_received]:
                    self._input_failed = True
                    self._conn_error(
                        ERR_PROTOCOL_ERROR,
                        String("bad client connection preface"),
                    )
                self._preface_received += 1
            offset = take
            if self._preface_received < preface_len:
                return processed
            self._queue_initial_settings()

        var decoded = List[Frame]()
        try:
            decoded = self._input_decoder.feed(data[offset : len(data)])
        except:
            self._input_failed = True
            self._conn_error(
                ERR_FRAME_SIZE_ERROR,
                String("frame exceeds max frame size"),
            )
        # Store in reverse wire order so pop() dispatches the first frame.
        while len(decoded) > 0:
            self._input_frames.append(decoded.pop())
        var remaining_budget = dispatch_budget
        if remaining_budget >= 0:
            remaining_budget -= processed
        return processed + self._process_pending_input(remaining_budget)

    def process_next_frame(mut self) raises:
        """Reads and processes the next complete protocol action.

        This blocking compatibility adapter reads one frame and delegates to
        `process_frame`. If that frame opens a fragmented header block, it
        continues reading through END_HEADERS, preserving the method's
        historical behavior for callers waiting on complete headers.

        Protocol violations follow §5.4: stream errors send RST_STREAM and
        return normally; connection errors send GOAWAY with the proper
        error code and then raise. Flood guards (PING/SETTINGS spam, rapid
        reset) escalate to ENHANCE_YOUR_CALM connection errors.

        Raises:
            On transport errors and on connection-level protocol errors
            (after GOAWAY has been sent). The connection is unusable
            afterwards.
        """
        self.flush_output()
        if not self.input_preface_complete():
            # Startup SETTINGS can exceed the generic ACK bound. Reserve
            # that output before read_exact consumes the transport preface.
            self._ensure_output_capacity(self._initial_settings_output_size())
        try:
            if not self.input_preface_complete():
                var preface = self.stream.read_exact(
                    StaticString(CONNECTION_PREFACE).byte_length()
                    - self._preface_received
                )
                _ = self.feed_input(Span(preface))
                # Flush SETTINGS (and WINDOW_UPDATE) so the first peer
                # frame's automatic responses have queue room.
                self.flush_output()
            self._ensure_output_capacity(2 * (FRAME_HEADER_LEN + 4))
            var frame = self._read_frame()
            self.process_frame(frame^)
            while self._pending_header_stream != 0:
                frame = self._read_frame()
                self.process_frame(frame^)
            self.flush_output()
        except error:
            try:
                self.flush_output()
            except:
                pass
            raise error

    def process_frame(mut self, var frame: Frame) raises:
        """Validates and dispatches one already-decoded HTTP/2 frame.

        This method performs no reads from the underlying stream. It lets a
        caller feed frames from an incremental decoder while retaining the
        same connection state machine used by `process_next_frame`. Automatic
        protocol responses are appended to the outbound queue in wire order.

        While a fragmented HEADERS block is open, only CONTINUATION on the
        same stream is legal. Each call processes exactly one frame; header
        fields become visible only after END_HEADERS arrives.

        Args:
            frame: A complete frame whose payload length matches its header.

        Raises:
            On a malformed frame or connection-level protocol error, after
            queueing GOAWAY when possible. If fewer than 26 outbound bytes
            are available, the frame is not processed and the caller can
            drain the queue before retrying it.
        """
        # One DATA frame can queue both RST_STREAM for a content-length
        # mismatch and a connection WINDOW_UPDATE. Reserve that worst case
        # before mutating receive state so queue backpressure is retryable.
        self._ensure_output_capacity(2 * (FRAME_HEADER_LEN + 4))
        var h = frame.header
        var payload_len = len(frame.payload)
        var frame_payload = frame.payload^
        frame.payload = List[Byte]()
        if h.length != payload_len:
            self._conn_error(
                ERR_FRAME_SIZE_ERROR, String("frame payload length mismatch")
            )
        if h.length > Int(self.our_settings.max_frame_size):
            self._conn_error(
                ERR_FRAME_SIZE_ERROR, String("frame exceeds max frame size")
            )

        if self._pending_header_stream != 0:
            if (
                h.frame_type != FRAME_CONTINUATION
                or h.stream_id != self._pending_header_stream
            ):
                self._conn_error(
                    ERR_PROTOCOL_ERROR, String("expected CONTINUATION")
                )
            self._on_continuation(h, frame_payload^)
            return

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
                self._queue_frame(FRAME_PING, FLAG_ACK, 0, frame_payload.copy())
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
            if self._is_closed(h.stream_id):
                # RST_STREAM on an already closed stream has no effect.
                return
            self.rst_received += 1
            if (
                self.rst_received > 512
                and self.rst_received * 2 > self._streams_opened
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
                self.hpack_enc.set_max_size(Int(value))
            elif ident == SETTINGS_ENABLE_PUSH:
                # RFC 9113 section 6.5.2 reserves ENABLE_PUSH for clients.
                # Any occurrence in a server's SETTINGS is a connection error.
                if self.is_client:
                    self._conn_error(
                        ERR_PROTOCOL_ERROR,
                        String("server sent ENABLE_PUSH"),
                    )
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
        self._queue_frame(FRAME_SETTINGS, FLAG_ACK, 0, List[Byte]())

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
        if self._is_closed(h.stream_id):
            # RFC 9113 section 5.1 permits this race after stream closure.
            return
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
        if self._is_closed(h.stream_id):
            # Preserve closed-vs-idle classification without recreating the
            # retired state record.
            self.queue_rst_stream(h.stream_id, ERR_STREAM_CLOSED)
            return
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
        self._queue_frame(FRAME_WINDOW_UPDATE, 0, 0, inc)

    def _check_content_length(mut self, sid: UInt32) raises:
        """Reset the stream if actual DATA length contradicts content-length."""
        var expected = self.streams[sid].expected_content_length
        if expected >= 0 and self.streams[sid].received_data_len != expected:
            self._stream_error(sid, ERR_PROTOCOL_ERROR)

    def _on_headers(
        mut self, h: FrameHeader, var frame_payload: List[Byte]
    ) raises:
        """Starts a HEADERS block and finishes it when END_HEADERS is set."""
        if h.stream_id == 0:
            self._conn_error(ERR_PROTOCOL_ERROR, String("HEADERS on stream 0"))
        if self._is_closed(h.stream_id):
            self._conn_error(
                ERR_STREAM_CLOSED, String("HEADERS on closed stream")
            )
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
        if len(block) > self.max_header_block_size:
            self._conn_error(
                ERR_ENHANCE_YOUR_CALM,
                String("compressed header block too large"),
            )
        if not h.has_flag(FLAG_END_HEADERS):
            self._pending_header_stream = h.stream_id
            self._pending_header_flags = h.flags
            self._pending_header_block = block^
            self._pending_header_is_new = is_new
            self._pending_header_peer_initiated = peer_initiated
            self._pending_header_self_dependency = self_dep
            self._pending_header_continuations = 0
            return

        self._finish_headers(
            h.stream_id,
            h.flags,
            block^,
            is_new,
            peer_initiated,
            self_dep,
        )

    def _on_continuation(
        mut self, h: FrameHeader, var frame_payload: List[Byte]
    ) raises:
        """Appends one CONTINUATION fragment to the pending header block."""
        self._pending_header_continuations += 1
        if self._pending_header_continuations > self.max_header_continuations:
            self._conn_error(
                ERR_ENHANCE_YOUR_CALM,
                String("too many CONTINUATION frames"),
            )
        if self.max_header_block_size < len(self._pending_header_block) or len(
            frame_payload
        ) > self.max_header_block_size - len(self._pending_header_block):
            self._conn_error(
                ERR_ENHANCE_YOUR_CALM,
                String("compressed header block too large"),
            )
        self._pending_header_block.extend(Span(frame_payload))
        if not h.has_flag(FLAG_END_HEADERS):
            return

        var stream_id = self._pending_header_stream
        var flags = self._pending_header_flags
        var is_new = self._pending_header_is_new
        var peer_initiated = self._pending_header_peer_initiated
        var self_dependency = self._pending_header_self_dependency
        var block = self._pending_header_block^
        self._pending_header_stream = 0
        self._pending_header_flags = 0
        self._pending_header_block = List[Byte]()
        self._pending_header_is_new = False
        self._pending_header_peer_initiated = False
        self._pending_header_self_dependency = False
        self._pending_header_continuations = 0
        self._finish_headers(
            stream_id,
            flags,
            block^,
            is_new,
            peer_initiated,
            self_dependency,
        )

    def _finish_headers(
        mut self,
        stream_id: UInt32,
        flags: UInt8,
        var block: List[Byte],
        is_new: Bool,
        peer_initiated: Bool,
        self_dependency: Bool,
    ) raises:
        """Decodes and applies a complete HEADERS plus CONTINUATION block."""

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
                self._ensure_stream(stream_id)
                self._stream_error(stream_id, ERR_REFUSED_STREAM)
                return
        # HEADERS opens/continues the stream even when we then reset it.
        self._ensure_stream(stream_id)
        if self_dependency:
            self._stream_error(stream_id, ERR_PROTOCOL_ERROR)
            return
        if self.streams[stream_id].reset_code:
            if self.streams[stream_id].local_reset:
                return
            self._conn_error(
                ERR_STREAM_CLOSED, String("HEADERS on closed stream")
            )
        var is_trailers = self.streams[stream_id].headers_done
        if self.streams[stream_id].end_stream:
            if self.streams[stream_id].local_end:
                # Fully closed stream (§5.1 "closed"): connection error.
                self._conn_error(
                    ERR_STREAM_CLOSED, String("HEADERS on closed stream")
                )
            self._stream_error(stream_id, ERR_STREAM_CLOSED)
            return
        if is_trailers and (flags & FLAG_END_STREAM) == 0:
            # Trailers must end the stream (§8.1).
            self._stream_error(stream_id, ERR_PROTOCOL_ERROR)
            return
        if self.validate_requests and not self._validate_header_block(
            stream_id, Span(fields), is_trailers
        ):
            self._stream_error(stream_id, ERR_PROTOCOL_ERROR)
            return
        if not is_trailers:
            self.streams[stream_id].headers = fields^
            self.streams[stream_id].headers_done = True
        else:
            self.streams[stream_id].trailers = fields^
            self.streams[stream_id].trailers_done = True
        if (flags & FLAG_END_STREAM) != 0:
            self.streams[stream_id].end_stream = True
            self._check_content_length(stream_id)

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

    def take_buffered_data(
        mut self, stream_id: UInt32, n: Int
    ) raises -> List[Byte]:
        """Consumes already-buffered bytes and queues flow-control credit.

        This method performs no transport I/O and never processes incoming
        frames. Use `buffered_data_len` first in a readiness-driven loop.

        Args:
            stream_id: The stream to consume from.
            n: Exact number of buffered bytes to consume.

        Returns:
            The first n buffered bytes, removed from the stream's buffer.

        Raises:
            If n is negative, the stream is unknown, too few bytes are
            buffered, or the WINDOW_UPDATE would exceed the outbound queue
            bound.
        """
        if n < 0:
            raise Error("h2: negative data length")
        if (
            stream_id not in self.streams
            or len(self.streams[stream_id].data) < n
        ):
            raise Error("h2: not enough buffered data")
        var should_update = (
            n > 0 and not self.streams[stream_id].closed_by_peer()
        )
        if should_update:
            self._ensure_output_capacity(FRAME_HEADER_LEN + 4)

        var out = List[Byte](Span(self.streams[stream_id].data)[0:n])
        var remaining = len(self.streams[stream_id].data)
        var rest = List[Byte](Span(self.streams[stream_id].data)[n:remaining])
        self.streams[stream_id].data = rest^
        if should_update:
            self.streams[stream_id].recv_window += n
            var inc = List[Byte](capacity=4)
            put_u32_be(inc, UInt32(n))
            self._queue_frame_unchecked(FRAME_WINDOW_UPDATE, 0, stream_id, inc)
        return out^

    def take_data(mut self, stream_id: UInt32, n: Int) raises -> List[Byte]:
        """Consumes exactly n bytes through the blocking compatibility path.

        Incoming frames are processed until enough data is buffered. Taking
        bytes replenishes the peer's stream window, and the queued
        WINDOW_UPDATE is flushed before this method returns.

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
        if n < 0:
            raise Error("h2: negative data length")
        while True:
            self._ensure_stream(stream_id)
            if len(self.streams[stream_id].data) >= n:
                self.flush_output()
                var out = self.take_buffered_data(stream_id, n)
                self.flush_output()
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

        Call `begin_graceful_shutdown` (or `send_goaway`) first for a
        graceful shutdown, and wait until `live_stream_count` is zero.
        """
        self.stream.close()
