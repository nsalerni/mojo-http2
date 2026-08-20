# HTTP/2 edge-case tests: frame header codec corners, byte helpers,
# Settings validation, CONTINUATION splitting on send, stream lifecycle
# corners (empty DATA, short streams, GOAWAY, RST_STREAM), flood guards,
# and server-role preface validation. Same loopback pattern as test_h2:
# a real client and server connection over TCP in one thread.

from std.testing import assert_equal, assert_false, assert_true

from h2 import (
    ERR_CANCEL,
    ERR_ENHANCE_YOUR_CALM,
    ERR_NO_ERROR,
    ERR_PROTOCOL_ERROR,
    FRAME_GOAWAY,
    FrameHeader,
    Http2Connection,
    Settings,
    get_u16_be,
    get_u24_be,
    get_u32_be,
    put_u16_be,
    put_u24_be,
    put_u32_be,
)
from h2.frame import (
    SETTINGS_ENABLE_PUSH,
    SETTINGS_HEADER_TABLE_SIZE,
    SETTINGS_INITIAL_WINDOW_SIZE,
    SETTINGS_MAX_CONCURRENT_STREAMS,
    SETTINGS_MAX_FRAME_SIZE,
    SETTINGS_MAX_HEADER_LIST_SIZE,
)
from hpack import Encoder as HpackEncoder
from hpack import HeaderField
from net import TCPListener, TCPStream


def hf(name: StringSpan, value: StringSpan) -> HeaderField:
    return HeaderField(name=String(name), value=String(value))


@fieldwise_init
struct ConnPair(Movable):
    var client: Http2Connection[TCPStream]
    var server: Http2Connection[TCPStream]


def make_pair() raises -> ConnPair:
    var listener = TCPListener("127.0.0.1", 0)
    var client_tcp = TCPStream.connect("127.0.0.1", listener.local_port)
    var server_tcp = listener.accept()
    # Client ctor writes preface+SETTINGS; server ctor reads them.
    var client = Http2Connection(client_tcp^, is_client=True)
    var server = Http2Connection(server_tcp^, is_client=False)
    # Let each side process the peer's SETTINGS (and ACK it).
    server.process_next_frame()  # client SETTINGS
    client.process_next_frame()  # server SETTINGS
    server.process_next_frame()  # client's ACK
    client.process_next_frame()  # server's ACK
    listener.close()
    return ConnPair(client=client^, server=server^)


# --- 11. FrameHeader codec corners ---


def test_frame_header_short_input_raises() raises:
    var short = List[Byte](length=8, fill=0)
    var raised = False
    try:
        _ = FrameHeader.parse(Span(short))
    except err:
        raised = True
        assert_true("short frame header" in String(err), String(err))
    assert_true(raised, "<9 bytes must raise")


def test_frame_header_reserved_bit_masked() raises:
    # Stream id bytes 0x80 00 00 01: the reserved high bit is masked off
    # on parse, yielding stream_id == 1.
    var raw = List[Byte]()
    put_u24_be(raw, 3)
    raw.append(0x0)  # DATA
    raw.append(0x0)
    raw.append(0x80)
    raw.append(0x00)
    raw.append(0x00)
    raw.append(0x01)
    var h = FrameHeader.parse(Span(raw))
    assert_equal(h.stream_id, 1)
    assert_equal(h.length, 3)

    # serialize always sends the reserved bit as 0.
    var out = List[Byte]()
    var h2 = FrameHeader(
        length=0, frame_type=0x0, flags=0x0, stream_id=0x80000001
    )
    h2.serialize(out)
    assert_equal(len(out), 9)
    assert_equal(Int(out[5]), 0x00)  # top bit cleared
    assert_equal(Int(out[8]), 0x01)
    var back = FrameHeader.parse(Span(out))
    assert_equal(back.stream_id, 1)


def test_frame_header_flags_and_length_extremes() raises:
    var h = FrameHeader(length=0, frame_type=0x1, flags=0x05, stream_id=9)
    assert_true(h.has_flag(0x1), "END_STREAM set")
    assert_true(h.has_flag(0x4), "END_HEADERS set")
    assert_false(h.has_flag(0x2), "unset flag")
    # Multi-bit query: true if ANY of the given bits are set.
    assert_true(h.has_flag(0x6), "multi-bit any-match")

    # length = 0 and the 24-bit maximum both round-trip.
    for value in [0, 0xFFFFFF]:
        var buf = List[Byte]()
        var hh = FrameHeader(
            length=value, frame_type=0x0, flags=0x0, stream_id=1
        )
        hh.serialize(buf)
        var parsed = FrameHeader.parse(Span(buf))
        assert_equal(parsed.length, value)


# --- 12. Big-endian byte helpers ---


def test_be_helpers() raises:
    var buf = List[Byte]()
    put_u16_be(buf, 0)
    put_u16_be(buf, 0xFFFF)
    assert_equal(Int(get_u16_be(Span(buf), 0)), 0)
    assert_equal(Int(get_u16_be(Span(buf), 2)), 0xFFFF)

    buf.clear()
    put_u24_be(buf, 0)
    put_u24_be(buf, 0xFFFFFF)
    assert_equal(Int(get_u24_be(Span(buf), 0)), 0)
    assert_equal(Int(get_u24_be(Span(buf), 3)), 0xFFFFFF)

    buf.clear()
    buf.append(0xAA)  # offset padding
    put_u32_be(buf, 0)
    put_u32_be(buf, 0xFFFFFFFF)
    put_u32_be(buf, 0x01020304)
    assert_equal(Int(get_u32_be(Span(buf), 1)), 0)
    assert_equal(Int(get_u32_be(Span(buf), 5)), 0xFFFFFFFF)
    assert_equal(Int(get_u32_be(Span(buf), 9)), 0x01020304)


# --- 6. Settings defaults, apply, and validation ---


def _one_setting(ident: UInt16, value: UInt32) -> List[Byte]:
    var p = List[Byte]()
    put_u16_be(p, ident)
    put_u32_be(p, value)
    return p^


def test_settings_defaults_and_apply() raises:
    var s = Settings()
    assert_equal(Int(s.header_table_size), 4096)
    assert_true(s.enable_push, "push defaults on")
    assert_equal(Int(s.max_concurrent_streams), 0xFFFFFFFF)
    assert_equal(Int(s.initial_window_size), 65535)
    assert_equal(Int(s.max_frame_size), 16384)
    assert_equal(Int(s.max_header_list_size), 0xFFFFFFFF)

    s.apply(Span(_one_setting(SETTINGS_HEADER_TABLE_SIZE, 8192)))
    assert_equal(Int(s.header_table_size), 8192)
    s.apply(Span(_one_setting(SETTINGS_ENABLE_PUSH, 0)))
    assert_false(s.enable_push, "push disabled")
    s.apply(Span(_one_setting(SETTINGS_MAX_CONCURRENT_STREAMS, 100)))
    assert_equal(Int(s.max_concurrent_streams), 100)
    s.apply(Span(_one_setting(SETTINGS_INITIAL_WINDOW_SIZE, 123)))
    assert_equal(Int(s.initial_window_size), 123)
    s.apply(Span(_one_setting(SETTINGS_MAX_FRAME_SIZE, 65536)))
    assert_equal(Int(s.max_frame_size), 65536)
    s.apply(Span(_one_setting(SETTINGS_MAX_HEADER_LIST_SIZE, 2222)))
    assert_equal(Int(s.max_header_list_size), 2222)

    # Unknown identifiers are ignored (§6.5.2) and change nothing.
    s.apply(Span(_one_setting(0x99, 42)))
    assert_equal(Int(s.header_table_size), 8192)
    assert_equal(Int(s.max_frame_size), 65536)


def test_settings_validation_raises() raises:
    # Payload length not a multiple of 6.
    var s = Settings()
    var bad_len = List[Byte](length=5, fill=0)
    var raised = False
    try:
        s.apply(Span(bad_len))
    except err:
        raised = True
        assert_true("multiple of 6" in String(err), String(err))
    assert_true(raised, "bad payload length must raise")

    # ENABLE_PUSH > 1.
    raised = False
    try:
        s.apply(Span(_one_setting(SETTINGS_ENABLE_PUSH, 2)))
    except err:
        raised = True
        assert_true("ENABLE_PUSH" in String(err), String(err))
    assert_true(raised, "ENABLE_PUSH=2 must raise")

    # INITIAL_WINDOW_SIZE > 2^31 - 1.
    raised = False
    try:
        s.apply(Span(_one_setting(SETTINGS_INITIAL_WINDOW_SIZE, 0x80000000)))
    except err:
        raised = True
        assert_true("INITIAL_WINDOW_SIZE" in String(err), String(err))
    assert_true(raised, "oversized INITIAL_WINDOW_SIZE must raise")

    # MAX_FRAME_SIZE outside [16384, 16777215].
    for bad in [16383, 16777216]:
        raised = False
        try:
            s.apply(Span(_one_setting(SETTINGS_MAX_FRAME_SIZE, UInt32(bad))))
        except err:
            raised = True
            assert_true("MAX_FRAME_SIZE" in String(err), String(err))
        assert_true(raised, "out-of-range MAX_FRAME_SIZE must raise")


# --- 13. HEADERS + CONTINUATION split on the send side ---


def test_send_headers_continuation_split() raises:
    var pair = make_pair()
    ref client = pair.client
    ref server = pair.server
    # Our receiver caps the uncompressed header list at 16 KB by default;
    # raise it so the oversized (but legal) block is accepted.
    server.max_header_list_size = 100_000

    var big = String()
    for _ in range(40_000):
        big += "x"
    var req_headers = [
        hf(":method", "POST"),
        hf(":scheme", "http"),
        hf(":path", "/big-headers"),
        hf("x-big", big),
    ]
    # The encoded block must exceed the peer's 16384 max_frame_size so
    # that send_headers has to split into HEADERS + CONTINUATION. Verify
    # with an identical fresh encoder (the client's encoder has the same
    # empty dynamic table at this point).
    var probe = HpackEncoder()
    var block = List[Byte]()
    probe.encode(Span(req_headers), block)
    assert_true(len(block) > 16384, "block must exceed max_frame_size")

    var sid = client.open_stream()
    client.send_headers(sid, Span(req_headers), end_stream=True)
    server.wait_headers(sid)
    assert_true(server.streams[sid].headers_done, "block reassembled")
    assert_equal(len(server.streams[sid].headers), 4)
    assert_equal(server.streams[sid].headers[3].name, String("x-big"))
    assert_equal(server.streams[sid].headers[3].value.byte_length(), 40_000)
    assert_equal(server.streams[sid].headers[3].value, big)
    client.close()
    server.close()


# --- 14. Empty DATA with END_STREAM; unknown-stream send_data ---


def test_send_data_empty_end_stream_and_unknown_stream() raises:
    var pair = make_pair()
    ref client = pair.client
    ref server = pair.server

    var sid = client.open_stream()
    var req_headers = [
        hf(":method", "POST"),
        hf(":scheme", "http"),
        hf(":path", "/empty"),
    ]
    client.send_headers(sid, Span(req_headers), end_stream=False)
    var empty = List[Byte]()
    client.send_data(sid, Span(empty), end_stream=True)
    server.wait_headers(sid)
    server.wait_stream_end(sid)
    assert_true(server.streams[sid].end_stream, "peer sees stream end")
    assert_equal(server.buffered_data_len(sid), 0)
    assert_true(client.streams[sid].local_end, "our side marked done")

    # A non-empty send_data on an unknown stream id raises. (Note: an
    # empty payload with end_stream=True on an unknown id skips the loop
    # and does NOT raise — actual source behavior, not exercised here
    # because it would emit a frame that confuses the peer.)
    var raised = False
    try:
        client.send_data(999, String("x").as_bytes(), end_stream=False)
    except err:
        raised = True
        assert_true("unknown stream" in String(err), String(err))
    assert_true(raised, "send_data on unknown stream must raise")
    client.close()
    server.close()


# --- 15. Short streams: take_data / wait_data / buffered_data_len ---


def test_take_and_wait_on_short_stream() raises:
    var pair = make_pair()
    ref client = pair.client
    ref server = pair.server

    var sid = client.open_stream()
    var req_headers = [
        hf(":method", "GET"),
        hf(":scheme", "http"),
        hf(":path", "/short"),
    ]
    client.send_headers(sid, Span(req_headers), end_stream=True)
    server.wait_headers(sid)

    var resp = [hf(":status", "200")]
    server.send_headers(sid, Span(resp), end_stream=False)
    server.send_data(sid, String("abc").as_bytes(), end_stream=True)

    client.wait_headers(sid)
    # Stream ends with only 3 bytes: waiting for 10 returns False.
    assert_false(client.wait_data(sid, 10), "wait_data short returns False")
    # The 3 buffered bytes are still consumable.
    var got = client.take_data(sid, 3)
    assert_equal(String(from_utf8=got), "abc")
    # Asking for more after the end raises.
    var raised = False
    try:
        _ = client.take_data(sid, 1)
    except err:
        raised = True
        assert_true("stream ended" in String(err), String(err))
    assert_true(raised, "take_data past stream end must raise")

    assert_equal(client.buffered_data_len(12345), 0)
    client.close()
    server.close()


# --- 16. GOAWAY blocks new streams ---


def test_goaway_blocks_open_stream() raises:
    var pair = make_pair()
    ref client = pair.client
    ref server = pair.server

    server.send_goaway(ERR_NO_ERROR)
    while not Bool(client.goaway_code):
        client.process_next_frame()
    assert_equal(client.goaway_code.value(), ERR_NO_ERROR)
    # Server never processed a client-initiated stream.
    assert_equal(client.goaway_last_stream, 0)

    var raised = False
    try:
        _ = client.open_stream()
    except err:
        raised = True
        assert_true("GOAWAY" in String(err), String(err))
    assert_true(raised, "open_stream after GOAWAY must raise")
    client.close()
    server.close()


# --- 17. RST_STREAM received on an open stream ---


def test_rst_stream_received() raises:
    var pair = make_pair()
    ref client = pair.client
    ref server = pair.server

    var sid = client.open_stream()
    var req_headers = [
        hf(":method", "POST"),
        hf(":scheme", "http"),
        hf(":path", "/cancel-me"),
    ]
    client.send_headers(sid, Span(req_headers), end_stream=False)
    server.wait_headers(sid)

    server.send_rst_stream(sid, ERR_CANCEL)
    while not Bool(client.streams[sid].reset_code):
        client.process_next_frame()
    assert_equal(client.streams[sid].reset_code.value(), ERR_CANCEL)
    assert_true(client.streams[sid].closed_by_peer(), "reset closes stream")
    assert_false(client.streams[sid].local_reset, "peer reset, not local")
    assert_false(client.streams[sid].end_stream, "reset is not END_STREAM")
    client.close()
    server.close()


# --- 18. Flood guards (ENHANCE_YOUR_CALM) ---


def test_ping_flood_guard() raises:
    # >1024 control frames with no DATA/HEADERS in between must cost the
    # connection (CVE-2019-9512-class guard).
    var pair = make_pair()
    ref client = pair.client
    ref server = pair.server

    # make_pair already delivered one SETTINGS + one ACK to the server
    # (control_frames == 2), so the 1023rd PING crosses the threshold;
    # send a full 1025 to be independent of that bookkeeping.
    for i in range(1025):
        client.send_ping(UInt64(i))

    var raised = False
    var msg = String()
    try:
        for _ in range(1100):
            server.process_next_frame()
    except err:
        raised = True
        msg = String(err)
    assert_true(raised, "PING flood must kill the connection")
    assert_true("control frame flood" in msg, msg)

    # The server sent GOAWAY(ENHANCE_YOUR_CALM) before raising; the
    # client sees it after draining the PING ACKs.
    while not Bool(client.goaway_code):
        client.process_next_frame()
    assert_equal(client.goaway_code.value(), ERR_ENHANCE_YOUR_CALM)
    client.close()
    server.close()


def test_rapid_reset_flood_guard() raises:
    # CVE-2023-44487-class guard: many streams opened and immediately
    # reset by the peer (> 512 RSTs and RSTs * 2 > total streams).
    var pair = make_pair()
    ref client = pair.client
    ref server = pair.server

    # All-static header fields keep every HEADERS frame tiny, so all 513
    # opens+resets fit in the kernel socket buffers without interleaving.
    var req_headers = [
        hf(":method", "POST"),
        hf(":scheme", "http"),
        hf(":path", "/"),
    ]
    for _ in range(513):
        var sid = client.open_stream()
        client.send_headers(sid, Span(req_headers), end_stream=False)
        client.send_rst_stream(sid, ERR_CANCEL)

    var raised = False
    var msg = String()
    try:
        for _ in range(1100):
            server.process_next_frame()
    except err:
        raised = True
        msg = String(err)
    assert_true(raised, "rapid reset must kill the connection")
    assert_true("stream reset flood" in msg, msg)

    while not Bool(client.goaway_code):
        client.process_next_frame()
    assert_equal(client.goaway_code.value(), ERR_ENHANCE_YOUR_CALM)
    client.close()
    server.close()


# --- 19. Server-role bad preface ---


def test_server_rejects_bad_preface() raises:
    var listener = TCPListener("127.0.0.1", 0)
    var client_tcp = TCPStream.connect("127.0.0.1", listener.local_port)
    var server_tcp = listener.accept()
    # 24 garbage bytes where the RFC 9113 §3.4 preface belongs.
    client_tcp.write_all(String("XXXXXXXXXXXXXXXXXXXXXXXX").as_bytes())

    var raised = False
    try:
        var server = Http2Connection(server_tcp^, is_client=False)
        server.close()
    except err:
        raised = True
        assert_true("bad client connection preface" in String(err), String(err))
    assert_true(raised, "garbage preface must raise")

    # §3.4: the server answers with GOAWAY(PROTOCOL_ERROR) before closing.
    var frame = client_tcp.read_exact(17)  # 9-byte header + 8-byte payload
    var h = FrameHeader.parse(Span(frame))
    assert_equal(h.frame_type, FRAME_GOAWAY)
    assert_equal(h.length, 8)
    assert_equal(h.stream_id, 0)
    assert_equal(get_u32_be(Span(frame), 13), ERR_PROTOCOL_ERROR)
    client_tcp.close()
    listener.close()


def main() raises:
    test_frame_header_short_input_raises()
    test_frame_header_reserved_bit_masked()
    test_frame_header_flags_and_length_extremes()
    test_be_helpers()
    test_settings_defaults_and_apply()
    test_settings_validation_raises()
    test_send_headers_continuation_split()
    test_send_data_empty_end_stream_and_unknown_stream()
    test_take_and_wait_on_short_stream()
    test_goaway_blocks_open_stream()
    test_rst_stream_received()
    test_ping_flood_guard()
    test_rapid_reset_flood_guard()
    test_server_rejects_bad_preface()
    print("test_h2_edges: all tests passed")
