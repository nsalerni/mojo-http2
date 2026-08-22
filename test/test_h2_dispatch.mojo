# Direct HTTP/2 frame-dispatch tests. Header bytes are fixed vectors produced
# by Python hpack so the receive path is not checked against our own encoder.

from std.testing import assert_equal, assert_false, assert_true

from h2 import (
    FLAG_END_HEADERS,
    FLAG_END_STREAM,
    FRAME_CONTINUATION,
    FRAME_HEADERS,
    Frame,
    FrameHeader,
    Http2Connection,
)
from net import IOStream
from testutil import from_hex


struct SinkStream(IOStream):
    """An IOStream whose writes succeed and whose reads are forbidden."""

    def __init__(out self):
        pass

    def read_exact(self, n: Int) raises -> List[Byte]:
        _ = n
        raise Error("SinkStream must not be read")

    def write_all(self, data: Span[Byte, _]) raises:
        _ = data

    def set_read_timeout(self, nanos: Int64) raises:
        _ = nanos

    def set_nodelay(self, enabled: Bool) raises:
        _ = enabled

    def close(mut self):
        pass


def make_client() raises -> Http2Connection[SinkStream]:
    var conn = Http2Connection(SinkStream(), is_client=True)
    _ = conn.take_pending_output()
    assert_equal(conn.open_stream(), 1)
    return conn^


def make_frame(
    frame_type: UInt8,
    flags: UInt8,
    stream_id: UInt32,
    var payload: List[Byte],
) -> Frame:
    return Frame(
        header=FrameHeader(
            length=len(payload),
            frame_type=frame_type,
            flags=flags,
            stream_id=stream_id,
        ),
        payload=payload^,
    )


def response_block() raises -> List[Byte]:
    # :status=200, content-type=application/grpc, x-sequence=one
    return from_hex("885f8b1d75d0620d263d4c4d65644088f2b20bdad2d442ff823d45")


def header_value(
    conn: Http2Connection[SinkStream], name: StringSpan
) raises -> String:
    for field in conn.streams[1].headers:
        if field.name == name:
            return field.value.copy()
    return String()


def test_process_frame_completes_split_headers() raises:
    var conn = make_client()
    var block = response_block()
    var first = List[Byte](Span(block)[0:7])
    var second = List[Byte](Span(block)[7 : len(block)])

    conn.process_frame(make_frame(FRAME_HEADERS, FLAG_END_STREAM, 1, first^))
    assert_false(conn.streams[1].headers_done, "partial block stays pending")
    assert_false(conn.streams[1].end_stream, "END_STREAM waits for headers")

    conn.process_frame(
        make_frame(FRAME_CONTINUATION, FLAG_END_HEADERS, 1, second^)
    )
    assert_true(conn.streams[1].headers_done, "END_HEADERS completes block")
    assert_true(conn.streams[1].end_stream, "initial END_STREAM is preserved")
    assert_equal(header_value(conn, "content-type"), "application/grpc")
    assert_equal(header_value(conn, "x-sequence"), "one")


def test_process_frame_accepts_multiple_continuations() raises:
    var conn = make_client()
    var block = response_block()
    var first = List[Byte](Span(block)[0:3])
    var second = List[Byte](Span(block)[3:11])
    var third = List[Byte](Span(block)[11 : len(block)])

    conn.process_frame(make_frame(FRAME_HEADERS, 0, 1, first^))
    conn.process_frame(make_frame(FRAME_CONTINUATION, 0, 1, second^))
    assert_false(conn.streams[1].headers_done, "middle fragment stays pending")
    conn.process_frame(
        make_frame(FRAME_CONTINUATION, FLAG_END_HEADERS, 1, third^)
    )
    assert_true(conn.streams[1].headers_done, "final fragment completes block")
    assert_equal(header_value(conn, ":status"), "200")


def test_process_frame_accepts_complete_headers() raises:
    var conn = make_client()
    conn.process_frame(
        make_frame(FRAME_HEADERS, FLAG_END_HEADERS, 1, response_block())
    )
    assert_true(conn.streams[1].headers_done, "complete block is immediate")
    assert_false(conn.streams[1].end_stream, "END_STREAM remains unset")


def test_process_frame_rejects_interleaving() raises:
    var conn = make_client()
    var block = response_block()
    var first = List[Byte](Span(block)[0:5])
    conn.process_frame(make_frame(FRAME_HEADERS, 0, 1, first^))

    var raised = False
    try:
        conn.process_frame(make_frame(0x6, 0, 0, List[Byte](length=8, fill=0)))
    except error:
        raised = True
        assert_true("expected CONTINUATION" in String(error), String(error))
    assert_true(raised, "PING cannot interleave a header block")
    assert_true(conn.sent_goaway, "connection error sends GOAWAY")


def test_process_frame_rejects_wrong_continuation_stream() raises:
    var conn = make_client()
    var block = response_block()
    var first = List[Byte](Span(block)[0:5])
    var rest = List[Byte](Span(block)[5 : len(block)])
    conn.process_frame(make_frame(FRAME_HEADERS, 0, 1, first^))

    var raised = False
    try:
        conn.process_frame(
            make_frame(FRAME_CONTINUATION, FLAG_END_HEADERS, 3, rest^)
        )
    except error:
        raised = True
        assert_true("expected CONTINUATION" in String(error), String(error))
    assert_true(raised, "CONTINUATION must stay on the opening stream")
    assert_true(conn.sent_goaway, "connection error sends GOAWAY")


def test_process_frame_rejects_stray_continuation() raises:
    var conn = make_client()
    var raised = False
    try:
        conn.process_frame(
            make_frame(
                FRAME_CONTINUATION,
                FLAG_END_HEADERS,
                1,
                List[Byte](),
            )
        )
    except error:
        raised = True
        assert_true("stray CONTINUATION" in String(error), String(error))
    assert_true(raised, "CONTINUATION requires an open header block")


def test_process_frame_bounds_fragmented_header_storage() raises:
    var block = response_block()
    var exact = make_client()
    exact.max_header_block_size = len(block)
    var exact_first = List[Byte](Span(block)[0:7])
    var exact_rest = List[Byte](Span(block)[7 : len(block)])
    exact.process_frame(make_frame(FRAME_HEADERS, 0, 1, exact_first^))
    exact.process_frame(
        make_frame(FRAME_CONTINUATION, FLAG_END_HEADERS, 1, exact_rest^)
    )
    assert_true(exact.streams[1].headers_done, "exact byte limit is accepted")

    var conn = make_client()
    conn.max_header_block_size = 8
    var first = List[Byte](Span(block)[0:7])
    var rest = List[Byte](Span(block)[7 : len(block)])
    conn.process_frame(make_frame(FRAME_HEADERS, 0, 1, first^))

    var raised = False
    try:
        conn.process_frame(
            make_frame(FRAME_CONTINUATION, FLAG_END_HEADERS, 1, rest^)
        )
    except error:
        raised = True
        assert_true("header block too large" in String(error), String(error))
    assert_true(raised, "fragmented header storage must stay bounded")
    assert_true(conn.sent_goaway, "header block limit sends GOAWAY")


def test_process_frame_bounds_continuation_count() raises:
    var block = response_block()
    var exact = make_client()
    exact.max_header_continuations = 1
    var exact_first = List[Byte](Span(block)[0:3])
    var exact_rest = List[Byte](Span(block)[3 : len(block)])
    exact.process_frame(make_frame(FRAME_HEADERS, 0, 1, exact_first^))
    exact.process_frame(
        make_frame(FRAME_CONTINUATION, FLAG_END_HEADERS, 1, exact_rest^)
    )
    assert_true(exact.streams[1].headers_done, "exact frame limit is accepted")

    var conn = make_client()
    conn.max_header_continuations = 1
    var first = List[Byte](Span(block)[0:3])
    var third = List[Byte](Span(block)[3 : len(block)])
    conn.process_frame(make_frame(FRAME_HEADERS, 0, 1, first^))
    conn.process_frame(make_frame(FRAME_CONTINUATION, 0, 1, List[Byte]()))

    var raised = False
    try:
        conn.process_frame(
            make_frame(FRAME_CONTINUATION, FLAG_END_HEADERS, 1, third^)
        )
    except error:
        raised = True
        assert_true("too many CONTINUATION" in String(error), String(error))
    assert_true(raised, "empty fragments cannot hold a connection forever")
    assert_true(conn.sent_goaway, "continuation count limit sends GOAWAY")


def test_process_frame_validates_payload_length_and_limit() raises:
    var conn = make_client()
    var mismatch = Frame(
        header=FrameHeader(length=1, frame_type=0xFE, flags=0, stream_id=0),
        payload=List[Byte](),
    )
    var raised = False
    try:
        conn.process_frame(mismatch^)
    except error:
        raised = True
        assert_true("payload length mismatch" in String(error), String(error))
    assert_true(raised, "header and payload lengths must agree")

    conn = make_client()
    var oversized = List[Byte](length=16385, fill=0)
    raised = False
    try:
        conn.process_frame(make_frame(0xFE, 0, 0, oversized^))
    except error:
        raised = True
        assert_true("exceeds max frame size" in String(error), String(error))
    assert_true(raised, "configured frame limit applies to direct dispatch")


def test_process_frame_ignores_unknown_type() raises:
    var conn = make_client()
    conn.process_frame(make_frame(0xFE, 0, 0, List[Byte]()))
    assert_false(conn.sent_goaway, "unknown frames are ignored")


def main() raises:
    test_process_frame_completes_split_headers()
    test_process_frame_accepts_multiple_continuations()
    test_process_frame_accepts_complete_headers()
    test_process_frame_rejects_interleaving()
    test_process_frame_rejects_wrong_continuation_stream()
    test_process_frame_rejects_stray_continuation()
    test_process_frame_bounds_fragmented_header_storage()
    test_process_frame_bounds_continuation_count()
    test_process_frame_validates_payload_length_and_limit()
    test_process_frame_ignores_unknown_type()
    print("test_h2_dispatch: all tests passed")
