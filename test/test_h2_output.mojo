# Outbound HTTP/2 queue tests. Expected wire bytes are fixed RFC frame
# encodings so queue order and flags are not checked against our serializer.

from std.testing import assert_equal, assert_false, assert_true

from h2 import (
    ERR_PROTOCOL_ERROR,
    FLAG_ACK,
    FLAG_END_STREAM,
    FRAME_DATA,
    FRAME_PING,
    FRAME_PRIORITY,
    FRAME_SETTINGS,
    FRAME_WINDOW_UPDATE,
    Frame,
    FrameHeader,
    Http2Connection,
)
from hpack import HeaderField
from net import IOStream
from testutil import from_hex, to_hex


struct RejectingStream(IOStream):
    """A transport that can reject unexpected writes."""

    var reject_writes: Bool

    def __init__(out self):
        self.reject_writes = True

    def read_exact(self, n: Int) raises -> List[Byte]:
        _ = n
        raise Error("RejectingStream must not be read")

    def write_all(self, data: Span[Byte, _]) raises:
        _ = data
        if self.reject_writes:
            raise Error("RejectingStream write rejected")

    def set_read_timeout(self, nanos: Int64) raises:
        _ = nanos

    def set_nodelay(self, enabled: Bool) raises:
        _ = enabled

    def close(mut self):
        pass


def make_client() raises -> Http2Connection[RejectingStream]:
    var conn = Http2Connection(RejectingStream(), is_client=True)
    _ = conn.take_pending_output()
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


def test_incremental_startup_and_every_split_point() raises:
    # Client preface followed by an empty SETTINGS frame produced by
    # hyper-h2's initiate_connection().
    var preface = from_hex(
        "505249202a20485454502f322e300d0a0d0a534d0d0a0d0a"
    )
    var settings = from_hex("000000040000000000")
    var wire = preface.copy()
    wire.extend(Span(settings))
    var expected_server_output = (
        "00000c040000000000000300000100000600004000"
        "000000040100000000"
    )

    for split in range(len(wire) + 1):
        var server = Http2Connection(RejectingStream(), is_client=False)
        assert_equal(server.pending_output_len(), 0)
        _ = server.feed_input(Span(wire)[0:split])
        _ = server.feed_input(Span(wire)[split : len(wire)])
        assert_true(server.input_preface_complete())
        assert_true(server.peer_settings_received)
        assert_equal(server.pending_input_frame_count(), 0)
        var output = server.take_pending_output()
        assert_equal(to_hex(Span(output)), expected_server_output)

    var bytewise = Http2Connection(RejectingStream(), is_client=False)
    for i in range(len(wire)):
        _ = bytewise.feed_input(Span(wire)[i : i + 1])
    assert_true(bytewise.input_preface_complete())
    assert_true(bytewise.peer_settings_received)
    var output = bytewise.take_pending_output()
    assert_equal(to_hex(Span(output)), expected_server_output)

    var partial = Http2Connection(RejectingStream(), is_client=False)
    _ = partial.feed_input(Span(preface)[0:1])
    partial.max_pending_output_size = 0
    _ = partial.feed_input(Span(preface)[0:0])
    assert_false(partial.input_preface_complete())

    var backpressured = Http2Connection(RejectingStream(), is_client=False)
    _ = backpressured.feed_input(Span(preface))
    backpressured.max_pending_output_size = 21
    assert_equal(backpressured.feed_input(Span(settings)), 0)
    assert_equal(backpressured.pending_input_frame_count(), 1)
    _ = backpressured.take_pending_output()
    backpressured.max_pending_output_size = 26
    var empty = List[Byte]()
    assert_equal(backpressured.feed_input(Span(empty)), 1)
    assert_equal(backpressured.pending_input_frame_count(), 0)
    output = backpressured.take_pending_output()
    assert_equal(to_hex(Span(output)), "000000040100000000")


def test_client_startup_is_queued_without_writes() raises:
    var client = Http2Connection(RejectingStream(), is_client=True)
    assert_true(client.input_preface_complete())
    var output = client.take_pending_output()
    assert_equal(
        to_hex(Span(output)),
        (
            "505249202a20485454502f322e300d0a0d0a534d0d0a0d0a"
            "00000c040000000000000300000100000600004000"
        ),
    )


def test_incremental_connection_error_is_terminal() raises:
    var client = make_client()
    # PING has a valid eight-byte payload but illegally targets stream 1.
    var malformed = from_hex(
        "0000080600000000013132333435363738"
    )
    var raised = False
    try:
        _ = client.feed_input(Span(malformed))
    except error:
        raised = True
        assert_true("PING on stream" in String(error), String(error))
    assert_true(raised, "connection error must raise")

    var empty = List[Byte]()
    raised = False
    try:
        _ = client.feed_input(Span(empty))
    except error:
        raised = True
        assert_true("incremental input is failed" in String(error), String(error))
    assert_true(raised, "connection error must reject later input")


def test_automatic_responses_queue_without_writes() raises:
    var conn = make_client()
    conn.stream.reject_writes = True
    conn.process_frame(make_frame(FRAME_SETTINGS, 0, 0, List[Byte]()))
    conn.process_frame(
        make_frame(FRAME_PING, 0, 0, from_hex("3132333435363738"))
    )

    assert_equal(conn.pending_output_len(), 26)
    var output = conn.take_pending_output()
    assert_equal(
        to_hex(Span(output)),
        "0000000401000000000000080601000000003132333435363738",
    )
    assert_equal(conn.pending_output_len(), 0, "take empties the queue")


def test_data_queues_connection_window_update() raises:
    var conn = make_client()
    _ = conn.open_stream()
    conn.stream.reject_writes = True
    conn.process_frame(make_frame(FRAME_DATA, 0, 1, from_hex("616263")))
    var output = conn.take_pending_output()
    assert_equal(to_hex(Span(output)), "00000408000000000000000003")

    conn.max_pending_output_size = 12
    var raised = False
    try:
        _ = conn.take_buffered_data(1, 3)
    except:
        raised = True
    assert_true(raised, "WINDOW_UPDATE must fit before data is consumed")
    assert_equal(conn.buffered_data_len(1), 3, "failed consume keeps data")
    conn.max_pending_output_size = 13
    var taken = conn.take_buffered_data(1, 3)
    assert_equal(to_hex(Span(taken)), "616263")
    output = conn.take_pending_output()
    assert_equal(
        to_hex(Span(output)),
        "00000408000000000100000003",
        "consumption queues the stream window update",
    )


def test_errors_queue_goaway_and_rst_stream() raises:
    var conn = make_client()
    conn.stream.reject_writes = True
    var raised = False
    try:
        conn.process_frame(
            make_frame(FRAME_PING, 0, 1, List[Byte](length=8, fill=0))
        )
    except error:
        raised = True
        assert_true("PING on stream" in String(error), String(error))
    assert_true(raised, "invalid PING raises")
    var output = conn.take_pending_output()
    assert_equal(to_hex(Span(output)), "0000080700000000000000000000000001")

    conn = make_client()
    _ = conn.open_stream()
    conn.stream.reject_writes = True
    conn.process_frame(make_frame(FRAME_PRIORITY, 0, 1, from_hex("0000000100")))
    output = conn.take_pending_output()
    assert_equal(to_hex(Span(output)), "00000403000000000100000001")


def test_queue_data_reports_flow_control_progress() raises:
    var conn = make_client()
    _ = conn.open_stream()
    conn.send_window = 5
    conn.streams[1].send_window = 7
    conn.stream.reject_writes = True
    var data = from_hex("00010203040506070809")

    var consumed = conn.queue_data(1, Span(data), end_stream=True)
    assert_equal(consumed, 5)
    assert_false(conn.streams[1].local_end, "partial queue omits END_STREAM")
    assert_equal(conn.send_window, 0)
    assert_equal(conn.streams[1].send_window, 2)
    var output = conn.take_pending_output()
    assert_equal(to_hex(Span(output)), "0000050000000000010001020304")

    conn.process_frame(
        make_frame(FRAME_WINDOW_UPDATE, 0, 0, from_hex("00000005"))
    )
    conn.process_frame(
        make_frame(FRAME_WINDOW_UPDATE, 0, 1, from_hex("00000003"))
    )
    consumed = conn.queue_data(1, Span(data)[5 : len(data)], end_stream=True)
    assert_equal(consumed, 5)
    assert_true(conn.streams[1].local_end, "final queue sets END_STREAM")
    output = conn.take_pending_output()
    assert_equal(to_hex(Span(output)), "0000050001000000010506070809")


def test_queue_data_respects_output_capacity() raises:
    var conn = make_client()
    _ = conn.open_stream()
    conn.max_pending_output_size = 20
    var data = from_hex("000102030405060708090a0b0c0d0e0f10111213")

    var consumed = conn.queue_data(1, Span(data), end_stream=True)
    assert_equal(consumed, 11, "queue admits payload plus one frame header")
    assert_false(conn.streams[1].local_end, "bounded prefix omits END_STREAM")
    var output = conn.take_pending_output()
    assert_equal(len(output), 20)
    assert_equal(to_hex(Span(output)[0:9]), "00000b000000000001")

    consumed = conn.queue_data(1, Span(data)[11 : len(data)], end_stream=True)
    assert_equal(consumed, 9)
    assert_true(conn.streams[1].local_end)
    output = conn.take_pending_output()
    assert_equal(to_hex(Span(output)[0:9]), "000009000100000001")


def test_header_rejection_preserves_hpack_state() raises:
    var headers = List[HeaderField]()
    headers.append(HeaderField(":method", "POST"))
    headers.append(HeaderField("x-queue-test", "first-value"))

    var retried = make_client()
    _ = retried.open_stream()
    retried.max_pending_output_size = 10
    var raised = False
    try:
        retried.queue_headers(1, Span(headers), end_stream=False)
    except:
        raised = True
    assert_true(raised, "header block above queue bound is rejected")
    assert_equal(retried.pending_output_len(), 0)
    retried.max_pending_output_size = 1024
    retried.queue_headers(1, Span(headers), end_stream=False)
    var retried_output = retried.take_pending_output()

    var fresh = make_client()
    _ = fresh.open_stream()
    fresh.queue_headers(1, Span(headers), end_stream=False)
    var fresh_output = fresh.take_pending_output()
    assert_equal(
        to_hex(Span(retried_output)),
        to_hex(Span(fresh_output)),
        "rejected headers do not advance the dynamic table",
    )


def test_public_queue_order_and_blocking_flush() raises:
    var conn = make_client()
    conn.stream.reject_writes = True
    conn.queue_ping(0x3132333435363738)
    conn.queue_rst_stream(1, ERR_PROTOCOL_ERROR)
    assert_equal(conn.pending_output_len(), 30)

    conn.stream.reject_writes = False
    conn.flush_output()
    assert_equal(conn.pending_output_len(), 0)


def test_queue_bound_is_atomic() raises:
    var conn = make_client()
    conn.max_pending_output_size = 16
    var raised = False
    try:
        conn.queue_ping(0)
    except error:
        raised = True
        assert_true("queue limit exceeded" in String(error), String(error))
    assert_true(raised, "frame above the queue bound is rejected")
    assert_equal(conn.pending_output_len(), 0, "rejection retains no prefix")

    conn.max_pending_output_size = 17
    conn.queue_ping(0)
    assert_equal(conn.pending_output_len(), 17, "exact queue bound is accepted")
    raised = False
    try:
        conn.queue_rst_stream(1, 0)
    except error:
        raised = True
    assert_true(raised, "second frame cannot overflow the queue")
    assert_equal(conn.pending_output_len(), 17, "existing output stays intact")

    conn = make_client()
    conn.max_pending_output_size = 16
    raised = False
    try:
        conn.queue_goaway(0)
    except:
        raised = True
    assert_true(raised, "GOAWAY above the queue bound is rejected")
    assert_false(conn.sent_goaway, "failed enqueue does not mark GOAWAY sent")


def test_dispatch_backpressure_is_retryable() raises:
    var conn = make_client()
    conn.max_pending_output_size = 42
    conn.queue_ping(0)
    var raised = False
    try:
        conn.process_frame(make_frame(0xFE, 0, 0, List[Byte]()))
    except error:
        raised = True
        assert_true("queue limit exceeded" in String(error), String(error))
    assert_true(raised, "dispatch waits for worst-case response capacity")
    assert_equal(conn.pending_output_len(), 17, "queued output is unchanged")

    _ = conn.take_pending_output()
    conn.process_frame(make_frame(0xFE, 0, 0, List[Byte]()))
    assert_equal(
        conn.pending_output_len(), 0, "same frame succeeds after drain"
    )


def test_failed_flush_retains_output() raises:
    var conn = make_client()
    conn.queue_ping(0)
    conn.stream.reject_writes = True
    var raised = False
    try:
        conn.flush_output()
    except:
        raised = True
    assert_true(raised, "flush propagates transport errors")
    assert_equal(conn.pending_output_len(), 17, "failed flush retains bytes")


def main() raises:
    test_incremental_startup_and_every_split_point()
    test_client_startup_is_queued_without_writes()
    test_incremental_connection_error_is_terminal()
    test_automatic_responses_queue_without_writes()
    test_data_queues_connection_window_update()
    test_errors_queue_goaway_and_rst_stream()
    test_queue_data_reports_flow_control_progress()
    test_queue_data_respects_output_capacity()
    test_header_rejection_preserves_hpack_state()
    test_public_queue_order_and_blocking_flush()
    test_queue_bound_is_atomic()
    test_dispatch_backpressure_is_retryable()
    test_failed_flush_retains_output()
    print("test_h2_output: all tests passed")
