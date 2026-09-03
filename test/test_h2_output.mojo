# Outbound HTTP/2 queue tests. Expected wire bytes are fixed RFC frame
# encodings so queue order and flags are not checked against our serializer.

from std.testing import assert_equal, assert_false, assert_true

from h2 import (
    ERR_CANCEL,
    ERR_NO_ERROR,
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
    put_u16_be,
    put_u32_be,
)
from h2.frame import SETTINGS_ENABLE_PUSH
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

    def write_some(self, data: Span[Byte, _]) raises -> Int:
        self.write_all(data)
        return len(data)

    def set_read_timeout(self, nanos: Int64) raises:
        _ = nanos

    def set_write_timeout(self, nanos: Int64) raises:
        _ = nanos

    def set_nodelay(self, enabled: Bool) raises:
        _ = enabled

    def close(mut self):
        pass


struct PartialThenFailStream(IOStream):
    """Accepts 5 bytes of a full PING, then fails on the remainder.

    `IOStream.write_some` takes an immutable `self`, so the failure is
    keyed off the offered span: a 17-byte PING is accepted in part, and
    the 12-byte retry raises.
    """

    def __init__(out self):
        pass

    def read_exact(self, n: Int) raises -> List[Byte]:
        _ = n
        raise Error("PartialThenFailStream must not be read")

    def write_all(self, data: Span[Byte, _]) raises:
        _ = data
        raise Error("PartialThenFailStream does not support write_all")

    def write_some(self, data: Span[Byte, _]) raises -> Int:
        if len(data) < 17:
            raise Error("flush failed after partial write")
        return min(5, len(data))

    def set_read_timeout(self, nanos: Int64) raises:
        _ = nanos

    def set_write_timeout(self, nanos: Int64) raises:
        _ = nanos

    def set_nodelay(self, enabled: Bool) raises:
        _ = enabled

    def close(mut self):
        pass


struct ScriptedStream(IOStream):
    """Serves queued input bytes and records writes.

    `read_exact` and `write_some` take an immutable `self`, so the byte
    buffers live behind pointers owned by the test.
    """

    var incoming: Pointer[List[Byte], MutUntrackedOrigin]
    var outgoing: Pointer[List[Byte], MutUntrackedOrigin]

    def __init__(
        out self,
        incoming: Pointer[List[Byte], MutUntrackedOrigin],
        outgoing: Pointer[List[Byte], MutUntrackedOrigin],
    ):
        self.incoming = incoming
        self.outgoing = outgoing

    def read_exact(self, n: Int) raises -> List[Byte]:
        if n < 0 or n > len(self.incoming[]):
            raise Error("ScriptedStream EOF")
        var out = List[Byte](Span(self.incoming[])[0:n])
        self.incoming[] = List[Byte](Span(self.incoming[])[n:])
        return out^

    def write_all(self, data: Span[Byte, _]) raises:
        _ = self.write_some(data)

    def write_some(self, data: Span[Byte, _]) raises -> Int:
        self.outgoing[].extend(data)
        return len(data)

    def set_read_timeout(self, nanos: Int64) raises:
        _ = nanos

    def set_write_timeout(self, nanos: Int64) raises:
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


def push_setting(value: UInt32) -> Frame:
    var payload = List[Byte]()
    put_u16_be(payload, SETTINGS_ENABLE_PUSH)
    put_u32_be(payload, value)
    return make_frame(FRAME_SETTINGS, 0, 0, payload^)


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
            "000012040000000000000200000000000300000100000600004000"
        ),
    )
    assert_false(client.our_settings.enable_push, "client disables push")


def test_configurable_initial_window() raises:
    var small = Http2Connection(
        RejectingStream(), is_client=True, initial_window_size=1024
    )
    assert_equal(small.our_settings.initial_window_size, 1024)
    assert_equal(small.recv_window, 65535, "connection window stays default")
    var small_sid = small.open_stream()
    assert_equal(small.streams[small_sid].recv_window, 1024)
    var small_out = small.take_pending_output()
    var small_hex = to_hex(Span(small_out))
    assert_true(
        "000400000400" in small_hex, "SETTINGS carries INITIAL_WINDOW_SIZE=1024"
    )
    assert_true(
        "00000408" not in small_hex, "smaller window needs no WINDOW_UPDATE"
    )

    var large = Http2Connection(
        RejectingStream(), is_client=True, initial_window_size=1048576
    )
    assert_equal(large.our_settings.initial_window_size, 1048576)
    assert_equal(large.recv_window, 1048576, "connection window matches stream")
    var large_sid = large.open_stream()
    assert_equal(large.streams[large_sid].recv_window, 1048576)
    var large_out = large.take_pending_output()
    var large_hex = to_hex(Span(large_out))
    assert_true(
        "000400100000" in large_hex,
        "SETTINGS carries INITIAL_WINDOW_SIZE=1048576",
    )
    # WINDOW_UPDATE increment is 1048576 - 65535 = 983041 = 0x000F0001.
    # 9-byte header (length=4, type=WINDOW_UPDATE, stream 0) plus increment.
    assert_true(
        "000004080000000000000f0001" in large_hex,
        "connection WINDOW_UPDATE raises the session window",
    )

    var raised = False
    try:
        _ = Http2Connection(
            RejectingStream(), is_client=True, initial_window_size=0x80000000
        )
    except error:
        raised = True
        assert_true("INITIAL_WINDOW_SIZE" in String(error), String(error))
    assert_true(raised, "window above 2^31-1 is rejected")


def test_large_window_startup_is_atomic() raises:
    var preface = from_hex(
        "505249202a20485454502f322e300d0a0d0a534d0d0a0d0a"
    )
    var server = Http2Connection(
        RejectingStream(), is_client=False, initial_window_size=1048576
    )
    # SETTINGS is 27 bytes; WINDOW_UPDATE is 13. 39 fits SETTINGS only.
    server.max_pending_output_size = 39
    var raised = False
    try:
        _ = server.feed_input(Span(preface))
    except error:
        raised = True
        assert_true("outbound frame queue" in String(error), String(error))
    assert_true(raised, "queue bound below SETTINGS+WINDOW_UPDATE is rejected")
    assert_equal(server.pending_output_len(), 0, "no partial SETTINGS")
    assert_equal(server.recv_window, 65535, "recv_window unchanged")
    assert_false(server.input_preface_complete(), "preface not consumed")

    server.max_pending_output_size = 1024
    _ = server.feed_input(Span(preface))
    assert_true(server.input_preface_complete())
    assert_equal(server.recv_window, 1048576)
    var out = server.take_pending_output()
    var out_hex = to_hex(Span(out))
    assert_true(
        "000400100000" in out_hex, "retried SETTINGS carries the window"
    )
    assert_true(
        "000004080000000000000f0001" in out_hex,
        "retried WINDOW_UPDATE raises the session window",
    )

    # A one-byte preface chunk must fail the same reserve, not commit a
    # byte that makes a later full-preface retry look malformed.
    var split = Http2Connection(
        RejectingStream(), is_client=False, initial_window_size=1048576
    )
    split.max_pending_output_size = 39
    raised = False
    try:
        _ = split.feed_input(Span(preface)[0:1])
    except error:
        raised = True
        assert_true("outbound frame queue" in String(error), String(error))
    assert_true(raised, "partial preface still requires full startup output")
    assert_equal(split.pending_output_len(), 0)
    assert_false(split.input_preface_complete())
    split.max_pending_output_size = 1024
    _ = split.feed_input(Span(preface))
    assert_true(split.input_preface_complete())
    assert_equal(split.recv_window, 1048576)

    # Blocking startup must not read_exact the preface when SETTINGS and
    # WINDOW_UPDATE cannot both fit. RejectingStream raises if it is read.
    var blocking = Http2Connection(
        RejectingStream(), is_client=False, initial_window_size=1048576
    )
    blocking.max_pending_output_size = 39
    raised = False
    try:
        blocking.process_next_frame()
    except error:
        raised = True
        var message = String(error)
        assert_true("outbound frame queue" in message, message)
        assert_true("must not be read" not in message, message)
    assert_true(raised, "blocking startup reserves before reading")
    assert_false(blocking.input_preface_complete())
    assert_equal(blocking.pending_output_len(), 0)
    blocking.max_pending_output_size = 1024
    _ = blocking.feed_input(Span(preface))
    assert_true(blocking.input_preface_complete())

    # A queue that fits SETTINGS plus WINDOW_UPDATE (40 bytes) must still
    # acknowledge the first peer SETTINGS frame. Flushing startup output
    # before that read leaves room for the ACK.
    var settings = from_hex("000000040000000000")
    var incoming = preface.copy()
    incoming.extend(Span(settings))
    var outgoing = List[Byte]()
    var scripted = Http2Connection(
        ScriptedStream(
            incoming=Pointer(to=incoming).unsafe_origin_cast[
                MutUntrackedOrigin
            ](),
            outgoing=Pointer(to=outgoing).unsafe_origin_cast[
                MutUntrackedOrigin
            ](),
        ),
        is_client=False,
        initial_window_size=1048576,
    )
    scripted.max_pending_output_size = 40
    scripted.process_next_frame()
    assert_true(scripted.input_preface_complete())
    assert_true(scripted.peer_settings_received)
    assert_equal(len(incoming), 0, "preface and SETTINGS were consumed")
    var flushed = to_hex(Span(outgoing))
    assert_true(
        "000400100000" in flushed, "flushed SETTINGS carries the window"
    )
    assert_true(
        "000004080000000000000f0001" in flushed,
        "flushed WINDOW_UPDATE raises the session window",
    )
    assert_true(
        "000000040100000000" in flushed, "peer SETTINGS was acknowledged"
    )


def test_enable_push_obeys_endpoint_roles() raises:
    for value in [UInt32(0), UInt32(1), UInt32(2)]:
        var client = make_client()
        var raised = False
        try:
            client.process_frame(push_setting(value))
        except error:
            raised = True
            assert_true("server sent ENABLE_PUSH" in String(error), String(error))
        assert_true(raised, "client rejects server ENABLE_PUSH")
        var output = client.take_pending_output()
        assert_equal(
            to_hex(Span(output)),
            "0000080700000000000000000000000001",
            "client sends GOAWAY(PROTOCOL_ERROR)",
        )

    for value in [UInt32(0), UInt32(1)]:
        var server = Http2Connection(RejectingStream(), is_client=False)
        server.process_frame(push_setting(value))
        assert_equal(
            server.peer_settings.enable_push,
            value == 1,
            "server applies a valid client setting",
        )
        var output = server.take_pending_output()
        assert_equal(
            to_hex(Span(output)),
            "000000040100000000",
            "server acknowledges a valid client setting",
        )

    var server = Http2Connection(RejectingStream(), is_client=False)
    var raised = False
    try:
        server.process_frame(push_setting(2))
    except error:
        raised = True
        assert_true("invalid ENABLE_PUSH" in String(error), String(error))
    assert_true(raised, "server rejects ENABLE_PUSH above one")
    var output = server.take_pending_output()
    assert_equal(
        to_hex(Span(output)),
        "0000080700000000000000000000000001",
        "server sends GOAWAY(PROTOCOL_ERROR)",
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


def test_incremental_dispatch_budget_resumes_in_order() raises:
    var conn = make_client()
    var wire = from_hex(
        "000000040000000000"
        "0000080600000000003132333435363738"
        "0000080600000000004142434445464748"
    )
    assert_equal(conn.feed_input(Span(wire), 1), 1)
    assert_equal(conn.pending_input_frame_count(), 2)
    assert_true(conn.peer_settings_received)
    var output = conn.take_pending_output()
    assert_equal(to_hex(Span(output)), "000000040100000000")

    var empty = List[Byte]()
    assert_equal(conn.feed_input(Span(empty), 1), 1)
    assert_equal(conn.pending_input_frame_count(), 1)
    output = conn.take_pending_output()
    assert_equal(
        to_hex(Span(output)),
        "0000080601000000003132333435363738",
    )
    assert_equal(conn.feed_input(Span(empty), 1), 1)
    assert_equal(conn.pending_input_frame_count(), 0)
    output = conn.take_pending_output()
    assert_equal(
        to_hex(Span(output)),
        "0000080601000000004142434445464748",
    )

    var unlimited = make_client()
    assert_equal(unlimited.feed_input(Span(wire)), 3)
    assert_equal(unlimited.pending_input_frame_count(), 0)

    var paused = make_client()
    assert_equal(paused.feed_input(Span(wire), 0), 0)
    assert_equal(paused.pending_input_frame_count(), 3)
    var more = from_hex("000000040000000000")
    var pending_raised = False
    try:
        _ = paused.feed_input(Span(more), 1)
    except error:
        pending_raised = True
        assert_true("resume pending frames" in String(error), String(error))
    assert_true(pending_raised, "pending frames reject new input")
    assert_equal(paused.pending_input_frame_count(), 3)
    assert_equal(paused.feed_input(Span(empty), 1), 1)
    assert_equal(paused.pending_input_frame_count(), 2)

    var invalid = make_client()
    var raised = False
    try:
        _ = invalid.feed_input(Span(empty), -2)
    except error:
        raised = True
        assert_true("dispatch budget" in String(error), String(error))
    assert_true(raised, "negative budgets below the sentinel are rejected")

    var malformed = make_client()
    var bad = from_hex(
        "000000040000000000"
        "0000080600000000013132333435363738"
    )
    assert_equal(malformed.feed_input(Span(bad), 1), 1)
    assert_equal(malformed.pending_input_frame_count(), 1)
    raised = False
    try:
        _ = malformed.feed_input(Span(empty), 1)
    except:
        raised = True
    assert_true(raised, "budgeted dispatch preserves malformed-frame errors")


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


def test_failed_flush_drops_accepted_prefix() raises:
    var expected = Http2Connection(PartialThenFailStream(), is_client=True)
    _ = expected.take_pending_output()
    expected.queue_ping(0)
    var full = expected.take_pending_output()
    assert_equal(len(full), 17)
    var suffix = List[Byte](Span(full)[5:])

    var conn = Http2Connection(PartialThenFailStream(), is_client=True)
    _ = conn.take_pending_output()
    conn.queue_ping(0)
    var raised = False
    try:
        conn.flush_output()
    except:
        raised = True
    assert_true(raised, "flush propagates errors after a partial write")
    var remaining = conn.take_pending_output()
    assert_equal(
        to_hex(Span(remaining)),
        to_hex(Span(suffix)),
        "accepted prefix is dropped from the queue",
    )


def test_local_goaway_blocks_open_stream() raises:
    var conn = make_client()
    assert_equal(conn.live_stream_count(), 0)
    assert_equal(conn.open_stream(), 1)
    assert_equal(conn.live_stream_count(), 1)
    conn.queue_goaway(ERR_NO_ERROR)
    assert_true(conn.sent_goaway)
    var raised = False
    var msg = String()
    try:
        _ = conn.open_stream()
    except error:
        raised = True
        msg = String(error)
    assert_true(raised, "open_stream after local GOAWAY must raise")
    assert_true("GOAWAY" in msg, msg)
    assert_equal(conn.live_stream_count(), 1)


def test_begin_graceful_shutdown_and_live_count() raises:
    var conn = make_client()
    assert_equal(conn.open_stream(), 1)
    conn.begin_graceful_shutdown()
    assert_true(conn.sent_goaway)
    var queued = conn.pending_output_len()
    conn.begin_graceful_shutdown()
    assert_equal(conn.pending_output_len(), queued, "second shutdown is a no-op")
    var raised = False
    try:
        _ = conn.open_stream()
    except:
        raised = True
    assert_true(raised, "graceful shutdown refuses new streams")

    conn.streams[1].local_end = True
    assert_equal(conn.live_stream_count(), 1, "half-closed still counts")
    conn.streams[1].end_stream = True
    assert_equal(conn.live_stream_count(), 0, "both ends closed")

    conn = make_client()
    assert_equal(conn.open_stream(), 1)
    conn.streams[1].reset_code = ERR_CANCEL
    assert_equal(conn.live_stream_count(), 0, "reset streams do not count")


def test_keepalive_ping_is_caller_driven() raises:
    var conn = make_client()
    assert_false(
        conn.maybe_keepalive_ping(100, 50), "first call starts the clock"
    )
    assert_equal(conn.pending_output_len(), 0)
    assert_false(
        conn.maybe_keepalive_ping(149, 50), "still inside the interval"
    )
    assert_true(conn.maybe_keepalive_ping(150, 50), "idle interval elapsed")
    assert_equal(conn.pending_output_len(), 17, "PING is one 9+8 byte frame")
    _ = conn.take_pending_output()
    conn.touch_keepalive(200)
    assert_false(
        conn.maybe_keepalive_ping(249, 50), "touch postpones the ping"
    )
    assert_true(conn.maybe_keepalive_ping(250, 50))

    var raised = False
    try:
        _ = conn.maybe_keepalive_ping(300, 0)
    except error:
        raised = True
        assert_true("interval" in String(error), String(error))
    assert_true(raised, "non-positive interval is rejected")

    conn = make_client()
    assert_false(
        conn.maybe_keepalive_ping(0, 10), "zero timestamp starts the clock"
    )
    assert_true(
        conn.maybe_keepalive_ping(10, 10), "zero start time still elapses"
    )

    conn = make_client()
    conn.queue_goaway(ERR_NO_ERROR)
    _ = conn.take_pending_output()
    assert_false(
        conn.maybe_keepalive_ping(1000, 1), "no ping after local GOAWAY"
    )

    conn = make_client()
    conn.goaway_code = ERR_NO_ERROR
    assert_false(
        conn.maybe_keepalive_ping(1000, 1), "no ping after received GOAWAY"
    )


def main() raises:
    test_incremental_startup_and_every_split_point()
    test_client_startup_is_queued_without_writes()
    test_configurable_initial_window()
    test_large_window_startup_is_atomic()
    test_enable_push_obeys_endpoint_roles()
    test_incremental_connection_error_is_terminal()
    test_incremental_dispatch_budget_resumes_in_order()
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
    test_failed_flush_drops_accepted_prefix()
    test_local_goaway_blocks_open_stream()
    test_begin_graceful_shutdown_and_live_count()
    test_keepalive_ping_is_caller_driven()
    print("test_h2_output: all tests passed")
