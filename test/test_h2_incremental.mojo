# Incremental HTTP/2 frame decoding with fixed reference vectors.

from std.testing import assert_equal, assert_true

from h2 import DEFAULT_MAX_FRAME_SIZE, IncrementalFrameDecoder
from testutil import from_hex, to_hex


def assert_hello_frame(
    frame_type: UInt8,
    flags: UInt8,
    stream_id: UInt32,
    payload: Span[Byte, _],
) raises:
    assert_equal(Int(frame_type), 0)
    assert_equal(Int(flags), 1)
    assert_equal(Int(stream_id), 1)
    assert_equal(to_hex(payload), "68656c6c6f")


def test_empty_and_partial_header() raises:
    var decoder = IncrementalFrameDecoder()
    var empty = List[Byte]()
    assert_equal(len(decoder.feed(Span(empty))), 0)

    # hyperframe DataFrame(1, data=b"hello", flags=["END_STREAM"])
    var wire = from_hex("00000500010000000168656c6c6f")
    var first = decoder.feed(Span(wire)[0:8])
    assert_equal(len(first), 0)
    assert_equal(decoder.buffered_len(), 8)
    var second = decoder.feed(Span(wire)[8:9])
    assert_equal(len(second), 0)
    assert_equal(decoder.buffered_len(), 0)
    var third = decoder.feed(Span(wire)[9 : len(wire)])
    assert_equal(len(third), 1)
    assert_hello_frame(
        third[0].header.frame_type,
        third[0].header.flags,
        third[0].header.stream_id,
        Span(third[0].payload),
    )
    assert_equal(decoder.buffered_len(), 0)


def test_every_split_point() raises:
    # This fixed byte string was produced by hyperframe, not our serializer.
    var wire = from_hex("00000500010000000168656c6c6f")
    for split in range(len(wire) + 1):
        var decoder = IncrementalFrameDecoder()
        var first = decoder.feed(Span(wire)[0:split])
        var second = decoder.feed(Span(wire)[split : len(wire)])
        assert_equal(len(first) + len(second), 1)
        if len(first) == 1:
            assert_hello_frame(
                first[0].header.frame_type,
                first[0].header.flags,
                first[0].header.stream_id,
                Span(first[0].payload),
            )
        else:
            assert_hello_frame(
                second[0].header.frame_type,
                second[0].header.flags,
                second[0].header.stream_id,
                Span(second[0].payload),
            )
        assert_equal(decoder.buffered_len(), 0)


def test_one_byte_chunks() raises:
    var wire = from_hex("00000500010000000168656c6c6f")
    var decoder = IncrementalFrameDecoder()
    for i in range(len(wire)):
        var frames = decoder.feed(Span(wire)[i : i + 1])
        if i + 1 == len(wire):
            assert_equal(len(frames), 1)
            assert_hello_frame(
                frames[0].header.frame_type,
                frames[0].header.flags,
                frames[0].header.stream_id,
                Span(frames[0].payload),
            )
        else:
            assert_equal(len(frames), 0)
            var retained_limit = 8 if i < 8 else 4
            assert_true(
                decoder.buffered_len() <= retained_limit,
                "retained input stays bounded",
            )


def test_coalesced_frames_and_incomplete_suffix() raises:
    # hyperframe DATA followed by PING with payload "12345678".
    var data = from_hex("00000500010000000168656c6c6f")
    var ping = from_hex("0000080600000000003132333435363738")
    var wire = data.copy()
    wire.extend(Span(ping)[0:4])

    var decoder = IncrementalFrameDecoder()
    var first = decoder.feed(Span(wire))
    assert_equal(len(first), 1)
    assert_equal(decoder.buffered_len(), 4)

    var second = decoder.feed(Span(ping)[4 : len(ping)])
    assert_equal(len(second), 1)
    assert_equal(Int(second[0].header.frame_type), 6)
    assert_equal(Int(second[0].header.flags), 0)
    assert_equal(Int(second[0].header.stream_id), 0)
    assert_equal(to_hex(Span(second[0].payload)), "3132333435363738")
    assert_equal(decoder.buffered_len(), 0)

    var both = data.copy()
    both.extend(Span(ping))
    var coalesced = IncrementalFrameDecoder()
    var frames = coalesced.feed(Span(both))
    assert_equal(len(frames), 2)
    assert_equal(Int(frames[0].header.frame_type), 0)
    assert_equal(Int(frames[1].header.frame_type), 6)


def test_maximum_allowed_payload() raises:
    # Fixed DATA header with length 0x004000 (16384), stream 1.
    var wire = from_hex("004000000000000001")
    for i in range(DEFAULT_MAX_FRAME_SIZE):
        wire.append(UInt8(i % 251))

    var decoder = IncrementalFrameDecoder()
    var head = decoder.feed(Span(wire)[0:9])
    assert_equal(len(head), 0)
    assert_equal(decoder.buffered_len(), 0)
    var body = decoder.feed(Span(wire)[9 : len(wire)])
    assert_equal(len(body), 1)
    assert_equal(body[0].header.length, DEFAULT_MAX_FRAME_SIZE)
    assert_equal(len(body[0].payload), DEFAULT_MAX_FRAME_SIZE)
    assert_equal(Int(body[0].payload[0]), 0)
    assert_equal(Int(body[0].payload[DEFAULT_MAX_FRAME_SIZE - 1]), 68)
    assert_equal(decoder.buffered_len(), 0)


def test_declared_over_limit_is_terminal() raises:
    # Header declares six payload bytes; the decoder limit is five.
    var header = from_hex("000006000000000001")
    var decoder = IncrementalFrameDecoder(max_frame_size=5)
    var raised = False
    try:
        _ = decoder.feed(Span(header))
    except err:
        raised = True
        assert_true(
            "exceeds incremental decoder limit" in String(err), String(err)
        )
    assert_true(raised, "over-limit header must raise")
    assert_equal(decoder.buffered_len(), 0)

    raised = False
    try:
        _ = decoder.feed(Span(from_hex("000000040000000000")))
    except err:
        raised = True
        assert_true("decoder is failed" in String(err), String(err))
    assert_true(raised, "failed decoder must stay failed")


def test_zero_length_unknown_type_and_reserved_bit() raises:
    # Unknown type 15, flags 0x7f, reserved stream bit set, no payload.
    var wire = from_hex("0000000f7f80000001")
    var decoder = IncrementalFrameDecoder(max_frame_size=0)
    var frames = decoder.feed(Span(wire))
    assert_equal(len(frames), 1)
    assert_equal(Int(frames[0].header.frame_type), 15)
    assert_equal(Int(frames[0].header.flags), 0x7F)
    assert_equal(Int(frames[0].header.stream_id), 1)
    assert_equal(frames[0].header.length, 0)
    assert_equal(len(frames[0].payload), 0)


def test_invalid_limit() raises:
    var raised = False
    try:
        _ = IncrementalFrameDecoder(max_frame_size=-1)
    except err:
        raised = True
        assert_true(
            "invalid incremental frame size limit" in String(err), String(err)
        )
    assert_true(raised, "negative limit must raise")

    raised = False
    try:
        _ = IncrementalFrameDecoder(max_frame_size=0x1000000)
    except err:
        raised = True
        assert_true(
            "invalid incremental frame size limit" in String(err), String(err)
        )
    assert_true(raised, "limit over 24 bits must raise")

    # The largest representable HTTP/2 length is accepted without reserving
    # its payload when only the header has arrived.
    var largest = IncrementalFrameDecoder(max_frame_size=0xFFFFFF)
    var frames = largest.feed(Span(from_hex("ffffff000000000001")))
    assert_equal(len(frames), 0)
    assert_equal(largest.buffered_len(), 0)


def main() raises:
    test_empty_and_partial_header()
    test_every_split_point()
    test_one_byte_chunks()
    test_coalesced_frames_and_incomplete_suffix()
    test_maximum_allowed_payload()
    test_declared_over_limit_is_terminal()
    test_zero_length_unknown_type_and_reserved_bit()
    test_invalid_limit()
    print("test_h2_incremental: all tests passed")
