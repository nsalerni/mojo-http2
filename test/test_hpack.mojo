# HPACK tests against RFC 7541 Appendix C vectors.

from std.testing import assert_equal, assert_true

from testutil import from_hex, to_hex
from hpack import Decoder, Encoder, HeaderField, encode_integer


def hf(name: StringSpan, value: StringSpan) -> HeaderField:
    return HeaderField(name=String(name), value=String(value))


def test_integer_coding() raises:
    # C.1.1: 10 with 5-bit prefix
    var b = List[Byte]()
    encode_integer(10, 5, 0, b)
    assert_equal(to_hex(b), "0a")
    # C.1.2: 1337 with 5-bit prefix
    b.clear()
    encode_integer(1337, 5, 0, b)
    assert_equal(to_hex(b), "1f9a0a")
    # C.1.3: 42 with 8-bit prefix
    b.clear()
    encode_integer(42, 8, 0, b)
    assert_equal(to_hex(b), "2a")


def test_c2_literals() raises:
    # C.2.1 Literal with Indexing
    var d = Decoder()
    var fields = d.decode(
        Span(from_hex("400a637573746f6d2d6b65790d637573746f6d2d686561646572"))
    )
    assert_equal(len(fields), 1)
    assert_equal(fields[0], hf("custom-key", "custom-header"))
    assert_equal(d.table.size, 55)

    # C.2.2 Literal without Indexing (:path from static index 4)
    var d2 = Decoder()
    var f2 = d2.decode(Span(from_hex("040c2f73616d706c652f70617468")))
    assert_equal(f2[0], hf(":path", "/sample/path"))
    assert_equal(d2.table.size, 0)

    # C.2.3 Never Indexed
    var d3 = Decoder()
    var f3 = d3.decode(Span(from_hex("100870617373776f726406736563726574")))
    assert_equal(f3[0], hf("password", "secret"))
    assert_equal(d3.table.size, 0)


def check_first_request(fields: List[HeaderField]) raises:
    assert_equal(len(fields), 4)
    assert_equal(fields[0], hf(":method", "GET"))
    assert_equal(fields[1], hf(":scheme", "http"))
    assert_equal(fields[2], hf(":path", "/"))
    assert_equal(fields[3], hf(":authority", "www.example.com"))


def test_c3_requests_plain() raises:
    var d = Decoder()
    var f1 = d.decode(
        Span(from_hex("828684410f7777772e6578616d706c652e636f6d"))
    )
    check_first_request(f1)
    assert_equal(d.table.size, 57)

    var f2 = d.decode(Span(from_hex("828684be58086e6f2d6361636865")))
    assert_equal(len(f2), 5)
    assert_equal(f2[3], hf(":authority", "www.example.com"))
    assert_equal(f2[4], hf("cache-control", "no-cache"))
    assert_equal(d.table.size, 110)

    var f3 = d.decode(
        Span(
            from_hex(
                "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565"
            )
        )
    )
    assert_equal(len(f3), 5)
    assert_equal(f3[1], hf(":scheme", "https"))
    assert_equal(f3[2], hf(":path", "/index.html"))
    assert_equal(f3[4], hf("custom-key", "custom-value"))
    assert_equal(d.table.size, 164)


def test_c4_requests_huffman_decode() raises:
    var d = Decoder()
    var f1 = d.decode(Span(from_hex("828684418cf1e3c2e5f23a6ba0ab90f4ff")))
    check_first_request(f1)
    var f2 = d.decode(Span(from_hex("828684be5886a8eb10649cbf")))
    assert_equal(f2[4], hf("cache-control", "no-cache"))
    var f3 = d.decode(
        Span(from_hex("828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf"))
    )
    assert_equal(f3[4], hf("custom-key", "custom-value"))
    assert_equal(d.table.size, 164)


def test_c4_requests_encoder_byte_exact() raises:
    # Our encoder (indexed match, then literal-with-indexing, huffman when
    # shorter) reproduces the C.4 request byte streams exactly.
    var e = Encoder()
    var out = List[Byte]()
    var req1 = [
        hf(":method", "GET"),
        hf(":scheme", "http"),
        hf(":path", "/"),
        hf(":authority", "www.example.com"),
    ]
    e.encode(Span(req1), out)
    assert_equal(to_hex(out), "828684418cf1e3c2e5f23a6ba0ab90f4ff")

    out.clear()
    var req2 = [
        hf(":method", "GET"),
        hf(":scheme", "http"),
        hf(":path", "/"),
        hf(":authority", "www.example.com"),
        hf("cache-control", "no-cache"),
    ]
    e.encode(Span(req2), out)
    assert_equal(to_hex(out), "828684be5886a8eb10649cbf")

    out.clear()
    var req3 = [
        hf(":method", "GET"),
        hf(":scheme", "https"),
        hf(":path", "/index.html"),
        hf(":authority", "www.example.com"),
        hf("custom-key", "custom-value"),
    ]
    e.encode(Span(req3), out)
    assert_equal(
        to_hex(out), "828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf"
    )


def test_c5_responses_eviction() raises:
    # SETTINGS_HEADER_TABLE_SIZE = 256 forces evictions.
    var d = Decoder(256)
    var f1 = d.decode(
        Span(
            from_hex(
                "4803333032580770726976617465611d4d6f6e2c203231204f6374"
                "20323031332032303a31333a323120474d546e1768747470733a2f"
                "2f7777772e6578616d706c652e636f6d"
            )
        )
    )
    assert_equal(len(f1), 4)
    assert_equal(f1[0], hf(":status", "302"))
    assert_equal(f1[3], hf("location", "https://www.example.com"))
    assert_equal(d.table.size, 222)

    var f2 = d.decode(Span(from_hex("4803333037c1c0bf")))
    assert_equal(f2[0], hf(":status", "307"))
    # ":status: 302" evicted
    assert_equal(d.table.size, 222)

    var f3 = d.decode(
        Span(
            from_hex(
                "88c1611d4d6f6e2c203231204f637420323031332032303a31333a"
                "323220474d54c05a04677a69707738666f6f3d4153444a4b48514b"
                "425a584f5157454f50495541585157454f49553b206d61782d6167"
                "653d333630303b2076657273696f6e3d31"
            )
        )
    )
    assert_equal(len(f3), 6)
    assert_equal(f3[0], hf(":status", "200"))
    assert_equal(f3[2], hf("date", "Mon, 21 Oct 2013 20:13:22 GMT"))
    assert_equal(f3[3], hf("location", "https://www.example.com"))
    assert_equal(f3[4], hf("content-encoding", "gzip"))
    assert_equal(
        f3[5],
        hf(
            "set-cookie",
            "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
        ),
    )
    assert_equal(d.table.size, 215)


def test_c6_responses_huffman() raises:
    var d = Decoder(256)
    var f1 = d.decode(
        Span(
            from_hex(
                "488264025885aec3771a4b6196d07abe941054d444a8200595040b"
                "8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3"
            )
        )
    )
    assert_equal(f1[0], hf(":status", "302"))
    assert_equal(f1[1], hf("cache-control", "private"))
    assert_equal(f1[2], hf("date", "Mon, 21 Oct 2013 20:13:21 GMT"))
    assert_equal(f1[3], hf("location", "https://www.example.com"))
    assert_equal(d.table.size, 222)

    # Encoder reproduces C.6 exactly with table size 256.
    var e = Encoder(256)
    var out = List[Byte]()
    var resp1 = [
        hf(":status", "302"),
        hf("cache-control", "private"),
        hf("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
        hf("location", "https://www.example.com"),
    ]
    e.encode(Span(resp1), out)
    assert_equal(
        to_hex(out),
        (
            "488264025885aec3771a4b6196d07abe941054d444a8200595040b"
            "8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3"
        ),
    )

    out.clear()
    var resp2 = [
        hf(":status", "307"),
        hf("cache-control", "private"),
        hf("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
        hf("location", "https://www.example.com"),
    ]
    e.encode(Span(resp2), out)
    assert_equal(to_hex(out), "4883640effc1c0bf")

    out.clear()
    var resp3 = [
        hf(":status", "200"),
        hf("cache-control", "private"),
        hf("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
        hf("location", "https://www.example.com"),
        hf("content-encoding", "gzip"),
        hf(
            "set-cookie",
            "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
        ),
    ]
    e.encode(Span(resp3), out)
    assert_equal(
        to_hex(out),
        (
            "88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a83"
            "9bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1"
            "ab270fb5291f9587316065c003ed4ee5b1063d5007"
        ),
    )


def test_roundtrip_binary_values() raises:
    # Arbitrary byte values in header values survive encode→decode.
    var e = Encoder()
    var d = Decoder()
    var out = List[Byte]()
    var weird = [
        hf("x-custom", "a b\tc~!@#$%^&*()"),
        hf("x-empty", ""),
        hf(":authority", "host:1234"),
    ]
    e.encode(Span(weird), out)
    var back = d.decode(Span(out))
    assert_equal(len(back), 3)
    for i in range(3):
        assert_equal(back[i], weird[i])


def test_invalid_inputs() raises:
    var d = Decoder()
    # Index 0
    var raised = False
    try:
        _ = d.decode(Span(from_hex("80")))
    except:
        raised = True
    assert_true(raised, "index 0 must raise")

    # Out-of-range index
    raised = False
    try:
        _ = d.decode(Span(from_hex("ff9f03")))
    except:
        raised = True
    assert_true(raised, "out-of-range index must raise")

    # Truncated string
    raised = False
    try:
        _ = d.decode(Span(from_hex("400a63")))
    except:
        raised = True
    assert_true(raised, "truncated literal must raise")


def main() raises:
    test_integer_coding()
    test_c2_literals()
    test_c3_requests_plain()
    test_c4_requests_huffman_decode()
    test_c4_requests_encoder_byte_exact()
    test_c5_responses_eviction()
    test_c6_responses_huffman()
    test_roundtrip_binary_values()
    test_invalid_inputs()
    print("test_hpack: all tests passed")
