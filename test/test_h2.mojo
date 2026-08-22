# HTTP/2 loopback tests: a real client and server connection over TCP in
# one thread, driven alternately (kernel socket buffers carry the bytes).

from std.testing import assert_equal, assert_true

from h2 import Http2Connection, Settings, FrameHeader, put_u32_be
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
    # Construction queues startup bytes without reading or writing sockets.
    var client = Http2Connection(client_tcp^, is_client=True)
    var server = Http2Connection(server_tcp^, is_client=False)
    client.flush_output()
    # Let each side process the peer's SETTINGS (and ACK it).
    server.process_next_frame()  # client SETTINGS
    client.process_next_frame()  # server SETTINGS
    server.process_next_frame()  # client's ACK
    client.process_next_frame()  # server's ACK
    listener.close()
    return ConnPair(client=client^, server=server^)


def test_settings_exchange() raises:
    var pair = make_pair()
    ref client = pair.client
    ref server = pair.server
    assert_true(client.peer_settings_received, "client got server SETTINGS")
    assert_true(server.peer_settings_received, "server got client SETTINGS")
    client.close()
    server.close()


def test_frame_header_roundtrip() raises:
    var buf = List[Byte]()
    var h = FrameHeader(length=1234, frame_type=0x1, flags=0x25, stream_id=77)
    h.serialize(buf)
    assert_equal(len(buf), 9)
    var parsed = FrameHeader.parse(Span(buf))
    assert_equal(parsed.length, 1234)
    assert_equal(parsed.frame_type, 0x1)
    assert_equal(parsed.flags, 0x25)
    assert_equal(parsed.stream_id, 77)


def test_request_response_cycle() raises:
    var pair = make_pair()
    ref client = pair.client
    ref server = pair.server

    # --- client sends a request ---
    var sid = client.open_stream()
    assert_equal(sid, 1)
    var req_headers = [
        hf(":method", "POST"),
        hf(":scheme", "http"),
        hf(":path", "/test.Service/Method"),
        hf(":authority", "localhost"),
        hf("content-type", "application/grpc"),
    ]
    client.send_headers(sid, Span(req_headers), end_stream=False)
    var body = String("hello over h2")
    client.send_data(sid, body.as_bytes(), end_stream=True)

    # --- server reads it ---
    server.wait_headers(sid)
    server.wait_stream_end(sid)
    assert_equal(len(server.streams[sid].headers), 5)
    assert_equal(server.streams[sid].headers[1], hf(":scheme", "http"))
    var got = server.take_data(sid, body.byte_length())
    assert_equal(String(from_utf8=got), body)
    assert_true(server.streams[sid].end_stream, "request ended")

    # --- server responds: headers, data, trailers ---
    var resp_headers = [
        hf(":status", "200"),
        hf("content-type", "application/grpc"),
    ]
    server.send_headers(sid, Span(resp_headers), end_stream=False)
    var resp_body = String("response payload")
    server.send_data(sid, resp_body.as_bytes(), end_stream=False)
    var trailers = [hf("grpc-status", "0")]
    server.send_headers(sid, Span(trailers), end_stream=True)

    # --- client reads it all ---
    client.wait_headers(sid)
    assert_equal(client.streams[sid].headers[0], hf(":status", "200"))
    var resp_got = client.take_data(sid, resp_body.byte_length())
    assert_equal(String(from_utf8=resp_got), resp_body)
    client.wait_stream_end(sid)
    assert_true(client.streams[sid].trailers_done, "trailers received")
    assert_equal(client.streams[sid].trailers[0], hf("grpc-status", "0"))

    client.close()
    server.close()


def test_large_data_flow_control() raises:
    # 200 KB exceeds both the 64 KB connection/stream windows and the
    # 16 KB max frame size: exercises chunking + WINDOW_UPDATE handling.
    var pair = make_pair()
    ref client = pair.client
    ref server = pair.server

    var sid = client.open_stream()
    var req_headers = [
        hf(":method", "POST"),
        hf(":scheme", "http"),
        hf(":path", "/big"),
    ]
    client.send_headers(sid, Span(req_headers), end_stream=False)

    var big = List[Byte](capacity=200_000)
    for i in range(200_000):
        big.append(UInt8(i % 251))

    # Interleave: client can't push 200 KB into kernel buffers while the
    # server isn't draining, so send in window-sized slices and let the
    # server consume between them.
    var off = 0
    while off < len(big):
        var end = min(off + 32768, len(big))
        client.send_data(sid, Span(big)[off:end], end_stream=(end == len(big)))
        # Server consumes what arrived (sends WINDOW_UPDATEs back).
        while server.buffered_data_len(sid) < end - off:
            server.process_next_frame()
        var chunk = server.take_data(sid, end - off)
        assert_equal(Int(chunk[0]), (off % 251))
        # Client absorbs WINDOW_UPDATE frames so its window refills.
        while client.send_window < 65535 and not server.streams[sid].end_stream:
            client.process_next_frame()
        off = end

    server.wait_stream_end(sid)
    assert_true(server.streams[sid].end_stream, "big stream ended")
    client.close()
    server.close()


def test_ping_pong() raises:
    var pair = make_pair()
    ref client = pair.client
    ref server = pair.server
    client.send_ping(0x1122334455667788)
    server.process_next_frame()  # PING -> auto ACK
    client.process_next_frame()  # PING ACK (ignored, no error)
    client.close()
    server.close()


def main() raises:
    test_frame_header_roundtrip()
    test_settings_exchange()
    test_request_response_cycle()
    test_large_data_flow_control()
    test_ping_pong()
    print("test_h2: all tests passed")
