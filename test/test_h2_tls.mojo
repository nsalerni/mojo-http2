# HTTP/2 over TLS functional test. The server runs in a forked child so
# both sides of the blocking TLS handshake can make progress.

from std.ffi import c_int, external_call
from std.testing import assert_equal

from h2 import H2TLSContext
from hpack import HeaderField
from net import TCPListener, TCPStream


comptime CA = "build/certs/ca.pem"
comptime SERVER_CERT = "build/certs/server.pem"
comptime SERVER_KEY = "build/certs/server.key"


def hf(name: StringSpan, value: StringSpan) -> HeaderField:
    return HeaderField(name=String(name), value=String(value))


def serve_one(listener: TCPListener) raises:
    var context = H2TLSContext.server(String(SERVER_CERT), String(SERVER_KEY))
    var tcp = listener.accept()
    var conn = context.accept(tcp^)
    assert_equal(conn.stream.negotiated_alpn(), "h2")

    var sid: UInt32 = 0
    while sid == 0:
        conn.process_next_frame()
        for stream_id in conn.stream_ids:
            if (
                conn.streams[stream_id].headers_done
                and conn.streams[stream_id].end_stream
            ):
                sid = stream_id

    var body = conn.take_data(sid, conn.buffered_data_len(sid))
    var headers = [hf(":status", "200"), hf("content-type", "text/plain")]
    conn.send_headers(sid, Span(headers), end_stream=False)
    conn.send_data(sid, Span(body), end_stream=True)
    conn.close()


def test_request_response_over_tls() raises:
    var listener = TCPListener("127.0.0.1", 0)
    var port = listener.local_port
    var pid = external_call["fork", c_int]()
    if pid == 0:
        try:
            serve_one(listener^)
            external_call["_exit", NoneType](c_int(0))
        except:
            external_call["_exit", NoneType](c_int(1))

    listener.close()
    var context = H2TLSContext.client(ca_file=String(CA))
    var tcp = TCPStream.connect("127.0.0.1", port)
    var conn = context.connect(tcp^, "localhost")
    assert_equal(conn.stream.negotiated_alpn(), "h2")

    var sid = conn.open_stream()
    var headers = [
        hf(":method", "POST"),
        hf(":scheme", "https"),
        hf(":path", "/tls"),
        hf(":authority", "localhost"),
    ]
    conn.send_headers(sid, Span(headers), end_stream=False)
    var body = String("hello over h2 TLS")
    conn.send_data(sid, body.as_bytes(), end_stream=True)

    conn.wait_headers(sid)
    assert_equal(conn.streams[sid].headers[0], hf(":status", "200"))
    var echoed = conn.take_data(sid, body.byte_length())
    assert_equal(String(from_utf8=echoed), body)
    conn.wait_stream_end(sid)
    conn.close()

    var status = c_int(0)
    _ = external_call["waitpid", c_int](pid, Pointer(to=status), c_int(0))
    assert_equal(status, 0, "TLS HTTP/2 server child failed")


def main() raises:
    test_request_response_over_tls()
    print("test_h2_tls: ok")
