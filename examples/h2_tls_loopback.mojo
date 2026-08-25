# One HTTP/2 request over a locally trusted TLS connection.
#
# The server runs in a child process because both TLS handshakes use blocking
# sockets. The certificate files come from `pixi run prepare-tls`.

from std.ffi import c_int, external_call

from h2 import ERR_NO_ERROR, H2TLSContext
from hpack import HeaderField
from net import TCPListener, TCPStream


comptime CA = "build/certs/ca.pem"
comptime SERVER_CERT = "build/certs/server.pem"
comptime SERVER_KEY = "build/certs/server.key"


def header(name: StringSpan, value: StringSpan) -> HeaderField:
    return HeaderField(name=String(name), value=String(value))


def require(condition: Bool, message: String) raises:
    if not condition:
        raise Error(message)


def serve_one(listener: TCPListener) raises:
    var tls = H2TLSContext.server(String(SERVER_CERT), String(SERVER_KEY))
    var tcp = listener.accept()
    var connection = tls.accept(tcp^)
    require(
        connection.stream.negotiated_alpn() == "h2",
        "server did not negotiate h2",
    )

    var stream_id: UInt32 = 0
    while stream_id == 0:
        connection.process_next_frame()
        for candidate in connection.stream_ids:
            if (
                connection.streams[candidate].headers_done
                and connection.streams[candidate].end_stream
            ):
                stream_id = candidate

    var request = connection.take_data(
        stream_id, connection.buffered_data_len(stream_id)
    )
    print("server received: " + String(from_utf8=request))

    var response_headers = [
        header(":status", "200"),
        header("content-type", "text/plain"),
    ]
    connection.send_headers(stream_id, Span(response_headers), end_stream=False)
    connection.send_data(stream_id, Span(request), end_stream=True)

    while not Bool(connection.goaway_code):
        connection.process_next_frame()
    require(
        connection.goaway_code.value() == ERR_NO_ERROR,
        "client closed with an HTTP/2 error",
    )
    connection.close()


def main() raises:
    var listener = TCPListener("127.0.0.1", 0)
    var port = listener.local_port
    var child = external_call["fork", c_int]()
    if child == 0:
        try:
            serve_one(listener^)
            external_call["_exit", NoneType](c_int(0))
        except:
            external_call["_exit", NoneType](c_int(1))

    listener.close()
    var tls = H2TLSContext.client(ca_file=String(CA))
    var tcp = TCPStream.connect("127.0.0.1", port)
    var connection = tls.connect(tcp^, "localhost")
    require(
        connection.stream.negotiated_alpn() == "h2",
        "client did not negotiate h2",
    )

    var stream_id = connection.open_stream()
    var request_headers = [
        header(":method", "POST"),
        header(":scheme", "https"),
        header(":path", "/example.Echo/Call"),
        header(":authority", "localhost"),
        header("content-type", "text/plain"),
    ]
    connection.send_headers(stream_id, Span(request_headers), end_stream=False)
    var request = String("hello over HTTP/2 and TLS")
    connection.send_data(stream_id, request.as_bytes(), end_stream=True)

    connection.wait_headers(stream_id)
    require(
        connection.streams[stream_id].headers[0] == header(":status", "200"),
        "server did not return status 200",
    )
    var response = connection.take_data(stream_id, request.byte_length())
    connection.wait_stream_end(stream_id)
    require(String(from_utf8=response) == request, "response body changed")
    print("client received: " + String(from_utf8=response))

    connection.send_goaway(ERR_NO_ERROR)
    connection.close()

    var status = c_int(0)
    _ = external_call["waitpid", c_int](child, Pointer(to=status), c_int(0))
    require(status == 0, "TLS HTTP/2 server child failed")
