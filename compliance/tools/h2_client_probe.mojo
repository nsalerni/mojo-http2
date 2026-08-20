# Compliance tool: drive our Http2Connection client against a reference
# hyper-h2 server. The reference server strictly validates every frame we
# send (it raises ProtocolError on violations), so a clean 200 + echoed
# body is a meaningful state-machine compliance signal.
#
# Usage: h2_client_probe <port> <nbytes>
# Sends POST /echo with nbytes of patterned data; prints:
#   status=<:status> len=<echoed bytes> match=<true|false> trailer=<x-check>

from std.sys import argv

from h2 import Http2Connection
from hpack import HeaderField
from net import TCPStream


def hf(name: StringSpan, value: StringSpan) -> HeaderField:
    return HeaderField(name=String(name), value=String(value))


def main() raises:
    var args = argv()
    var port = UInt16(Int(args[1]))
    var n = Int(args[2])

    var tcp = TCPStream.connect("127.0.0.1", port)
    var conn = Http2Connection(tcp^, is_client=True)
    # The reference server responds with a ~32KB header block (to exercise
    # CONTINUATION reassembly); raise the advisory header-list cap for it.
    conn.max_header_list_size = 65536
    var sid = conn.open_stream()
    var headers = [
        hf(":method", "POST"),
        hf(":scheme", "http"),
        hf(":path", "/echo"),
        hf(":authority", "localhost"),
        hf("content-type", "application/octet-stream"),
        hf("x-probe", "grpc-mojo-h2"),
    ]
    conn.send_headers(sid, Span(headers), end_stream=False)

    var body = List[Byte](capacity=n)
    for i in range(n):
        body.append(UInt8(i % 251))
    conn.send_data(sid, Span(body), end_stream=True)

    conn.wait_headers(sid)
    var status = String("?")
    var header_bytes = 0
    for f in conn.streams[sid].headers:
        header_bytes += f.name.byte_length() + f.value.byte_length()
        if f.name == ":status":
            status = f.value.copy()
    # Consume incrementally: stream flow-control credit is granted on
    # consumption, so draining as data arrives keeps the sender moving.
    var echoed = List[Byte]()
    while True:
        var avail = conn.buffered_data_len(sid)
        if avail > 0:
            echoed.extend(Span(conn.take_data(sid, avail)))
            continue
        if conn.streams[sid].closed_by_peer():
            break
        conn.process_next_frame()
    var matched = len(echoed) == n
    if matched:
        for i in range(n):
            if echoed[i] != body[i]:
                matched = False
                break
    var trailer = String("-")
    for f in conn.streams[sid].trailers:
        if f.name == "x-check":
            trailer = f.value.copy()
    print(
        "status=",
        status,
        " len=",
        len(echoed),
        " match=",
        matched,
        " trailer=",
        trailer,
        " hdrbytes=",
        header_bytes,
        sep="",
    )
    conn.close()
