# Compliance tool: run our Http2Connection as a SERVER against a reference
# hyper-h2 client, which strictly validates every frame we emit.
#
# Usage: h2_server_probe [cert_pem key_pem]
# Prints the bound port, accepts ONE connection, waits for one complete
# request stream, echoes the body back with response headers + trailers,
# then serves until the client disconnects.

from std.sys import argv

from h2 import H2TLSContext, Http2Connection
from hpack import HeaderField
from net import IOStream, TCPListener


def hf(name: StringSpan, value: StringSpan) -> HeaderField:
    return HeaderField(name=String(name), value=String(value))


def serve[S: IOStream](mut conn: Http2Connection[S]) raises:
    # Wait for the first client-initiated stream to complete.
    var sid: UInt32 = 0
    while sid == 0:
        conn.process_next_frame()
        for id in conn.stream_ids:
            if conn.streams[id].headers_done and conn.streams[id].end_stream:
                sid = id

    var body = conn.take_data(sid, conn.buffered_data_len(sid))
    var resp_headers = [
        hf(":status", "200"),
        hf("content-type", "application/octet-stream"),
        hf("x-echo-len", String(len(body))),
    ]
    conn.send_headers(sid, Span(resp_headers), end_stream=False)
    conn.send_data(sid, Span(body), end_stream=False)
    var trailers = [hf("x-check", "ok")]
    conn.send_headers(sid, Span(trailers), end_stream=True)

    # Drain until the client closes.
    try:
        while True:
            conn.process_next_frame()
    except:
        pass
    conn.close()


def main() raises:
    var args = argv()
    var listener = TCPListener("127.0.0.1", 0)
    print("PORT ", listener.local_port, sep="")
    var tcp = listener.accept()
    if len(args) > 1:
        var context = H2TLSContext.server(String(args[1]), String(args[2]))
        var conn = context.accept(tcp^)
        serve(conn)
    else:
        var conn = Http2Connection(tcp^, is_client=False)
        serve(conn)
    listener.close()
