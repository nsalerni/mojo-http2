# Produce queued HTTP/2 request bytes for an independent hyper-h2 peer.

from std.sys import argv

from h2 import Http2Connection
from hpack import HeaderField
from net import IOStream
from testutil import to_hex


struct SinkStream(IOStream):
    """An IOStream that discards constructor output and permits no reads."""

    def __init__(out self):
        pass

    def read_exact(self, n: Int) raises -> List[Byte]:
        _ = n
        raise Error("output probe performed an unexpected read")

    def write_all(self, data: Span[Byte, _]) raises:
        _ = data

    def set_read_timeout(self, nanos: Int64) raises:
        _ = nanos

    def set_nodelay(self, enabled: Bool) raises:
        _ = enabled

    def close(mut self):
        pass


def main() raises:
    var args = argv()
    if len(args) != 2:
        raise Error("usage: h2_output_tool <outfile>")

    var conn = Http2Connection(SinkStream(), is_client=True)
    var stream_id = conn.open_stream()
    var headers = List[HeaderField]()
    headers.append(HeaderField(":method", "POST"))
    headers.append(HeaderField(":scheme", "https"))
    headers.append(HeaderField(":path", "/queue.Test/Stream"))
    headers.append(HeaderField(":authority", "localhost"))
    headers.append(HeaderField("content-type", "application/grpc"))
    conn.queue_headers(stream_id, Span(headers), end_stream=False)

    var payload = List[Byte](capacity=20000)
    for i in range(20000):
        payload.append(UInt8(i % 251))
    var consumed = conn.queue_data(stream_id, Span(payload), end_stream=True)
    var output = conn.take_pending_output()

    var outfile = open(String(args[1]), "w")
    outfile.write_all((String(consumed) + "\n").as_bytes())
    outfile.write_all((to_hex(Span(output)) + "\n").as_bytes())
    outfile.close()
