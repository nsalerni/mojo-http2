# Compliance tool: exercise bounded sequential stream retirement with
# hyper-h2-generated response bytes.
#
# Usage: h2_retirement_tool <infile> <outfile>
# Input:
#   COUNT <n>
#   STREAM <expected-id> <hex response bytes>
#   ...
#   STALE <hex DATA frame for the first retired id>

from std.sys import argv

from h2 import (
    ERR_STREAM_CLOSED,
    FRAME_HEADER_LEN,
    FRAME_RST_STREAM,
    FrameHeader,
    Http2Connection,
    get_u32_be,
)
from hpack import HeaderField
from net import IOStream
from testutil import from_hex


struct SinkStream(IOStream):
    """A transport that rejects hidden I/O."""

    def __init__(out self):
        pass

    def read_exact(self, n: Int) raises -> List[Byte]:
        _ = n
        raise Error("retirement probe performed an unexpected read")

    def write_all(self, data: Span[Byte, _]) raises:
        _ = data
        raise Error("retirement probe performed an unexpected write")

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


def hf(name: StringSpan, value: StringSpan) -> HeaderField:
    return HeaderField(name=String(name), value=String(value))


def main() raises:
    var args = argv()
    if len(args) != 3:
        raise Error("usage: h2_retirement_tool <infile> <outfile>")

    var infile = open(String(args[1]), "r")
    var lines = infile.read().split("\n")
    infile.close()
    if len(lines) < 3 or not lines[0].startswith("COUNT "):
        raise Error("invalid retirement probe input")
    var expected_count = Int(lines[0][byte=6:])

    var conn = Http2Connection(SinkStream(), is_client=True)
    _ = conn.take_pending_output()
    var request_headers = [
        hf(":method", "GET"),
        hf(":scheme", "https"),
        hf(":path", "/retire"),
        hf(":authority", "localhost"),
    ]
    var completed = 0
    var max_live = 0
    var stale_wire = List[Byte]()
    for raw_line in lines[1 : len(lines)]:
        var line = raw_line.strip()
        if line.byte_length() == 0:
            continue
        if line.startswith("STREAM "):
            var parts = line.split(" ")
            if len(parts) != 3:
                raise Error("invalid STREAM line")
            var expected_id = UInt32(Int(parts[1]))
            var stream_id = conn.open_stream()
            if stream_id != expected_id:
                raise Error("stream id mismatch")
            conn.queue_headers(
                stream_id, Span(request_headers), end_stream=True
            )
            _ = conn.take_pending_output()

            var response = from_hex(parts[2])
            _ = conn.feed_input(Span(response))
            max_live = max(max_live, len(conn.stream_ids))
            if (
                not conn.streams[stream_id].headers_done
                or not conn.streams[stream_id].end_stream
                or conn.buffered_data_len(stream_id) != 1
            ):
                raise Error("incomplete hyper-h2 response")
            _ = conn.take_buffered_data(stream_id, 1)
            if not conn.retire_stream(stream_id):
                raise Error("completed stream did not retire")
            if stream_id in conn.streams:
                raise Error("retired stream state remained live")
            _ = conn.take_pending_output()
            completed += 1
            continue
        if line.startswith("STALE "):
            stale_wire = from_hex(line[byte=6:])
            continue
        raise Error("unknown retirement probe input")

    if completed != expected_count or len(stale_wire) == 0:
        raise Error("retirement probe input count mismatch")
    _ = conn.feed_input(Span(stale_wire))
    var output = conn.take_pending_output()
    if len(output) != FRAME_HEADER_LEN + 4:
        raise Error("retired stream did not produce one RST_STREAM")
    var header = FrameHeader.parse(Span(output))
    var code = get_u32_be(Span(output), FRAME_HEADER_LEN)
    if (
        header.frame_type != FRAME_RST_STREAM
        or header.stream_id != 1
        or code != ERR_STREAM_CLOSED
    ):
        raise Error("retired stream was not classified closed")

    var outfile = open(String(args[2]), "w")
    var result = (
        "completed="
        + String(completed)
        + " live="
        + String(len(conn.stream_ids))
        + " max_live="
        + String(max_live)
        + " rst="
        + String(code)
        + "\n"
    )
    outfile.write_all(result.as_bytes())
    outfile.close()
