# Drive Http2Connection.process_frame with hyperframe-built wire frames.
#
# Usage: h2_dispatch_tool <infile> <outfile>
# Input groups:
#   CASE <name>
#   OPEN
#   FRAME <hex frame>
#   ...
#   END

from std.sys import argv

from h2 import FRAME_HEADER_LEN, Frame, FrameHeader, Http2Connection
from net import IOStream
from testutil import from_hex, to_hex


struct SinkStream(IOStream):
    """An IOStream that records no output and permits no reads."""

    def __init__(out self):
        pass

    def read_exact(self, n: Int) raises -> List[Byte]:
        _ = n
        raise Error("h2 dispatch probe performed an unexpected read")

    def write_all(self, data: Span[Byte, _]) raises:
        _ = data

    def set_read_timeout(self, nanos: Int64) raises:
        _ = nanos

    def set_nodelay(self, enabled: Bool) raises:
        _ = enabled

    def close(mut self):
        pass


def emit_state(conn: Http2Connection[SinkStream]) raises -> String:
    var out = String()
    for stream_id in conn.stream_ids:
        out += (
            "S "
            + String(stream_id)
            + " "
            + String(conn.streams[stream_id].headers_done)
            + " "
            + String(conn.streams[stream_id].end_stream)
            + "\n"
        )
        if conn.streams[stream_id].headers_done:
            for field in conn.streams[stream_id].headers:
                out += (
                    "H "
                    + String(stream_id)
                    + " "
                    + to_hex(field.name.as_bytes())
                    + " "
                    + to_hex(field.value.as_bytes())
                    + "\n"
                )
    return out^


def main() raises:
    var args = argv()
    if len(args) != 3:
        raise Error("usage: h2_dispatch_tool <infile> <outfile>")

    var infile = open(String(args[1]), "r")
    var input = infile.read()
    infile.close()

    var conn = Http2Connection(SinkStream(), is_client=True)
    _ = conn.take_pending_output()
    var active = False
    var failed = False
    var failure = String()
    var output = String()
    for line in input.split("\n"):
        var stripped = line.strip()
        if stripped.byte_length() == 0:
            continue
        if stripped.startswith("CASE "):
            if active:
                raise Error("CASE inside CASE")
            conn = Http2Connection(SinkStream(), is_client=True)
            _ = conn.take_pending_output()
            active = True
            failed = False
            failure = String()
            output += "CASE " + stripped[byte=5:] + "\n"
            continue
        if stripped == "OPEN":
            if not active or failed:
                raise Error("OPEN outside active CASE")
            _ = conn.open_stream()
            continue
        if stripped.startswith("FRAME "):
            if not active or failed:
                raise Error("FRAME outside active CASE")
            var wire = from_hex(stripped[byte=6:])
            if len(wire) < FRAME_HEADER_LEN:
                raise Error("short wire frame in dispatch probe")
            var header = FrameHeader.parse(Span(wire))
            var payload = List[Byte](Span(wire)[FRAME_HEADER_LEN : len(wire)])
            try:
                conn.process_frame(Frame(header=header, payload=payload^))
            except error:
                failed = True
                failure = String(error)
            continue
        if stripped == "END":
            if not active:
                raise Error("END outside CASE")
            output += emit_state(conn)
            var pending = conn.take_pending_output()
            output += "OUT " + to_hex(Span(pending)) + "\n"
            if failed:
                output += "ERROR " + failure + "\n"
            output += (
                "END "
                + ("ERROR" if failed else "OK")
                + " "
                + String(conn.sent_goaway)
                + "\n"
            )
            active = False
            continue
        raise Error("unknown dispatch probe input")
    if active:
        raise Error("unterminated CASE")

    var outfile = open(String(args[2]), "w")
    outfile.write_all(output.as_bytes())
    outfile.close()
