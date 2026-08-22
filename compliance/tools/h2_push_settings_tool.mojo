# Exercise role-specific SETTINGS_ENABLE_PUSH behavior with externally built
# wire frames.
#
# Usage: h2_push_settings_tool <infile> <outfile>
# Input lines: <CLIENT|SERVER> <value> <hex SETTINGS frame>

from std.sys import argv

from h2 import FRAME_HEADER_LEN, Frame, FrameHeader, Http2Connection
from net import IOStream
from testutil import from_hex, to_hex


struct SinkStream(IOStream):
    """An IOStream that permits no reads and discards writes."""

    def __init__(out self):
        pass

    def read_exact(self, n: Int) raises -> List[Byte]:
        _ = n
        raise Error("ENABLE_PUSH probe performed an unexpected read")

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
    if len(args) != 3:
        raise Error("usage: h2_push_settings_tool <infile> <outfile>")

    var infile = open(String(args[1]), "r")
    var input = infile.read()
    infile.close()

    var startup_conn = Http2Connection(SinkStream(), is_client=True)
    var startup = startup_conn.take_pending_output()
    var output = "STARTUP " + to_hex(Span(startup)) + "\n"

    for line in input.split("\n"):
        var stripped = line.strip()
        if stripped.byte_length() == 0:
            continue
        var parts = stripped.split(" ")
        if len(parts) != 3:
            raise Error("bad ENABLE_PUSH probe input")
        var role = String(parts[0])
        var is_client = role == "CLIENT"
        if not is_client and role != "SERVER":
            raise Error("unknown ENABLE_PUSH endpoint role")

        var wire = from_hex(parts[2])
        if len(wire) < FRAME_HEADER_LEN:
            raise Error("short ENABLE_PUSH wire frame")
        var header = FrameHeader.parse(Span(wire))
        var payload = List[Byte](Span(wire)[FRAME_HEADER_LEN : len(wire)])
        var conn = Http2Connection(SinkStream(), is_client=is_client)
        _ = conn.take_pending_output()
        var status = String("OK")
        try:
            conn.process_frame(Frame(header=header, payload=payload^))
        except:
            status = "ERROR"
        var pending = conn.take_pending_output()
        output += (
            role
            + " "
            + String(parts[1])
            + " "
            + status
            + " "
            + String(conn.sent_goaway)
            + " "
            + to_hex(Span(pending))
            + "\n"
        )

    var outfile = open(String(args[2]), "w")
    outfile.write_all(output.as_bytes())
    outfile.close()
