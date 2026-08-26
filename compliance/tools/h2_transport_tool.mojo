# Compliance tool: feed hyper-h2 startup bytes through Http2Connection.
#
# Usage: h2_transport_tool <infile> <outfile>
# Input groups:
#   CASE <name>
#   <hex chunk>
#   ...
#   END

from std.sys import argv

from h2 import Http2Connection
from net import IOStream
from testutil import from_hex, to_hex


struct RejectingStream(IOStream):
    """A transport that rejects hidden reads and writes."""

    def __init__(out self):
        pass

    def read_exact(self, n: Int) raises -> List[Byte]:
        _ = n
        raise Error("transport probe performed an unexpected read")

    def write_all(self, data: Span[Byte, _]) raises:
        _ = data
        raise Error("transport probe performed an unexpected write")

    def write_some(self, data: Span[Byte, _]) raises -> Int:
        self.write_all(data)
        return len(data)

    def set_read_timeout(self, nanos: Int64) raises:
        _ = nanos

    def set_nodelay(self, enabled: Bool) raises:
        _ = enabled

    def close(mut self):
        pass


def main() raises:
    var args = argv()
    if len(args) != 3:
        raise Error("usage: h2_transport_tool <infile> <outfile>")

    var infile = open(String(args[1]), "r")
    var input = infile.read()
    infile.close()

    var conn = Http2Connection(RejectingStream(), is_client=False)
    var active = False
    var output = String()
    for line in input.split("\n"):
        var stripped = line.strip()
        if stripped.byte_length() == 0:
            continue
        if stripped.startswith("CASE "):
            if active:
                raise Error("CASE inside CASE")
            conn = Http2Connection(RejectingStream(), is_client=False)
            active = True
            output += "CASE " + stripped[byte=5:] + "\n"
            continue
        if stripped == "END":
            if not active:
                raise Error("END outside CASE")
            var pending = conn.take_pending_output()
            output += (
                "STATE "
                + String(conn.input_preface_complete())
                + " "
                + String(conn.peer_settings_received)
                + " "
                + String(conn.pending_input_frame_count())
                + " "
                + to_hex(Span(pending))
                + "\n"
            )
            active = False
            continue
        if not active:
            raise Error("chunk outside CASE")
        var chunk = from_hex(stripped)
        _ = conn.feed_input(Span(chunk))

    if active:
        raise Error("unterminated CASE")

    var outfile = open(String(args[2]), "w")
    outfile.write_all(output.as_bytes())
    outfile.close()
