# Compliance tool: dispatch coalesced frames one at a time.
#
# Usage: h2_budget_tool <infile> <outfile>

from std.sys import argv

from h2 import Http2Connection
from net import IOStream
from testutil import from_hex, to_hex


struct RejectingStream(IOStream):
    def __init__(out self):
        pass

    def read_exact(self, n: Int) raises -> List[Byte]:
        _ = n
        raise Error("unexpected read")

    def write_all(self, data: Span[Byte, _]) raises:
        _ = data
        raise Error("unexpected write")

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
        raise Error("usage: h2_budget_tool <infile> <outfile>")
    var infile = open(String(args[1]), "r")
    var wire = from_hex(infile.read().strip())
    infile.close()
    var conn = Http2Connection(RejectingStream(), is_client=True)
    _ = conn.take_pending_output()
    var output = String()
    var processed = conn.feed_input(Span(wire), 1)
    while True:
        var pending = conn.pending_input_frame_count()
        var automatic = conn.take_pending_output()
        output += (
            String(processed) + " " + String(pending) + " "
            + to_hex(Span(automatic)) + "\n"
        )
        if pending == 0:
            break
        var empty = List[Byte]()
        processed = conn.feed_input(Span(empty), 1)
    var outfile = open(String(args[2]), "w")
    outfile.write_all(output.as_bytes())
    outfile.close()
