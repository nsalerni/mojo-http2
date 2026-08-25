# Drive incremental HTTP/2 connection cases from the randomized suite.
#
# Usage: h2_randomized_tool <infile> <outfile>
# Input groups:
#   CASE <name>
#   OPEN <count>
#   CHUNK <hex bytes>
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
        raise Error("randomized probe performed an unexpected read")

    def write_all(self, data: Span[Byte, _]) raises:
        _ = data
        raise Error("randomized probe performed an unexpected write")

    def set_read_timeout(self, nanos: Int64) raises:
        _ = nanos

    def set_nodelay(self, enabled: Bool) raises:
        _ = enabled

    def close(mut self):
        pass


def main() raises:
    var args = argv()
    if len(args) != 3:
        raise Error("usage: h2_randomized_tool <infile> <outfile>")

    var infile = open(String(args[1]), "r")
    var input = infile.read()
    infile.close()

    var conn = Http2Connection(RejectingStream(), is_client=True)
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
            conn = Http2Connection(RejectingStream(), is_client=True)
            _ = conn.take_pending_output()
            active = True
            failed = False
            failure = String()
            output += "CASE " + stripped[byte=5:] + "\n"
            continue
        if stripped.startswith("OPEN "):
            if not active or failed:
                raise Error("OPEN outside active CASE")
            var count = Int(stripped[byte=5:])
            if count < 0 or count > 8:
                raise Error("invalid OPEN count")
            for _ in range(count):
                _ = conn.open_stream()
            _ = conn.take_pending_output()
            continue
        if stripped.startswith("CHUNK "):
            if not active:
                raise Error("CHUNK outside active CASE")
            if failed:
                continue
            var chunk = from_hex(stripped[byte=6:])
            try:
                _ = conn.feed_input(Span(chunk))
            except error:
                failed = True
                failure = String(error)
            continue
        if stripped == "END":
            if not active:
                raise Error("END outside CASE")
            var pending = conn.take_pending_output()
            output += "OUT " + to_hex(Span(pending)) + "\n"
            output += (
                "STATE "
                + String(conn.peer_settings.header_table_size)
                + " "
                + String(conn.peer_settings.max_concurrent_streams)
                + " "
                + String(conn.peer_settings.initial_window_size)
                + " "
                + String(conn.peer_settings.max_frame_size)
                + " "
                + String(conn.peer_settings.max_header_list_size)
                + " "
                + String(conn.send_window)
                + " "
                + String(conn.goaway_last_stream)
                + " "
                + (String(conn.goaway_code.value()) if conn.goaway_code else "none")
                + "\n"
            )
            if failed:
                output += "ERROR " + failure + "\n"
            output += "END " + ("ERROR" if failed else "OK") + "\n"
            active = False
            continue
        raise Error("unknown randomized probe input")
    if active:
        raise Error("unterminated CASE")

    var outfile = open(String(args[2]), "w")
    outfile.write_all(output.as_bytes())
    outfile.close()
