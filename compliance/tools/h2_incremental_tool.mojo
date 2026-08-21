# Compliance tool: incrementally decode hyperframe-built HTTP/2 bytes.
#
# Usage: h2_incremental_tool <infile> <outfile>
# Input groups:
#   CASE <name>
#   <hex chunk>
#   ...
#   END
# Output groups contain one F line per complete frame and the retained byte
# count at END.

from std.sys import argv

from h2 import IncrementalFrameDecoder
from testutil import from_hex, to_hex


def main() raises:
    var args = argv()
    if len(args) != 3:
        raise Error("usage: h2_incremental_tool <infile> <outfile>")

    var infile = open(String(args[1]), "r")
    var text = infile.read()
    infile.close()

    var decoder = IncrementalFrameDecoder()
    var active = False
    var out = String()
    for line in text.split("\n"):
        var stripped = line.strip()
        if stripped.byte_length() == 0:
            continue
        if stripped.startswith("CASE "):
            decoder = IncrementalFrameDecoder()
            active = True
            out += "CASE " + stripped[byte=5:] + "\n"
            continue
        if stripped == "END":
            if not active:
                raise Error("END outside CASE")
            out += "END " + String(decoder.buffered_len()) + "\n"
            active = False
            continue
        if not active:
            raise Error("chunk outside CASE")
        var chunk = from_hex(stripped)
        var frames = decoder.feed(Span(chunk))
        for i in range(len(frames)):
            out += (
                "F "
                + String(frames[i].header.frame_type)
                + " "
                + String(frames[i].header.flags)
                + " "
                + String(frames[i].header.stream_id)
                + " "
                + String(frames[i].header.length)
                + " "
                + to_hex(Span(frames[i].payload))
                + "\n"
            )
    if active:
        raise Error("unterminated CASE")

    var outfile = open(String(args[2]), "w")
    outfile.write_all(out.as_bytes())
    outfile.close()
