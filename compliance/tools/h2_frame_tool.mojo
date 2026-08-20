# Compliance tool: HTTP/2 frame header codec, cross-checked vs hyperframe.
#
# Usage: h2_frame_tool <parse|build> <infile> <outfile>
#   parse: input lines = hex of a full frame (9-byte header + payload);
#          output "type flags stream_id length payload_hex" or "ERR <msg>".
#   build: input lines = "type flags stream_id payload_hex";
#          output = hex of the serialized frame.

from std.sys import argv

from testutil import from_hex, to_hex
from h2 import FrameHeader


def run_parse(text: String) raises -> String:
    var out = String()
    for line in text.split("\n"):
        var stripped = line.strip()
        if stripped.byte_length() == 0:
            continue
        try:
            var raw = from_hex(stripped)
            var h = FrameHeader.parse(Span(raw))
            if len(raw) != 9 + h.length:
                raise Error("frame length mismatch")
            var payload = List[Byte](Span(raw)[9 : len(raw)])
            out += (
                String(h.frame_type)
                + " "
                + String(h.flags)
                + " "
                + String(h.stream_id)
                + " "
                + String(h.length)
                + " "
                + to_hex(payload)
                + "\n"
            )
        except e:
            out += "ERR " + String(e) + "\n"
    return out^


def run_build(text: String) raises -> String:
    var out = String()
    for line in text.split("\n"):
        var stripped = line.strip()
        if stripped.byte_length() == 0:
            continue
        var parts = stripped.split(" ")
        if len(parts) < 3:
            raise Error("bad build line")
        var payload = List[Byte]()
        if len(parts) >= 4 and parts[3].byte_length() > 0:
            payload = from_hex(parts[3])
        var h = FrameHeader(
            length=len(payload),
            frame_type=UInt8(Int(parts[0])),
            flags=UInt8(Int(parts[1])),
            stream_id=UInt32(Int(parts[2])),
        )
        var buf = List[Byte]()
        h.serialize(buf)
        buf.extend(Span(payload))
        out += to_hex(buf) + "\n"
    return out^


def main() raises:
    var args = argv()
    if len(args) != 4:
        raise Error("usage: h2_frame_tool <parse|build> <infile> <outfile>")
    var infile = open(String(args[2]), "r")
    var text = infile.read()
    infile.close()
    var result: String
    if args[1] == "parse":
        result = run_parse(text)
    else:
        result = run_build(text)
    var outfile = open(String(args[3]), "w")
    outfile.write_all(result.as_bytes())
    outfile.close()
