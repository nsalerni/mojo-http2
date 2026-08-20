# Compliance tool: HPACK encode/decode with a persistent dynamic table.
#
# Usage: hpack_tool <encode|decode> <infile> <outfile>
#
# decode mode:
#   infile:  one hex header-block per line, decoded SEQUENTIALLY on one
#            Decoder (dynamic table state carries across lines).
#   outfile: per block: one "name\x1fvalue" line per header, then "===".
#            On error: "ERR <msg>" then "===".
#
# encode mode:
#   infile:  blocks of "name\x1fvalue" lines separated by "===" lines,
#            encoded sequentially on one Encoder.
#   outfile: one hex header-block per line.

from std.sys import argv

from testutil import from_hex, to_hex
from hpack import Decoder, Encoder, HeaderField


def run_decode(text: String) raises -> String:
    var out = String()
    var dec = Decoder()
    for line in text.split("\n"):
        var stripped = line.strip()
        if stripped.byte_length() == 0:
            continue
        try:
            var fields = dec.decode(Span(from_hex(stripped)))
            for f in fields:
                out += f.name + "\x1f" + f.value + "\n"
        except e:
            out += "ERR " + String(e) + "\n"
        out += "===\n"
    return out^


def run_encode(text: String) raises -> String:
    var out = String()
    var enc = Encoder()
    var block = List[HeaderField]()
    for line in text.split("\n"):
        if line.strip() == "===":
            var buf = List[Byte]()
            enc.encode(Span(block), buf)
            out += to_hex(buf) + "\n"
            block = List[HeaderField]()
            continue
        if line.byte_length() == 0:
            continue
        var sep = line.find("\x1f")
        if sep < 0:
            raise Error("bad input line (no unit separator)")
        var total = line.byte_length()
        block.append(
            HeaderField(
                name=String(line[byte=0:sep]),
                value=String(line[byte = sep + 1 : total]),
            )
        )
    return out^


def main() raises:
    var args = argv()
    if len(args) != 4:
        raise Error("usage: hpack_tool <encode|decode> <infile> <outfile>")
    var infile = open(String(args[2]), "r")
    var text = infile.read()
    infile.close()
    var result: String
    if args[1] == "decode":
        result = run_decode(text)
    else:
        result = run_encode(text)
    var outfile = open(String(args[3]), "w")
    outfile.write_all(result.as_bytes())
    outfile.close()
