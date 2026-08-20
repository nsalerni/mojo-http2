# ===----------------------------------------------------------------------=== #
# Copyright (c) 2026 the grpc-mojo contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# ===----------------------------------------------------------------------=== #

"""HPACK Huffman coding ([RFC 7541](https://www.rfc-editor.org/rfc/rfc7541) §5.2, Appendix B).

Encoding walks the canonical code table; decoding walks a binary tree built
from the same table, enforcing the RFC's padding rules: any final partial
byte must be a prefix of the EOS code (all 1 bits), padding longer than
7 bits is rejected, and the EOS symbol itself must never appear in the
encoded stream. The code table lives in `tables.mojo`, generated from the
RFC text by `tools/gen_hpack_tables.py`.
"""

from .tables import HUFFMAN_CODE, HUFFMAN_LEN


def huffman_encoded_len(data: Span[Byte, _]) -> Int:
    """Computes the exact byte length of the Huffman encoding of a string.

    Lets an encoder decide between the Huffman and raw representations
    without producing the encoding first.

    Args:
        data: The bytes that would be encoded.

    Returns:
        The number of bytes `huffman_encode` would append, including the
        final partially-filled byte, if any.
    """
    var lens = materialize[HUFFMAN_LEN]()
    var bits = 0
    for b in data:
        bits += Int(lens[Int(b)])
    return (bits + 7) // 8


def huffman_encode(data: Span[Byte, _], mut out_buf: List[Byte]):
    """Appends the Huffman encoding of a byte string to a buffer.

    A final partial byte is padded with the most-significant bits of the
    EOS code (all 1 bits), as required by
    [RFC 7541](https://www.rfc-editor.org/rfc/rfc7541) §5.2.

    Args:
        data: The bytes to encode.
        out_buf: Buffer the encoded bytes are appended to.
    """
    var codes = materialize[HUFFMAN_CODE]()
    var lens = materialize[HUFFMAN_LEN]()
    var acc: UInt64 = 0
    var acc_bits = 0
    for b in data:
        var code = UInt64(codes[Int(b)])
        var n = Int(lens[Int(b)])
        acc = (acc << UInt64(n)) | code
        acc_bits += n
        while acc_bits >= 8:
            acc_bits -= 8
            out_buf.append(UInt8((acc >> UInt64(acc_bits)) & 0xFF))
    if acc_bits > 0:
        # Pad with the most-significant bits of EOS (all 1s).
        var pad = 8 - acc_bits
        var last = (acc << UInt64(pad)) | ((UInt64(1) << UInt64(pad)) - 1)
        out_buf.append(UInt8(last & 0xFF))


struct HuffmanTree(Movable):
    """Flat binary tree for Huffman decoding.

    node i has children at self.children[2*i + bit]; a negative child
    value encodes (symbol + 1) as -(symbol + 1); 0 means absent.
    """

    var children: List[Int32]
    """Flattened child links; see the struct docstring for the layout."""

    def __init__(out self):
        """Builds the decoding tree from the canonical HPACK code table.

        Inserts all 257 symbols (the 256 byte values plus EOS); the EOS leaf
        stays in the tree so `decode` can detect and reject it explicitly.
        """
        self.children = List[Int32](length=2, fill=0)
        var codes = materialize[HUFFMAN_CODE]()
        var lens = materialize[HUFFMAN_LEN]()
        for sym in range(257):
            var code = UInt32(codes[sym])
            var n = Int(lens[sym])
            var node = 0
            for i in range(n):
                var bit = Int((code >> UInt32(n - 1 - i)) & 1)
                var slot = 2 * node + bit
                if i == n - 1:
                    self.children[slot] = Int32(-(sym + 1))
                else:
                    var next = Int(self.children[slot])
                    if next == 0:
                        next = len(self.children) // 2
                        self.children[slot] = Int32(next)
                        self.children.append(0)
                        self.children.append(0)
                    node = next

    def decode(self, data: Span[Byte, _]) raises -> List[Byte]:
        """Decodes a complete Huffman-coded string.

        Enforces the [RFC 7541](https://www.rfc-editor.org/rfc/rfc7541)
        §5.2 rules that make encodings canonical: a trailing incomplete
        code is accepted only as padding that is a prefix of the EOS code
        (all 1 bits) and shorter than 8 bits, and the EOS symbol itself is
        rejected wherever it appears.

        Args:
            data: The complete Huffman-coded string.

        Returns:
            The decoded bytes.

        Raises:
            If the input contains a bit sequence that is not a valid code,
            contains the EOS symbol, or ends with invalid padding (a 0 bit,
            or 8 or more padding bits). The caller should treat this as a
            COMPRESSION_ERROR at the connection level.
        """
        var out = List[Byte]()
        var node = 0
        var pad_bits = 0  # consecutive 1-bits since the last symbol
        for b in data:
            for i in range(8):
                var bit = Int((b >> UInt8(7 - i)) & 1)
                if bit == 1:
                    pad_bits += 1
                var child = Int(self.children[2 * node + bit])
                if child == 0:
                    raise Error("hpack: invalid huffman code")
                if child < 0:
                    var sym = -child - 1
                    if sym == 256:
                        # EOS must never appear in the encoding itself.
                        raise Error("hpack: EOS in huffman string")
                    out.append(UInt8(sym))
                    node = 0
                    pad_bits = 0
                else:
                    node = child
                    if bit == 0:
                        pad_bits = 0
        if node != 0:
            # Unfinished code: valid only as EOS-prefix padding (all 1s, <8).
            if pad_bits > 7:
                raise Error("hpack: huffman padding too long")
            # Walking 1-bits from the root must have consumed exactly the
            # trailing 1s; if any 0 appeared, pad_bits was reset and the
            # dangling state is invalid.
            var expected = pad_bits
            var check = 0
            for _ in range(expected):
                var child = Int(self.children[2 * check + 1])
                if child <= 0:
                    raise Error("hpack: invalid huffman padding")
                check = child
            if check != node:
                raise Error("hpack: invalid huffman padding")
        return out^
