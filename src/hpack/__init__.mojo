# ===----------------------------------------------------------------------=== #
# Copyright (c) 2026 the grpc-mojo contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# ===----------------------------------------------------------------------=== #

"""HPACK header compression for HTTP/2 ([RFC 7541](https://www.rfc-editor.org/rfc/rfc7541)).

Provides `Encoder` and `Decoder` for HPACK header blocks, the shared
`DynamicTable`, the `HeaderField` name/value pair, and the Huffman coding
primitives (`HuffmanTree`, `huffman_encode`, `huffman_encoded_len`).

Standalone by design: this package depends only on the standard library and
can be extracted for use outside grpc-mojo. The static header table and the
Huffman code table live in `tables.mojo`, which is generated from the RFC
text by `tools/gen_hpack_tables.py` — never edit it by hand.

Correctness is pinned to the RFC: encoding and decoding are byte-exact on
every RFC 7541 Appendix C test vector.
"""

from .hpack import Decoder, DynamicTable, Encoder, HeaderField, encode_integer
from .huffman import HuffmanTree, huffman_encode, huffman_encoded_len
