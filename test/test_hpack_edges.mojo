# HPACK edge-case tests: never-indexed literals, Huffman rejection paths,
# DynamicTable mechanics, decoder size-update errors, integer overflow,
# raw-vs-huffman selection, static table sweep, and HeaderField basics.

from std.testing import assert_equal, assert_false, assert_true

from hpack import (
    Decoder,
    DynamicTable,
    Encoder,
    HeaderField,
    HuffmanTree,
    encode_integer,
    huffman_encode,
    huffman_encoded_len,
)
from hpack.tables import (
    HUFFMAN_LEN,
    STATIC_NAMES,
    STATIC_TABLE_SIZE,
    STATIC_VALUES,
)


def hf(name: StringSpan, value: StringSpan) -> HeaderField:
    return HeaderField(name=String(name), value=String(value))


# --- 1. Never-indexed (sensitive) literals ---


def test_sensitive_static_name() raises:
    # ":authority" is static index 1 with an empty value: sensitive encode
    # must emit 0x10 | 1 (never-indexed, 4-bit name index) and insert
    # nothing into the encoder's dynamic table.
    var e = Encoder()
    var out = List[Byte]()
    var field = hf(":authority", "secret.example.com")
    e.encode_field(field, out, sensitive=True)
    assert_equal(Int(out[0]), 0x11)
    assert_equal(len(e.table.entries), 0)
    assert_equal(e.table.size, 0)

    # A decoder decodes it identically and does not index it either.
    var d = Decoder()
    var back = d.decode(Span(out))
    assert_equal(len(back), 1)
    assert_true(back[0] == field, "sensitive round trip")
    assert_equal(len(d.table.entries), 0)


def test_sensitive_unknown_name() raises:
    # A name with no static match: first byte is exactly 0x10 (index 0),
    # then a literal name and value.
    var e = Encoder()
    var out = List[Byte]()
    var field = hf("x-token", "abc123")
    e.encode_field(field, out, sensitive=True)
    assert_equal(Int(out[0]), 0x10)
    assert_equal(len(e.table.entries), 0)
    var d = Decoder()
    var back = d.decode(Span(out))
    assert_true(back[0] == field, "sensitive literal-name round trip")


def test_encode_honors_field_sensitive() raises:
    var e = Encoder()
    var fields = List[HeaderField]()
    fields.append(
        HeaderField(name=String("password"), value=String("secret"), sensitive=True)
    )
    var out = List[Byte]()
    e.encode(Span(fields), out)
    assert_equal(Int(out[0]), 0x10)
    assert_equal(e.table.size, 0, "sensitive encode must not insert")
    var d = Decoder()
    var back = d.decode(Span(out))
    assert_equal(len(back), 1)
    assert_true(back[0] == hf("password", "secret"))
    assert_false(back[0].sensitive, "decoder does not reconstruct the hint")


def test_sensitive_ignores_dynamic_name_match() raises:
    # Only static name indices may be used for sensitive fields: a name
    # that matches a dynamic-table entry is still emitted literally.
    var e = Encoder()
    var out = List[Byte]()
    e.encode_field(hf("x-dyn", "v1"), out)  # inserts into dynamic table
    assert_equal(len(e.table.entries), 1)
    out.clear()
    e.encode_field(hf("x-dyn", "v2"), out, sensitive=True)
    assert_equal(Int(out[0]), 0x10)  # index 0: literal name follows
    assert_equal(len(e.table.entries), 1)  # nothing new inserted


# --- 2. Huffman decode rejection paths ---


def test_huffman_eos_in_string() raises:
    # 0xFF 0xFF 0xFF 0xFF starts with the 30-bit EOS code (0x3fffffff):
    # the EOS symbol must be rejected wherever it appears.
    var data = List[Byte](length=4, fill=0xFF)
    var tree = HuffmanTree()
    var raised = False
    try:
        _ = tree.decode(Span(data))
    except err:
        raised = True
        assert_true("EOS" in String(err), String(err))
    assert_true(raised, "embedded EOS must raise")

    # NOTE: the "invalid huffman code" branch (child == 0) is unreachable
    # through decode: the HPACK Huffman code including EOS is a complete
    # canonical code, so every bit path leads to a symbol. Long runs of
    # 1-bits hit either the EOS symbol or the padding checks instead:
    # 16 one-bits dangle inside the tree and fail the <8-bit padding rule.
    var two_ff = List[Byte](length=2, fill=0xFF)
    raised = False
    try:
        _ = tree.decode(Span(two_ff))
    except err:
        raised = True
        assert_true("padding too long" in String(err), String(err))
    assert_true(raised, "16 bits of 1s must raise")


def test_huffman_padding_too_long() raises:
    # Build an encoding that ends exactly on a byte boundary, then append
    # a full 0xFF byte: 8 bits of padding exceeds the 7-bit maximum.
    var lens = materialize[HUFFMAN_LEN]()
    var syms = List[Byte]()
    var bits = 0
    var b = 0
    while bits == 0 or bits % 8 != 0:
        syms.append(UInt8(b % 256))
        bits += Int(lens[b % 256])
        b += 1
    var enc = List[Byte]()
    huffman_encode(Span(syms), enc)
    assert_equal(len(enc), bits // 8)
    enc.append(0xFF)
    var tree = HuffmanTree()
    var raised = False
    try:
        _ = tree.decode(Span(enc))
    except err:
        raised = True
        assert_true("padding too long" in String(err), String(err))
    assert_true(raised, "8-bit padding must raise")


def test_huffman_padding_with_zero_bit() raises:
    # '0' encodes as 00000 (5 bits); the valid padded byte is 0x07
    # (00000 111). 0x00 pads with 0-bits, which is not an EOS prefix.
    var tree = HuffmanTree()
    var good = List[Byte]()
    good.append(0x07)
    var ok = tree.decode(Span(good))
    assert_equal(len(ok), 1)
    assert_equal(Int(ok[0]), Int(ord("0")))

    var bad = List[Byte]()
    bad.append(0x00)
    var raised = False
    try:
        _ = tree.decode(Span(bad))
    except err:
        raised = True
        assert_true("invalid huffman padding" in String(err), String(err))
    assert_true(raised, "0-bit padding must raise")


# --- 3. DynamicTable mechanics ---


def test_dynamic_table_insert_order() raises:
    var t = DynamicTable(4096)
    assert_equal(t.size, 0)
    assert_equal(t.max_size, 4096)
    t.insert(hf("a", "1"))
    t.insert(hf("b", "2"))
    # Index 0 is the newest insertion.
    assert_true(t.get(0) == hf("b", "2"), "index 0 is newest")
    assert_true(t.get(1) == hf("a", "1"), "index 1 is oldest")
    assert_equal(t.size, 68)  # two entries of 1 + 1 + 32

    var raised = False
    try:
        _ = t.get(2)
    except err:
        raised = True
        assert_true("out of range" in String(err), String(err))
    assert_true(raised, "get past the end must raise")


def test_dynamic_table_eviction() raises:
    # Each ("x", "y") entry costs 34 bytes; a 100-byte table holds two.
    var t = DynamicTable(100)
    t.insert(hf("a", "1"))
    t.insert(hf("b", "2"))
    t.insert(hf("c", "3"))
    assert_equal(len(t.entries), 2)
    assert_equal(t.size, 68)
    assert_true(t.get(0) == hf("c", "3"), "newest kept")
    assert_true(t.get(1) == hf("b", "2"), "middle kept")
    # "a" (the oldest) was evicted.

    # Shrinking the limit evicts from the oldest end.
    t.set_max_size(40)
    assert_equal(len(t.entries), 1)
    assert_equal(t.size, 34)
    assert_true(t.get(0) == hf("c", "3"), "shrink keeps newest")

    t.set_max_size(0)
    assert_equal(len(t.entries), 0)
    assert_equal(t.size, 0)


def test_dynamic_table_oversized_entry_empties() raises:
    # RFC 7541 §4.4: an entry larger than max_size empties the table and
    # is itself not inserted; this is not an error.
    var t = DynamicTable(50)
    t.insert(hf("a", "1"))
    assert_equal(len(t.entries), 1)
    t.insert(hf("big-name", "a value much larger than fifty bytes total!"))
    assert_equal(len(t.entries), 0)
    assert_equal(t.size, 0)


# --- 4. Decoder size-update rules ---


def test_size_update_applies_before_fields() raises:
    var d = Decoder()
    var block = List[Byte]()
    encode_integer(2048, 5, 0x20, block)
    block.append(0x82)  # :method GET
    var fields = d.decode(Span(block))
    assert_equal(len(fields), 1)
    assert_equal(d.table.max_size, 2048)


def test_size_update_after_field_raises() raises:
    var d = Decoder()
    var block = List[Byte]()
    block.append(0x82)  # :method GET
    block.append(0x20)  # size update to 0 — illegal after a field
    var raised = False
    try:
        _ = d.decode(Span(block))
    except err:
        raised = True
        assert_true("after fields" in String(err), String(err))
    assert_true(raised, "size update after a field must raise")


def test_size_update_above_limit_raises() raises:
    var d = Decoder()  # protocol_max_size = 4096
    var block = List[Byte]()
    encode_integer(4097, 5, 0x20, block)
    var raised = False
    try:
        _ = d.decode(Span(block))
    except err:
        raised = True
        assert_true("above limit" in String(err), String(err))
    assert_true(raised, "size update above the limit must raise")


# --- 5. Prefixed-integer overflow ---


def test_integer_overflow_raises() raises:
    # 0xFF opens an indexed field with a saturated 7-bit prefix; five
    # continuation bytes with the high bit set push the shift past 28.
    var d = Decoder()
    var block = List[Byte]()
    block.append(0xFF)
    for _ in range(5):
        block.append(0x80)
    var raised = False
    try:
        _ = d.decode(Span(block))
    except err:
        raised = True
        assert_true("integer overflow" in String(err), String(err))
    assert_true(raised, "shift past 28 must raise")


# --- 7. Raw representation when Huffman would be longer ---


def test_raw_string_when_huffman_longer() raises:
    # Bytes in 0x00-0x1f have Huffman codes of 20+ bits, so the raw
    # representation must win.
    var raw_value = List[Byte](length=10, fill=0x01)
    assert_true(
        huffman_encoded_len(Span(raw_value)) > len(raw_value),
        "huffman must be longer for control bytes",
    )
    var e = Encoder()
    var out = List[Byte]()
    var field = HeaderField(
        name=String(":authority"), value=String(from_utf8=raw_value)
    )
    e.encode_field(field, out)
    # 0x41: literal with incremental indexing, name = static index 1.
    assert_equal(Int(out[0]), 0x41)
    # 0x0a: raw string (huffman bit clear), length 10.
    assert_equal(Int(out[1]), 0x0A)
    assert_false((out[1] & 0x80) != 0, "huffman bit must be clear")
    assert_equal(len(out), 12)
    for i in range(10):
        assert_equal(Int(out[2 + i]), 0x01)
    var d = Decoder()
    var back = d.decode(Span(out))
    assert_true(back[0] == field, "raw literal round trip")


# --- 8. Full static table sweep ---


def test_static_table_sweep() raises:
    # Every static index 1..61 decodes as an indexed field; name-only
    # entries yield an empty-string value (the whole entry is referenced,
    # its value just happens to be empty).
    var names = materialize[STATIC_NAMES]()
    var values = materialize[STATIC_VALUES]()
    var d = Decoder()
    var saw_empty_value = False
    for i in range(1, STATIC_TABLE_SIZE + 1):
        var block = List[Byte]()
        block.append(UInt8(0x80 | i))
        var fields = d.decode(Span(block))
        assert_equal(len(fields), 1)
        assert_equal(fields[0].name, String(names[i]))
        assert_equal(fields[0].value, String(values[i]))
        assert_true(fields[0].name.byte_length() > 0, "names are non-empty")
        if fields[0].value.byte_length() == 0:
            saw_empty_value = True
    assert_true(saw_empty_value, "static table has name-only entries")
    # Indexed static references never touch the dynamic table.
    assert_equal(len(d.table.entries), 0)


# --- 9. Huffman round trip over all byte values ---


def test_huffman_all_bytes_roundtrip() raises:
    var data = List[Byte](capacity=256)
    for i in range(256):
        data.append(UInt8(i))
    var enc = List[Byte]()
    huffman_encode(Span(data), enc)
    assert_equal(len(enc), huffman_encoded_len(Span(data)))
    var tree = HuffmanTree()
    var back = tree.decode(Span(enc))
    assert_equal(len(back), 256)
    for i in range(256):
        assert_equal(Int(back[i]), i)


# --- 10. HeaderField basics ---


def test_header_field_basics() raises:
    # size() counts UTF-8 bytes, not code points: "ï" and "é" are 2 bytes.
    var plain = hf("name", "value")
    assert_equal(plain.size(), 4 + 5 + 32)
    var utf8 = hf("naïve", "héllo")
    assert_equal(String("naïve").byte_length(), 6)
    assert_equal(utf8.size(), 6 + 6 + 32)

    assert_true(hf("a", "b") == hf("a", "b"), "equal fields")
    assert_false(hf("a", "b") == hf("x", "b"), "name differs")
    assert_false(hf("a", "b") == hf("a", "x"), "value differs")
    assert_true(
        HeaderField(name=String("a"), value=String("b"), sensitive=True)
        == hf("a", "b"),
        "sensitive is not part of equality",
    )

    var s = String()
    s.write(hf("content-type", "text/plain"))
    assert_equal(s, "content-type: text/plain")


def main() raises:
    test_sensitive_static_name()
    test_sensitive_unknown_name()
    test_encode_honors_field_sensitive()
    test_sensitive_ignores_dynamic_name_match()
    test_huffman_eos_in_string()
    test_huffman_padding_too_long()
    test_huffman_padding_with_zero_bit()
    test_dynamic_table_insert_order()
    test_dynamic_table_eviction()
    test_dynamic_table_oversized_entry_empties()
    test_size_update_applies_before_fields()
    test_size_update_after_field_raises()
    test_size_update_above_limit_raises()
    test_integer_overflow_raises()
    test_raw_string_when_huffman_longer()
    test_static_table_sweep()
    test_huffman_all_bytes_roundtrip()
    test_header_field_basics()
    print("test_hpack_edges: all tests passed")
