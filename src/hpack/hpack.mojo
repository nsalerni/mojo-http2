# ===----------------------------------------------------------------------=== #
# Copyright (c) 2026 the grpc-mojo contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# ===----------------------------------------------------------------------=== #

"""HPACK encoder and decoder ([RFC 7541](https://www.rfc-editor.org/rfc/rfc7541)).

Implements the full header block coding scheme: indexed fields against the
static and dynamic tables, literal fields with and without incremental
indexing, never-indexed literals for sensitive values, dynamic table size
updates, and the primitive prefixed-integer and string codings.

`Encoder` and `Decoder` each own an independent `DynamicTable`, matching the
two unidirectional table instances the RFC requires per connection.
"""

from .huffman import HuffmanTree, huffman_encode, huffman_encoded_len
from .tables import STATIC_NAMES, STATIC_TABLE_SIZE, STATIC_VALUES


@fieldwise_init
struct HeaderField(Copyable, Equatable, Movable, Writable):
    """A single HTTP header as an HPACK name/value pair.

    Names are kept exactly as decoded; HTTP/2 requires field names to be
    lowercase on the wire, but this type does not normalize case itself.
    """

    var name: String
    """Header field name (for example `:method` or `content-type`)."""
    var value: String
    """Header field value."""

    def size(self) -> Int:
        """Computes the table entry size of this field.

        Per [RFC 7541](https://www.rfc-editor.org/rfc/rfc7541) §4.1 an entry
        costs the byte lengths of its name and value plus a 32-byte overhead.

        Returns:
            The entry size in bytes, counted against a table's maximum size.
        """
        return self.name.byte_length() + self.value.byte_length() + 32

    def __eq__(self, other: Self) -> Bool:
        """Compares two fields for byte-exact equality of name and value.

        Args:
            other: The field to compare against.

        Returns:
            True if both name and value match exactly.
        """
        return self.name == other.name and self.value == other.value

    def write_to(self, mut writer: Some[Writer]):
        """Writes the field as `name: value` for display.

        Args:
            writer: The writer to receive the formatted field.
        """
        writer.write(self.name, ": ", self.value)


# --- Primitive integer coding (RFC 7541 §5.1) ---


def encode_integer(
    value: Int,
    prefix_bits: Int,
    first_byte_flags: UInt8,
    mut out_buf: List[Byte],
):
    """Appends an HPACK prefixed integer to a buffer.

    Implements the N-bit prefix integer coding of
    [RFC 7541](https://www.rfc-editor.org/rfc/rfc7541) §5.1: values below
    2^N - 1 fit in the prefix of the first byte; larger values fill the
    prefix and continue in 7-bit little-endian groups with a continuation
    bit.

    Args:
        value: The non-negative integer to encode.
        prefix_bits: Width N of the prefix in the first byte (1-8).
        first_byte_flags: Pattern for the bits of the first byte above the
            prefix (for example 0x80 for an indexed field).
        out_buf: Buffer the encoded bytes are appended to.
    """
    var max_prefix = (1 << prefix_bits) - 1
    if value < max_prefix:
        out_buf.append(first_byte_flags | UInt8(value))
        return
    out_buf.append(first_byte_flags | UInt8(max_prefix))
    var v = value - max_prefix
    while v >= 128:
        out_buf.append(UInt8((v % 128) + 128))
        v //= 128
    out_buf.append(UInt8(v))


struct _Cursor(Movable):
    """Read cursor over a header block with HPACK primitive decoders."""

    var data: List[Byte]
    var pos: Int

    def __init__(out self, data: Span[Byte, _]):
        self.data = List[Byte](data)
        self.pos = 0

    def done(self) -> Bool:
        return self.pos >= len(self.data)

    def byte(mut self) raises -> UInt8:
        if self.done():
            raise Error("hpack: truncated header block")
        var b = self.data[self.pos]
        self.pos += 1
        return b

    def integer(mut self, first: UInt8, prefix_bits: Int) raises -> Int:
        """Decode a §5.1 prefixed integer whose first byte is `first`."""
        var max_prefix = (1 << prefix_bits) - 1
        var v = Int(first) & max_prefix
        if v < max_prefix:
            return v
        var shift = 0
        while True:
            var b = self.byte()
            v += (Int(b) & 0x7F) << shift
            if (b & 0x80) == 0:
                return v
            shift += 7
            if shift > 28 or v > (1 << 30):
                raise Error("hpack: integer overflow")

    def string(mut self, tree: HuffmanTree) raises -> String:
        """Decode a §5.2 string literal (raw or Huffman-coded)."""
        var first = self.byte()
        var huffman = (first & 0x80) != 0
        var n = self.integer(first, 7)
        if self.pos + n > len(self.data):
            raise Error("hpack: truncated string literal")
        var raw = Span(self.data)[self.pos : self.pos + n]
        self.pos += n
        if huffman:
            return String(from_utf8=tree.decode(raw))
        return String(from_utf8=raw)


# --- Dynamic table (RFC 7541 §4, §2.3.2) ---


struct DynamicTable(Movable):
    """Bounded FIFO of header fields shared by encoder and decoder.

    Entries are ordered most-recent-first (index 0 is the newest insertion).
    Inserting evicts from the oldest end until the total size, computed with
    the 32-byte-per-entry overhead of
    [RFC 7541](https://www.rfc-editor.org/rfc/rfc7541) §4.1, fits within
    `max_size` (§4.4).
    """

    var entries: List[HeaderField]
    """Live entries, most recently inserted first."""
    var size: Int
    """Current total size in bytes per the §4.1 entry-size formula."""
    var max_size: Int
    """Size limit in bytes; insertions evict old entries to respect it."""

    def __init__(out self, max_size: Int = 4096):
        """Creates an empty table.

        Args:
            max_size: Initial size limit in bytes; the protocol default
                is 4096.
        """
        self.entries = List[HeaderField]()
        self.size = 0
        self.max_size = max_size

    def _evict(mut self):
        while self.size > self.max_size and len(self.entries) > 0:
            var evicted = self.entries.pop()
            self.size -= evicted.size()

    def insert(mut self, var field: HeaderField):
        """Inserts a field at index 0, evicting old entries as needed.

        A field larger than the whole table empties the table and is not
        inserted, per [RFC 7541](https://www.rfc-editor.org/rfc/rfc7541)
        §4.4; this is not an error.

        Args:
            field: The field to add; ownership is taken.
        """
        var entry_size = field.size()
        if entry_size > self.max_size:
            # An oversized entry empties the table (RFC 7541 §4.4).
            self.entries.clear()
            self.size = 0
            return
        self.entries.insert(0, field^)
        self.size += entry_size
        self._evict()

    def set_max_size(mut self, max_size: Int):
        """Changes the size limit, evicting entries that no longer fit.

        Corresponds to a dynamic table size update
        ([RFC 7541](https://www.rfc-editor.org/rfc/rfc7541) §6.3) on the
        decoder side, or a local policy change on the encoder side.

        Args:
            max_size: The new size limit in bytes.
        """
        self.max_size = max_size
        self._evict()

    def get(self, index: Int) raises -> HeaderField:
        """Returns a copy of the entry at a 0-based dynamic table index.

        Index 0 is the most recently inserted entry. Callers translating
        wire indices must subtract the static table size and the 1-based
        offset first (see `_lookup_table_entry`).

        Args:
            index: 0-based position within the dynamic table.

        Returns:
            A copy of the entry at that position.

        Raises:
            If the index is negative or beyond the last entry.
        """
        if index < 0 or index >= len(self.entries):
            raise Error("hpack: dynamic table index out of range")
        return self.entries[index].copy()


def _lookup_table_entry(index: Int, table: DynamicTable) raises -> HeaderField:
    """Resolve a 1-based HPACK index across static + dynamic tables."""
    if index <= 0:
        raise Error("hpack: index 0 is invalid")
    if index <= STATIC_TABLE_SIZE:
        var names = materialize[STATIC_NAMES]()
        var values = materialize[STATIC_VALUES]()
        return HeaderField(
            name=String(names[index]), value=String(values[index])
        )
    return table.get(index - STATIC_TABLE_SIZE - 1)


# --- Decoder ---


struct Decoder(Movable):
    """Stateful HPACK decoder for one direction of a connection.

    Decodes header blocks in the order the peer produced them; the dynamic
    table state carries across calls to `decode`, so blocks from a single
    connection must be fed to a single decoder instance, in order.
    """

    var table: DynamicTable
    """Dynamic table populated by literals with incremental indexing."""
    var tree: HuffmanTree
    """Decoding tree for Huffman-coded string literals."""
    var protocol_max_size: Int
    """Ceiling for dynamic table size updates (SETTINGS_HEADER_TABLE_SIZE)."""

    def __init__(out self, max_table_size: Int = 4096):
        """Creates a decoder with an empty dynamic table.

        Args:
            max_table_size: Both the initial dynamic table limit and the
                ceiling the peer may raise it to via size updates; matches
                the SETTINGS_HEADER_TABLE_SIZE value advertised to the peer.
        """
        self.table = DynamicTable(max_table_size)
        self.tree = HuffmanTree()
        self.protocol_max_size = max_table_size

    def decode(mut self, data: Span[Byte, _]) raises -> List[HeaderField]:
        """Decodes one complete header block into its fields.

        Handles every representation of
        [RFC 7541](https://www.rfc-editor.org/rfc/rfc7541) §6: indexed
        fields, literals with incremental indexing (which update the dynamic
        table), literals without indexing, never-indexed literals, and
        dynamic table size updates. Size updates are only legal before the
        first field of the block and may not exceed `protocol_max_size`.

        Args:
            data: The complete header block (all HEADERS plus CONTINUATION
                fragments already concatenated).

        Returns:
            The decoded fields in wire order.

        Raises:
            On any malformed block: truncated input, invalid index, bad
            Huffman coding, integer overflow, or a misplaced or oversized
            table size update. The caller should treat this as a
            COMPRESSION_ERROR at the connection level.
        """
        var out = List[HeaderField]()
        var cur = _Cursor(data)
        var saw_field = False
        while not cur.done():
            var first = cur.byte()
            if (first & 0x80) != 0:
                # Indexed Header Field (§6.1)
                var index = cur.integer(first, 7)
                out.append(_lookup_table_entry(index, self.table))
                saw_field = True
            elif (first & 0xC0) == 0x40:
                # Literal with Incremental Indexing (§6.2.1)
                var field = self._literal(cur, first, 6)
                self.table.insert(field.copy())
                out.append(field^)
                saw_field = True
            elif (first & 0xE0) == 0x20:
                # Dynamic Table Size Update (§6.3) — must precede fields.
                if saw_field:
                    raise Error("hpack: table size update after fields")
                var new_size = cur.integer(first, 5)
                if new_size > self.protocol_max_size:
                    raise Error("hpack: table size update above limit")
                self.table.set_max_size(new_size)
            else:
                # Literal without Indexing (§6.2.2, prefix 0000) or
                # Never Indexed (§6.2.3, prefix 0001): 4-bit name index.
                var field = self._literal(cur, first, 4)
                out.append(field^)
                saw_field = True
        return out^

    def _literal(
        self, mut cur: _Cursor, first: UInt8, prefix_bits: Int
    ) raises -> HeaderField:
        """Decode a literal field: indexed-or-literal name, literal value."""
        var name_index = cur.integer(first, prefix_bits)
        var name: String
        if name_index == 0:
            name = cur.string(self.tree)
        else:
            name = _lookup_table_entry(name_index, self.table).name
        var value = cur.string(self.tree)
        return HeaderField(name=name^, value=value^)


# --- Encoder ---


struct Encoder(Movable):
    """Stateful HPACK encoder for one direction of a connection.

    Emits the shortest available representation: a full name/value match in
    the static or dynamic table becomes an indexed field; otherwise a
    literal with incremental indexing (reusing an indexed name when one
    matches) that also inserts the field into the dynamic table. String
    literals use Huffman coding whenever it is not longer than the raw
    bytes; on a tie Huffman wins, matching the
    [RFC 7541](https://www.rfc-editor.org/rfc/rfc7541) Appendix C examples.

    The dynamic table state carries across calls, so all header blocks of a
    connection must be produced by a single encoder instance, in order.
    """

    var table: DynamicTable
    """Dynamic table mirroring the insertions the peer's decoder makes."""
    var pending_table_size: Int
    """Size update to emit at the start of the next header block, or -1."""

    def __init__(out self, max_table_size: Int = 4096):
        """Creates an encoder with an empty dynamic table.

        Args:
            max_table_size: Dynamic table size limit in bytes; must not
                exceed the SETTINGS_HEADER_TABLE_SIZE the peer advertised.
        """
        self.table = DynamicTable(max_table_size)
        self.pending_table_size = -1

    def set_max_size(mut self, max_size: Int):
        """Lowers or raises the encoder table to the peer's decoder ceiling.

        Evicts entries that no longer fit and emits a dynamic table size
        update at the start of the next header block
        ([RFC 7541](https://www.rfc-editor.org/rfc/rfc7541) §6.3).

        Args:
            max_size: The peer's SETTINGS_HEADER_TABLE_SIZE, in bytes.
        """
        self.table.set_max_size(max_size)
        self.pending_table_size = max_size

    def _flush_table_size_update(mut self, mut out_buf: List[Byte]):
        if self.pending_table_size >= 0:
            encode_integer(self.pending_table_size, 5, 0x20, out_buf)
            self.pending_table_size = -1

    def _find(self, field: HeaderField) -> Tuple[Int, Int]:
        """Returns (full_match_index, name_match_index), 0 = none, 1-based."""
        var names = materialize[STATIC_NAMES]()
        var values = materialize[STATIC_VALUES]()
        var name_match = 0
        for i in range(1, STATIC_TABLE_SIZE + 1):
            if String(names[i]) == field.name:
                if String(values[i]) == field.value:
                    return (i, i)
                if name_match == 0:
                    name_match = i
        for i in range(len(self.table.entries)):
            ref e = self.table.entries[i]
            if e.name == field.name:
                var idx = STATIC_TABLE_SIZE + 1 + i
                if e.value == field.value:
                    return (idx, idx)
                if name_match == 0:
                    name_match = idx
        return (0, name_match)

    def _string(self, s: StringSpan, mut out_buf: List[Byte]):
        """Emit a string literal, Huffman-coded unless raw is shorter."""
        var raw = s.as_bytes()
        var hlen = huffman_encoded_len(raw)
        if hlen <= len(raw):
            encode_integer(hlen, 7, 0x80, out_buf)
            huffman_encode(raw, out_buf)
        else:
            encode_integer(len(raw), 7, 0x00, out_buf)
            out_buf.extend(raw)

    def encode_field(
        mut self,
        field: HeaderField,
        mut out_buf: List[Byte],
        *,
        sensitive: Bool = False,
    ):
        """Appends the encoding of one field to a header block.

        Non-sensitive fields use the shortest representation and may insert
        into the dynamic table (see the struct docstring). Sensitive fields
        are emitted as never-indexed literals
        ([RFC 7541](https://www.rfc-editor.org/rfc/rfc7541) §6.2.3), which
        keeps values such as authorization tokens out of both endpoints'
        tables (mitigating CRIME-style attacks) and instructs intermediaries
        to preserve the never-indexed representation when re-encoding; only
        static-table name indices are used for the name.

        Args:
            field: The header field to encode.
            out_buf: Buffer the encoded representation is appended to.
            sensitive: True to force the never-indexed representation.
        """
        self._flush_table_size_update(out_buf)
        if sensitive:
            # Never Indexed (§6.2.3): protects e.g. authorization values
            # from CRIME-style attacks; forwards must preserve this.
            var m = self._find(field)
            var name_match = m[1]
            encode_integer(
                name_match if name_match <= STATIC_TABLE_SIZE else 0,
                4,
                0x10,
                out_buf,
            )
            if name_match == 0 or name_match > STATIC_TABLE_SIZE:
                self._string(field.name, out_buf)
            self._string(field.value, out_buf)
            return
        var m = self._find(field)
        var full = m[0]
        var name_match = m[1]
        if full != 0:
            encode_integer(full, 7, 0x80, out_buf)
            return
        # Literal with incremental indexing.
        encode_integer(name_match, 6, 0x40, out_buf)
        if name_match == 0:
            self._string(field.name, out_buf)
        self._string(field.value, out_buf)
        self.table.insert(field.copy())

    def encode(mut self, fields: Span[HeaderField, _], mut out_buf: List[Byte]):
        """Appends the encoding of a whole header list to a buffer.

        Equivalent to calling `encode_field` on each field in order with
        `sensitive=False`.

        Args:
            fields: The header fields to encode, in wire order.
            out_buf: Buffer the header block is appended to.
        """
        self._flush_table_size_update(out_buf)
        for f in fields:
            self.encode_field(f, out_buf)
