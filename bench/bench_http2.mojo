# ===----------------------------------------------------------------------=== #
# Copyright (c) 2026 the grpc-mojo contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
# ===----------------------------------------------------------------------=== #

"""Throughput benchmarks for HPACK coding and HTTP/2 frame handling.

Run: `pixi run bench`. Pass `--smoke` for a milliseconds-long CI run that
proves the benchmarks build and execute.
"""

from std.benchmark import Unit, run
from std.sys import argv

from hpack import Decoder, Encoder, HeaderField
from hpack.huffman import HuffmanTree, huffman_encode
from h2 import Frame, Http2Connection
from h2.frame import FrameHeader, IncrementalFrameDecoder
from net import IOStream


struct SinkStream(IOStream):
    """An in-memory benchmark transport that discards protocol output."""

    def __init__(out self):
        pass

    def read_exact(self, n: Int) raises -> List[Byte]:
        _ = n
        raise Error("benchmark SinkStream cannot read")

    def write_all(self, data: Span[Byte, _]) raises:
        _ = data

    def set_read_timeout(self, nanos: Int64) raises:
        _ = nanos

    def set_nodelay(self, enabled: Bool) raises:
        _ = enabled

    def close(mut self):
        pass


def is_smoke() -> Bool:
    for a in argv():
        if a == "--smoke":
            return True
    return False


def bench_time() -> Float64:
    return 0.005 if is_smoke() else 0.5


def run_capped[F: def() raises](f: F, secs: Float64) raises -> Float64:
    """Runs a benchmark bounded by `secs` and returns the mean in ns."""
    var report = run(f, min_runtime_secs=secs, max_runtime_secs=secs * 3)
    return report.mean(Unit.ns)


def report_line(name: StringSpan, ns_per_op: Float64, bytes_per_op: Int):
    var mib_s = 0.0
    if ns_per_op > 0:
        mib_s = (Float64(bytes_per_op) / (1024 * 1024)) / (ns_per_op / 1e9)
    print(
        String(name),
        ": ",
        Int(ns_per_op),
        " ns/op",
        ", ",
        Int(mib_s),
        " MiB/s",
        sep="",
    )


def grpc_request_block() -> List[HeaderField]:
    """A realistic gRPC request header block (what a channel sends)."""
    var h = List[HeaderField]()
    h.append(HeaderField(name=String(":method"), value=String("POST")))
    h.append(HeaderField(name=String(":scheme"), value=String("http")))
    h.append(HeaderField(name=String(":path"), value=String("/echo.Echo/Say")))
    h.append(
        HeaderField(name=String(":authority"), value=String("api.example.com"))
    )
    h.append(HeaderField(name=String("te"), value=String("trailers")))
    h.append(
        HeaderField(
            name=String("content-type"), value=String("application/grpc+proto")
        )
    )
    h.append(
        HeaderField(name=String("user-agent"), value=String("grpc-mojo/0.1.0"))
    )
    h.append(
        HeaderField(
            name=String("x-request-id"),
            value=String("4f9a1c2e-77b3-4d10-9e5f-2b6c8a1d0e42"),
        )
    )
    return h^


def main() raises:
    var secs = bench_time()
    var block = grpc_request_block()

    # Raw byte size of the block (name + value), for throughput math.
    var block_bytes = 0
    for f in block:
        block_bytes += f.name.byte_length() + f.value.byte_length()

    # --- HPACK encode ---
    def encode_cold() raises {block}:
        var enc = Encoder()
        var out = List[Byte]()
        enc.encode(Span(block), out)
        if len(out) == 0:
            raise Error("unreachable")

    var r = run_capped(encode_cold, secs)
    report_line("hpack encode 8 headers (cold table)", r, block_bytes)

    # Warm: a persistent encoder converges to indexed lookups, the way a
    # long-lived connection behaves.
    var warm_enc = Encoder()
    var warmup_buf = List[Byte]()
    warm_enc.encode(Span(block), warmup_buf)

    def encode_warm() raises {mut warm_enc, block}:
        var out = List[Byte]()
        warm_enc.encode(Span(block), out)
        if len(out) == 0:
            raise Error("unreachable")

    r = run_capped(encode_warm, secs)
    report_line("hpack encode 8 headers (warm table)", r, block_bytes)

    # --- HPACK decode ---
    var one_enc = Encoder()
    var wire = List[Byte]()
    one_enc.encode(Span(block), wire)
    var warm_wire = List[Byte]()  # indexed form after the first block
    one_enc.encode(Span(block), warm_wire)
    print(
        "encoded block: ", len(wire), " -> ", len(warm_wire), " bytes", sep=""
    )

    var dec = Decoder()
    _ = dec.decode(Span(wire))

    def decode_warm() raises {mut dec, warm_wire}:
        var fields = dec.decode(Span(warm_wire))
        if len(fields) == 0:
            raise Error("unreachable")

    r = run_capped(decode_warm, secs)
    report_line("hpack decode 8 headers (warm table)", r, block_bytes)

    # --- Huffman coding ---
    var text = String(
        "grpc-message: the quick brown fox jumps over the lazy dog 0123456789"
    )
    var coded = List[Byte]()
    huffman_encode(text.as_bytes(), coded)
    var tree = HuffmanTree()

    def huff_encode() raises {text}:
        var out = List[Byte]()
        huffman_encode(text.as_bytes(), out)
        if len(out) == 0:
            raise Error("unreachable")

    r = run_capped(huff_encode, secs)
    report_line("huffman encode 69 bytes", r, text.byte_length())

    def huff_decode() raises {tree, coded}:
        var out = tree.decode(Span(coded))
        if len(out) == 0:
            raise Error("unreachable")

    r = run_capped(huff_decode, secs)
    report_line("huffman decode 69 bytes", r, text.byte_length())

    # --- frame header coding ---
    var hdr = FrameHeader(
        length=16384, frame_type=0, flags=0x1, stream_id=1234567
    )

    def frame_roundtrip() raises {hdr}:
        var wire_h = List[Byte]()
        hdr.serialize(wire_h)
        var back = FrameHeader.parse(Span(wire_h))
        if back.length != 16384:
            raise Error("unreachable")

    r = run_capped(frame_roundtrip, secs)
    report_line("frame header serialize+parse", r, 9)

    # --- connection dispatch without transport reads ---
    # Unknown types are the smallest valid no-op in RFC 9113. This isolates
    # public process_frame routing and validation from socket and HPACK work.
    var dispatch_conn = Http2Connection(SinkStream(), is_client=True)
    var dispatch_count = 0

    def dispatch_unknown() raises {mut dispatch_conn, mut dispatch_count}:
        dispatch_conn.process_frame(
            Frame(
                header=FrameHeader(
                    length=0, frame_type=0xFE, flags=0, stream_id=0
                ),
                payload=List[Byte](),
            )
        )
        dispatch_count += 1

    r = run_capped(dispatch_unknown, secs)
    if dispatch_count == 0:
        raise Error("frame dispatch benchmark did not run")
    print(
        "connection frame dispatch (unknown no-op): ",
        Int(r),
        " ns/op",
        sep="",
    )

    # --- outbound frame queue ---
    var queue_conn = Http2Connection(SinkStream(), is_client=True)
    var queued_bytes = 0

    def queue_ping() raises {mut queue_conn, mut queued_bytes}:
        queue_conn.queue_ping(0x3132333435363738)
        var output = queue_conn.take_pending_output()
        queued_bytes += len(output)

    r = run_capped(queue_ping, secs)
    if queued_bytes == 0 or queued_bytes % 17 != 0:
        raise Error("outbound queue benchmark produced invalid output")
    report_line("queue and take PING frame", r, 17)

    # Incremental decoder over 1 MiB of prebuilt DATA frames. Both paths
    # decode identical bytes; the chunked case models readiness-driven reads.
    var frame_count = 64
    var frame_payload_len = 16384
    var incremental_wire = List[Byte](
        capacity=frame_count * (9 + frame_payload_len)
    )
    var fixed_header = List[Byte]()
    fixed_header.append(0x00)
    fixed_header.append(0x40)
    fixed_header.append(0x00)
    fixed_header.append(0x00)
    fixed_header.append(0x00)
    fixed_header.append(0x00)
    fixed_header.append(0x00)
    fixed_header.append(0x00)
    fixed_header.append(0x01)
    for _ in range(frame_count):
        incremental_wire.extend(Span(fixed_header))
        for i in range(frame_payload_len):
            incremental_wire.append(UInt8(i % 251))
    var expected_checksum = 0
    for i in range(frame_payload_len):
        expected_checksum += i % 251
    expected_checksum *= frame_count

    def decode_single_chunk() raises {
        incremental_wire, frame_count, expected_checksum
    }:
        var decoder = IncrementalFrameDecoder()
        var frames = decoder.feed(Span(incremental_wire))
        var checksum = 0
        for i in range(len(frames)):
            for byte in frames[i].payload:
                checksum += Int(byte)
        if (
            len(frames) != frame_count
            or decoder.buffered_len() != 0
            or checksum != expected_checksum
        ):
            raise Error("incremental single-chunk decode mismatch")

    r = run_capped(decode_single_chunk, secs)
    report_line(
        "incremental frame decode and scan (single chunk)",
        r,
        len(incremental_wire),
    )

    def decode_4k_chunks() raises {
        incremental_wire, frame_count, expected_checksum
    }:
        var decoder = IncrementalFrameDecoder()
        var offset = 0
        var decoded = 0
        var checksum = 0
        while offset < len(incremental_wire):
            var end = min(offset + 4096, len(incremental_wire))
            var frames = decoder.feed(Span(incremental_wire)[offset:end])
            decoded += len(frames)
            for i in range(len(frames)):
                for byte in frames[i].payload:
                    checksum += Int(byte)
            offset = end
        if (
            decoded != frame_count
            or decoder.buffered_len() != 0
            or checksum != expected_checksum
        ):
            raise Error("incremental 4 KiB decode mismatch")

    r = run_capped(decode_4k_chunks, secs)
    report_line(
        "incremental frame decode and scan (4 KiB chunks)",
        r,
        len(incremental_wire),
    )

    print("bench_http2: done")
