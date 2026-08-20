#!/usr/bin/env python3
"""mojo-http2 compliance suite.

Differentially tests the `hpack` and `h2` packages against the established
Python references:

  hpack  vs  python-hpack (the HPACK used by hyper-h2 / httpx)
  h2     vs  hyper-h2 + hyperframe (strict: raises ProtocolError on any
             protocol violation by our side)

Plus h2spec (the standard RFC 9113/7541 conformance tool) when the binary
is on PATH.

The `h2` package depends on mojo-net; the runner locates its sources via
MOJO_DEPS_DIR, ./.deps/mojo-net/src, or the monorepo sibling
../mojo-net/src (see dep_path()).

Rerun with: pixi run compliance   (from the package root)
Writes COMPLIANCE.md at the package root and exits non-zero on any failure.
With --json PATH, also dumps {"sections": {...}} for the umbrella suite.
"""

import argparse
import json
import os
import platform
import random
import re
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent  # package root
BUILD = ROOT / "build"
TOOLS = ROOT / "compliance" / "tools"
REPORT = ROOT / "COMPLIANCE.md"
CERTS = BUILD / "certs"

RESULTS: dict[str, list[tuple[str, bool, str]]] = {}
US = "\x1f"
MOJO_RUN: list[str] = []


def dep_path(name: str) -> Path:
    """Locate a dependency package's src/ directory.

    Search order: $MOJO_DEPS_DIR/<name>/src, <package>/.deps/<name>/src,
    then the monorepo sibling <package>/../<name>/src.
    """
    candidates = []
    deps_dir = os.environ.get("MOJO_DEPS_DIR")
    if deps_dir:
        candidates.append(Path(deps_dir) / name / "src")
    candidates.append(ROOT / ".deps" / name / "src")
    candidates.append(ROOT.parent / name / "src")
    for c in candidates:
        if c.exists():
            return c
    sys.exit(
        f"error: cannot find dependency '{name}': looked in "
        + ", ".join(str(c) for c in candidates)
        + "; set MOJO_DEPS_DIR or place the package under .deps/"
    )


def record(section: str, name: str, ok: bool, detail: str = ""):
    RESULTS.setdefault(section, []).append((name, bool(ok), detail))
    print(f"  {'PASS' if ok else 'FAIL'} [{section}] {name}" + ("" if ok else f"  <- {detail}"))


def run_tool(binary: str, *args, timeout=60) -> subprocess.CompletedProcess:
    return subprocess.run(
        [*MOJO_RUN, str(TOOLS / f"{binary}.mojo"), *map(str, args)],
        capture_output=True, text=True, timeout=timeout, cwd=ROOT,
    )


def build_tools():
    global MOJO_RUN
    print("== preparing Mojo compliance tools ==")
    BUILD.mkdir(exist_ok=True)
    net_src = dep_path("mojo-net")
    tls_src = dep_path("mojo-tls")
    # `mojo build` on the conda Linux toolchain does not link libdl for
    # OwnedDLHandle users. `mojo run` does, and is also the invocation used
    # by mojo-tls for its Linux compliance probes.
    MOJO_RUN = [
        "mojo", "run", "-I", "src", "-I", str(net_src),
        "-I", str(tls_src), "-I", "test",
    ]


# ---------------------------------------------------------------- hpack ---

def hpack_corpus(rng):
    """Header blocks: RFC examples, realistic gRPC traffic, random values."""
    blocks = [
        [(":method", "GET"), (":scheme", "http"), (":path", "/"), (":authority", "www.example.com")],
        [(":method", "GET"), (":scheme", "http"), (":path", "/"), (":authority", "www.example.com"), ("cache-control", "no-cache")],
        [(":method", "POST"), (":scheme", "https"), (":path", "/pkg.Svc/Method"), ("te", "trailers"),
         ("content-type", "application/grpc+proto"), ("grpc-timeout", "10S"), ("user-agent", "grpc-mojo/0.1.0")],
        [(":status", "200"), ("content-type", "application/grpc+proto")],
        [("grpc-status", "0"), ("grpc-message", ""), ("x-trace-bin", "3q2+7w")],
        [("x-empty", ""), ("x-space", "a b  c")],
    ]
    for _ in range(40):
        block = []
        for _ in range(rng.randint(1, 8)):
            name = rng.choice([":path", "x-a", "x-longer-header-name", "authorization", "accept", "x-id"])
            value = "".join(rng.choice("abcdefghij0123456789-_ .~!*'()%") for _ in range(rng.randint(0, 30)))
            block.append((name, value))
        blocks.append(block)
    return blocks


def section_hpack(tmp: Path):
    print("== hpack vs python-hpack ==")
    import hpack as pyhpack
    rng = random.Random(7541)
    blocks = hpack_corpus(rng)

    # Direction A: python-hpack encodes (one encoder, dynamic table evolves)
    # -> our decoder (one decoder) must recover every block.
    enc = pyhpack.Encoder()
    encoded = [enc.encode(b).hex() for b in blocks]
    infile = tmp / "hp_a_in.txt"; outfile = tmp / "hp_a_out.txt"
    infile.write_text("".join(h + "\n" for h in encoded))
    r = run_tool("hpack_tool", "decode", infile, outfile)
    ok, detail = True, ""
    if r.returncode != 0:
        ok, detail = False, r.stderr[:200]
    else:
        got_blocks, cur = [], []
        for line in outfile.read_text().split("\n"):
            if line == "===":
                got_blocks.append(cur); cur = []
            elif line:
                if line.startswith("ERR"):
                    cur.append(("ERR", line))
                else:
                    name, _, value = line.partition(US)
                    cur.append((name, value))
        for i, (want, got) in enumerate(zip(blocks, got_blocks)):
            if [(-1, w) for w in want] != [(-1, g) for g in got] and list(want) != got:
                ok, detail = False, f"block {i}: want {want} got {got}"
                break
    record("hpack", f"python-hpack encode -> mojo decode ({len(blocks)} blocks, shared dynamic table)", ok, detail)

    # Direction B: our encoder -> python-hpack decoder.
    infile = tmp / "hp_b_in.txt"; outfile = tmp / "hp_b_out.txt"
    infile.write_text("".join(
        "".join(f"{n}{US}{v}\n" for n, v in b) + "===\n" for b in blocks
    ))
    r = run_tool("hpack_tool", "encode", infile, outfile)
    ok, detail = True, ""
    if r.returncode != 0:
        ok, detail = False, r.stderr[:200]
    else:
        dec = pyhpack.Decoder()
        hex_blocks = outfile.read_text().splitlines()
        total_mojo = total_py = 0
        for i, (h, want) in enumerate(zip(hex_blocks, blocks)):
            total_mojo += len(h) // 2
            try:
                got = [(n, v) for n, v in dec.decode(bytes.fromhex(h))]
            except Exception as e:
                ok, detail = False, f"block {i}: python-hpack rejected our bytes: {e}"
                break
            if got != [tuple(x) for x in want]:
                ok, detail = False, f"block {i}: want {want} got {got}"
                break
        enc2 = pyhpack.Encoder()
        total_py = sum(len(enc2.encode(b)) for b in blocks)
    record("hpack", f"mojo encode -> python-hpack decode ({len(blocks)} blocks)", ok, detail)
    if ok:
        record("hpack", f"compression ratio sanity (mojo {total_mojo}B vs python {total_py}B, within 25%)",
               total_mojo <= total_py * 1.25, f"{total_mojo} vs {total_py}")

    # Dynamic table size updates mid-stream (RFC 7541 SS6.3): python-hpack
    # shrinks then restores its table; our decoder must track evictions.
    enc3 = pyhpack.Encoder()
    seq = [
        [(":method", "GET"), ("x-a", "one"), ("x-b", "two")],
        [("x-a", "one"), ("x-b", "two")],
    ]
    encoded3 = [enc3.encode(b).hex() for b in seq]
    enc3.header_table_size = 64        # emits a size update, evicts entries
    encoded3.append(enc3.encode([("x-a", "one")]).hex())
    enc3.header_table_size = 4096      # grows back
    encoded3.append(enc3.encode([("x-a", "one"), ("x-c", "three")]).hex())
    seq += [[("x-a", "one")], [("x-a", "one"), ("x-c", "three")]]
    infile = tmp / "hp_c_in.txt"; outfile = tmp / "hp_c_out.txt"
    infile.write_text("".join(h + "\n" for h in encoded3))
    r = run_tool("hpack_tool", "decode", infile, outfile)
    ok, detail = r.returncode == 0, r.stderr[:200]
    if ok:
        got_blocks, cur = [], []
        for line in outfile.read_text().split("\n"):
            if line == "===":
                got_blocks.append(cur); cur = []
            elif line:
                name, _, value = line.partition(US)
                cur.append((name, value))
        for i, (want, got) in enumerate(zip(seq, got_blocks)):
            if [tuple(x) for x in want] != got:
                ok, detail = False, f"block {i}: want {want} got {got}"
                break
    record("hpack", "dynamic table size updates mid-stream (python-hpack -> mojo)",
           ok, detail)

    # Multibyte UTF-8 header values survive both directions.
    utf8_blocks = [
        [("x-emoji", "fire \U0001f525 ok"), ("x-accent", "résumé")],
        [("x-cjk", "你好世界"), ("x-mixed", "aß☃z")],
    ]
    enc4 = pyhpack.Encoder(); dec4 = pyhpack.Decoder()
    infile = tmp / "hp_d_in.txt"; outfile = tmp / "hp_d_out.txt"
    infile.write_text("".join(
        enc4.encode([(k, v.encode()) for k, v in b]).hex() + "\n"
        for b in utf8_blocks))
    r = run_tool("hpack_tool", "decode", infile, outfile)
    ok = r.returncode == 0
    if ok:
        text = outfile.read_text()
        ok = "fire \U0001f525 ok" in text and "你好世界" in text and "résumé" in text
    record("hpack", "multibyte UTF-8 header values roundtrip (python -> mojo)",
           ok, r.stderr[:150] if not ok else "")


# ------------------------------------------------------------------- h2 ---

def section_h2_frames(tmp: Path):
    print("== h2 frame codec vs hyperframe ==")
    import hyperframe.frame as hf

    frames = [
        hf.DataFrame(1, data=b"hello", flags=["END_STREAM"]),
        hf.HeadersFrame(3, data=b"\x82\x86", flags=["END_HEADERS"]),
        hf.PriorityFrame(5, depends_on=1, stream_weight=200, exclusive=True),
        hf.RstStreamFrame(7, error_code=8),
        hf.SettingsFrame(0, settings={hf.SettingsFrame.MAX_FRAME_SIZE: 65536}),
        hf.PushPromiseFrame(9, promised_stream_id=10, data=b"\x82"),
        hf.PingFrame(0, opaque_data=b"12345678"),
        hf.GoAwayFrame(0, last_stream_id=7, error_code=2, additional_data=b"bye"),
        hf.WindowUpdateFrame(0, window_increment=100000),
        hf.WindowUpdateFrame(2**31 - 1, window_increment=1),
        hf.ContinuationFrame(11, data=b"\x84", flags=["END_HEADERS"]),
        hf.DataFrame(13, data=b"", flags=[]),
    ]
    serialized = [f.serialize().hex() for f in frames]
    infile = tmp / "h2f_in.txt"; outfile = tmp / "h2f_out.txt"
    infile.write_text("".join(h + "\n" for h in serialized))
    r = run_tool("h2_frame_tool", "parse", infile, outfile)
    ok, detail = r.returncode == 0, r.stderr[:200]
    if ok:
        for i, line in enumerate(outfile.read_text().splitlines()):
            f = frames[i]
            want_flags = 0
            for flag in f.flags:
                want_flags |= dict(
                    END_STREAM=1, ACK=1, END_HEADERS=4, PADDED=8, PRIORITY=32
                ).get(flag, 0)
            raw = bytes.fromhex(serialized[i])
            parts = line.split(" ")
            got = (int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3]))
            want = (raw[3], raw[4], f.stream_id, len(raw) - 9)
            if got != want:
                ok, detail = False, f"frame {i}: want {want} got {got}"
                break
    record("h2", f"parse hyperframe-built frames (all 10 types, {len(frames)} cases)", ok, detail)

    # Build direction: our serializer -> hyperframe parser.
    build_lines, want_frames = [], []
    for f, h in zip(frames, serialized):
        raw = bytes.fromhex(h)
        build_lines.append(f"{raw[3]} {raw[4]} {f.stream_id} {raw[9:].hex()}")
        want_frames.append(h)
    infile = tmp / "h2b_in.txt"; outfile = tmp / "h2b_out.txt"
    infile.write_text("".join(l + "\n" for l in build_lines))
    r = run_tool("h2_frame_tool", "build", infile, outfile)
    ok, detail = r.returncode == 0, r.stderr[:200]
    if ok:
        got = outfile.read_text().splitlines()
        for i, (g, w) in enumerate(zip(got, want_frames)):
            if g != w:
                ok, detail = False, f"frame {i}: want {w} got {g}"
                break
            hf.Frame.parse_frame_header(memoryview(bytes.fromhex(g)[:9]))
    record("h2", f"byte-identical frame serialization vs hyperframe ({len(frames)} cases)", ok, detail)


def h2_reference_echo_server(
    sock: socket.socket, result: dict, tls_context: ssl.SSLContext | None = None
):
    """Reference hyper-h2 echo server for one connection; strict validation."""
    import h2.connection, h2.config, h2.events
    try:
        conn_sock, _ = sock.accept()
        conn_sock.settimeout(30)
        if tls_context is not None:
            conn_sock = tls_context.wrap_socket(conn_sock, server_side=True)
            result["alpn"] = conn_sock.selected_alpn_protocol()
        config = h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
        conn = h2.connection.H2Connection(config=config)
        conn.initiate_connection()
        conn_sock.sendall(conn.data_to_send())
        bodies: dict[int, bytearray] = {}
        pending: list[int] = []
        while True:
            data = conn_sock.recv(65535)
            if not data:
                break
            for event in conn.receive_data(data):  # raises on protocol violations
                if isinstance(event, h2.events.RequestReceived):
                    bodies[event.stream_id] = bytearray()
                elif isinstance(event, h2.events.DataReceived):
                    bodies[event.stream_id] += event.data
                    conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                elif isinstance(event, h2.events.StreamEnded):
                    pending.append(event.stream_id)
                elif isinstance(event, h2.events.WindowUpdated):
                    pass
            # Serve any completed streams (windowed send).
            still = []
            for sid in pending:
                body = bytes(bodies.get(sid, b""))
                if "started" not in result.setdefault(f"s{sid}", {}):
                    # Bulky response headers force HEADERS+CONTINUATION on
                    # the wire; our client must reassemble the block.
                    resp_headers = [(":status", "200"), ("x-len", str(len(body)))]
                    for i in range(8):
                        resp_headers.append((f"x-bulk-{i}", "v" * 4000))
                    conn.send_headers(sid, resp_headers)
                    result[f"s{sid}"]["started"] = True
                    result[f"s{sid}"]["offset"] = 0
                off = result[f"s{sid}"]["offset"]
                while off < len(body):
                    window = conn.local_flow_control_window(sid)
                    chunk = min(window, conn.max_outbound_frame_size - 64,
                                len(body) - off)
                    if chunk <= 0:
                        break
                    # Padding exercises the client's PADDED handling.
                    conn.send_data(sid, body[off:off + chunk],
                                   pad_length=16 if off == 0 else None)
                    off += chunk
                result[f"s{sid}"]["offset"] = off
                if off >= len(body):
                    conn.send_headers(sid, [("x-check", "ok")], end_stream=True)
                    result["served"] = result.get("served", 0) + 1
                else:
                    still.append(sid)
            pending = still
            conn_sock.sendall(conn.data_to_send())
        conn_sock.close()
    except Exception as e:  # ProtocolError from our client = compliance failure
        result["error"] = repr(e)


def section_h2_live(tmp: Path):
    print("== h2 live vs hyper-h2 ==")
    # Our client against the strict reference server.
    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0)); lsock.listen(1)
    port = lsock.getsockname()[1]
    result: dict = {}
    t = threading.Thread(target=h2_reference_echo_server, args=(lsock, result), daemon=True)
    t.start()
    n = 200_000
    r = run_tool("h2_client_probe", port, n, timeout=60)
    t.join(timeout=30)
    lsock.close()
    out = r.stdout.strip()
    ok = (r.returncode == 0 and "error" not in result
          and f"status=200 len={n} match=True trailer=ok" in out)
    record("h2", f"mojo client vs hyper-h2 server (200KB echo, strict validation)",
           ok, f"out={out!r} err={r.stderr[:150]!r} server={result.get('error','')}")
    m_hdr = re.search(r"hdrbytes=(\d+)", out)
    record("h2", "mojo client reassembles HEADERS+CONTINUATION (32KB header block) and padded DATA",
           bool(m_hdr) and int(m_hdr.group(1)) > 32000,
           out[-120:])

    # Reference client against our server.
    import h2.connection, h2.config, h2.events
    proc = subprocess.Popen(
        [*MOJO_RUN, str(TOOLS / "h2_server_probe.mojo")],
        stdout=subprocess.PIPE, text=True, cwd=ROOT,
    )
    try:
        port = int(proc.stdout.readline().strip().split(" ")[-1].replace("PORT", "").strip() or
                   re.search(r"\d+", "0").group())
    except Exception:
        port = 0
    ok, detail = False, ""
    try:
        csock = socket.create_connection(("127.0.0.1", port), timeout=10)
        csock.settimeout(30)
        config = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
        conn = h2.connection.H2Connection(config=config)
        conn.initiate_connection()
        csock.sendall(conn.data_to_send())
        sid = conn.get_next_available_stream_id()
        conn.send_headers(sid, [(":method", "POST"), (":scheme", "http"),
                                (":path", "/echo"), (":authority", "t")])
        payload = bytes(i % 251 for i in range(50_000))
        sent = 0
        received = bytearray()
        status = trailer = None
        ended = False
        while not ended:
            while sent < len(payload):
                window = conn.local_flow_control_window(sid)
                chunk = min(window, conn.max_outbound_frame_size, len(payload) - sent)
                if chunk <= 0:
                    break
                conn.send_data(sid, payload[sent:sent + chunk])
                sent += chunk
            if sent >= len(payload) and not getattr(conn, "_probe_es", False):
                conn.end_stream(sid)
                conn._probe_es = True
            csock.sendall(conn.data_to_send())
            data = csock.recv(65535)
            if not data:
                break
            for event in conn.receive_data(data):  # strict validation of OUR server
                if isinstance(event, h2.events.ResponseReceived):
                    status = dict(event.headers).get(":status")
                elif isinstance(event, h2.events.DataReceived):
                    received += event.data
                    conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                elif isinstance(event, h2.events.TrailersReceived):
                    trailer = dict(event.headers).get("x-check")
                elif isinstance(event, h2.events.StreamEnded):
                    ended = True
            csock.sendall(conn.data_to_send())
        ok = status == "200" and bytes(received) == payload and trailer == "ok"
        detail = f"status={status} len={len(received)} trailer={trailer}"
        csock.close()
    except Exception as e:
        detail = f"reference client rejected our server: {e!r}"
    finally:
        proc.kill(); proc.wait()
    record("h2", "hyper-h2 client vs mojo server (50KB echo, strict validation)", ok, detail)


def python_h2_server_context(*, advertise_h2: bool = True) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERTS / "server.pem", CERTS / "server.key")
    if advertise_h2:
        context.set_alpn_protocols(["h2"])
    return context


def section_h2_tls(tmp: Path):
    print("== h2 over TLS vs CPython ssl + hyper-h2 ==")

    # Our TLS client and HTTP/2 state machine against the two reference
    # layers in the same connection.
    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    port = lsock.getsockname()[1]
    result: dict = {}
    thread = threading.Thread(
        target=h2_reference_echo_server,
        args=(lsock, result, python_h2_server_context()),
        daemon=True,
    )
    thread.start()
    n = 80_000
    r = run_tool(
        "h2_client_probe", port, n, CERTS / "ca.pem", "localhost", timeout=60
    )
    thread.join(timeout=30)
    lsock.close()
    output = r.stdout.strip()
    ok = (
        r.returncode == 0
        and "error" not in result
        and result.get("alpn") == "h2"
        and f"status=200 len={n} match=True trailer=ok" in output
    )
    record(
        "h2_tls",
        "mojo client vs CPython ssl + hyper-h2 server (80KB echo, ALPN h2)",
        ok,
        f"out={output!r} err={r.stderr[:150]!r} server={result.get('error', '')}",
    )

    # The strict reference client runs HTTP/2 over a verified TLS channel
    # to our server.
    proc = subprocess.Popen(
        [
            *MOJO_RUN,
            str(TOOLS / "h2_server_probe.mojo"),
            str(CERTS / "server.pem"),
            str(CERTS / "server.key"),
        ],
        stdout=subprocess.PIPE,
        text=True,
        cwd=ROOT,
    )
    port = int(proc.stdout.readline().strip().removeprefix("PORT "))
    ok, detail = False, ""
    try:
        context = ssl.create_default_context(cafile=str(CERTS / "ca.pem"))
        context.set_alpn_protocols(["h2"])
        raw = socket.create_connection(("127.0.0.1", port), timeout=10)
        tls_sock = context.wrap_socket(raw, server_hostname="localhost")
        tls_sock.settimeout(30)

        import h2.connection
        import h2.config
        import h2.events

        config = h2.config.H2Configuration(
            client_side=True, header_encoding="utf-8"
        )
        conn = h2.connection.H2Connection(config=config)
        conn.initiate_connection()
        tls_sock.sendall(conn.data_to_send())
        sid = conn.get_next_available_stream_id()
        conn.send_headers(
            sid,
            [
                (":method", "POST"),
                (":scheme", "https"),
                (":path", "/echo"),
                (":authority", "localhost"),
            ],
        )
        payload = bytes(i % 251 for i in range(32_000))
        conn.send_data(sid, payload[:16_000], end_stream=False)
        conn.send_data(sid, payload[16_000:], end_stream=True)
        tls_sock.sendall(conn.data_to_send())
        received = bytearray()
        status = trailer = None
        ended = False
        while not ended:
            data = tls_sock.recv(65535)
            if not data:
                break
            for event in conn.receive_data(data):
                if isinstance(event, h2.events.ResponseReceived):
                    status = dict(event.headers).get(":status")
                elif isinstance(event, h2.events.DataReceived):
                    received += event.data
                    conn.acknowledge_received_data(
                        event.flow_controlled_length, event.stream_id
                    )
                elif isinstance(event, h2.events.TrailersReceived):
                    trailer = dict(event.headers).get("x-check")
                elif isinstance(event, h2.events.StreamEnded):
                    ended = True
            tls_sock.sendall(conn.data_to_send())
        ok = (
            tls_sock.selected_alpn_protocol() == "h2"
            and status == "200"
            and bytes(received) == payload
            and trailer == "ok"
        )
        detail = (
            f"alpn={tls_sock.selected_alpn_protocol()} status={status} "
            f"len={len(received)} trailer={trailer}"
        )
        tls_sock.close()
    except Exception as error:
        detail = f"reference client rejected our server: {error!r}"
    finally:
        proc.kill()
        proc.wait()
    record(
        "h2_tls",
        "CPython ssl + hyper-h2 client vs mojo server (verified TLS, ALPN h2)",
        ok,
        detail,
    )

    # A TLS peer that completes the handshake without selecting h2 must
    # not be allowed to start the HTTP/2 connection preface.
    lsock = socket.socket()
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(1)
    port = lsock.getsockname()[1]
    result = {}
    thread = threading.Thread(
        target=h2_reference_echo_server,
        args=(lsock, result, python_h2_server_context(advertise_h2=False)),
        daemon=True,
    )
    thread.start()
    r = run_tool(
        "h2_client_probe", port, 16, CERTS / "ca.pem", "localhost", timeout=30
    )
    thread.join(timeout=10)
    lsock.close()
    client_rejected = (
        r.returncode != 0
        and "required h2 ALPN token" in (r.stderr + r.stdout)
        and result.get("alpn") is None
    )

    proc = subprocess.Popen(
        [
            *MOJO_RUN,
            str(TOOLS / "h2_server_probe.mojo"),
            str(CERTS / "server.pem"),
            str(CERTS / "server.key"),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        cwd=ROOT,
    )
    port = int(proc.stdout.readline().strip().removeprefix("PORT "))
    server_rejected = False
    try:
        context = ssl.create_default_context(cafile=str(CERTS / "ca.pem"))
        context.set_alpn_protocols(["http/1.1"])
        raw = socket.create_connection(("127.0.0.1", port), timeout=10)
        context.wrap_socket(raw, server_hostname="localhost")
    except ssl.SSLError:
        server_rejected = True
    except Exception:
        pass
    finally:
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    record(
        "h2_tls",
        "both HTTP/2 roles reject TLS connections without negotiated h2 ALPN",
        client_rejected and server_rejected,
        f"client={client_rejected} server={server_rejected} err={r.stderr[:150]!r}",
    )


def section_h2spec(tmp: Path):
    print("== h2spec (RFC 9113/7541 conformance tool) ==")
    h2spec_bin = shutil.which("h2spec")
    if not h2spec_bin:
        record("h2", "h2spec conformance (tool not installed; brew install h2spec)",
               False, "h2spec binary not found on PATH")
        return
    for use_tls in (False, True):
        server_args = [*MOJO_RUN, str(TOOLS / "h2spec_server.mojo")]
        h2spec_args = [h2spec_bin, "-h", "127.0.0.1"]
        if use_tls:
            server_args += [
                str(CERTS / "server.pem"), str(CERTS / "server.key")
            ]
            h2spec_args += ["--tls", "--insecure"]
        proc = subprocess.Popen(
            server_args,
            stdout=subprocess.PIPE,
            text=True,
            cwd=ROOT,
            start_new_session=True,
        )
        port = proc.stdout.readline().strip().removeprefix("PORT ")
        try:
            r = subprocess.run(
                [*h2spec_args, "-p", port],
                capture_output=True,
                text=True,
                timeout=600,
            )
            msum = re.search(
                r"(\d+) tests, (\d+) passed, (\d+) skipped, (\d+) failed",
                r.stdout,
            )
            ok = bool(msum) and msum.group(4) == "0"
            section = "h2_tls" if use_tls else "h2"
            mode = "TLS" if use_tls else "cleartext"
            record(
                section,
                f"h2spec {mode} full run ({msum.group(0) if msum else 'no summary'})",
                ok,
                r.stdout[-300:] if not ok else "",
            )
        finally:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            proc.wait()


# --------------------------------------------------------------- report ---

def versions() -> dict[str, str]:
    import hpack, h2, hyperframe
    mojo = subprocess.run(["mojo", "--version"], capture_output=True, text=True, cwd=ROOT).stdout.strip()
    return {
        "mojo": mojo,
        "python": platform.python_version(),
        "hpack (reference for hpack)": hpack.__version__,
        "h2/hyper-h2 (reference for h2)": h2.__version__,
        "hyperframe (reference for h2 frames)": hyperframe.__version__,
        "ssl (reference for TLS)": ssl.OPENSSL_VERSION,
        "platform": f"{platform.system()} {platform.release()} {platform.machine()}",
    }


SECTION_TITLES = {
    "hpack": "`hpack` vs python-hpack",
    "h2": "`h2` vs hyper-h2 / hyperframe / h2spec",
    "h2_tls": "`h2` over TLS vs CPython ssl / hyper-h2 / h2spec",
}


def write_report() -> bool:
    total = sum(len(v) for v in RESULTS.values())
    passed = sum(1 for v in RESULTS.values() for _, ok, _ in v if ok)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# mojo-http2 Compliance Report",
        "",
        "<!-- GENERATED by compliance/run_compliance.py; do not edit. -->",
        "<!-- Regenerate with: pixi run compliance -->",
        "",
        f"**Result: {passed}/{total} checks passed.** Generated {now}.",
        "",
        "Every check compares mojo-http2 against an established reference:",
        "python-hpack, hyper-h2/hyperframe (strict: any protocol violation",
        "raises), CPython ssl, and h2spec. It never grades itself.",
        "",
        "## Environment",
        "",
        "| Component | Version |",
        "|---|---|",
    ]
    for k, v in versions().items():
        lines.append(f"| {k} | {v} |")
    for section, rows in RESULTS.items():
        p = sum(1 for _, ok, _ in rows if ok)
        title = SECTION_TITLES.get(section, f"`{section}`")
        lines += ["", f"## {title}: {p}/{len(rows)}", "",
                  "| Check | Result |", "|---|---|"]
        for name, ok, detail in rows:
            status = "✅ pass" if ok else f"❌ **fail**: {detail[:160]}"
            lines.append(f"| {name} | {status} |")
    lines += [
        "",
        "## How to rerun",
        "",
        "```sh",
        "pixi run compliance   # from this package root",
        "```",
        "",
        "h2spec must be on PATH (`brew install h2spec`); mojo-net and mojo-tls",
        "sources are located via MOJO_DEPS_DIR, .deps/, or sibling checkouts.",
        "",
    ]
    REPORT.write_text("\n".join(lines))
    print(f"\ncompliance: {passed}/{total} checks passed")
    print(f"report: {REPORT}")
    return passed == total


HTML_REPORT = ROOT / "COMPLIANCE.html"

HTML_HEAD = """<!-- GENERATED by compliance/run_compliance.py - regenerate with: pixi run compliance -->
<title>mojo-http2 Compliance</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans+Condensed:wght@600&display=swap">
<style>
:root {
  --paper: #FAFAF8; --ink: #22262B; --muted: #6E6A62; --accent: #C2551F;
  --pass: #2E7D4F; --fail: #B3362B; --line: #E4E0D8; --panel: #F2F0EA;
  --mono: "IBM Plex Mono", ui-monospace, "SF Mono", Menlo, monospace;
  --sans: "IBM Plex Sans", -apple-system, "Segoe UI", sans-serif;
  --cond: "IBM Plex Sans Condensed", "Arial Narrow", var(--sans);
}
@media (prefers-color-scheme: dark) {
  :root:not([data-theme="light"]) {
    --paper: #16181C; --ink: #E8E6E1; --muted: #98938A; --accent: #E0663A;
    --pass: #5EC08D; --fail: #E5776C; --line: #2C2F35; --panel: #1D2025;
  }
}
:root[data-theme="dark"] {
  --paper: #16181C; --ink: #E8E6E1; --muted: #98938A; --accent: #E0663A;
  --pass: #5EC08D; --fail: #E5776C; --line: #2C2F35; --panel: #1D2025;
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--paper); color: var(--ink); font: 16px/1.6 var(--sans); -webkit-font-smoothing: antialiased; }
main { max-width: 76ch; margin: 0 auto; padding: 3.5rem 1.5rem 5rem; }
header { border-bottom: 2px solid var(--ink); padding-bottom: 1.75rem; margin-bottom: 2.5rem; }
.eyebrow { font: 500 0.72rem/1 var(--mono); letter-spacing: 0.14em; text-transform: uppercase; color: var(--accent); margin: 0 0 0.9rem; }
h1 { font: 600 clamp(1.9rem, 5vw, 2.6rem)/1.1 var(--cond); margin: 0 0 1.1rem; text-wrap: balance; letter-spacing: -0.01em; }
.verdict { display: flex; align-items: baseline; gap: 0.75rem; flex-wrap: wrap; }
.verdict .score { font: 500 2rem/1 var(--mono); font-variant-numeric: tabular-nums; color: var(--pass); }
.verdict .score.failing { color: var(--fail); }
.verdict .when { color: var(--muted); font-size: 0.85rem; }
.thesis { color: var(--muted); margin: 0.9rem 0 0; max-width: 62ch; }
.scorecard { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 1.5rem; padding: 0; list-style: none; }
.scorecard li { font: 400 0.78rem/1 var(--mono); padding: 0.45rem 0.7rem; border: 1px solid var(--line); border-radius: 3px; background: var(--panel); display: flex; gap: 0.55rem; align-items: center; }
.scorecard .n { font-variant-numeric: tabular-nums; color: var(--pass); font-weight: 500; }
.scorecard .n.failing { color: var(--fail); }
section { margin: 2.75rem 0; }
h2 { font: 600 1.15rem/1.3 var(--sans); margin: 0 0 0.35rem; text-wrap: balance; }
h2 .pkg { font-family: var(--mono); font-weight: 500; color: var(--accent); }
.vs { color: var(--muted); font-weight: 400; }
.method { color: var(--muted); font-size: 0.88rem; margin: 0 0 1.1rem; max-width: 68ch; }
.tablewrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 0.88rem; }
th { text-align: left; font: 500 0.7rem/1 var(--mono); letter-spacing: 0.1em; text-transform: uppercase; color: var(--muted); padding: 0 0.75rem 0.5rem 0; border-bottom: 1px solid var(--ink); }
td { padding: 0.5rem 0.75rem 0.5rem 0; border-bottom: 1px solid var(--line); vertical-align: top; }
td.result { white-space: nowrap; font: 500 0.78rem/1.8 var(--mono); }
.pass { color: var(--pass); }
.fail { color: var(--fail); }
td .detail { display: block; color: var(--muted); font-size: 0.8rem; }
.envtable td:first-child { color: var(--muted); width: 40%; }
.envtable td { font-family: var(--mono); font-size: 0.8rem; }
.gaps { border-left: 3px solid var(--accent); background: var(--panel); padding: 1.1rem 1.4rem; }
.gaps h2 { margin-top: 0; }
.gaps ul { margin: 0.5rem 0 0; padding-left: 1.1rem; }
.gaps li { margin: 0.45rem 0; font-size: 0.9rem; }
.gaps strong { font-weight: 600; }
footer { margin-top: 3rem; color: var(--muted); font: 400 0.78rem/1.6 var(--mono); border-top: 1px solid var(--line); padding-top: 1rem; }
code { font-family: var(--mono); font-size: 0.92em; }
</style>
"""


def esc(t: str) -> str:
    return t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


HTML_EYEBROW = "mojo-http2 &middot; differential compliance run"
HTML_H1 = "HPACK and HTTP/2 checked against the tools that reject violations"
HTML_THESIS = ("No self-grading: header compression is judged by python-hpack in both directions, frames byte-for-byte by hyperframe, live connections by strict hyper-h2 peers, TLS by CPython ssl, and the full RFC 9113/7541 surface by h2spec in cleartext and TLS modes.")
HTML_GAPS = [
    ("Priority scheduling", "PRIORITY frames are validated and ignored (per RFC 9113 deprecation)."),
    ("hpack value encoding", "header values are UTF-8 Strings; arbitrary octets are out of scope for now (gRPC uses base64 -bin metadata)."),
]
HTML_SECTIONS = {
    "hpack": ("`hpack` vs python-hpack",
              "Sequential header blocks encoded by one implementation and decoded by the other, in both directions, with dynamic-table state carried across blocks, mid-stream size updates, and multibyte UTF-8 values."),
    "h2": ("`h2` vs hyper-h2 / hyperframe / h2spec",
           "Frame codec cross-checked byte-for-byte against hyperframe in both directions. Live connections run against hyper-h2, which raises ProtocolError on any protocol violation by the peer. h2spec runs its full RFC 9113/7541 suite against our server."),
    "h2_tls": ("`h2` over TLS vs CPython ssl / hyper-h2 / h2spec",
               "Both HTTP/2 roles run through verified CPython TLS peers and strict hyper-h2 state machines. ALPN omission and mismatch are rejected. h2spec repeats its complete run over TLS."),
}


def write_html_report():
    total = sum(len(v) for v in RESULTS.values())
    passed = sum(1 for v in RESULTS.values() for _, ok, _ in v if ok)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    all_ok = passed == total
    h = [HTML_HEAD, "<main>", "<header>"]
    h.append(f'<p class="eyebrow">{HTML_EYEBROW}</p>')
    h.append(f"<h1>{HTML_H1}</h1>")
    h.append(
        f'<div class="verdict"><span class="score{"" if all_ok else " failing"}">'
        f"{passed}/{total}</span><span>checks passed</span>"
        f'<span class="when">{now}</span></div>'
    )
    h.append(f'<p class="thesis">{HTML_THESIS}</p>')
    h.append('<ul class="scorecard">')
    for section, rows in RESULTS.items():
        p = sum(1 for _, ok, _ in rows if ok)
        cls = "" if p == len(rows) else " failing"
        h.append(f'<li>{esc(section)} <span class="n{cls}">{p}/{len(rows)}</span></li>')
    h.append("</ul></header>")

    for section, rows in RESULTS.items():
        title, blurb = HTML_SECTIONS.get(section, (section, ""))
        pkg, _, ref = title.replace("`", "").partition(" vs ")
        h.append("<section>")
        if ref:
            h.append(f'<h2><span class="pkg">{esc(pkg)}</span> <span class="vs">vs</span> {esc(ref)}</h2>')
        else:
            h.append(f"<h2>{esc(pkg)}</h2>")
        if blurb:
            h.append(f'<p class="method">{esc(blurb)}</p>')
        h.append('<div class="tablewrap"><table>')
        h.append("<tr><th>Check</th><th>Result</th></tr>")
        for name, ok, detail in rows:
            cell = '<span class="pass">PASS</span>' if ok else '<span class="fail">FAIL</span>'
            extra = "" if ok else f'<span class="detail">{esc(detail[:200])}</span>'
            h.append(f"<tr><td>{esc(name)}</td><td class=\"result\">{cell}{extra}</td></tr>")
        h.append("</table></div></section>")

    h.append("<section><h2>Environment</h2>")
    h.append('<div class="tablewrap"><table class="envtable">')
    for k, v in versions().items():
        h.append(f"<tr><td>{esc(k)}</td><td>{esc(v)}</td></tr>")
    h.append("</table></div></section>")

    h.append('<section class="gaps"><h2>Known gaps (tracked, not silent)</h2><ul>')
    for k, v in HTML_GAPS:
        h.append(f"<li><strong>{esc(k)}</strong>: {esc(v)}</li>")
    h.append("</ul></section>")
    h.append(
        "<footer>Generated by compliance/run_compliance.py &middot; "
        "rerun with <code>pixi run compliance</code> &middot; canonical copy: "
        "COMPLIANCE.md</footer>"
    )
    h.append("</main>")
    HTML_REPORT.write_text("\n".join(h))
    print(f"report: {HTML_REPORT.relative_to(ROOT)}")



def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", type=Path, default=None,
                    help="dump {'sections': ...} JSON for the umbrella suite")
    args = ap.parse_args()
    build_tools()
    with tempfile.TemporaryDirectory(prefix="mojo_http2_compliance_") as tmp_s:
        tmp = Path(tmp_s)
        section_hpack(tmp)
        section_h2_frames(tmp)
        section_h2_live(tmp)
        section_h2_tls(tmp)
        section_h2spec(tmp)
    ok = write_report()
    write_html_report()
    if args.json:
        args.json.write_text(json.dumps(
            {"sections": {s: [[n, o, d] for n, o, d in rows]
                          for s, rows in RESULTS.items()}}))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
