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
import socket
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

RESULTS: dict[str, list[tuple[str, bool, str]]] = {}
US = "\x1f"


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
        + " — set MOJO_DEPS_DIR or place the package under .deps/"
    )


def record(section: str, name: str, ok: bool, detail: str = ""):
    RESULTS.setdefault(section, []).append((name, bool(ok), detail))
    print(f"  {'PASS' if ok else 'FAIL'} [{section}] {name}" + ("" if ok else f"  <- {detail}"))


def run_tool(binary: str, *args, timeout=60) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(BUILD / binary), *map(str, args)],
        capture_output=True, text=True, timeout=timeout, cwd=ROOT,
    )


def build_tools():
    print("== building Mojo compliance tools ==")
    BUILD.mkdir(exist_ok=True)
    net_src = dep_path("mojo-net")
    for src in sorted(TOOLS.glob("*.mojo")):
        out = BUILD / src.stem
        subprocess.run(
            ["mojo", "build", "-I", "src", "-I", str(net_src), "-I", "test",
             str(src.relative_to(ROOT)), "-o", str(out)],
            check=True, cwd=ROOT,
        )
        print(f"  built {src.stem}")


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


def h2_reference_echo_server(sock: socket.socket, result: dict):
    """Reference hyper-h2 echo server for one connection; strict validation."""
    import h2.connection, h2.config, h2.events
    try:
        conn_sock, _ = sock.accept()
        conn_sock.settimeout(30)
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
    proc = subprocess.Popen([str(BUILD / "h2_server_probe")], stdout=subprocess.PIPE, text=True, cwd=ROOT)
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


def section_h2spec(tmp: Path):
    print("== h2spec (RFC 9113/7541 conformance tool) ==")
    h2spec_bin = shutil.which("h2spec")
    if not h2spec_bin:
        record("h2", "h2spec conformance (tool not installed; brew install h2spec)",
               False, "h2spec binary not found on PATH")
        return
    proc = subprocess.Popen([str(BUILD / "h2spec_server")],
                            stdout=subprocess.PIPE, text=True, cwd=ROOT)
    port = proc.stdout.readline().strip().removeprefix("PORT ")
    try:
        r = subprocess.run([h2spec_bin, "-p", port, "-h", "127.0.0.1"],
                           capture_output=True, text=True, timeout=600)
        msum = re.search(r"(\d+) tests, (\d+) passed, (\d+) skipped, (\d+) failed",
                         r.stdout)
        ok = bool(msum) and msum.group(4) == "0"
        record("h2", f"h2spec full run ({msum.group(0) if msum else 'no summary'})",
               ok, r.stdout[-300:] if not ok else "")
    finally:
        proc.kill(); proc.wait()
        subprocess.run(["pkill", "-f", "h2spec_server"], capture_output=True)


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
        "platform": f"{platform.system()} {platform.release()} {platform.machine()}",
    }


SECTION_TITLES = {
    "hpack": "`hpack` vs python-hpack",
    "h2": "`h2` vs hyper-h2 / hyperframe / h2spec",
}


def write_report() -> bool:
    total = sum(len(v) for v in RESULTS.values())
    passed = sum(1 for v in RESULTS.values() for _, ok, _ in v if ok)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# mojo-http2 Compliance Report",
        "",
        "<!-- GENERATED by compliance/run_compliance.py — do not edit. -->",
        "<!-- Regenerate with: pixi run compliance -->",
        "",
        f"**Result: {passed}/{total} checks passed.** Generated {now}.",
        "",
        "Every check compares mojo-http2 against an established reference —",
        "python-hpack, hyper-h2/hyperframe (strict: any protocol violation",
        "raises), and h2spec — never against itself.",
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
        lines += ["", f"## {title} — {p}/{len(rows)}", "",
                  "| Check | Result |", "|---|---|"]
        for name, ok, detail in rows:
            status = "✅ pass" if ok else f"❌ **fail** — {detail[:160]}"
            lines.append(f"| {name} | {status} |")
    lines += [
        "",
        "## How to rerun",
        "",
        "```sh",
        "pixi run compliance   # from this package root",
        "```",
        "",
        "h2spec must be on PATH (`brew install h2spec`); mojo-net sources are",
        "located via MOJO_DEPS_DIR, .deps/mojo-net/src, or ../mojo-net/src.",
        "",
    ]
    REPORT.write_text("\n".join(lines))
    print(f"\ncompliance: {passed}/{total} checks passed")
    print(f"report: {REPORT}")
    return passed == total


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
        section_h2spec(tmp)
    ok = write_report()
    if args.json:
        args.json.write_text(json.dumps(
            {"sections": {s: [[n, o, d] for n, o, d in rows]
                          for s, rows in RESULTS.items()}}))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
