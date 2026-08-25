#!/usr/bin/env python3
"""Check deterministic HTTP/2 connection-state sequences against hyper-h2."""

from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import tempfile
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import cast

import h2.config
import h2.connection
import h2.events
import h2.exceptions


ROOT = Path(__file__).resolve().parent.parent
TOOLS = ROOT / "compliance" / "tools"
DEFAULT_ARTIFACT = ROOT / "build" / "h2-state-mismatch.json"
FrameSignature = tuple[int, int, int, str]


@dataclass(frozen=True)
class StateCase:
    name: str
    open_count: int
    frames: tuple[bytes, ...]
    chunk_sizes: tuple[int, ...]
    changed_settings: tuple[int, ...] = ()
    check_window: bool = False
    check_goaway: bool = False
    # RFC 9113 supplies the code when hyper-h2 agrees on rejection but sends
    # a different error code or escalates a stream error to the connection.
    expected_error_code: int | None = None
    expected_stream_error_code: int | None = None

    def wire(self) -> bytes:
        return b"".join(self.frames)

    def chunks(self) -> tuple[bytes, ...]:
        wire = self.wire()
        chunks = []
        offset = 0
        for size in self.chunk_sizes:
            if offset >= len(wire):
                break
            chunks.append(wire[offset : offset + size])
            offset += size
        if offset < len(wire):
            chunks.append(wire[offset:])
        return tuple(chunks)


def dependency_source(name: str) -> Path:
    candidates = []
    if deps_dir := os.environ.get("MOJO_DEPS_DIR"):
        candidates.append(Path(deps_dir) / name / "src")
    candidates.extend((ROOT / ".deps" / name / "src", ROOT.parent / name / "src"))
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    searched = ", ".join(str(path) for path in candidates)
    raise SystemExit(f"cannot find dependency {name!r}; searched {searched}")


def mojo_command(tool: str) -> list[str]:
    return [
        "mojo",
        "run",
        "-I",
        "src",
        "-I",
        str(dependency_source("mojo-net")),
        "-I",
        str(dependency_source("mojo-tls")),
        "-I",
        "test",
        str(TOOLS / tool),
    ]


def frame(
    frame_type: int,
    flags: int,
    stream_id: int,
    payload: bytes,
    *,
    declared_length: int | None = None,
    reserved_stream_bit: bool = False,
) -> bytes:
    length = len(payload) if declared_length is None else declared_length
    if not 0 <= length <= 0xFFFFFF:
        raise ValueError("frame length is outside the 24-bit wire range")
    if not 0 <= frame_type <= 0xFF or not 0 <= flags <= 0xFF:
        raise ValueError("frame type and flags must fit in one byte")
    if not 0 <= stream_id <= 0x7FFFFFFF:
        raise ValueError("stream identifier is outside the 31-bit wire range")
    wire_stream_id = stream_id | (0x80000000 if reserved_stream_bit else 0)
    return (
        length.to_bytes(3, "big")
        + bytes((frame_type, flags))
        + wire_stream_id.to_bytes(4, "big")
        + payload
    )


def setting(identifier: int, value: int) -> bytes:
    return identifier.to_bytes(2, "big") + value.to_bytes(4, "big")


def chunks_for_frames(frames: tuple[bytes, ...], rng: random.Random) -> tuple[int, ...]:
    wire_length = sum(len(member) for member in frames)
    sizes = []
    remaining = wire_length
    while remaining:
        size = rng.randint(1, min(31, remaining))
        sizes.append(size)
        remaining -= size
    return tuple(sizes)


def make_state_case(index: int, rng: random.Random) -> StateCase:
    category = index % 24
    open_count = 0
    changed_settings: tuple[int, ...] = ()
    check_window = False
    check_goaway = False
    expected_error_code = None
    expected_stream_error_code = None

    if category == 0:
        identifiers = rng.sample((1, 3, 4, 5, 6, 0xA0), rng.randint(1, 4))
        values = {
            1: rng.randrange(0, 1 << 20),
            3: rng.randrange(0, 1025),
            4: rng.randrange(0, 0x80000000),
            5: rng.randrange(16384, 16777216),
            6: rng.randrange(0, 1 << 20),
            0xA0: rng.randrange(0, 1 << 32),
        }
        payload = b"".join(
            setting(identifier, values[identifier]) for identifier in identifiers
        )
        frames = (frame(4, rng.choice((0, 0x80)), 0, payload),)
        changed_settings = tuple(
            identifier for identifier in identifiers if identifier <= 6
        )
    elif category == 1:
        frames = (frame(4, 0, rng.choice((1, 3, 0x7FFFFFFF)), b""),)
        expected_error_code = 1
    elif category == 2:
        frames = (frame(4, 0, 0, rng.randbytes(rng.choice((1, 2, 3, 4, 5)))),)
        expected_error_code = 6
    elif category == 3:
        frames = (frame(4, 1, 0, setting(1, rng.randrange(1 << 16))),)
        expected_error_code = 6
    elif category == 4:
        frames = (frame(4, 0, 0, setting(4, rng.randrange(0x80000000, 1 << 32))),)
        expected_error_code = 3
    elif category == 5:
        value = rng.choice((0, 1, 16383, 16777216, 0xFFFFFFFF))
        frames = (frame(4, 0, 0, setting(5, value)),)
        expected_error_code = 1
    elif category == 6:
        frames = (frame(6, rng.choice((0, 0x80)), 0, rng.randbytes(8)),)
    elif category == 7:
        frames = (frame(6, 1, 0, rng.randbytes(8)),)
    elif category == 8:
        frames = (frame(6, 0, rng.choice((1, 3, 0x7FFFFFFF)), rng.randbytes(8)),)
        expected_error_code = 1
    elif category == 9:
        frames = (frame(6, 0, 0, rng.randbytes(rng.choice((0, 1, 7, 9, 12)))),)
        expected_error_code = 6
    elif category == 10:
        increment = rng.randrange(1, 0x7FFF0000)
        frames = (frame(8, rng.choice((0, 0x80)), 0, increment.to_bytes(4, "big")),)
        check_window = True
    elif category == 11:
        frames = (frame(8, 0, 0, b"\x00\x00\x00\x00"),)
        expected_error_code = 1
    elif category == 12:
        open_count = rng.randint(1, 3)
        stream_id = 2 * rng.randrange(open_count) + 1
        increment = rng.randrange(1, 1 << 20)
        frames = (frame(8, 0, stream_id, increment.to_bytes(4, "big")),)
    elif category == 13:
        open_count = 1
        frames = (frame(8, 0, 1, b"\x00\x00\x00\x00"),)
        expected_stream_error_code = 1
    elif category == 14:
        frames = (
            frame(
                8, 0, rng.choice((1, 3, 9)), rng.randrange(1, 100).to_bytes(4, "big")
            ),
        )
        expected_error_code = 1
    elif category == 15:
        open_count = rng.randint(1, 3)
        stream_id = 2 * rng.randrange(open_count) + 1
        frames = (
            frame(
                3,
                rng.choice((0, 0x80)),
                stream_id,
                rng.randrange(14).to_bytes(4, "big"),
            ),
        )
    elif category == 16:
        frames = (frame(3, 0, 0, rng.randrange(14).to_bytes(4, "big")),)
        expected_error_code = 1
    elif category == 17:
        open_count = 1
        frames = (frame(3, 0, 1, rng.randbytes(rng.choice((0, 1, 3, 5, 8)))),)
        expected_error_code = 6
    elif category == 18:
        frames = (
            frame(3, 0, rng.choice((1, 3, 9)), rng.randrange(14).to_bytes(4, "big")),
        )
        expected_error_code = 1
    elif category == 19:
        last_stream = rng.choice((0, 1, 3, 0x7FFFFFFF))
        code = rng.randrange(14)
        payload = (
            last_stream.to_bytes(4, "big")
            + code.to_bytes(4, "big")
            + rng.randbytes(rng.randrange(0, 9))
        )
        frames = (frame(7, rng.choice((0, 0x80)), 0, payload),)
        check_goaway = True
    elif category == 20:
        frames = (frame(7, 0, rng.choice((1, 3, 0x7FFFFFFF)), b"\x00" * 8),)
        expected_error_code = 1
    elif category == 21:
        frames = (frame(7, 0, 0, rng.randbytes(rng.randrange(0, 8))),)
        expected_error_code = 6
    elif category == 22:
        settings = frame(4, 0, 0, setting(1, rng.randrange(0, 1 << 16)))
        ping = frame(6, 0, 0, rng.randbytes(8))
        update = frame(8, 0, 0, rng.randrange(1, 1 << 18).to_bytes(4, "big"))
        frames = (settings, ping, update)
        changed_settings = (1,)
        check_window = True
    else:
        payload = setting(3, rng.randrange(0, 1025))
        settings = frame(4, 0x80, 0, payload, reserved_stream_bit=True)
        ping = frame(6, 0x80, 0, rng.randbytes(8), reserved_stream_bit=True)
        frames = (settings, ping)
        changed_settings = (3,)

    return StateCase(
        name=f"state-{index}-{category}",
        open_count=open_count,
        frames=frames,
        chunk_sizes=chunks_for_frames(frames, rng),
        changed_settings=changed_settings,
        check_window=check_window,
        check_goaway=check_goaway,
        expected_error_code=expected_error_code,
        expected_stream_error_code=expected_stream_error_code,
    )


def run_process(command: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
    if timeout <= 0:
        raise TimeoutError("randomized suite exhausted its timeout")
    return subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=timeout,
        check=False,
    )


def output_signatures(data: bytes) -> tuple[tuple[int, int, int, str], ...]:
    signatures = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 9:
            raise ValueError("short output frame header")
        length = int.from_bytes(data[offset : offset + 3], "big")
        end = offset + 9 + length
        if end > len(data):
            raise ValueError("short output frame payload")
        frame_type = data[offset + 3]
        flags = data[offset + 4]
        stream_id = int.from_bytes(data[offset + 5 : offset + 9], "big") & 0x7FFFFFFF
        payload = data[offset + 9 : end]
        if frame_type == 7:
            payload = payload[:8]
        signatures.append((frame_type, flags, stream_id, payload.hex()))
        offset = end
    return tuple(signatures)


def reference_state(case: StateCase) -> dict[str, object]:
    connection = h2.connection.H2Connection(
        config=h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
    )
    connection.initiate_connection()
    connection.data_to_send()
    for _ in range(case.open_count):
        stream_id = connection.get_next_available_stream_id()
        connection.send_headers(
            stream_id,
            [
                (":method", "GET"),
                (":scheme", "https"),
                (":path", "/randomized"),
                (":authority", "localhost"),
            ],
            end_stream=True,
        )
    connection.data_to_send()

    status = "OK"
    goaway_last = None
    goaway_code = None
    try:
        for chunk in case.chunks():
            events = connection.receive_data(chunk)
            for event in events:
                if isinstance(event, h2.events.ConnectionTerminated):
                    goaway_last = event.last_stream_id
                    goaway_code = (
                        int(event.error_code) if event.error_code is not None else None
                    )
    except h2.exceptions.H2Error:
        status = "ERROR"

    settings = {}
    names = {
        1: "header_table_size",
        3: "max_concurrent_streams",
        4: "initial_window_size",
        5: "max_frame_size",
        6: "max_header_list_size",
    }
    for identifier in case.changed_settings:
        settings[identifier] = getattr(connection.remote_settings, names[identifier])
    return {
        "status": status,
        "output": output_signatures(connection.data_to_send()),
        "settings": settings,
        "send_window": connection.outbound_flow_control_window,
        "goaway_last": goaway_last,
        "goaway_code": goaway_code,
    }


def parse_state_output(text: str) -> dict[str, dict[str, object]]:
    parsed = {}
    current = None
    for line in text.splitlines():
        if line.startswith("CASE "):
            if current is not None:
                raise ValueError("nested state case output")
            current = {"name": line[5:], "output_seen": False, "state_seen": False}
        elif line.startswith("OUT ") and current is not None:
            if current["output_seen"]:
                raise ValueError("duplicate state output bytes")
            current["output"] = output_signatures(bytes.fromhex(line[4:]))
            current["output_seen"] = True
        elif line.startswith("STATE ") and current is not None:
            if current["state_seen"]:
                raise ValueError("duplicate state values")
            fields = line.split()
            if len(fields) != 9:
                raise ValueError("malformed state values")
            current["settings"] = {
                1: int(fields[1]),
                3: int(fields[2]),
                4: int(fields[3]),
                5: int(fields[4]),
                6: int(fields[5]),
            }
            current["send_window"] = int(fields[6])
            current["goaway_last"] = int(fields[7])
            current["goaway_code"] = None if fields[8] == "none" else int(fields[8])
            current["state_seen"] = True
        elif line.startswith("ERROR ") and current is not None:
            current["error"] = line[6:]
        elif line.startswith("END ") and current is not None:
            if not current["output_seen"] or not current["state_seen"]:
                raise ValueError("incomplete state output")
            current["status"] = line[4:]
            name = str(current.pop("name"))
            current.pop("output_seen")
            current.pop("state_seen")
            if name in parsed:
                raise ValueError(f"duplicate state case {name}")
            parsed[name] = current
            current = None
        else:
            raise ValueError(f"unexpected state output line {line!r}")
    if current is not None:
        raise ValueError("unterminated state output")
    return parsed


def run_state_cases(
    cases: list[StateCase], timeout: float
) -> dict[str, dict[str, object]]:
    with tempfile.TemporaryDirectory(prefix="h2-randomized-state-") as temp:
        infile = Path(temp) / "input.txt"
        outfile = Path(temp) / "output.txt"
        lines = []
        for case in cases:
            lines.append(f"CASE {case.name}")
            lines.append(f"OPEN {case.open_count}")
            lines.extend(f"CHUNK {chunk.hex()}" for chunk in case.chunks())
            lines.append("END")
        infile.write_text("\n".join(lines) + "\n")
        result = run_process(
            [*mojo_command("h2_randomized_tool.mojo"), str(infile), str(outfile)],
            timeout,
        )
        if result.returncode != 0:
            raise RuntimeError(f"stateful Mojo probe failed: {result.stderr[:500]}")
        return parse_state_output(outfile.read_text())


def state_mismatch(case: StateCase, actual: dict[str, object]) -> str | None:
    expected = reference_state(case)
    if case.expected_stream_error_code is not None:
        if expected["status"] != "ERROR":
            return f"hyper-h2 accepted an RFC 9113 stream error: {expected}"
        if actual.get("status") != "OK":
            return f"Mojo escalated an RFC 9113 stream error: {actual.get('status')}"
        mojo_output = cast(tuple[FrameSignature, ...], actual.get("output", ()))
        if not mojo_output or mojo_output[-1][0] != 3:
            return f"Mojo did not send RST_STREAM for a stream error: {mojo_output}"
        payload = bytes.fromhex(mojo_output[-1][3])
        code = int.from_bytes(payload, "big") if len(payload) == 4 else None
        if code != case.expected_stream_error_code:
            return (
                f"RFC 9113 stream error code: expected={case.expected_stream_error_code} "
                f"mojo={code}"
            )
        return None
    if actual.get("status") != expected["status"]:
        return f"status: hyper-h2={expected['status']} mojo={actual.get('status')}"
    if expected["status"] == "ERROR":
        reference_output = cast(tuple[FrameSignature, ...], expected["output"])
        mojo_output = cast(tuple[FrameSignature, ...], actual.get("output", ()))
        if not reference_output or reference_output[-1][0] != 7:
            return f"hyper-h2 did not send GOAWAY after its protocol error: {reference_output}"
        if not mojo_output or mojo_output[-1][0] != 7:
            return f"Mojo did not send GOAWAY after its protocol error: {mojo_output}"
        if case.expected_error_code is not None:
            payload = bytes.fromhex(mojo_output[-1][3])
            code = int.from_bytes(payload[4:8], "big") if len(payload) >= 8 else None
            if code != case.expected_error_code:
                return (
                    f"RFC 9113 error code: expected={case.expected_error_code} "
                    f"mojo={code}"
                )
        return None
    if actual.get("output") != expected["output"]:
        return f"output: hyper-h2={expected['output']} mojo={actual.get('output')}"
    expected_settings = cast(dict[int, int], expected["settings"])
    actual_settings = cast(dict[int, int], actual.get("settings", {}))
    for identifier, value in expected_settings.items():
        if actual_settings.get(identifier) != value:
            return (
                f"setting {identifier}: hyper-h2={value} "
                f"mojo={actual_settings.get(identifier)}"
            )
    if case.check_window and actual.get("send_window") != expected["send_window"]:
        return (
            f"send window: hyper-h2={expected['send_window']} "
            f"mojo={actual.get('send_window')}"
        )
    if case.check_goaway:
        if actual.get("goaway_last") != expected["goaway_last"]:
            return (
                f"GOAWAY last stream: hyper-h2={expected['goaway_last']} "
                f"mojo={actual.get('goaway_last')}"
            )
        if actual.get("goaway_code") != expected["goaway_code"]:
            return (
                f"GOAWAY code: hyper-h2={expected['goaway_code']} "
                f"mojo={actual.get('goaway_code')}"
            )
    return None


def minimize_items(items, mismatch, deadline: float):
    """Greedily removes members while the supplied mismatch remains."""
    result = list(items)
    index = 0
    while len(result) > 1 and index < len(result) and time.monotonic() < deadline:
        candidate = result[:index] + result[index + 1 :]
        if mismatch(candidate):
            result = candidate
        else:
            index += 1
    return result


def mismatch_class(reason: str) -> str:
    return reason.partition(":")[0]


def minimize_state_case(
    case: StateCase, target_class: str, deadline: float
) -> StateCase:
    def still_fails(frames: list[bytes]) -> bool:
        if time.monotonic() >= deadline:
            return False
        candidate = replace(
            case,
            frames=tuple(frames),
            chunk_sizes=(sum(len(member) for member in frames),),
        )
        try:
            actual = run_state_cases([candidate], max(1.0, deadline - time.monotonic()))
            reason = state_mismatch(candidate, actual[candidate.name])
            return reason is not None and mismatch_class(reason) == target_class
        except (RuntimeError, subprocess.TimeoutExpired, TimeoutError):
            return False

    frames = minimize_items(case.frames, still_fails, deadline)
    return replace(
        case,
        frames=tuple(frames),
        chunk_sizes=(sum(len(member) for member in frames),),
    )


def write_failure_artifact(
    path: Path,
    *,
    seed: int,
    case_count: int,
    kind: str,
    index: int,
    name: str,
    chunks: tuple[bytes, ...],
    reason: str,
    open_count: int = 0,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    document = {
        "schema": 1,
        "seed": seed,
        "case_count": case_count,
        "kind": kind,
        "case_index": index,
        "case_name": name,
        "open_streams": open_count,
        "chunks_hex": [chunk.hex() for chunk in chunks],
        "reason": reason,
        "failure_class": mismatch_class(reason),
        "replay": (
            f"pixi run h2-state-compatibility --seed {seed} "
            f"--case-count {case_count} "
            f"--failure-artifact {path}"
        ),
    }
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=9113)
    parser.add_argument("--case-count", type=int, default=250)
    parser.add_argument("--failure-artifact", type=Path, default=DEFAULT_ARTIFACT)
    parser.add_argument("--timeout-seconds", type=int, default=300)
    parser.add_argument("--minimize-seconds", type=int, default=10)
    args = parser.parse_args(argv)
    if not 0 <= args.seed <= 0xFFFFFFFFFFFFFFFF:
        parser.error("--seed must be between 0 and 18446744073709551615")
    if not 1 <= args.case_count <= 100000:
        parser.error("--case-count must be between 1 and 100000")
    if not 30 <= args.timeout_seconds <= 1500:
        parser.error("--timeout-seconds must be between 30 and 1500")
    if not 0 <= args.minimize_seconds <= 60:
        parser.error("--minimize-seconds must be between 0 and 60")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    artifact = args.failure_artifact.resolve()
    if artifact.exists():
        artifact.unlink()
    deadline = time.monotonic() + args.timeout_seconds
    rng = random.Random(args.seed)
    state_cases = [make_state_case(index, rng) for index in range(args.case_count)]

    try:
        state_actual = run_state_cases(state_cases, deadline - time.monotonic())
        for index, case in enumerate(state_cases):
            actual = state_actual.get(case.name)
            reason = (
                "missing Mojo result"
                if actual is None
                else state_mismatch(case, actual)
            )
            if reason is not None:
                minimize_deadline = min(
                    deadline - 5,
                    time.monotonic() + args.minimize_seconds,
                )
                minimized = (
                    minimize_state_case(case, mismatch_class(reason), minimize_deadline)
                    if args.minimize_seconds and minimize_deadline > time.monotonic()
                    else case
                )
                write_failure_artifact(
                    artifact,
                    seed=args.seed,
                    case_count=args.case_count,
                    kind="connection-state",
                    index=index,
                    name=case.name,
                    chunks=minimized.chunks(),
                    reason=reason,
                    open_count=case.open_count,
                )
                print(f"FAIL {case.name}: {reason}")
                print(f"reproduction: {artifact}")
                return 1
    except (RuntimeError, subprocess.TimeoutExpired, TimeoutError, ValueError) as error:
        write_failure_artifact(
            artifact,
            seed=args.seed,
            case_count=args.case_count,
            kind="runner",
            index=-1,
            name="runner",
            chunks=(),
            reason=str(error),
        )
        print(f"FAIL runner: {error}")
        print(f"reproduction: {artifact}")
        return 1

    print(
        f"PASS HTTP/2 state compatibility: {args.case_count} cases "
        f"with seed {args.seed}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
