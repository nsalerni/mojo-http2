#!/usr/bin/env python3
"""Run deterministic HPACK compatibility sequences in both directions."""

import argparse
import hashlib
import random
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "compliance"))

from deterministic_sequences import (  # noqa: E402
    Failure,
    minimize_failure,
    worst_case_tool_runtime_seconds,
    write_artifact,
)
from run_compliance import hpack_corpus  # noqa: E402
from hpack.hpack import Decoder as PythonDecoder  # noqa: E402
from hpack.hpack import Encoder as PythonEncoder  # noqa: E402


UNIT_SEPARATOR = "\x1f"
HPACK_TOOL = ROOT / "compliance" / "tools" / "hpack_tool.mojo"
DEFAULT_MISMATCH_FILE = ROOT / "hpack-compatibility-mismatch.json"
MAX_SEED = (1 << 32) - 1
MAX_CASE_COUNT = 100_000
WORKFLOW_SETUP_RESERVE_SECONDS = 300

Header = tuple[str, str]
HeaderBlock = list[Header]

RFC_BLOCKS: list[HeaderBlock] = [
    [
        (":method", "GET"),
        (":scheme", "http"),
        (":path", "/"),
        (":authority", "www.example.com"),
    ],
    [
        (":method", "GET"),
        (":scheme", "http"),
        (":path", "/"),
        (":authority", "www.example.com"),
        ("cache-control", "no-cache"),
    ],
    [
        (":method", "GET"),
        (":scheme", "https"),
        (":path", "/index.html"),
        (":authority", "www.example.com"),
        ("custom-key", "custom-value"),
    ],
    [
        (":status", "302"),
        ("cache-control", "private"),
        ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
        ("location", "https://www.example.com"),
    ],
    [
        (":status", "307"),
        ("cache-control", "private"),
        ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
        ("location", "https://www.example.com"),
    ],
    [
        (":status", "200"),
        ("cache-control", "private"),
        ("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
        ("location", "https://www.example.com"),
        ("content-encoding", "gzip"),
        ("set-cookie", "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1"),
    ],
]
HEADER_NAMES = [
    ":authority",
    ":method",
    ":path",
    ":scheme",
    ":status",
    "accept",
    "authorization",
    "cache-control",
    "content-type",
    "grpc-message",
    "grpc-status",
    "te",
    "user-agent",
    "x-empty",
    "x-id",
    "x-longer-header-name",
    "x-randomized",
    "x-trace-bin",
]
VALUE_ALPHABET = "abcdefghij0123456789-_ .~!*'()%/:;=+"
UTF8_VALUES = ["résumé", "你好世界", "aß☃z", "fire 🔥 ok"]


def bounded_int(text: str, minimum: int, maximum: int) -> int:
    try:
        value = int(text, 0)
    except ValueError as error:
        raise argparse.ArgumentTypeError("must be an integer") from error
    if value < minimum or value > maximum:
        raise argparse.ArgumentTypeError(f"must be between {minimum} and {maximum}")
    return value


def seed_int(text: str) -> int:
    return bounded_int(text, 0, MAX_SEED)


def case_count_int(text: str) -> int:
    return bounded_int(text, 1, MAX_CASE_COUNT)


def positive_int(text: str) -> int:
    return bounded_int(text, 1, 86_400)


def random_value(rng: random.Random) -> str:
    roll = rng.randrange(12)
    if roll == 0:
        return ""
    if roll == 1:
        return rng.choice(UTF8_VALUES)
    return "".join(rng.choice(VALUE_ALPHABET) for _ in range(rng.randint(1, 96)))


def mutate_block(
    rng: random.Random, block: HeaderBlock, recent: list[HeaderBlock]
) -> HeaderBlock:
    result = list(block)
    for _ in range(rng.randint(1, 3)):
        operation = rng.choice(["append", "change", "drop", "repeat"])
        if operation == "append" or not result:
            result.append((rng.choice(HEADER_NAMES), random_value(rng)))
        elif operation == "change":
            index = rng.randrange(len(result))
            result[index] = (result[index][0], random_value(rng))
        elif operation == "drop" and len(result) > 1:
            del result[rng.randrange(len(result))]
        elif recent:
            prior = rng.choice(recent)
            result.insert(rng.randrange(len(result) + 1), rng.choice(prior))
    return result


def generate_blocks(seed: int, case_count: int) -> list[HeaderBlock]:
    rng = random.Random(seed)
    corpus = [
        [(str(name), str(value)) for name, value in block]
        for block in hpack_corpus(random.Random(seed ^ 0x7541))
    ]
    templates = [list(block) for block in RFC_BLOCKS] + corpus
    rng.shuffle(templates)
    blocks: list[HeaderBlock] = []
    while len(blocks) < case_count:
        if len(blocks) < len(templates):
            block = list(templates[len(blocks)])
        elif rng.randrange(10) < 3:
            block = list(rng.choice(blocks[-32:]))
        elif rng.randrange(10) < 8:
            block = mutate_block(rng, rng.choice(blocks[-32:]), blocks[-32:])
        else:
            block = [
                (rng.choice(HEADER_NAMES), random_value(rng))
                for _ in range(rng.randint(1, 10))
            ]
        blocks.append(block)
    return blocks


class ToolOutputError(ValueError):
    def __init__(self, kind: str, detail: str):
        super().__init__(detail)
        self.kind = kind


def parse_decoded(path: Path) -> list[HeaderBlock]:
    blocks: list[HeaderBlock] = []
    current: HeaderBlock = []
    for line in path.read_text().splitlines():
        if line == "===":
            blocks.append(current)
            current = []
        elif line.startswith("ERR "):
            current.append(("ERR", line[4:]))
        else:
            name, separator, value = line.partition(UNIT_SEPARATOR)
            if not separator:
                raise ToolOutputError("bad-line", repr(line))
            current.append((name, value))
    if current:
        raise ToolOutputError("unterminated-block", "missing block separator")
    return blocks


def parse_encoded(path: Path) -> list[str]:
    lines = path.read_text().splitlines()
    for line in lines:
        try:
            bytes.fromhex(line)
        except ValueError as error:
            raise ToolOutputError("bad-hex", repr(line)) from error
    return lines


def stable_signature(*parts: str) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(part.encode("utf-8", errors="backslashreplace") + b"\0")
    return digest.hexdigest()[:16]


def process_failure(mode: str, error: Exception) -> Failure:
    if isinstance(error, subprocess.TimeoutExpired):
        return Failure(
            "timeout",
            f"timeout:mode={mode}",
            f"Mojo tool timed out after {error.timeout} seconds",
        )
    signature = stable_signature(type(error).__name__, str(error))
    return Failure(
        "tool-error",
        f"tool-error:{type(error).__name__}:{signature}",
        f"Mojo tool failed: {error}",
    )


def exit_failure(result: subprocess.CompletedProcess[str]) -> Failure:
    signature = stable_signature(result.stdout, result.stderr)
    return Failure(
        "tool-exit",
        f"tool-exit:status={result.returncode}:streams={signature}",
        f"Mojo tool exited with status {result.returncode}",
        {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        },
    )


def output_failure(error: OSError | ValueError, path: Path) -> Failure:
    if isinstance(error, ToolOutputError):
        kind = error.kind
    elif isinstance(error, UnicodeDecodeError):
        kind = "invalid-utf8"
    elif isinstance(error, FileNotFoundError):
        kind = "missing-output"
    else:
        kind = type(error).__name__
    signature = stable_signature(type(error).__name__, str(error))
    actual = {"output": path.read_text()} if path.exists() else None
    return Failure(
        "malformed-output",
        f"malformed-output:{kind}:{signature}",
        f"Malformed Mojo output: {error}",
        actual,
    )


Parser = Callable[[Path], Any]


@dataclass
class ToolSpec:
    mode: str
    direction: str
    input_text: Callable[[int], str]
    parser: Parser
    encoded: list[str] | None = None


@dataclass
class ToolObservation:
    failure: Failure | None
    value: Any = None


def observe_tool(
    spec: ToolSpec, prefix_count: int, timeout: int, infile: Path, outfile: Path
) -> ToolObservation:
    infile.write_text(spec.input_text(prefix_count))
    outfile.unlink(missing_ok=True)
    try:
        result = subprocess.run(
            [
                "mojo",
                "run",
                "-I",
                "src",
                "-I",
                "test",
                str(HPACK_TOOL),
                spec.mode,
                str(infile),
                str(outfile),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return ToolObservation(process_failure(spec.mode, error))
    if result.returncode != 0:
        return ToolObservation(exit_failure(result))
    try:
        return ToolObservation(None, spec.parser(outfile))
    except (OSError, ValueError) as error:
        return ToolObservation(output_failure(error, outfile))


def run_tool_sequence(
    spec: ToolSpec,
    *,
    blocks: list[HeaderBlock],
    seed: int,
    initial_timeout: int,
    probe_timeout: int,
    mismatch_file: Path,
    temp: Path,
) -> tuple[bool, Any]:
    infile = temp / f"{spec.mode}-input.txt"
    outfile = temp / f"{spec.mode}-output.txt"
    observation = observe_tool(spec, len(blocks), initial_timeout, infile, outfile)
    if observation.failure is None:
        return True, observation.value
    prefix_count, failure = minimize_failure(
        len(blocks),
        observation.failure,
        lambda count: observe_tool(spec, count, probe_timeout, infile, outfile).failure,
    )
    write_artifact(
        mismatch_file,
        seed=seed,
        case_count=len(blocks),
        direction=spec.direction,
        sequence=blocks,
        prefix_count=prefix_count,
        failure=failure,
        encoded=spec.encoded,
    )
    print(
        f"FAIL {failure.reason}; shortest failing prefix has {prefix_count} cases",
        file=sys.stderr,
    )
    print(f"Mismatch input: {mismatch_file}", file=sys.stderr)
    return False, None


def first_difference(
    expected: list[HeaderBlock], actual: list[HeaderBlock]
) -> int | None:
    for index, pair in enumerate(zip(expected, actual)):
        if pair[0] != pair[1]:
            return index
    return None if len(expected) == len(actual) else min(len(expected), len(actual))


def record_mismatch(
    path: Path,
    seed: int,
    blocks: list[HeaderBlock],
    direction: str,
    index: int,
    reason: str,
    actual: Any,
    encoded: list[str] | None = None,
) -> int:
    failure = Failure(
        "compatibility-mismatch",
        f"compatibility-mismatch:{direction}:{index}:{stable_signature(reason)}",
        reason,
        actual,
    )
    write_artifact(
        path,
        seed=seed,
        case_count=len(blocks),
        direction=direction,
        sequence=blocks,
        prefix_count=index + 1,
        failure=failure,
        encoded=encoded,
    )
    print(f"FAIL {reason} at case {index}\nMismatch input: {path}", file=sys.stderr)
    return 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--seed", type=seed_int, default=7541, help=f"random seed, maximum {MAX_SEED}"
    )
    parser.add_argument(
        "--case-count",
        "--cases",
        dest="cases",
        type=case_count_int,
        default=250,
        help=f"header block count, maximum {MAX_CASE_COUNT}",
    )
    parser.add_argument("--mismatch-file", type=Path, default=DEFAULT_MISMATCH_FILE)
    parser.add_argument("--timeout", type=positive_int, default=120)
    parser.add_argument("--probe-timeout", type=positive_int, default=30)
    parser.add_argument("--workflow-limit-minutes", type=positive_int)
    args = parser.parse_args()
    bound = worst_case_tool_runtime_seconds(
        args.cases, args.timeout, args.probe_timeout
    )
    if args.workflow_limit_minutes:
        allowance = args.workflow_limit_minutes * 60 - WORKFLOW_SETUP_RESERVE_SECONDS
        if bound > allowance:
            parser.error(f"tool runtime bound {bound}s exceeds {allowance}s allowance")
    args.runtime_bound = bound
    return args


def main() -> int:
    args = parse_args()
    mismatch_file = args.mismatch_file.resolve()
    mismatch_file.unlink(missing_ok=True)
    print(f"HPACK stateful compatibility seed={args.seed} cases={args.cases}")
    print(f"Worst-case tool runtime bound={args.runtime_bound}s")

    blocks = generate_blocks(args.seed, args.cases)
    encoder = PythonEncoder()
    reference_hex = [encoder.encode(block).hex() for block in blocks]
    decode_spec = ToolSpec(
        "decode",
        "python-encode-mojo-decode",
        lambda count: "".join(f"{line}\n" for line in reference_hex[:count]),
        parse_decoded,
        reference_hex,
    )
    encode_spec = ToolSpec(
        "encode",
        "mojo-encode-python-decode",
        lambda count: "".join(
            "".join(f"{name}{UNIT_SEPARATOR}{value}\n" for name, value in block)
            + "===\n"
            for block in blocks[:count]
        ),
        parse_encoded,
    )

    with tempfile.TemporaryDirectory(prefix="hpack-compatibility-") as temp_dir:
        temp = Path(temp_dir)
        ok, decoded = run_tool_sequence(
            decode_spec,
            blocks=blocks,
            seed=args.seed,
            initial_timeout=args.timeout,
            probe_timeout=args.probe_timeout,
            mismatch_file=mismatch_file,
            temp=temp,
        )
        if not ok:
            return 1
        index = first_difference(blocks, decoded)
        if index is not None:
            actual = decoded[index] if index < len(decoded) else None
            return record_mismatch(
                mismatch_file,
                args.seed,
                blocks,
                decode_spec.direction,
                index,
                "decoded headers differ",
                actual,
                reference_hex,
            )

        ok, encoded = run_tool_sequence(
            encode_spec,
            blocks=blocks,
            seed=args.seed,
            initial_timeout=args.timeout,
            probe_timeout=args.probe_timeout,
            mismatch_file=mismatch_file,
            temp=temp,
        )
        if not ok:
            return 1
        decoder = PythonDecoder()
        decoded = []
        for index, line in enumerate(encoded):
            try:
                fields = decoder.decode(bytes.fromhex(line))
            except Exception as error:
                return record_mismatch(
                    mismatch_file,
                    args.seed,
                    blocks,
                    encode_spec.direction,
                    index,
                    f"Python decoder rejected the block: {error}",
                    None,
                    encoded,
                )
            decoded.append([(str(name), str(value)) for name, value in fields])
        index = first_difference(blocks, decoded)
        if index is not None:
            actual = decoded[index] if index < len(decoded) else None
            return record_mismatch(
                mismatch_file,
                args.seed,
                blocks,
                encode_spec.direction,
                index,
                "decoded headers differ",
                actual,
                encoded,
            )

    print(f"PASS {args.cases} shared-table cases in both directions")
    return 0


if __name__ == "__main__":
    sys.exit(main())
