"""Helpers for reproducible stateful compatibility checks."""

import json
import math
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class Failure:
    """A reproducible failure with a stable identity."""

    category: str
    fingerprint: str
    reason: str
    actual: Any = None


Probe = Callable[[int], Failure | None]


def _require_positive(name: str, value: int) -> None:
    if value <= 0:
        raise ValueError(f"{name} must be positive")


def maximum_prefix_probe_count(case_count: int) -> int:
    """Return the maximum probes needed to minimize a stateful prefix."""
    _require_positive("case_count", case_count)
    return math.ceil(math.log2(case_count)) + 1


def worst_case_tool_runtime_seconds(
    case_count: int, initial_timeout: int, probe_timeout: int
) -> int:
    """Bound two normal tool calls and every possible prefix probe."""
    _require_positive("initial_timeout", initial_timeout)
    _require_positive("probe_timeout", probe_timeout)
    return (
        2 * initial_timeout
        + maximum_prefix_probe_count(case_count) * probe_timeout
    )


def minimize_failure(
    case_count: int, known: Failure, probe: Probe
) -> tuple[int, Failure]:
    """Find the shortest monotonic prefix with the known fingerprint."""
    _require_positive("case_count", case_count)
    observations: dict[int, Failure | None] = {case_count: known}

    def matches(prefix_count: int) -> bool:
        if prefix_count not in observations:
            observations[prefix_count] = probe(prefix_count)
        failure = observations[prefix_count]
        return failure is not None and failure.fingerprint == known.fingerprint

    low, high = 1, case_count
    while low < high:
        midpoint = (low + high) // 2
        if matches(midpoint):
            high = midpoint
        else:
            low = midpoint + 1

    if low not in observations:
        observations[low] = probe(low)
    failure = observations[low]
    if failure is None or failure.fingerprint != known.fingerprint:
        raise RuntimeError("failure did not reproduce during prefix minimization")
    return low, failure


def write_artifact(
    path: Path,
    *,
    seed: int,
    case_count: int,
    direction: str,
    sequence: Sequence[Any],
    prefix_count: int,
    failure: Failure,
    encoded: Sequence[str] | None = None,
) -> None:
    """Write only the stateful prefix needed to reproduce a failure."""
    if case_count != len(sequence):
        raise ValueError("case_count does not match the sequence")
    if prefix_count <= 0 or prefix_count > len(sequence):
        raise ValueError("prefix_count falls outside the sequence")
    if encoded is not None and prefix_count > len(encoded):
        raise ValueError("encoded data is shorter than the required prefix")
    document = {
        "seed": seed,
        "case_count": case_count,
        "direction": direction,
        "mismatch_index": prefix_count - 1,
        "failure_class": failure.category,
        "failure_fingerprint": failure.fingerprint,
        "reason": failure.reason,
        "sequence": sequence[:prefix_count],
    }
    if encoded is not None:
        document["encoded_hex"] = encoded[:prefix_count]
    if failure.actual is not None:
        document["actual"] = failure.actual
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, ensure_ascii=False, indent=2) + "\n")
