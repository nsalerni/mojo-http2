#!/usr/bin/env python3
"""Test deterministic compatibility-sequence helpers."""

import json
import math
import tempfile
import unittest
from pathlib import Path

from deterministic_sequences import (
    Failure,
    maximum_prefix_probe_count,
    minimize_failure,
    worst_case_tool_runtime_seconds,
    write_artifact,
)


class DeterministicSequenceTests(unittest.TestCase):
    def test_minimizes_only_the_matching_failure(self) -> None:
        target = Failure("exit", "status-2", "target failure")
        earlier = Failure("exit", "status-1", "different failure")
        probes: list[int] = []

        def probe(prefix_count: int) -> Failure | None:
            probes.append(prefix_count)
            if prefix_count >= 11:
                return target
            if prefix_count >= 3:
                return earlier
            return None

        prefix_count, failure = minimize_failure(16, target, probe)
        self.assertEqual(prefix_count, 11)
        self.assertEqual(failure.fingerprint, target.fingerprint)
        self.assertLessEqual(
            len(probes), maximum_prefix_probe_count(16)
        )

    def test_one_case_uses_the_known_failure(self) -> None:
        target = Failure("mismatch", "case-0", "first case")
        prefix_count, failure = minimize_failure(
            1,
            target,
            lambda _: self.fail("one known case needs no probe"),
        )
        self.assertEqual(prefix_count, 1)
        self.assertIs(failure, target)

    def test_runtime_bound_covers_every_probe(self) -> None:
        self.assertEqual(maximum_prefix_probe_count(250), 9)
        self.assertEqual(maximum_prefix_probe_count(10_000), 15)
        self.assertEqual(worst_case_tool_runtime_seconds(250, 60, 10), 210)
        self.assertEqual(
            worst_case_tool_runtime_seconds(10_000, 120, 30), 690
        )

    def test_rejects_nonpositive_limits(self) -> None:
        for value in (0, -1):
            with self.subTest(case_count=value):
                with self.assertRaises(ValueError):
                    maximum_prefix_probe_count(value)
                with self.assertRaises(ValueError):
                    minimize_failure(
                        value, Failure("x", "x", "x"), lambda _: None
                    )
        with self.assertRaises(ValueError):
            worst_case_tool_runtime_seconds(1, 0, 1)
        with self.assertRaises(ValueError):
            worst_case_tool_runtime_seconds(1, 1, 0)

    def test_artifact_contains_only_the_required_prefix(self) -> None:
        failure = Failure(
            "mismatch", "case-2", "different output", {"actual": 7}
        )
        sequence = [["zero"], ["one"], ["two"], ["three"]]
        encoded = ["00", "01", "02", "03"]
        with tempfile.TemporaryDirectory(prefix="sequence-artifact-") as temp:
            path = Path(temp) / "failure.json"
            write_artifact(
                path,
                seed=7541,
                case_count=len(sequence),
                direction="reference-to-mojo",
                sequence=sequence,
                prefix_count=3,
                failure=failure,
                encoded=encoded,
            )
            document = json.loads(path.read_text())

        self.assertEqual(document["mismatch_index"], 2)
        self.assertEqual(document["sequence"], sequence[:3])
        self.assertEqual(document["encoded_hex"], encoded[:3])
        self.assertEqual(document["failure_fingerprint"], "case-2")
        self.assertEqual(document["actual"], {"actual": 7})

        with self.assertRaises(ValueError):
            write_artifact(
                Path("unused"),
                seed=0,
                case_count=1,
                direction="test",
                sequence=[1],
                prefix_count=2,
                failure=failure,
            )
        with self.assertRaises(ValueError):
            write_artifact(
                Path("unused"),
                seed=0,
                case_count=2,
                direction="test",
                sequence=[1],
                prefix_count=1,
                failure=failure,
            )
        with self.assertRaises(ValueError):
            write_artifact(
                Path("unused"),
                seed=0,
                case_count=2,
                direction="test",
                sequence=[1, 2],
                prefix_count=2,
                failure=failure,
                encoded=["01"],
            )

    def test_probe_bound_matches_binary_search(self) -> None:
        for case_count in (1, 2, 3, 16, 250, 10_000):
            with self.subTest(case_count=case_count):
                self.assertEqual(
                    maximum_prefix_probe_count(case_count),
                    math.ceil(math.log2(case_count)) + 1,
                )


if __name__ == "__main__":
    unittest.main()
