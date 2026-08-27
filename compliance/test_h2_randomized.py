#!/usr/bin/env python3
"""Tests for the deterministic HTTP/2 randomized runner."""

import json
import io
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import run_h2_randomized as randomized


class RandomizedRunnerTests(unittest.TestCase):
    def test_state_chunks_reconstruct_wire_exactly(self):
        members = (
            randomized.frame(4, 0, 0, b""),
            randomized.frame(6, 0, 0, b"abcdefgh"),
        )
        case = randomized.StateCase(
            name="split",
            open_count=0,
            frames=members,
            chunk_sizes=(1, 2, 7, 100),
        )
        self.assertEqual(b"".join(case.chunks()), b"".join(members))

    def test_minimizer_removes_irrelevant_members(self):
        result = randomized.minimize_items(
            ["keep", "drop-a", "drop-b"],
            lambda members: "keep" in members,
            time.monotonic() + 1,
        )
        self.assertEqual(result, ["keep"])

    def test_state_minimizer_preserves_failure_class(self):
        case = randomized.StateCase(
            name="identity",
            open_count=0,
            frames=(b"keep", b"drop-a", b"drop-b"),
            chunk_sizes=(5, 6, 6),
        )

        def mismatch(candidate, _actual):
            return (
                "target: mismatch" if b"keep" in candidate.frames else "other: mismatch"
            )

        with (
            patch.object(randomized, "run_state_cases", return_value={"identity": {}}),
            patch.object(randomized, "state_mismatch", side_effect=mismatch),
        ):
            minimized = randomized.minimize_state_case(
                case, "target", time.monotonic() + 1
            )
        self.assertEqual(minimized.frames, (b"keep",))

    def test_argument_bounds_reject_unbounded_runs(self):
        for arguments in (
            ["--seed", "-1"],
            ["--case-count", "0"],
            ["--case-count", "100001"],
            ["--timeout-seconds", "29"],
            ["--timeout-seconds", "1501"],
            ["--minimize-seconds", "61"],
        ):
            with self.subTest(arguments=arguments):
                with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                    randomized.parse_args(arguments)

    def test_state_mismatch_ignores_window_update_acks(self):
        case = randomized.StateCase(
            name="data",
            open_count=1,
            frames=(randomized.frame(0, 0x01, 1, b"abcd"),),
            chunk_sizes=(13,),
        )
        reference = {
            "status": "OK",
            "output": (),
            "settings": {},
            "send_window": 65535,
            "goaway_last": None,
            "goaway_code": None,
        }
        with patch.object(randomized, "reference_state", return_value=reference):
            reason = randomized.state_mismatch(
                case,
                {
                    **reference,
                    "output": ((8, 0, 0, "00000004"),),
                },
            )
        self.assertIsNone(reason)

        with patch.object(randomized, "reference_state", return_value=reference):
            reason = randomized.state_mismatch(
                case,
                {
                    **reference,
                    "output": ((6, 1, 0, "abcdefgh"),),
                },
            )
        self.assertIsNotNone(reason)
        self.assertTrue(reason.startswith("output:"))

    def test_mismatch_writes_a_compact_reproduction(self):
        with tempfile.TemporaryDirectory() as temp:
            artifact = Path(temp) / "failure.json"
            arguments = [
                "--seed",
                "17",
                "--case-count",
                "2",
                "--timeout-seconds",
                "30",
                "--minimize-seconds",
                "0",
                "--failure-artifact",
                str(artifact),
            ]
            with patch.object(randomized, "run_state_cases", return_value={}):
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(randomized.main(arguments), 1)
            document = json.loads(artifact.read_text())
            self.assertEqual(document["schema"], 1)
            self.assertEqual(document["seed"], 17)
            self.assertEqual(document["case_count"], 2)
            self.assertEqual(document["kind"], "connection-state")
            self.assertEqual(document["failure_class"], "missing Mojo result")
            self.assertTrue(document["chunks_hex"])
            self.assertIn("pixi run h2-state-compatibility", document["replay"])


if __name__ == "__main__":
    unittest.main()
