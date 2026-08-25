#!/usr/bin/env python3
"""Test HPACK compatibility failure records and command-line bounds."""

import argparse
import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import test_hpack_randomized as target
from deterministic_sequences import maximum_prefix_probe_count


class FailureArtifactTests(unittest.TestCase):
    def _run_failure_case(
        self, failure_class: str, threshold: int
    ) -> tuple[dict, list[int]]:
        blocks: list[target.HeaderBlock] = [[] for _ in range(16)]
        probe_counts: list[int] = []

        def fake_run(command: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
            del kwargs
            input_path = Path(command[-2])
            output_path = Path(command[-1])
            prefix_count = len(input_path.read_text().splitlines())
            probe_counts.append(prefix_count)

            if failure_class == "timeout" and prefix_count >= threshold:
                raise subprocess.TimeoutExpired(command, 2)

            returncode = 0
            if failure_class == "tool-exit":
                if prefix_count >= threshold:
                    returncode = 2
                elif prefix_count >= 3:
                    returncode = 1

            output = "===\n" * prefix_count
            if failure_class == "malformed-output":
                if prefix_count >= threshold:
                    output = "===\n" * (prefix_count - 1) + "bad output\n"
                elif prefix_count >= 3:
                    output = (
                        "===\n" * (prefix_count - 1)
                        + f"x-state{target.UNIT_SEPARATOR}value\n"
                    )
            output_path.write_text(output)
            return subprocess.CompletedProcess(
                args=command,
                returncode=returncode,
                stdout="",
                stderr="",
            )

        with tempfile.TemporaryDirectory(prefix="hpack-failure-test-") as temp:
            directory = Path(temp)
            artifact = directory / "failure.json"
            spec = target.ToolSpec(
                mode="decode",
                direction="test-direction",
                input_text=lambda count: "00\n" * count,
                parser=target.parse_decoded,
                encoded=[f"{index:02x}" for index in range(len(blocks))],
            )
            with (
                mock.patch.object(target.subprocess, "run", side_effect=fake_run),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                ok, _ = target.run_tool_sequence(
                    spec,
                    blocks=blocks,
                    seed=7541,
                    initial_timeout=2,
                    probe_timeout=1,
                    mismatch_file=artifact,
                    temp=directory,
                )
            self.assertFalse(ok)
            record = json.loads(artifact.read_text())
        return record, probe_counts

    def test_minimizes_matching_failures_without_switching_identity(self) -> None:
        cases = [
            ("tool-exit", 11),
            ("timeout", 9),
            ("malformed-output", 13),
        ]
        for failure_class, threshold in cases:
            with self.subTest(failure_class=failure_class):
                record, probes = self._run_failure_case(failure_class, threshold)
                self.assertEqual(record["failure_class"], failure_class)
                self.assertEqual(record["mismatch_index"], threshold - 1)
                self.assertEqual(len(record["sequence"]), threshold)
                self.assertEqual(len(record["encoded_hex"]), threshold)
                self.assertLessEqual(
                    len(probes),
                    maximum_prefix_probe_count(16) + 1,
                )

    def test_numeric_arguments_are_bounded(self) -> None:
        self.assertEqual(target.seed_int("0xffffffff"), target.MAX_SEED)
        self.assertEqual(
            target.case_count_int(str(target.MAX_CASE_COUNT)),
            target.MAX_CASE_COUNT,
        )
        for value in ["-1", "4294967296", "1\n2", "seed"]:
            with self.subTest(seed=value):
                with self.assertRaises(argparse.ArgumentTypeError):
                    target.seed_int(value)
        for value in ["0", "-1", "100001", "1\n2", "many"]:
            with self.subTest(case_count=value):
                with self.assertRaises(argparse.ArgumentTypeError):
                    target.case_count_int(value)

    def test_output_parsers_reject_incomplete_data(self) -> None:
        with tempfile.TemporaryDirectory(prefix="hpack-output-test-") as temp:
            path = Path(temp) / "output.txt"
            path.write_text(f"name{target.UNIT_SEPARATOR}value\n")
            with self.assertRaisesRegex(ValueError, "missing block separator"):
                target.parse_decoded(path)
            path.write_text("not hexadecimal\n")
            with self.assertRaises(ValueError):
                target.parse_encoded(path)


if __name__ == "__main__":
    unittest.main()
