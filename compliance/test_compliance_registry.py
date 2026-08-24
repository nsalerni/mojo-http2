#!/usr/bin/env python3
"""Regression checks for the compliance result registry."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import run_compliance


def complete_results() -> dict[str, list[tuple[str, bool, str]]]:
    return {
        section: [(name, True, "") for name in names]
        for section, names in run_compliance.EXPECTED_CHECKS.items()
    }


class ComplianceRegistryTest(unittest.TestCase):
    def test_complete_result_set_reports_exact_score(self):
        self.assertEqual(
            run_compliance.result_summary(complete_results()),
            (30, 30, True),
        )

    def test_failed_check_is_counted(self):
        results = complete_results()
        name, _, _ = results["h2"][0]
        results["h2"][0] = (name, False, "reference mismatch")

        self.assertEqual(
            run_compliance.result_summary(results),
            (29, 30, True),
        )

    def test_missing_check_invalidates_each_section(self):
        for section in run_compliance.EXPECTED_CHECKS:
            with self.subTest(section=section):
                results = complete_results()
                results[section].pop()

                passed, total, valid = run_compliance.result_summary(results)

                self.assertEqual((passed, total), (29, 30))
                self.assertFalse(valid)

    def test_duplicate_check_invalidates_each_section(self):
        for section in run_compliance.EXPECTED_CHECKS:
            with self.subTest(section=section):
                results = complete_results()
                results[section].append(results[section][0])

                _, _, valid = run_compliance.result_summary(results)

                self.assertFalse(valid)

    def test_unexpected_check_invalidates_each_section(self):
        for section in run_compliance.EXPECTED_CHECKS:
            with self.subTest(section=section):
                results = complete_results()
                results[section].append(("unregistered check", True, ""))

                self.assertEqual(
                    run_compliance.result_summary(results),
                    (30, 30, False),
                )

    def test_unexpected_section_invalidates_result_set(self):
        results = complete_results()
        results["unknown"] = [("unregistered check", True, "")]

        self.assertEqual(
            run_compliance.result_summary(results),
            (30, 30, False),
        )

    def test_missing_check_cannot_produce_a_passing_report(self):
        results = complete_results()
        results["hpack"].pop()

        with tempfile.TemporaryDirectory(dir=run_compliance.ROOT) as directory:
            markdown = Path(directory) / "COMPLIANCE.md"
            html = Path(directory) / "COMPLIANCE.html"
            with (
                patch.object(run_compliance, "RESULTS", results),
                patch.object(run_compliance, "REPORT", markdown),
                patch.object(run_compliance, "HTML_REPORT", html),
                patch.object(run_compliance, "versions", return_value={}),
            ):
                self.assertFalse(run_compliance.write_report())
                self.assertFalse(run_compliance.write_html_report())

            verdict = "29/30 registered checks passed; results incomplete"
            self.assertIn(verdict, markdown.read_text())
            html_text = html.read_text()
            self.assertIn('class="score failing">29/30</span>', html_text)
            self.assertIn("registered checks passed; results incomplete", html_text)


if __name__ == "__main__":
    unittest.main()
