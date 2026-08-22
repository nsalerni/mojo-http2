#!/usr/bin/env python3
"""Regression checks for the generated h2spec Shields endpoint."""

import json
import unittest

from run_compliance import h2spec_badge_json, h2spec_badge_payload


class H2SpecBadgeTest(unittest.TestCase):
    def test_full_runs_report_both_exact_scores(self):
        payload = h2spec_badge_payload({
            "cleartext": (146, 146, 0, 0),
            "TLS": (146, 146, 0, 0),
        })

        self.assertEqual(payload, {
            "schemaVersion": 1,
            "label": "h2spec",
            "message": "cleartext 146/146 | TLS 146/146",
            "color": "brightgreen",
        })
        serialized = h2spec_badge_json({
            "TLS": (146, 146, 0, 0),
            "cleartext": (146, 146, 0, 0),
        })
        self.assertEqual(json.loads(serialized), payload)
        self.assertEqual(serialized, h2spec_badge_json({
            "cleartext": (146, 146, 0, 0),
            "TLS": (146, 146, 0, 0),
        }))

    def test_failure_cannot_produce_a_green_badge(self):
        payload = h2spec_badge_payload({
            "cleartext": (146, 145, 0, 1),
            "TLS": (146, 146, 0, 0),
        })

        self.assertEqual(
            payload["message"], "cleartext 145/146 | TLS 146/146"
        )
        self.assertEqual(payload["color"], "red")

    def test_missing_run_is_visible_and_not_green(self):
        payload = h2spec_badge_payload({
            "cleartext": (146, 146, 0, 0),
        })

        self.assertEqual(
            payload["message"], "cleartext 146/146 | TLS unavailable"
        )
        self.assertEqual(payload["color"], "red")


if __name__ == "__main__":
    unittest.main()
