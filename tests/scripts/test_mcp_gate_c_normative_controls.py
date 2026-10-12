#!/usr/bin/env python3
"""Integrity checks for the normative Gate C ledger; never turns lab PASS into release PASS."""
from __future__ import annotations

import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / "docs/mcp-gate-c-normative-controls.json"
ALLOWED = {
    "LAB_PASS", "PARTIAL", "NOT_PROVEN",
    "NOT_ADVERTISED", "REAL_ENV_PENDING", "RAW_FAIL",
}
APPLICABILITY = {
    "MUST", "MUST_CONDITIONAL", "MUST_IF_OAUTH",
    "MUST_IF_TOOLS", "MUST_IF_PROMPTS", "MUST_IF_RESOURCES",
    "MUST_IF_LOGGING", "MUST_IF_SCHEMA", "MUST_SECURITY",
    "PRODUCT_SECURITY", "CONDITIONAL", "OPTIONAL",
    "REAL_WORLD_GATE", "RELEASE_GATE", "RELEASE_EVIDENCE",
}


class NormativeControlInventory(unittest.TestCase):
    def setUp(self):
        self.doc = json.loads(DOC.read_text(encoding="utf-8"))
        self.rows = self.doc["controls"]

    def test_revision_scope_and_no_automatic_release(self):
        self.assertEqual(self.doc["schema_version"], 1)
        self.assertEqual(self.doc["protocol_revision"], "2026-07-28")
        self.assertEqual(
            self.doc["pinned_upstream"],
            "c37eec888e1c6ff140af79987a40008548b7cc5f",
        )
        self.assertIn("BLOCKED", self.doc["freeze_rule"])
        self.assertIn("false", self.doc["controls"][-1]["limitation"])
        self.assertNotIn("release_gate_passed=true", DOC.read_text())

    def test_unique_all_evidence_paths_and_unproven_statuses(self):
        self.assertEqual(len(self.rows), 36)
        ids = [r["id"] for r in self.rows]
        self.assertEqual(ids, [f"C{i:02d}" for i in range(1, 37)])
        for row in self.rows:
            with self.subTest(control=row["id"]):
                self.assertEqual(
                    set(row),
                    {"id", "family", "rule", "applicability",
                     "status", "evidence", "limitation"},
                )
                self.assertIn(row["status"], ALLOWED)
                self.assertIn(row["applicability"], APPLICABILITY)
                self.assertGreaterEqual(len(row["rule"].strip()), 12)
                self.assertGreaterEqual(len(row["limitation"].strip()), 16)
                self.assertTrue(re.fullmatch(r"[A-Za-z0-9_./-]+", row["evidence"]))
                file = (ROOT / row["evidence"]).resolve()
                self.assertTrue(file.is_relative_to(ROOT.resolve()))
                self.assertTrue(file.is_file(), f"missing evidence file {file}")
                if row["status"] == "LAB_PASS":
                    self.assertTrue(
                        row["evidence"].startswith(
                            ("tests/", "internal/gateway/", "scripts/")
                        )
                    )
        self.assertGreaterEqual(
            sum(r["status"] in {"PARTIAL", "NOT_PROVEN", "REAL_ENV_PENDING"}
                for r in self.rows), 10)
        self.assertEqual(sum(r["status"] == "RAW_FAIL" for r in self.rows), 1)
        self.assertEqual(sum(r["status"] == "REAL_ENV_PENDING" for r in self.rows), 3)

    def test_frozen_scenarios_not_reclassified(self):
        row = self.rows[-1]
        self.assertEqual(row["id"], "C36")
        self.assertEqual(row["status"], "RAW_FAIL")
        self.assertIn("8/2/3/24", row["limitation"])
        self.assertIn("35/1/1/0", row["limitation"])
        self.assertIn("release_gate_passed=false", row["limitation"])

    def test_no_local_fixture_mislabeled_real_environment(self):
        for row in self.rows:
            if "real" in row["rule"].lower() and row["id"] in {"C33", "C34", "C35"}:
                self.assertEqual(row["status"], "REAL_ENV_PENDING")
        self.assertEqual(self.rows[16]["id"], "C17")
        self.assertIn("UNVALIDATED", self.rows[16]["limitation"])


if __name__ == "__main__":
    unittest.main()
