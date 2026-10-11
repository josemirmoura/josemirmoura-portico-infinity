"""Freeze the 37-scenario normative audit inventory against the upstream SHA.

These tests validate evidence-document integrity, NOT protocol conformance or
independent reviewer approval.
"""
from collections import Counter
import importlib.util
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "scripts/mcp_release_scope_audit.py"
DOCUMENT = ROOT / "docs/mcp-gate-c-audit-20261011.md"

spec = importlib.util.spec_from_file_location("pinned_scope_audit", SOURCE)
assert spec and spec.loader
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)

PATTERN = re.compile(
    r"^\|\s*(\d{2})\s*\|\s*`([a-z0-9-]+)`\s*\|\s*([PFNS])\s*\|\s*([PFNS])\s*\|"
)
EXPECTED_NORMAL = {"P":8, "F":2, "S":3, "N":24}
EXPECTED_LAB = {"P":35, "F":1, "S":1, "N":0}

def audit_rows(text: str):
    results = []
    for line in text.splitlines():
        match = PATTERN.match(line)
        if match:
            results.append((int(match.group(1)), match.group(2),
                            match.group(3), match.group(4)))
    return results

class AuditInventoryTests(unittest.TestCase):
    def test_every_frozen_scenario_in_source_order(self):
        text = DOCUMENT.read_text(encoding="utf-8")
        rows = audit_rows(text)
        self.assertEqual(len(rows), 37)
        self.assertEqual([index for index, *_ in rows], list(range(1, 38)))
        self.assertEqual([name for _, name, *_ in rows], list(audit.REQUIRED_SERVER))

    def test_historical_raw_scores_are_not_rewritten(self):
        rows = audit_rows(DOCUMENT.read_text(encoding="utf-8"))
        self.assertEqual(dict(Counter(normal for _, _, normal, _ in rows)),
                         {key: value for key, value in EXPECTED_NORMAL.items() if value})
        self.assertEqual(dict(Counter(lab for _, _, _, lab in rows)),
                         {key: value for key, value in EXPECTED_LAB.items() if value})

    def test_no_false_approval_or_fixture_certification(self):
        text = DOCUMENT.read_text(encoding="utf-8")
        self.assertIn("Gate C full frozen conformance: FAIL / BLOCKED", text)
        self.assertIn("Gate C advertised-profile normative acceptance: NOT YET APPROVED", text)
        self.assertIn("this author cannot sign their own review as independent", text)
        self.assertIn("`release_gate_passed=false`", text)
        self.assertIn("19/19 GitHub Actions workflow runs SUCCESS", text)

if __name__ == "__main__":
    unittest.main()
