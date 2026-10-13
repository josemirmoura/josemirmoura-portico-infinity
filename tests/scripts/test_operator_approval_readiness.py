"""No-secret, no-shell diagnostics for first-E2E operator approval UI."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/operator-approval-readiness.py"

ORIGIN = "https://operator.example.test"
SECRET = "Q" * 48
SCRYPT = "a" * 48 + ":" + "b" * 64


class ApprovalReadinessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="approval-readiness-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.envfile = self.base / ".env"

    def write_env(self, text):
        self.envfile.write_text(text, encoding="utf-8")
        self.envfile.chmod(0o600)

    def run_check(self):
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--env-file", str(self.envfile)],
            capture_output=True, text=True, timeout=10,
        )

    def valid(self, apps=False):
        self.write_env("\n".join([
            f"PORTICO_OPERATOR_PUBLIC_ORIGIN={ORIGIN}",
            f"VPS_AGENT_OPERATOR_PORTAL_URL={ORIGIN}/operator",
            f"VPS_AGENT_OPERATOR_APPROVAL_TOKEN={SECRET}",
            f"PORTICO_OPERATOR_PASSWORD_SCRYPT={SCRYPT}",
            f"VPS_AGENT_MCP_APPS={'1' if apps else '0'}",
        ]) + "\n")

    def test_missing_env_reports_cli_fallback(self):
        result = self.run_check()
        self.assertEqual(result.returncode, 0)
        self.assertIn("operator_fallback", result.stdout)

    def test_complete_credentials_are_candidate_only(self):
        self.valid()
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("operator_web_candidate", result.stdout)
        self.assertIn("ainda não verificados", result.stdout)
        self.assertIn("MCP Apps desabilitado", result.stdout)
        self.assertNotIn(SECRET, result.stdout + result.stderr)
        self.assertNotIn(SCRYPT, result.stdout + result.stderr)

    def test_embedded_requires_actual_client_validation(self):
        self.valid(apps=True)
        result = self.run_check()
        self.assertIn("operator_web_candidate", result.stdout)
        self.assertIn("não presumir UI embutida", result.stdout)

    def test_invalid_url_and_short_secrets_fail_closed(self):
        for override in (
            f"VPS_AGENT_OPERATOR_PORTAL_URL=https://evil.test/operator",
            f"PORTICO_OPERATOR_PUBLIC_ORIGIN=http://operator.example.test",
            "VPS_AGENT_OPERATOR_APPROVAL_TOKEN=weak",
            "PORTICO_OPERATOR_PASSWORD_SCRYPT=bad",
        ):
            with self.subTest(value=override.split("=")[0]):
                self.valid()
                key = override.split("=", 1)[0]
                lines = self.envfile.read_text().splitlines()
                self.write_env("\n".join(override if line.startswith(key + "=") else line for line in lines))
                result = self.run_check()
                self.assertIn("operator_fallback", result.stdout)
                self.assertNotIn(SECRET, result.stdout)

    def test_world_readable_env_is_not_read(self):
        self.valid()
        self.envfile.chmod(0o644)
        result = self.run_check()
        self.assertIn("operator_fallback", result.stdout)
        self.assertNotIn(SECRET, result.stdout)

    def test_symlink_env_is_rejected(self):
        self.valid()
        target = self.base / "source"
        self.envfile.rename(target)
        self.envfile.symlink_to(target)
        result = self.run_check()
        self.assertIn("operator_fallback", result.stdout)
        self.assertNotIn(SECRET, result.stdout)

    def test_env_is_data_not_executable_shell(self):
        sentinel = self.base / "SHOULD_NOT_EXIST"
        self.valid()
        with self.envfile.open("a", encoding="utf-8") as handle:
            handle.write(f"HOSTILE=$(touch {sentinel})\n")
        result = self.run_check()
        self.assertIn("operator_web_candidate", result.stdout)
        self.assertFalse(sentinel.exists(), "readiness must never source or execute .env")


if __name__ == "__main__":
    unittest.main()
