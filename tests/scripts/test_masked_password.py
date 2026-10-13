"""Masked OAuth terminal prompt acceptance, no real credentials or TTY needed."""
from __future__ import annotations
from pathlib import Path
import shlex
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts/lib/masked-password.sh"
SETUP = ROOT / "scripts/setup-integrated-auth.sh"


class MaskedPasswordTests(unittest.TestCase):
    def run_prompt(self, typed):
        code = (
            "set -euo pipefail\n"
            "source " + shlex.quote(str(HELPER)) + "\n"
            "PASSWORD=''\n"
            "vps_agent_read_masked_password PASSWORD 'Create: '\n"
            "printf 'LEN=%s\\n' \"$(printf %s \"$PASSWORD\" | wc -c)\"\n"
        )
        return subprocess.run(
            ["bash", "-c", code], input=typed,
            capture_output=True, text=True, timeout=8, check=False,
        )

    def test_single_asterisk_per_character_and_secret_not_echoed(self):
        result = self.run_prompt("correct-horse13\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "LEN=15")
        self.assertEqual(result.stderr.count("*"), 15)
        self.assertNotIn("correct-horse13", result.stderr + result.stdout)

    def test_backspace_works(self):
        result = self.run_prompt("abcdefghijkl" + "\x7f" + "Z\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "LEN=12")
        self.assertIn("\b \b", result.stderr)
        self.assertNotIn("abcdefghijkl", result.stderr + result.stdout)

    def test_ctrl_u_erases_current_line(self):
        result = self.run_prompt("to-be-erased" + "\x15" + "123456789012\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "LEN=12")
        self.assertNotIn("to-be-erased", result.stderr + result.stdout)

    def test_eof_fails_without_accepting_partial_password(self):
        result = self.run_prompt("unfinished")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("LEN=", result.stdout)

    def test_setup_keeps_noninteractive_guard_and_private_fd(self):
        source = SETUP.read_text(encoding="utf-8")
        self.assertIn('if [ ! -t 0 ]; then', source)
        self.assertIn('VPS_AGENT_OPERATOR_PASSWORD', source)
        self.assertIn("vps_agent_read_masked_password PASSWORD", source)
        self.assertIn("vps_agent_read_masked_password PASSWORD2", source)
        self.assertIn('3<<<"$PASSWORD"', source)
        self.assertIn('unset PASSWORD PASSWORD2', source)
        for sourcefile in (SETUP, HELPER):
            result = subprocess.run(["bash", "-n", str(sourcefile)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
