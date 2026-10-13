"""Terminal welcome banner contract: English identity, Unicode and ASCII mode."""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]


class BannerTests(unittest.TestCase):
    def run_banner(self, *, language="pt-BR", locale="C.UTF-8", ascii_mode="0", columns="80"):
        env = os.environ | {
            "VPS_AGENT_LANG": language,
            "VPS_AGENT_BANNER_ASCII": ascii_mode,
            "COLUMNS": columns,
            "LC_ALL": locale,
        }
        return subprocess.run(
            ["bash", "-c", "source scripts/lib/product.sh; vps_agent_banner"],
            cwd=ROOT, env=env, text=True, capture_output=True, check=True,
        ).stdout

    def test_block_logo_and_english_identity_are_stable_in_pt_br(self):
        output = self.run_banner(language="pt-BR")
        self.assertEqual(sum("█" in line for line in output.splitlines()), 5)
        self.assertIn("Secure MCP Gateway for Linux Hosts", output)
        self.assertIn("Made by Josemir Moura | github.com/josemirmoura", output)
        self.assertIn("Version: 0.1.0-rc.7", output)
        self.assertNotIn("Feito por", output)
        self.assertNotIn("Versão:", output)
        self.assertEqual(len(set(len(line) for line in output.splitlines() if line.startswith(("+", "|")))), 1)
        self.assertEqual(len(next(line for line in output.splitlines() if line.startswith("+"))), 62)

    def test_identity_lines_are_invariant_across_languages(self):
        english = self.run_banner(language="en")
        portuguese = self.run_banner(language="pt-BR")
        self.assertEqual(english, portuguese)

    def test_ascii_fallback_is_usable_and_aligned(self):
        output = self.run_banner(ascii_mode="1")
        self.assertIn("| PORTICO MCP", output)
        self.assertNotIn("█", output)
        self.assertIn("Secure MCP Gateway for Linux Hosts", output)

    def test_non_utf8_and_narrow_terminal_use_ascii(self):
        for locale, columns in (("C", "80"), ("C.UTF-8", "48")):
            with self.subTest(locale=locale, columns=columns):
                out = self.run_banner(locale=locale, columns=columns)
                self.assertIn("PORTICO MCP", out)
                self.assertNotIn("█", out)


if __name__ == "__main__":
    unittest.main()
