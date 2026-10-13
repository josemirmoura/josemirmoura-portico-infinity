"""Ensure the connection prompt links multiclient docs without weakening E2E (#159)."""
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
CONNECT = ROOT / "scripts" / "connect-chatgpt.sh"
PT = ROOT / "docs" / "connect-ai-clients.pt-BR.md"
EN = ROOT / "docs" / "connect-ai-clients.md"


class AIClientConnectionGuideTests(unittest.TestCase):
    def test_shell_syntax(self):
        proc = subprocess.run(["bash", "-n", str(CONNECT)], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_docs_exist_and_show_multiple_clients(self):
        for path in (PT, EN):
            with self.subTest(path=path):
                self.assertTrue(path.is_file())
                content = path.read_text(encoding="utf-8")
                for name in ("ChatGPT", "Claude", "Cursor", "VS Code"):
                    self.assertIn(name, content)
                self.assertIn("https://YOUR-DOMAIN/mcp" if path == EN
                              else "https://SEU-DOMINIO/mcp", content)

    def test_terminal_points_to_real_repo_docs(self):
        source = CONNECT.read_text(encoding="utf-8")
        for name in ("connect-ai-clients.md", "connect-ai-clients.pt-BR.md"):
            with self.subTest(name=name):
                self.assertIn(
                    "https://github.com/josemirmoura/mcp-vps-agent-gateway/blob/${documentation_ref}/docs/" + name,
                    source,
                )

    def test_docs_are_pinned_to_running_checkout(self):
        source = CONNECT.read_text(encoding="utf-8")
        self.assertIn("git rev-parse --verify HEAD", source)
        self.assertNotIn("blob/main/docs/connect-ai-clients.", source)

    def test_chatgpt_audit_gate_still_required(self):
        source = CONNECT.read_text(encoding="utf-8")
        self.assertIn("wait-tool", source)
        self.assertIn("--subject \"$SUBJECT\" --tool system.info", source)
        self.assertIn("verify_now", source)
        self.assertIn("INSTALLATION COMPLETE", source)
        self.assertIn("CHATGPT WEB CONNECTION VERIFIED", source)
        self.assertIn("Call system.info on my VPS MCP", source)


if __name__ == "__main__":
    unittest.main()
