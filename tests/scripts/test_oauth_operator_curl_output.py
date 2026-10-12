"""Regression guards for the OAuth operator POST response path (#157).

The internal curl command runs in an ephemeral container. Its --output path
must exist *inside that container*, not merely under the host private /tmp.
This guards the exact HTTP 200 / curl exit 23 failure found during E2E.
The on-host Docker/HTTP end-to-end acceptance remains a separate gate.
"""
from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SETUP = ROOT / "scripts" / "setup-integrated-auth.sh"


class OperatorCurlOutputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.source = SETUP.read_text(encoding="utf-8")
        cls.operator_post = cls.source.split('HTTP_CODE="$(', 1)[1].split(
            '\n  CURL_STATUS=$?', 1
        )[0]

    def test_shell_parses(self):
        proc = subprocess.run(["bash", "-n", str(SETUP)], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)

    def test_post_does_not_write_to_unmounted_host_temp(self):
        self.assertIn('--output /dev/null', self.operator_post)
        self.assertNotIn('--output "$VPS_AGENT_SETUP_TMP/', self.operator_post)

    def test_status_remains_checked_before_persisting_subject(self):
        self.assertIn("--write-out '%{http_code}'", self.operator_post)
        self.assertIn('if [ "$CURL_STATUS" -ne 0 ]', self.source)
        self.assertIn('upsert_env VPS_AGENT_SUBJECT "$OPERATOR_ID"', self.source)

    def test_operator_post_executes_as_one_contiguous_command(self):
        # bash -n cannot detect a shell continuation broken by a comment.
        # Exercise the original POST stanza with a fake helper, never Docker.
        start = self.source.index('  HTTP_CODE="$(\\n')
        end = self.source.index('\\n  CURL_STATUS=$?', start)
        post = self.source[start:end]
        with tempfile.TemporaryDirectory(prefix="portico-oauth-test-") as td:
            root = Path(td)
            (root / "request.json").write_text("{}", encoding="utf-8")
            env = {
                **os.environ,
                "REQUEST_FILE": str(root / "request.json"),
                "ARG_FILE": str(root / "args.txt"),
                "BOOTSTRAP_PAT": "test-only",
                "ZITADEL_INTERACTIVE_USER_KIND": "human",
                "VPS_AGENT_SETUP_TMP": str(root / "host-temp"),
            }
            command = (
                "set -eu\\n"
                'curl_zitadel_internal() { printf "%s\\\\n" "$@" > "$ARG_FILE"; printf 200; }\\n'
                + post
                + '\\ntest "$HTTP_CODE" = 200\\n'
            )
            proc = subprocess.run(["bash", "-c", command], env=env,
                                  capture_output=True, text=True, timeout=10)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            args = (root / "args.txt").read_text(encoding="utf-8").splitlines()
            self.assertIn("--output", args)
            self.assertEqual(args[args.index("--output") + 1], "/dev/null")
            self.assertIn("--write-out", args)

    def test_no_stale_host_response_dump_on_error(self):
        self.assertNotIn(
            'cat "$VPS_AGENT_SETUP_TMP/vps-agent-create-operator.json"', self.source
        )


if __name__ == "__main__":
    unittest.main()
