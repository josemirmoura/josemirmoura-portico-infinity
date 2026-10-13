"""Crash recovery and fail-closed operator bootstrap tests, all offline."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / "scripts/oauth-operator-reconcile.py"
SETUP = ROOT / "scripts/setup-integrated-auth.sh"
DOMAIN = "mcp.example.test"
USERNAME = "vps-operator"
EMAIL = "operator@example.test"


class OperatorRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="oauth-reconcile-")
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name) / "state"
        self.journal = self.state / "oauth-operator-create.json"
        self.marker = self.state / "integrated-auth.json"
        self.probe_file = Path(self.tmp.name) / "lookup.txt"

    def helper(self, *args):
        return subprocess.run([sys.executable, str(HELPER), *map(str, args)],
                              capture_output=True, text=True, timeout=10)

    def prepare(self, name=USERNAME, email=EMAIL):
        return self.helper("prepare", self.journal, DOMAIN, name, email)

    def response(self, http_code, payload):
        self.probe_file.write_text(
            json.dumps(payload) + "\n__PORTICO_HTTP_STATUS__" + str(http_code) + "\n"
        )

    def probe(self, planned_id, username=USERNAME, email=EMAIL):
        return self.helper("probe", self.probe_file, planned_id, username, email)

    def test_prepare_is_durable_private_and_idempotent(self):
        a = self.prepare()
        b = self.prepare()
        self.assertEqual(a.returncode, 0, a.stderr)
        self.assertEqual(b.returncode, 0, b.stderr)
        self.assertEqual(a.stdout, b.stdout)
        self.assertEqual(uuid.UUID(a.stdout.strip()).version, 4)
        self.assertEqual(self.journal.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.state.stat().st_mode & 0o777, 0o700)
        self.assertNotIn("password", self.journal.read_text().lower())
        self.assertNotIn("token", self.journal.read_text().lower())

    def test_changed_operator_is_blocked_before_post(self):
        a = self.prepare()
        b = self.prepare(email="someone-else@example.test")
        self.assertEqual(a.returncode, 0)
        self.assertNotEqual(b.returncode, 0)
        self.assertIn("differs", b.stderr)
        self.assertEqual(json.loads(self.journal.read_text())["id"], a.stdout.strip())

    def test_missing_user_is_distinct_from_network_or_server_error(self):
        ident = self.prepare().stdout.strip()
        self.response(404, {"code": 5, "message": "not found"})
        absent = self.probe(ident)
        self.assertEqual((absent.returncode, absent.stdout.strip()), (0, "ABSENT"), absent.stderr)
        for code, payload in [(403, {"code": 7}), (500, {"code": 13}),
                              (404, {"notZitadel": True})]:
            self.response(code, payload)
            blocked = self.probe(ident)
            self.assertNotEqual(blocked.returncode, 0)
            self.assertNotIn("ABSENT", blocked.stdout)
            self.assertNotIn("FOUND", blocked.stdout)

    def test_existing_matching_identity_recovery_without_new_post(self):
        ident = self.prepare().stdout.strip()
        self.response(200, {
            "user": {"userId": ident, "username": USERNAME,
                     "human": {"email": {"email": EMAIL, "isVerified": True}}}
        })
        result = self.probe(ident)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "FOUND")

    def test_wrong_id_username_email_and_nonhuman_are_rejected(self):
        ident = self.prepare().stdout.strip()
        examples = [
            {"userId": str(uuid.uuid4()), "username": USERNAME,
             "human": {"email": {"email": EMAIL}}},
            {"userId": ident, "username": "another-account",
             "human": {"email": {"email": EMAIL}}},
            {"userId": ident, "username": USERNAME,
             "human": {"email": {"email": "wrong@example.test"}}},
            {"userId": ident, "username": USERNAME, "machine": {}},
        ]
        for user in examples:
            with self.subTest(user=user):
                self.response(200, {"user": user})
                result = self.probe(ident)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("BLOCKED", result.stderr)

    def test_corrupted_private_journal_fails_closed(self):
        self.prepare()
        self.journal.write_text("not json")
        result = self.prepare()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("malformed", result.stderr)

    def test_world_readable_and_symlink_journal_blocked(self):
        self.prepare()
        self.journal.chmod(0o644)
        self.assertNotEqual(self.prepare().returncode, 0)
        self.journal.unlink()
        target = Path(self.tmp.name) / "target.json"
        target.write_text("{}")
        self.journal.symlink_to(target)
        self.assertNotEqual(self.prepare().returncode, 0)
        self.assertEqual(target.read_text(), "{}")

    def test_finalize_requires_exact_committed_identity(self):
        ident = self.prepare().stdout.strip()
        self.marker.write_text(json.dumps({
            "domain": DOMAIN, "subject": "different-id",
            "username": USERNAME, "email": EMAIL
        }))
        blocked = self.helper("finalize", self.journal, self.marker, ident)
        self.assertNotEqual(blocked.returncode, 0)
        self.assertTrue(self.journal.exists())
        self.marker.write_text(json.dumps({
            "domain": DOMAIN, "subject": ident,
            "username": USERNAME, "email": EMAIL,
        }))
        ok = self.helper("finalize", self.journal, self.marker, ident)
        self.assertEqual(ok.returncode, 0, ok.stderr)
        self.assertFalse(self.journal.exists())

    def test_installer_probes_before_post_and_preserves_journal_on_unknown(self):
        source = SETUP.read_text()
        begin = source.index("# BEGIN RESUMABLE OPERATOR CREATION")
        end = source.index("# END RESUMABLE OPERATOR CREATION")
        block = source[begin:end]
        self.assertLess(block.index("reconcile.py prepare"), block.index('PROBE_STATE="$(probe_operator_identity)"'))
        self.assertLess(block.index('PROBE_STATE="$(probe_operator_identity)"'),
                        block.index('--request POST'))
        self.assertIn("journal preserved", block)
        self.assertIn("reconcile.py finalize", block)
        self.assertIn('3<<<"$PASSWORD"', block)
        self.assertIn('unset PASSWORD PASSWORD2', block)
        result = subprocess.run(["bash", "-n", str(SETUP)],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
