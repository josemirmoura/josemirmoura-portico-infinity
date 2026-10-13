"""Fail-closed removal regression tests for independent audit B2/B4 (#177)."""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class RemoveAuditGates(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="portico-audit-b2-b4-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "scripts/lib").mkdir(parents=True)
        shutil.copy2(ROOT / "scripts/remove.sh", self.root / "scripts/remove.sh")
        shutil.copy2(ROOT / "scripts/lib/product.sh", self.root / "scripts/lib/product.sh")
        (self.root / "VERSION").write_text("0.1.0-rc.7\n")
        binpath = self.root / "bin"
        binpath.mkdir()
        docker = binpath / "docker"
        docker.write_text("""#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$MOCK_LOG"
if [ "$1" = "ps" ]; then
  if [ "$MOCK_ACTIVE" = "1" ]; then echo deadbeef0000; fi
  exit 0
fi
if [ "$1" = "inspect" ]; then
  if [[ "$*" == *working_dir* ]]; then pwd -P; else echo mcp-vps-agent; fi
  exit 0
fi
if [ "$1" = "volume" ] && [ "$2" = "ls" ]; then
  if [ "$MOCK_FOREIGN_VOLUME" = "1" ]; then echo mcp-vps-agent_operator-run; fi
  exit 0
fi
if [ "$1" = "volume" ] && [ "$2" = "inspect" ]; then
  if [ "$MOCK_FOREIGN_VOLUME" = "1" ]; then echo foreign-project; else echo mcp-vps-agent; fi
  exit 0
fi
exit 0
""")
        docker.chmod(0o755)
        findmnt = binpath / "findmnt"
        findmnt.write_text("""#!/usr/bin/env bash
set -euo pipefail
echo /
if [ -n "$MOCK_MOUNT_TARGET" ]; then echo "$MOCK_MOUNT_TARGET"; fi
""")
        findmnt.chmod(0o755)
        self.log = self.root / "docker.log"
        self.env = os.environ | {
            "PATH": str(binpath) + os.pathsep + os.environ.get("PATH", ""),
            "MOCK_LOG": str(self.log),
            "MOCK_ACTIVE": "1",
            "MOCK_FOREIGN_VOLUME": "0",
            "MOCK_MOUNT_TARGET": "",
            "VPS_AGENT_PURGE_CONFIRM": "PURGE",
            "VPS_AGENT_LANG": "en",
        }

    def run_remove(self, *args, **env):
        return subprocess.run(
            ["bash", "scripts/remove.sh", *args],
            cwd=self.root, env=self.env | env, capture_output=True,
            text=True, timeout=15,
        )

    def assert_no_destructive_docker(self):
        calls = self.log.read_text().splitlines() if self.log.exists() else []
        self.assertFalse(any(
            call.startswith(("rm ", "volume rm ", "network rm ", "image rm "))
            or " down" in call or " exec" in call
            for call in calls
        ), calls)

    def test_dry_run_reveals_foreign_named_volume_without_mutation(self):
        result = self.run_remove("--purge", "--dry-run", MOCK_FOREIGN_VOLUME="1")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("mcp-vps-agent_operator-run [owner=foreign-project]", result.stdout)
        self.assertIn("FOREIGN/UNVERIFIED", result.stdout)
        self.assert_no_destructive_docker()

    def test_safe_without_env_and_live_containers_fails_closed(self):
        result = self.run_remove("safe")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("cannot confirm temporary grant revocation", result.stderr)
        self.assert_no_destructive_docker()

    def test_foreign_named_volume_blocks_purge_before_any_mutation(self):
        (self.root / ".env").write_text("COMPOSE_PROJECT_NAME=mcp-vps-agent\n")
        result = self.run_remove("--purge", MOCK_FOREIGN_VOLUME="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("foreign or unlabeled project-named volume", result.stderr)
        self.assert_no_destructive_docker()
        self.assertTrue((self.root / ".env").exists())

    def test_state_bind_mount_blocks_purge_before_mutation(self):
        (self.root / ".env").write_text("COMPOSE_PROJECT_NAME=mcp-vps-agent\n")
        state = self.root / "state"
        state.mkdir()
        (state / "foreign-data").write_text("preserve")
        result = self.run_remove("--purge", MOCK_MOUNT_TARGET=str(state))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("mountpoint at or beneath purge target", result.stderr)
        self.assert_no_destructive_docker()
        self.assertEqual((state / "foreign-data").read_text(), "preserve")

    def test_nested_mountpoint_under_backups_blocks(self):
        (self.root / ".env").write_text("COMPOSE_PROJECT_NAME=mcp-vps-agent\n")
        nested = self.root / "backups" / "thirdparty"
        nested.mkdir(parents=True)
        result = self.run_remove("--purge", MOCK_MOUNT_TARGET=str(nested))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("mountpoint at or beneath purge target", result.stderr)
        self.assert_no_destructive_docker()

    def test_state_symlink_to_external_directory_blocks(self):
        (self.root / ".env").write_text("COMPOSE_PROJECT_NAME=mcp-vps-agent\n")
        outside = self.root / "foreign-folder"
        outside.mkdir()
        (outside / "file").write_text("keep")
        (self.root / "state").symlink_to(outside, target_is_directory=True)
        result = self.run_remove("--purge")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("local purge target is a symlink", result.stderr)
        self.assert_no_destructive_docker()
        self.assertEqual((outside / "file").read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
