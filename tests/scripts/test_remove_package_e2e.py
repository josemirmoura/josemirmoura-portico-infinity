"""Disposable mocked acceptance of the Portico removal package (#154)."""
from __future__ import annotations
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
REMOVE = ROOT / "scripts/remove.sh"
PRODUCT = ROOT / "scripts/lib/product.sh"


class RemovalPackageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="portico-purge-mock-")
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.log = self.dir / "docker.log"
        self.script = REMOVE.read_text(encoding="utf-8")
        self.fake = self.dir / "bin"
        self.fake.mkdir()
        (self.dir / "scripts/lib").mkdir(parents=True)
        shutil.copy2(REMOVE, self.dir / "scripts/remove.sh")
        shutil.copy2(PRODUCT, self.dir / "scripts/lib/product.sh")
        (self.dir / "VERSION").write_text("e2e-test\n")
        docker = self.fake / "docker"
        docker.write_text(r"""#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$MOCK_DOCKER_LOG"
if [ "$1" = "ps" ]; then exit 0; fi
if [ "$1" = "volume" ] && [ "$2" = "inspect" ]; then
  if [ "$3" = "--format" ]; then echo "$MOCK_VOLUME_OWNER"; fi
  exit 0
fi
if [ "$1" = "network" ] && [ "$2" = "ls" ]; then
  if [ -f "$MOCK_NETWORK_REMOVED" ]; then
    echo "traefik-public"
  else
    printf '%s\n' "mcp-vps-agent_default" "traefik-public"
  fi
  exit 0
fi
if [ "$1" = "network" ] && [ "$2" = "rm" ]; then
  touch "$MOCK_NETWORK_REMOVED"
  exit 0
fi
if [ "$1" = "network" ] && [ "$2" = "inspect" ]; then
  echo "mcp-vps-agent"
  exit 0
fi
if [ "$1" = "volume" ] && [ "$2" = "rm" ] && [ "$MOCK_FAIL_VOLUME_RM" = 1 ]; then
  exit 7
fi
exit 0
""")
        docker.chmod(0o755)
        self.env = os.environ | {
            "PATH": str(self.fake) + os.pathsep + os.environ.get("PATH", ""),
            "MOCK_DOCKER_LOG": str(self.log),
            "MOCK_NETWORK_REMOVED": str(self.dir / "network-removed"),
            "MOCK_VOLUME_OWNER": "mcp-vps-agent",
            "MOCK_FAIL_VOLUME_RM": "0",
            "VPS_AGENT_LANG": "en",
        }

    def commands(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_shell_syntax(self):
        run = subprocess.run(["bash", "-n", str(REMOVE)], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)

    def test_purge_preview_is_read_only_without_confirmation(self):
        result = subprocess.run(
            ["bash", "scripts/remove.sh", "--purge", "--dry-run"],
            cwd=self.dir, env=self.env, capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("REMOVAL PREVIEW", result.stdout)
        self.assertFalse(
            any(x.startswith(("rm ", "compose ", "exec ")) or " down " in x
                for x in self.commands()), self.commands()
        )

    def test_preview_never_sources_a_command_in_env(self):
        sentinel = self.dir / "should-never-be-created"
        (self.dir / ".env").write_text("COMMAND_SUBSTITUTION=$(touch " + str(sentinel) + ")\n")
        result = subprocess.run(
            ["bash", "scripts/remove.sh", "--purge", "--dry-run"],
            cwd=self.dir, env=self.env, capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("REMOVAL PREVIEW", result.stdout)
        self.assertFalse(sentinel.exists(), "preview must not evaluate shell code from .env")
    def test_env_cannot_change_compose_project_name(self):
        (self.dir / ".env").write_text("COMPOSE_PROJECT_NAME=foreign-project\n")
        env = self.env | {"VPS_AGENT_PURGE_CONFIRM": "PURGE"}
        result = subprocess.run(
            ["bash", "scripts/remove.sh", "--purge"],
            cwd=self.dir, env=env, capture_output=True, text=True, timeout=15,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("noncanonical Compose project", result.stderr)
        self.assertFalse(any(x.startswith("rm ") or " down " in x
                             for x in self.commands()))
    def test_optional_profile_is_included_in_compose_down(self):
        self.assertIn("compose=(docker compose --profile operator-portal -f compose.yaml)",
                      self.script)
        self.assertIn("down --remove-orphans", self.script)
        self.assertIn("com.docker.compose.project.working_dir", self.script)

    def test_all_package_volumes_are_named_and_verified(self):
        for name in ("broker-run", "operator-run", "zitadel-postgres-data",
                     "zitadel-bootstrap", "vps-agent-letsencrypt"):
            self.assertIn("mcp-vps-agent_" + name, self.script)
        self.assertIn('docker volume rm "$volume"', self.script)
        self.assertNotIn("docker volume rm   mcp-vps-agent_broker-run", self.script)

    def _run_purge_block(self, **overrides):
        start = self.script.index("# BEGIN VERIFIED PURGE RESOURCES")
        end = self.script.index("# END VERIFIED PURGE RESOURCES") + len(
            "# END VERIFIED PURGE RESOURCES"
        )
        env = self.env | overrides
        return subprocess.run(
            ["bash", "-c", 'set -euo pipefail\n'
             'compose=(docker compose --profile operator-portal -f compose.yaml)\n'
             'VPS_AGENT_EDGE_NETWORK=traefik-public\n'
             + self.script[start:end] + '\necho PURGE_BLOCK_OK\n'],
            cwd=self.dir, env=env, capture_output=True, text=True, timeout=15,
        )

    def test_labeled_volumes_removed_external_network_preserved(self):
        result = self._run_purge_block()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("PURGE_BLOCK_OK", result.stdout)
        calls = self.commands()
        self.assertEqual(sum(x.startswith("volume rm mcp-vps-agent_") for x in calls), 5)
        self.assertIn("network rm mcp-vps-agent_default", calls)
        self.assertFalse(any("network rm traefik-public" in x for x in calls))

    def test_foreign_owned_volume_fails_closed(self):
        result = self._run_purge_block(MOCK_VOLUME_OWNER="another-project")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("REMOVE BLOCKED", result.stderr)
        self.assertFalse(any(x.startswith("volume rm ") for x in self.commands()))

    def test_volume_removal_error_is_not_hidden(self):
        result = self._run_purge_block(MOCK_FAIL_VOLUME_RM="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("REMOVE INCOMPLETE", result.stderr)


if __name__ == "__main__":
    unittest.main()
