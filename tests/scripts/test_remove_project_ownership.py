"""Regression for fail-closed Portico removal from foreign Docker checkouts.

Executes only the isolated shell ownership guard with a fake Docker function.
Never accesses host Docker, Pórtico, or real files outside temporary test dirs.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[2] / "scripts/remove.sh"
START = "# BEGIN REMOVE PROJECT OWNERSHIP GUARD"
END = "# END REMOVE PROJECT OWNERSHIP GUARD"


class RemoveProjectOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="portico-remove-owner-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.log = self.root / "docker.log"
        source = SOURCE.read_text()
        self.assertEqual(source.count(START), 1)
        self.assertEqual(source.count(END), 1)
        self.assertLess(source.index('repo_root="$PWD"'), source.index(START))
        self.assertLess(source.index(END), source.index('if [ -f .env ]; then'))
        self.assertLess(source.index(END), source.index('\nproject_ids="$(docker ps'))
        self.guard = source[source.index(START):source.index(END) + len(END)]

    def execute(self, *, project="mcp-vps-agent", ids="deadc0dedead\nfeedfacefeed",
                owner=None, second_owner=None, project_label="mcp-vps-agent",
                mode="safe", volumes="", networks="", images=""):
        code = r"""
set -euo pipefail
repo_root="$PWD"
mode="$MOCK_MODE"
docker() {
  printf '%s\n' "$*" >> "$MOCK_DOCKER_LOG"
  if [ "$1" = ps ]; then
    printf '%s\n' "$MOCK_IDS"
    return 0
  fi
  if [ "$1" = volume ] && [ "$2" = ls ]; then
    printf '%s\n' "$MOCK_VOLUMES"
    return 0
  fi
  if [ "$1" = network ] && [ "$2" = ls ]; then
    printf '%s\n' "$MOCK_NETWORKS"
    return 0
  fi
  if [ "$1" = image ] && [ "$2" = ls ]; then
    printf '%s\n' "$MOCK_IMAGES"
    return 0
  fi
  if [ "$1" = inspect ]; then
    if [[ "$3" == *working_dir* ]]; then
      if [ "$4" = feedfacefeed ]; then
        printf '%s\n' "$MOCK_SECOND_OWNER"
      else
        printf '%s\n' "$MOCK_OWNER"
      fi
    else
      printf '%s\n' "$MOCK_PROJECT_LABEL"
    fi
    return 0
  fi
  return 94
}
"""
        env = dict(
            os.environ, COMPOSE_PROJECT_NAME=project, MOCK_IDS=ids,
            MOCK_OWNER=owner if owner is not None else str(self.root),
            MOCK_SECOND_OWNER=second_owner if second_owner is not None else str(self.root),
            MOCK_PROJECT_LABEL=project_label,
            MOCK_DOCKER_LOG=str(self.log), MOCK_MODE=mode,
            MOCK_VOLUMES=volumes, MOCK_NETWORKS=networks, MOCK_IMAGES=images,
        )
        run = subprocess.run(["bash", "-c", code + "\n" + self.guard +
                              "\nprintf 'REMOVE_OWNER_OK\n'"],
                             cwd=self.root, env=env, capture_output=True,
                             text=True, timeout=10, check=False)
        calls = self.log.read_text().splitlines() if self.log.exists() else []
        self.assertFalse(any(" down" in c or " rm " in c or " exec " in c
                             for c in calls), calls)
        return run, calls

    def test_foreign_checkout_fails_before_removal(self):
        run, _ = self.execute(owner="/opt/other-checkout")
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("another checkout", run.stderr)

    def test_second_foreign_container_fails_before_removal(self):
        run, _ = self.execute(second_owner="/opt/other-checkout")
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("another checkout", run.stderr)

    def test_wrong_project_env_fails_without_docker(self):
        run, calls = self.execute(project="portico-gate-c-lab")
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("canonical", run.stderr)
        self.assertEqual(calls, [])

    def test_foreign_project_label_fails(self):
        run, _ = self.execute(project_label="different-project")
        self.assertNotEqual(run.returncode, 0)

    def test_ambiguous_container_ids_fail(self):
        run, _ = self.execute(ids="not-a-container")
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("unexpected", run.stderr)

    def test_exact_owner_allows_guard(self):
        run, calls = self.execute()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("REMOVE_OWNER_OK", run.stdout)
        self.assertEqual(len(calls), 5)

    def test_orphaned_identity_volume_refuses_purge(self):
        run, calls = self.execute(ids="", mode="--purge",
                                  volumes="mcp-vps-agent_zitadel-postgres-data")
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("manual ownership verification", run.stderr)
        self.assertFalse(any(" rm " in c for c in calls))

    def test_orphaned_project_network_refuses_purge(self):
        run, _ = self.execute(ids="", mode="--purge",
                              networks="mcp-vps-agent_default")
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("REMOVE BLOCKED", run.stderr)

    def test_orphaned_local_image_refuses_purge(self):
        run, _ = self.execute(ids="", mode="--purge",
                              images="mcp-vps-agent-broker:local")
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("REMOVE BLOCKED", run.stderr)

    def test_absent_docker_resources_allow_idempotent_purge(self):
        run, calls = self.execute(ids="", mode="--purge")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(len(calls), 4)

    def test_safe_removal_without_containers_does_not_delete_orphans(self):
        run, calls = self.execute(ids="", mode="safe",
                                  volumes="mcp-vps-agent_zitadel-bootstrap")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(len(calls), 1)

    def test_project_absent_allows_idempotent_remove(self):
        run, calls = self.execute(ids="")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
