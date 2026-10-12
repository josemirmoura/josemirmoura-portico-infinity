"""Fail-closed checkout ownership regression for the Community release updater.

Only a selected shell guard is executed, with Docker mocked as a shell function.
No actual Docker daemon, production checkout, network or credentials are used.
"""
from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

UPDATER = Path(__file__).resolve().parents[2] / "scripts/update.sh"
BEGIN = "# BEGIN UPDATE PROJECT OWNERSHIP GUARD"
END = "# END UPDATE PROJECT OWNERSHIP GUARD"


class UpdateProjectOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="portico-project-guard-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        source = UPDATER.read_text(encoding="utf-8")
        self.assertEqual(source.count(BEGIN), 1)
        self.assertEqual(source.count(END), 1)
        self.assertLess(source.index("verify-update-publication.py"), source.index(BEGIN))
        self.assertLess(source.index(BEGIN), source.index('"\${compose[@]}" stop'.replace("\\", "")))
        self.guard = source[source.index(BEGIN):source.index(END) + len(END)]
        self.log = self.root / "docker.log"

    def check(self, *, project="mcp-vps-agent", owner=None,
              label="mcp-vps-agent", broker_id="deadbeefdead"):
        # These commands are entirely mocked inside the bash subprocess.
        mock = r"""
set -euo pipefail
compose=(docker compose -f compose.yaml)
docker() {
    printf '%s\n' "$*" >> "$TEST_DOCKER_LOG"
    if [ "$1" = compose ]; then
        printf '%s\n' "$MOCK_BROKER_ID"
        return 0
    fi
    if [ "$1" = inspect ]; then
        if [[ "$3" == *working_dir* ]]; then
            printf '%s\n' "$MOCK_OWNER"
        else
            printf '%s\n' "$MOCK_PROJECT_LABEL"
        fi
        return 0
    fi
    return 98
}
"""
        script = mock + "\n" + self.guard + "\nprintf 'GUARD_OK\n'\n"
        env = dict(os.environ,
                   COMPOSE_PROJECT_NAME=project,
                   MOCK_BROKER_ID=broker_id,
                   MOCK_OWNER=owner if owner is not None else str(self.root),
                   MOCK_PROJECT_LABEL=label,
                   TEST_DOCKER_LOG=str(self.log))
        result = subprocess.run(["bash", "-c", script], cwd=self.root,
                                env=env, capture_output=True, text=True,
                                timeout=10, check=False)
        commands = self.log.read_text().splitlines() if self.log.exists() else []
        self.assertFalse(any(" stop" in c or " run " in c for c in commands))
        return result, commands

    def test_wrong_compose_project_fails_before_any_docker_call(self):
        r, cmds = self.check(project="portico-gate-c-lab")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("canonical", r.stderr)
        self.assertEqual(cmds, [])

    def test_other_checkout_cannot_manage_running_production_broker(self):
        r, cmds = self.check(owner="/home/other-user/live-portico")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("different Docker project or checkout", r.stderr)
        self.assertTrue(any("inspect" in c for c in cmds))

    def test_different_broker_project_label_fails_closed(self):
        r, _ = self.check(label="foreign-project")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("different Docker project or checkout", r.stderr)

    def test_missing_broker_fails_closed(self):
        r, _ = self.check(broker_id="")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("expected exactly one", r.stderr)

    def test_unexpected_container_id_fails_closed(self):
        r, _ = self.check(broker_id="deadbeefdead\nfeedfacefeed")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("expected exactly one", r.stderr)

    def test_same_checkout_canonical_project_passes_guard(self):
        r, cmds = self.check()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("GUARD_OK", r.stdout)
        self.assertEqual(len(cmds), 3)


if __name__ == "__main__":
    unittest.main()
