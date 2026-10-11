"""Operator-safe, no-Docker A1 migration regression tests.

The fake Docker binary only returns a disposable inactive-token response.
No VPS, secrets, network or actual container is accessed.
"""
from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

SOURCE=Path(__file__).resolve().parents[2]/"scripts/prepare-https-introspection.sh"
LEGACY="http://zitadel-auth-internal:8080/oauth/v2/introspect"
TARGET="https://mcp.example.invalid/oauth/v2/introspect"

class HTTPSMigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        (self.root/"scripts").mkdir()
        shutil.copyfile(SOURCE,self.root/"scripts/prepare-https-introspection.sh")
        (self.root/"bin").mkdir()
        docker=self.root/"bin/docker"
        docker.write_text("""#!/bin/sh
if [ "$PORTICO_FAKE_DOCKER_MODE" = "fail" ]; then exit 23; fi
# The only container command accepted by this mock must use stdin curl config.
case "$*" in
  *"--user "*|*"disposable-secret"*) exit 48 ;;
esac
case "$*" in
  *"--config -"*) ;;
  *) exit 49 ;;
esac
printf '%s\\n' '{"active":false}'
""")
        docker.chmod(0o700)
        self.env=self.root/".env"
        self.env.write_text(
            "VPS_AGENT_AUTH_MODE=integrated\n"
            "VPS_AGENT_DOMAIN=mcp.example.invalid\n"
            "VPS_AGENT_INTEGRATED_INTROSPECTION_URL="+LEGACY+"\n"
            "VPS_AGENT_INTEGRATED_INTROSPECTION_CLIENT_ID=test-id\n"
            "VPS_AGENT_INTEGRATED_INTROSPECTION_CLIENT_SECRET=disposable-secret\n"
            "VPS_AGENT_WHOLE_HOST=0\nVPS_AGENT_BUNDLED_PROXY=0\n"
        )
        self.env.chmod(0o600)
    def run_helper(self, mode, fake="ok"):
        env={**os.environ, "PATH":str(self.root/"bin")+os.pathsep+os.environ.get("PATH",""),
            "PORTICO_FAKE_DOCKER_MODE":fake}
        return subprocess.run(["bash",str(self.root/"scripts/prepare-https-introspection.sh"),mode],
                              cwd=self.root,env=env,capture_output=True,text=True,timeout=25)

    def test_probe_does_not_expose_credentials_in_process_arguments(self):
        source=SOURCE.read_text()
        self.assertIn("curl -q --config -",source)
        self.assertNotIn("--user ",source)
        run=self.run_helper("--check")
        self.assertEqual(run.returncode,0,run.stderr)
        self.assertNotIn("disposable-secret",run.stdout+run.stderr)

    def test_default_dry_run_is_read_only(self):
        before=self.env.read_bytes()
        run=self.run_helper("--check")
        self.assertEqual(run.returncode,0,run.stderr)
        self.assertEqual(self.env.read_bytes(),before)
        self.assertFalse((self.root/"backups").exists())

    def test_apply_atomic_migration_retains_restricted_backup(self):
        run=self.run_helper("--apply")
        self.assertEqual(run.returncode,0,run.stderr)
        self.assertIn("VPS_AGENT_INTEGRATED_INTROSPECTION_URL="+TARGET,self.env.read_text())
        self.assertEqual(self.env.stat().st_mode & 0o777,0o600)
        copies=list((self.root/"backups").glob("https-introspection.*/previous.env"))
        self.assertEqual(len(copies),1)
        self.assertIn("VPS_AGENT_INTEGRATED_INTROSPECTION_URL="+LEGACY,copies[0].read_text())
        self.assertEqual(copies[0].stat().st_mode & 0o777,0o600)
        self.assertIn("No services restarted",run.stdout)

    def test_probe_failure_must_not_mutate_configuration(self):
        before=self.env.read_bytes()
        run=self.run_helper("--apply","fail")
        self.assertNotEqual(run.returncode,0)
        self.assertEqual(self.env.read_bytes(),before)
        self.assertFalse((self.root/"backups").exists())

    def test_unknown_http_endpoint_never_overwritten(self):
        before=self.env.read_text()
        self.env.write_text(before.replace(LEGACY,"http://custom-host.invalid/introspect"))
        state=self.env.read_bytes()
        run=self.run_helper("--apply")
        self.assertNotEqual(run.returncode,0)
        self.assertEqual(self.env.read_bytes(),state)

    def test_migration_roundtrip_backup_restore_in_disposable_directory(self):
        original=self.env.read_bytes()
        applied=self.run_helper("--apply")
        self.assertEqual(applied.returncode,0,applied.stderr)
        migrated=self.env.read_bytes()
        self.assertNotEqual(original,migrated)
        self.assertIn(TARGET,self.env.read_text())
        checked=self.run_helper("--check")
        self.assertEqual(checked.returncode,0,checked.stderr)
        self.assertEqual(self.env.read_bytes(),migrated)
        backups=list((self.root/"backups").glob("https-introspection.*/previous.env"))
        self.assertEqual(len(backups),1)
        self.assertEqual(backups[0].read_bytes(),original)
        # Rehearse operator-controlled restore, without any real Docker/VPS.
        shutil.copyfile(backups[0],self.env)
        self.env.chmod(0o600)
        self.assertEqual(self.env.read_bytes(),original)
        self.assertEqual(self.env.stat().st_mode & 0o777,0o600)

    def test_preflight_observes_well_formed_inactive_token_response(self):
        before=self.env.read_bytes()
        docker=self.root/"bin/docker"
        docker.write_text("""#!/bin/sh
printf '%s\\n' '{"active":true}'
""")
        docker.chmod(0o700)
        result=self.run_helper("--apply")
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(self.env.read_bytes(),before)
        self.assertFalse((self.root/"backups").exists())

    def test_unknown_config_not_overwritten_and_secrets_not_reported(self):
        original=self.env.read_text()
        self.env.write_text(original.replace(LEGACY,"https://unknown.example.invalid/introspect"))
        result=self.run_helper("--apply")
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn("disposable-secret",result.stdout+result.stderr)
        self.assertFalse((self.root/"backups").exists())

    def test_symlinked_env_rejected_without_mutation(self):
        path=self.root/"real.env"
        self.env.rename(path)
        self.env.symlink_to(path)
        run=self.run_helper("--apply")
        self.assertNotEqual(run.returncode,0)
        self.assertIn("unsafe",run.stderr)
        self.assertIn(LEGACY,path.read_text())

if __name__=="__main__":
    unittest.main()
