"""Read-only runtime readiness contract for live HTTPS approval rollout."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts/operator-approval-runtime-readiness.py"
SECRET = "PRIVATE-OPERATOR-TOKEN-DO-NOT-PRINT-" + ("x" * 48)
PASSWORD = ("a" * 48) + ":" + ("b" * 64)
ORIGIN = "https://example.test"
PROJECT = "mcp-vps-agent"


def fake_container(service: str, env: dict[str, str], *, running=True):
    labels = {
        "com.docker.compose.project": PROJECT,
        "com.docker.compose.service": service,
    }
    if service == "operator-portal":
        labels.update({
            "traefik.enable": "true",
            "traefik.http.routers.vps-agent-operator.rule":
                "Host(" + ORIGIN + ") && PathPrefix(/operator)",
        })
    return {
        "Config": {
            "Labels": labels,
            "Env": [f"{key}={value}" for key, value in env.items()],
        },
        "State": {"Running": running},
    }


def ready_containers():
    return [
        fake_container("gateway", {
            "VPS_AGENT_OPERATOR_PORTAL_URL": ORIGIN + "/operator",
            "VPS_AGENT_INSTANCE_ID": "node-1",
        }),
        fake_container("broker", {
            "VPS_AGENT_OPERATOR_APPROVAL_TOKEN": SECRET,
            "VPS_AGENT_OPERATOR_ID": "owner-1",
        }),
        fake_container("operator-portal", {
            "PORTICO_OPERATOR_PUBLIC_ORIGIN": ORIGIN,
            "PORTICO_OPERATOR_PASSWORD_SCRYPT": PASSWORD,
            "PORTICO_OPERATOR_APPROVAL_TOKEN": SECRET,
            "PORTICO_OPERATOR_ID": "owner-1",
            "PORTICO_OPERATOR_NODE_ID": "node-1",
        }),
    ]


class RuntimeReadinessTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="portico-runtime-ready-")
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.bin = self.base / "bin"
        self.bin.mkdir()
        docker = self.bin / "docker"
        docker.write_text(
            '#!' + sys.executable + '\n'
            'import os,sys,json\n'
            'args=sys.argv[1:]\n'
            'if os.environ.get("MOCK_FAIL")=="1":\n'
            '  print("SECRET-SERVER-ERROR",file=sys.stderr);sys.exit(1)\n'
            'if args[0]=="ps":print("container-a");sys.exit(0)\n'
            'if args[0]=="inspect":print(open(os.environ["MOCK_DATA"]).read());sys.exit(0)\n'
            'sys.exit(1)\n', encoding="utf-8"
        )
        docker.chmod(0o700)
        self.data = self.base / "docker.json"
        self.env = dict(os.environ)
        self.env["PATH"] = str(self.bin) + os.pathsep + self.env.get("PATH", "")
        self.env["MOCK_DATA"] = str(self.data)

    def run_check(self, containers=None, **custom_env):
        self.data.write_text(json.dumps(containers if containers is not None else ready_containers()))
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--json"],
            capture_output=True, text=True,
            env=self.env | custom_env, timeout=12,
        )

    def test_healthy_topology_is_candidate_not_verified(self):
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "CONFIGURED_NOT_BROWSER_VERIFIED")
        self.assertTrue(all(payload["checks"].values()))
        self.assertNotIn(SECRET, result.stdout + result.stderr)
        self.assertNotIn(PASSWORD, result.stdout + result.stderr)
        self.assertNotIn(ORIGIN, result.stdout + result.stderr)

    def test_gateway_url_missing_reports_root_cause_not_secrets(self):
        containers = ready_containers()
        containers[0]["Config"]["Env"] = ["VPS_AGENT_INSTANCE_ID=node-1"]
        result = self.run_check(containers)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["status"], "GATEWAY_MISSING_OPERATOR_URL")

    def test_portal_not_running_stops_ready_label(self):
        containers = ready_containers()
        containers[2]["State"]["Running"] = False
        result = self.run_check(containers)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)["status"], "OPERATOR_PORTAL_NOT_RUNNING")

    def test_project_label_does_not_accept_foreign_container(self):
        containers = ready_containers()
        containers[2]["Config"]["Labels"]["com.docker.compose.project"] = "foreign-project"
        result = self.run_check(containers)
        self.assertEqual(json.loads(result.stdout)["status"], "OPERATOR_PORTAL_NOT_RUNNING")

    def test_mismatched_identity_and_approval_token_not_ready(self):
        containers = ready_containers()
        containers[2]["Config"]["Env"] = [
            val.replace(SECRET, SECRET+"different").replace("owner-1", "someone-else")
            for val in containers[2]["Config"]["Env"]
        ]
        result = self.run_check(containers)
        self.assertEqual(result.returncode, 1)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "PORTAL_CONFIGURATION_INCOMPLETE")
        self.assertFalse(payload["checks"]["portal_broker_token_match"])
        self.assertFalse(payload["checks"]["portal_operator_id_matches_broker"])
        self.assertNotIn(SECRET, result.stdout)

    def test_duplicate_service_fails_closed_independent_of_order(self):
        containers = ready_containers()
        stale = fake_container("gateway", {
            "VPS_AGENT_OPERATOR_PORTAL_URL": ORIGIN + "/operator",
            "VPS_AGENT_INSTANCE_ID": "node-1",
        }, running=False)
        for order in (containers + [stale], [stale] + containers):
            with self.subTest(last=order[-1]["State"]["Running"]):
                result = self.run_check(order)
                self.assertEqual(result.returncode, 1)
                payload = json.loads(result.stdout)
                self.assertEqual(payload["status"], "PORTAL_CONFIGURATION_INCOMPLETE")
                self.assertFalse(payload["checks"]["no_duplicate_service_containers"])
                self.assertNotIn(SECRET, result.stdout + result.stderr)

    def test_https_url_origin_mismatch_rejects_without_leaking_endpoint(self):
        containers = ready_containers()
        containers[0]["Config"]["Env"] = [
            line.replace(ORIGIN + "/operator", "https://other.example.test/operator")
            for line in containers[0]["Config"]["Env"]
        ]
        result = self.run_check(containers)
        self.assertEqual(result.returncode, 1)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "PORTAL_CONFIGURATION_INCOMPLETE")
        self.assertFalse(payload["checks"]["gateway_portal_url_matches_origin"])
        self.assertNotIn("other.example.test", result.stdout + result.stderr)

    def test_invalid_scrypt_verifier_rejected_without_disclosure(self):
        containers = ready_containers()
        containers[2]["Config"]["Env"] = [
            line.replace(PASSWORD, "not-a-valid-verifier")
            for line in containers[2]["Config"]["Env"]
        ]
        result = self.run_check(containers)
        self.assertEqual(result.returncode, 1)
        payload = json.loads(result.stdout)
        self.assertEqual(payload["status"], "PORTAL_CONFIGURATION_INCOMPLETE")
        self.assertFalse(payload["checks"]["portal_password_verifier_format_valid"])
        self.assertNotIn("not-a-valid-verifier", result.stdout + result.stderr)

    def test_docker_failure_is_redacted_and_fail_closed(self):
        result = self.run_check(MOCK_FAIL="1")
        self.assertEqual(result.returncode, 2)
        self.assertIn("UNAVAILABLE", result.stdout)
        self.assertNotIn("SECRET-SERVER-ERROR", result.stdout + result.stderr)

    def test_foreign_project_name_rejected_before_docker(self):
        self.data.write_text("[]")
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "--project", "../../unsafe"],
            capture_output=True, text=True, env=self.env, timeout=12,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid Compose project name", result.stderr)


if __name__ == "__main__":
    unittest.main()
