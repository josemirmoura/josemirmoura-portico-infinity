"""Mutation/negative tests: the normal MCP profile verifier must fail closed."""
from __future__ import annotations
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[2] / "scripts/mcp_community_profile_probe.py"
spec = importlib.util.spec_from_file_location("portico_profile_probe", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
URL = "http://127.0.0.1:18997/mcp"

class FakeGateway:
    def __init__(self):
        self.capabilities = {"tools": {"listChanged": False}, "prompts": {}}
        self.tools = ["system.info", "permissions.status"]
        self.origin_rejected = True
        self.metadata_rejected = True
        self.completion_rejected = True
    def rpc(self, _url, method, params, ident, *, origin=None):
        def ok(result):
            return 200, {"jsonrpc": "2.0", "id": ident, "result": result}
        def err(status, code):
            return status, {"jsonrpc": "2.0", "id": ident, "error": {"code": code, "message": "rejected"}}
        if origin == "https://attacker.invalid":
            return (403, None) if self.origin_rejected else ok({"content": [{"type": "text", "text": "unsafe"}]})
        if method == "server/discover":
            if not params.get("_meta") and self.metadata_rejected:
                return err(400, -32602)
            return ok({"supportedVersions": ["2026-07-28"], "capabilities": self.capabilities})
        if method == "tools/list":
            return ok({"tools": [{"name": n} for n in self.tools]})
        if method == "prompts/list":
            return ok({"prompts": []})
        if method == "resources/list":
            return ok({"resources": []})
        if method == "tools/call":
            return ok({"content": [{"type": "text", "text": "safe"}]})
        if method == "completion/complete":
            return err(404, -32601) if self.completion_rejected else ok({"completion": {"values": []}})
        raise AssertionError(method)

class CommunityProfileProbeTests(unittest.TestCase):
    def run_fixture(self, f):
        with patch.object(module, "rpc", side_effect=f.rpc):
            return module.probe(URL)

    def test_realistic_profile_preserves_separate_gates(self):
        r = self.run_fixture(FakeGateway())
        self.assertTrue(r["profile_http_checks_passed"])
        self.assertFalse(r["full_frozen_37_suite_passed"])
        self.assertFalse(r["owner_client_acceptance_verified"])
        self.assertFalse(r["normative_gate_approved"])
        self.assertGreaterEqual(len(r["checks"]), 8)

    def test_unreviewed_optional_completion_announcement_is_blocked(self):
        f = FakeGateway()
        f.capabilities["completions"] = {}
        with self.assertRaisesRegex(module.ProfileFailure, "unreviewed optional"):
            self.run_fixture(f)

    def test_false_dynamic_list_change_announcement_is_blocked(self):
        f = FakeGateway()
        f.capabilities["tools"]["listChanged"] = True
        with self.assertRaisesRegex(module.ProfileFailure, "unreviewed optional"):
            self.run_fixture(f)

    def test_fake_test_tool_is_blocked(self):
        f = FakeGateway()
        f.tools.append("test_input_required_result_multi_round")
        with self.assertRaisesRegex(module.ProfileFailure, "synthetic diagnostic"):
            self.run_fixture(f)

    def test_invalid_origin_reaching_executor_is_blocked(self):
        f = FakeGateway()
        f.origin_rejected = False
        with self.assertRaisesRegex(module.ProfileFailure, "Origin"):
            self.run_fixture(f)

    def test_missing_metadata_not_enforced_is_blocked(self):
        f = FakeGateway()
        f.metadata_rejected = False
        with self.assertRaisesRegex(module.ProfileFailure, "mandatory request"):
            self.run_fixture(f)

    def test_unannounced_completion_executing_is_blocked(self):
        f = FakeGateway()
        f.completion_rejected = False
        with self.assertRaisesRegex(module.ProfileFailure, "unadvertised completion"):
            self.run_fixture(f)

    def test_refuses_network_or_credential_bearing_urls(self):
        urls = (
            "https://127.0.0.1:18997/mcp", "http://example.org:18997/mcp",
            "http://10.77.77.2:18997/mcp", "http://127.0.0.1:18997/wrong",
            "http://127.0.0.1:18997/mcp?secret=token",
            "http://user:pass@127.0.0.1:18997/mcp",
        )
        for url in urls:
            with self.subTest(url=url), self.assertRaises(module.ProfileFailure):
                module.loopback_endpoint(url)

    def test_failure_output_never_reports_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = FakeGateway()
            f.origin_rejected = False
            output = Path(tmp) / "evidence.json"
            with patch.object(module, "rpc", side_effect=f.rpc):
                rc = module.main(["--url", URL, "--output", str(output)])
            self.assertEqual(rc, 1)
            self.assertIn('"profile_http_checks_passed": false', output.read_text())

if __name__ == "__main__":
    unittest.main()
