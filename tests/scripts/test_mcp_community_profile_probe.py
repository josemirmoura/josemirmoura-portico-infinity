"""Mutation/negative tests: the normal MCP profile verifier must fail closed."""
from __future__ import annotations
import importlib.util
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
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
        if method == "resources/templates/list":
            return ok({"resourceTemplates": []})
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

    def test_synthetic_resource_template_is_blocked(self):
        f = FakeGateway()
        original = f.rpc
        def fake_rpc(url, method, params, ident, *, origin=None):
            if method == "resources/templates/list":
                return 200, {"jsonrpc":"2.0", "id":ident, "result":{
                    "resourceTemplates":[{"name":"fake", "uriTemplate":"test://secret/{id}"}]
                }}
            return original(url, method, params, ident, origin=origin)
        with patch.object(module, "rpc", side_effect=fake_rpc):
            with self.assertRaisesRegex(module.ProfileFailure, "synthetic resource template"):
                module.probe(URL)

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

    def test_redirect_is_refused_without_followup_even_on_loopback(self):
        observed = []
        class RedirectingGateway(BaseHTTPRequestHandler):
            def do_POST(self):
                observed.append(self.path)
                if self.path == "/mcp":
                    self.send_response(302)
                    self.send_header("Location", "http://127.0.0.1:%d/remote" % self.server.server_port)
                    self.end_headers()
                else:
                    # This route must never be requested.
                    self.send_response(200)
                    self.end_headers()
            def do_GET(self):
                observed.append(self.path)
                self.send_response(200)
                self.end_headers()
            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), RedirectingGateway)
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = "http://127.0.0.1:%d/mcp" % server.server_port
            with self.assertRaisesRegex(module.ProfileFailure, "redirect"):
                module.rpc(url, "server/discover", {"_meta": module.META}, 31)
            self.assertEqual(observed, ["/mcp"], "verifier followed a redirect")
        finally:
            server.shutdown()
            thread.join(timeout=3)
            server.server_close()

    def test_transport_disables_environment_proxies(self):
        from urllib.request import ProxyHandler
        # An explicit empty ProxyHandler must be installed for EVERY request.
        with patch.object(module, "build_opener", wraps=module.build_opener) as build:
            with self.assertRaises(module.ProfileFailure):
                module.rpc("http://127.0.0.1:1/mcp", "server/discover", {"_meta": module.META}, 32)
            self.assertTrue(build.called)
            handlers = build.call_args.args
            self.assertTrue(any(isinstance(h, ProxyHandler) and h.proxies == {} for h in handlers))
            self.assertTrue(any(isinstance(h, module.DenyRedirect) for h in handlers))

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
