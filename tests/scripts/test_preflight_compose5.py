#!/usr/bin/env python3
"""Regression tests for the operator preflight (no Docker or package changes)."""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import pathlib
import sys
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "preflight.py"
spec = importlib.util.spec_from_file_location("portico_preflight", SCRIPT)
assert spec is not None and spec.loader is not None
preflight = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = preflight
spec.loader.exec_module(preflight)


class ComposePreflightTests(unittest.TestCase):
    def run_preflight(self, compose_version: str, compose_rc: int = 0) -> dict:
        def simulated_cmd(*args: str) -> tuple[int, str]:
            if args[:2] == ("docker", "version"):
                return 0, "29.7.1"
            if args[:3] == ("docker", "compose", "version"):
                return compose_rc, compose_version
            if args[:2] == ("git", "rev-parse"):
                return 0, "true"
            return 0, ""

        stdout = io.StringIO()
        with (
            mock.patch.object(preflight, "cmd", side_effect=simulated_cmd),
            mock.patch.object(preflight.shutil, "which", side_effect=lambda binary: "/usr/bin/" + binary),
            mock.patch.object(preflight.sys, "argv", ["preflight.py", "--json"]),
            contextlib.redirect_stdout(stdout),
        ):
            preflight.main()
        return json.loads(stdout.getvalue())

    def compose_check(self, version: str, rc: int = 0) -> dict:
        result = self.run_preflight(version, rc)
        return next(check for check in result["checks"] if check["key"] == "compose")

    def test_docker_compose_v2_remains_supported(self) -> None:
        self.assertEqual(self.compose_check("2.39.4")["status"], "ok")

    def test_docker_compose_v5_is_supported(self) -> None:
        result = self.compose_check("5.3.1")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["detail"], "5.3.1")

    def test_unapproved_major_not_described_as_missing(self) -> None:
        result = self.compose_check("3.0.0")
        self.assertEqual(result["status"], "fail")
        self.assertIn("unsupported", result["detail"])

    def test_unavailable_compose_fails(self) -> None:
        result = self.compose_check("", 1)
        self.assertEqual(result["status"], "fail")
        self.assertIn("not installed", result["detail"])

    def test_ubuntu_repair_commands_are_printed_only(self) -> None:
        checks = [
            preflight.Check("git", "Git", "fail", "not found"),
            preflight.Check("ss", "ss", "fail", "not found"),
            preflight.Check("compose", "Docker Compose", "fail", "unsupported version 3.0"),
        ]
        stdout = io.StringIO()
        with (
            mock.patch.object(preflight.shutil, "which", return_value="/usr/bin/apt-get"),
            mock.patch.object(preflight.platform, "freedesktop_os_release", return_value={"ID": "ubuntu"}),
            contextlib.redirect_stdout(stdout),
        ):
            preflight.print_package_repair(checks)
        output = stdout.getvalue()
        self.assertIn("sudo apt-get update", output)
        self.assertIn("sudo apt-get install git iproute2", output)
        self.assertNotIn("install docker", output)

    def test_non_apt_host_does_not_receive_apt_commands(self) -> None:
        checks = [preflight.Check("git", "Git", "fail", "not found")]
        stdout = io.StringIO()
        with (
            mock.patch.object(preflight.shutil, "which", return_value=None),
            contextlib.redirect_stdout(stdout),
        ):
            preflight.print_package_repair(checks)
        self.assertEqual(stdout.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
