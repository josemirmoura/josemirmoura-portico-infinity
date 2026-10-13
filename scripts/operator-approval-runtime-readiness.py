#!/usr/bin/env python3
"""Read-only, secret-free readiness check for a running Portico operator portal.

Run by the trusted host operator. Requires Docker read permission; never print
docker inspect payloads, environment values, passwords, tokens or cookies.
Does not run docker compose, modify containers, read .env or execute shell.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from urllib.parse import urlsplit

PROJECT_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,80}\Z")
SCOPES = ("broker", "gateway", "operator-portal")


def variables(container: dict) -> dict[str, str]:
    # Private and never returned to the caller or printed.
    result: dict[str, str] = {}
    for line in container.get("Config", {}).get("Env") or []:
        if isinstance(line, str) and "=" in line:
            key, value = line.split("=", 1)
            result[key] = value
    return result


def valid_portal_url(raw: str, origin: str) -> bool:
    try:
        u, o = urlsplit(raw), urlsplit(origin)
        return (
                u.scheme == "https" and bool(u.netloc) and u.path == "/operator" and
                not u.username and not u.password and not u.query and not u.fragment and
                o.scheme == "https" and bool(o.netloc) and o.netloc == u.netloc and
                o.path in ("", "/") and not o.username and not o.password and
                not o.query and not o.fragment and
                # Accessing .port checks for an invalid numeric port.
                u.port == o.port
            )
    except ValueError:
        return False


def report(containers: list[dict], project: str) -> dict:
    services: dict[str, dict] = {}
    for item in containers:
        labels = item.get("Config", {}).get("Labels") or {}
        if labels.get("com.docker.compose.project") != project:
            continue
        service = labels.get("com.docker.compose.service")
        if service in SCOPES:
            services[service] = item

    flags: dict[str, bool] = {}
    for svc in SCOPES:
        obj = services.get(svc, {})
        flags[svc.replace("-", "_") + "_running"] = (
            obj.get("State", {}).get("Running") is True
        )

    g = variables(services.get("gateway", {}))
    b = variables(services.get("broker", {}))
    p = variables(services.get("operator-portal", {}))
    gateway_url = g.get("VPS_AGENT_OPERATOR_PORTAL_URL", "")
    origin = p.get("PORTICO_OPERATOR_PUBLIC_ORIGIN", "")
    flags["gateway_https_operator_url_present"] = bool(
        gateway_url.startswith("https://")
    )
    flags["portal_https_origin_present"] = bool(origin.startswith("https://"))
    flags["gateway_portal_url_matches_origin"] = valid_portal_url(
        gateway_url, origin
    )
    flags["portal_password_verifier_present"] = bool(
        p.get("PORTICO_OPERATOR_PASSWORD_SCRYPT")
    )
    # Compare token only in process memory; never print or return its value.
    broker_token = b.get("VPS_AGENT_OPERATOR_APPROVAL_TOKEN", "")
    portal_token = p.get("PORTICO_OPERATOR_APPROVAL_TOKEN", "")
    flags["portal_broker_token_match"] = bool(
        len(broker_token) >= 32 and broker_token == portal_token
    )
    flags["portal_operator_id_matches_broker"] = bool(
        p.get("PORTICO_OPERATOR_ID")
        and p.get("PORTICO_OPERATOR_ID") == b.get("VPS_AGENT_OPERATOR_ID")
    )
    flags["portal_node_id_matches_gateway"] = bool(
        p.get("PORTICO_OPERATOR_NODE_ID")
        and p.get("PORTICO_OPERATOR_NODE_ID") == g.get("VPS_AGENT_INSTANCE_ID")
    )
    labels = services.get("operator-portal", {}).get("Config", {}).get("Labels") or {}
    flags["operator_traefik_router_declared"] = bool(
        labels.get("traefik.http.routers.vps-agent-operator.rule")
        and labels.get("traefik.enable") == "true"
    )
    flags["apps_not_required_for_external_https"] = True

    if not flags["gateway_running"] or not flags["broker_running"]:
        state = "GATEWAY_OR_BROKER_NOT_RUNNING"
    elif not flags["gateway_https_operator_url_present"]:
        state = "GATEWAY_MISSING_OPERATOR_URL"
    elif not flags["operator_portal_running"]:
        state = "OPERATOR_PORTAL_NOT_RUNNING"
    elif not all(flags.values()):
        state = "PORTAL_CONFIGURATION_INCOMPLETE"
    else:
        state = "CONFIGURED_NOT_BROWSER_VERIFIED"
    return {
        "project": project,
        "status": state,
        "checks": flags,
        "warning": "Not proof of HTTPS reachability, browser login or Broker grant. No changes made.",
    }


def docker_inspect(project: str) -> list[dict]:
    ids = subprocess.run(
        ["docker", "ps", "-aq",
         "--filter", "label=com.docker.compose.project=" + project],
        capture_output=True, text=True, timeout=12, check=True,
    ).stdout.splitlines()
    if not ids:
        return []
    if len(ids) > 250:
        raise ValueError("too many containers for bounded inspection")
    proc = subprocess.run(
        ["docker", "inspect", *ids],
        capture_output=True, text=True, timeout=25, check=True,
    )
    if len(proc.stdout) > 20_000_000:
        raise ValueError("container metadata exceeds memory safety bound")
    result = json.loads(proc.stdout)
    if not isinstance(result, list):
        raise ValueError("unexpected Docker response type")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Non-mutating runtime check; print booleans only."
    )
    parser.add_argument("--project", default="mcp-vps-agent")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if not PROJECT_RE.fullmatch(args.project):
        parser.error("invalid Compose project name")
    try:
        result = report(docker_inspect(args.project), args.project)
    except (OSError, ValueError, subprocess.SubprocessError, json.JSONDecodeError):
        print("PORTICO_OPERATOR_RUNTIME: UNAVAILABLE (cannot inspect Docker safely)")
        return 2
    if args.json:
        print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    else:
        print("PORTICO_OPERATOR_RUNTIME: " + result["status"])
        for name, value in result["checks"].items():
            print("  " + name + ": " + ("YES" if value else "NO"))
        print("  Live HTTPS/login/grants: NOT_TESTED")
        print("  No Docker changes; no configuration values printed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
