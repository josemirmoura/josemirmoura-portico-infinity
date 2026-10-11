#!/usr/bin/env python3
"""Fail-closed MCP profile probe against the UNMODIFIED production Gateway binary.

These HTTP checks do not replace the official 37-scenario frozen conformance
results or operator acceptance. Only an isolated numeric loopback URL is safe.
"""
from __future__ import annotations
import argparse
import ipaddress
import json
from pathlib import Path
import sys
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

PROTOCOL = "2026-07-28"
MAX_RESPONSE = 1024 * 1024
META = {
    "io.modelcontextprotocol/protocolVersion": PROTOCOL,
    "io.modelcontextprotocol/clientInfo": {"name": "portico-profile-probe", "version": "1.0"},
    "io.modelcontextprotocol/clientCapabilities": {},
}

class ProfileFailure(RuntimeError):
    pass

def loopback_endpoint(url: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme != "http" or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ProfileFailure("refusing non-disposable or credential-bearing probe URL")
    if parsed.path != "/mcp" or parsed.port is None:
        raise ProfileFailure("expected explicit loopback port and /mcp path")
    try:
        ip = ipaddress.ip_address(parsed.hostname or "")
    except ValueError as exc:
        raise ProfileFailure("use a numeric loopback IP, never DNS") from exc
    if not ip.is_loopback:
        raise ProfileFailure("profile probe must not contact production hosts")

def rpc(url: str, method: str, params: dict, request_id: int, *, origin: str | None = None) -> tuple[int, dict | None]:
    body = json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}).encode()
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": PROTOCOL,
        "Mcp-Method": method,
    }
    if method == "tools/call":
        headers["Mcp-Name"] = params["name"]
    if origin is not None:
        headers["Origin"] = origin
    request = Request(url, data=body, headers=headers, method="POST")
    try:
        response = urlopen(request, timeout=8)
    except HTTPError as exc:
        response = exc
    except (URLError, TimeoutError, OSError) as exc:
        raise ProfileFailure("Gateway request failed on localhost") from exc
    with response:
        status = response.status
        if status == 403:
            return status, None
        raw = response.read(MAX_RESPONSE + 1)
        if len(raw) > MAX_RESPONSE:
            raise ProfileFailure("Gateway response exceeded the bounded limit")
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProfileFailure("non-JSON RPC response from disposable normal Gateway") from exc
    if not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0" or payload.get("id") != request_id:
        raise ProfileFailure("malformed JSON-RPC envelope or mismatched request id")
    return status, payload

def checked_result(status: int, response: dict | None, label: str) -> dict:
    if status != 200 or not isinstance(response, dict) or not isinstance(response.get("result"), dict):
        raise ProfileFailure(label + " did not return a successful MCP result")
    if response.get("error") is not None:
        raise ProfileFailure(label + " returned an MCP error")
    return response["result"]

def is_synthetic(name: str) -> bool:
    return name.startswith("test_") or name.startswith("conformance_")

def probe(url: str) -> dict:
    loopback_endpoint(url)
    checks: list[str] = []
    status, response = rpc(url, "server/discover", {"_meta": META}, 101)
    discovered = checked_result(status, response, "server/discover")
    if PROTOCOL not in discovered.get("supportedVersions", []):
        raise ProfileFailure("Gateway did not advertise the tested MCP protocol version")
    caps = discovered.get("capabilities")
    if not isinstance(caps, dict) or not isinstance(caps.get("tools"), dict):
        raise ProfileFailure("missing advertised tools capability")
    checks.append("real HTTP server/discover, protocol version and capabilities")

    # Preserve a truthful static profile. Any capability expansion requires a
    # real implementation and new security tests before advertisement.
    if "completions" in caps or any(
        isinstance(caps.get(section), dict) and caps[section].get("listChanged")
        for section in ("tools", "prompts", "resources")
    ):
        raise ProfileFailure("Gateway advertised an unreviewed optional capability")
    checks.append("unimplemented optional capabilities not advertised")

    tools: list[str] = []
    cursor = None
    for page in range(20):
        params: dict = {"_meta": META}
        if cursor is not None:
            params["cursor"] = cursor
        status, response = rpc(url, "tools/list", params, 200 + page)
        records = checked_result(status, response, "tools/list").get("tools")
        if not isinstance(records, list):
            raise ProfileFailure("tools/list omitted tools array")
        for record in records:
            if not isinstance(record, dict) or not isinstance(record.get("name"), str):
                raise ProfileFailure("invalid MCP tool descriptor")
            name = record["name"]
            if is_synthetic(name):
                raise ProfileFailure("synthetic diagnostic tool exposed in production catalog")
            if name in tools:
                raise ProfileFailure("duplicate tool in paginated catalog")
            tools.append(name)
        # The cursor is not allowed to cycle or leave the catalog uninspected.
        status_result = response["result"]
        next_cursor = status_result.get("nextCursor")
        if not next_cursor:
            break
        if not isinstance(next_cursor, str) or next_cursor == cursor:
            raise ProfileFailure("invalid or repeated pagination cursor")
        cursor = next_cursor
    else:
        raise ProfileFailure("tool catalog exceeded bounded pages, isolation unverified")
    if "system.info" not in tools or "permissions.status" not in tools:
        raise ProfileFailure("essential read-only Community tools absent")
    checks.append("production tool catalog inspected without synthetic fixtures")

    for method, key in (("prompts/list", "prompts"), ("resources/list", "resources")):
        status, response = rpc(url, method, {"_meta": META}, 301 if key == "prompts" else 302)
        items = checked_result(status, response, method).get(key)
        if not isinstance(items, list):
            raise ProfileFailure(method + " omitted array")
        for item in items:
            if not isinstance(item, dict):
                raise ProfileFailure("invalid resource/prompt entry")
            if any(is_synthetic(str(item.get(field, ""))) for field in ("name", "uri")):
                raise ProfileFailure("synthetic diagnostic resource or prompt exposed")
            if str(item.get("uri", "")).startswith("test://"):
                raise ProfileFailure("test:// fixture resource exposed")
    checks.append("production prompts/resources have no synthetic fixture")

    status, response = rpc(url, "tools/call", {"name": "system.info", "arguments": {}, "_meta": META}, 401)
    result = checked_result(status, response, "system.info")
    if result.get("isError") is True or not (result.get("content") or result.get("structuredContent")):
        raise ProfileFailure("real safe tool returned error or empty result")
    checks.append("real stateless tools/call executes safe Community operation")

    status, _ = rpc(url, "tools/call", {"name": "system.info", "arguments": {}, "_meta": META}, 402, origin="https://attacker.invalid")
    if status != 403:
        raise ProfileFailure("malicious HTTP Origin was not rejected before executor")
    checks.append("cross-origin HTTP request rejected 403")

    status, response = rpc(url, "server/discover", {}, 501)
    if status != 400 or not response or (response.get("error") or {}).get("code") != -32602:
        raise ProfileFailure("missing mandatory request _meta was not rejected 400/-32602")
    checks.append("missing stateless request metadata rejected")

    status, response = rpc(url, "completion/complete", {
        "ref": {"type": "ref/prompt", "name": "test_prompt_with_arguments"},
        "argument": {"name": "arg1", "value": "test"}, "_meta": META,
    }, 601)
    if status != 404 or not response or (response.get("error") or {}).get("code") != -32601:
        raise ProfileFailure("unadvertised completion/complete was not rejected 404/-32601")
    checks.append("unsupported optional completion rejected, not fabricated")

    return {
        "profile": "community-server-mcp-2026-07-28",
        "scope": "normal-production-binary-on-disposable-loopback",
        "checks": checks,
        "profile_http_checks_passed": True,
        "full_frozen_37_suite_passed": False,
        "owner_client_acceptance_verified": False,
        "normative_gate_approved": False,
        "warnings": [
            "These HTTP checks are not the official frozen 37-scenario conformance score.",
            "OAuth, scoped Broker and independent owner/client acceptance remain separate.",
        ],
    }

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    try:
        result = probe(args.url)
    except (ProfileFailure, ValueError) as exc:
        args.output.write_text(json.dumps({"profile_http_checks_passed": False, "reason": str(exc)}, indent=2) + "\n")
        print("COMMUNITY MCP PROFILE BLOCKED: " + str(exc), file=sys.stderr)
        return 1
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(f"COMMUNITY MCP PROFILE HTTP CHECKS: {len(result['checks'])} PASS (NOT a release gate)")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
