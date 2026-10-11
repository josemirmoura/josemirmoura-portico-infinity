# MCP Community production profile: executable real-Gateway evidence

**Scope:** one compatible AI chat ↔ one Linux computer, **Scoped** authority. This page records a focused production-profile validation, **not** conformance certification or a replacement for the official frozen 37-scenario suite.

## Engineering decision

The user-facing Community Gateway must not gain synthetic `test_*` tools, prompts, resources, completion handlers or dynamic list notification endpoints merely to pass a test suite. The fixture executable remains isolated by the `portico_conformance_fixture` Go build tag, disposable loopback configuration and no privileged Broker socket. New advertised capabilities must have a real use case, a complete implementation and negative security tests first.

## Dedicated CI: `mcp-community-production-profile-evidence`

This workflow:

1. Builds the **real distributed** `./cmd/vps-agent-gateway` with no conformance fixture tag. Starts it on **numeric loopback only** (`127.0.0.1:18997`), with `auth=none` exclusively in that disposable CI process. The local fixture has no owner secrets or privileged Broker.
2. Probes actual 2026-07-28 MCP HTTP `/mcp` and checks:
   - Stateless `server/discover` and correct advertised protocol and capabilities;
   - every paginated tool in the production catalog, rejecting synthetic `test_*` or `conformance_*` tools;
   - resource and prompt lists with no synthetic `test://` entries;
   - real `system.info` tool call, not a fake diagnostic tool;
   - invalid browser `Origin` fails closed with HTTP 403;
   - missing mandatory per-request `_meta` fails with HTTP 400 / JSON-RPC `-32602`;
   - absent optional `completion/complete` remains unadvertised and returns HTTP 404 / `-32601`, and static tool/prompt/resource catalogs do not advertise list-changed.
3. Runs the real Go Gateway and integration test packages under the race detector, requires explicit PASS results for six named tests covering OAuth resource metadata, token claims and scope, the MCP Origin/header boundary, production fixture isolation, and the actual OAuth→Unix IPC→Scoped Broker positive/negative flow. A missing or SKIPPED test cannot silently count as success.
4. Runs nine negative unit regressions on the probe itself; records only structured, redacted proof and the exact candidate SHA, not raw OAuth logs or operator credentials.

## Interpretation

| Claim | Meaning |
|---|---|
| Real HTTP profile PASS | These selected advertised behaviors passed against the standard Gateway binary at a specific commit |
| Disposable OAuth→Broker tests PASS | Synthetic issuer but real resource-server/IPC/Broker logic passed the selected E2E regressions |
| Official frozen full suite | **Still blocked** until its own 37 required server scenarios and runner exit actually pass, or an independently approved normative profile gate is established |
| Normative profile sign-off | **PENDING** independent per-requirement review beyond this subset |
| Real ChatGPT/mobile client and operator acceptance | **NOT TESTED** by this workflow |
| Signed release, license/IP and owner promotion | **NOT TESTED** by this workflow |

Historical official scores: normal Gateway **8 PASS / 2 FAIL / 3 SKIPPED / 24 NOT TESTED**; test-only fixture **35 PASS / 1 FAIL / 1 SKIPPED / 0 NOT TESTED**; both `release_gate_passed=false`. A new green profile workflow must never overwrite those values, declare full conformance or authorize promotion to `main`.

Reference: [frozen upstream requirements](https://github.com/modelcontextprotocol/conformance/blob/c37eec888e1c6ff140af79987a40008548b7cc5f/requirements/2026-07-28.yaml), [forensic report](mcp-gate-c-forensic-review.md), [release ledger](release-integration-gates.md), [tracking #79](https://github.com/josemirmoura/mcp-vps-agent-gateway/issues/79), [planning #127](https://github.com/josemirmoura/mcp-vps-agent-gateway/issues/127).
