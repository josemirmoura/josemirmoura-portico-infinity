# Gate C audit: MCP 2026-07-28 normative applicability and evidence

**Review date:** 2026-10-11. **Assessed Community staging code:** `46c128e4f594d92ad560c10a27a104cb9d5c2f7a`, [PR #99](https://github.com/josemirmoura/mcp-vps-agent-gateway/pull/99). This document is a **technical audit draft** prepared by an implementing assistant. It is **not** an independent reviewer signature, a conformance certification, or permission to release.

## Decision first

**Gate C full frozen conformance: FAIL / BLOCKED. Gate C advertised-profile normative acceptance: NOT YET APPROVED.**

The assessed staging SHA has **19/19 GitHub Actions workflow runs SUCCESS**, including the real production-profile probe [run 38099937078](https://github.com/josemirmoura/mcp-vps-agent-gateway/actions/runs/38099937078), frozen-score collection runs [38099937034](https://github.com/josemirmoura/mcp-vps-agent-gateway/actions/runs/38099937034) and [38099937240](https://github.com/josemirmoura/mcp-vps-agent-gateway/actions/runs/38099937240), and docker rollback [38099937059](https://github.com/josemirmoura/mcp-vps-agent-gateway/actions/runs/38099937059). A workflow's green status confirms **tests/report generation**, not a passing MCP full-suite release gate.

**Frozen upstream:** [requirements/2026-07-28.yaml](https://github.com/modelcontextprotocol/conformance/blob/c37eec888e1c6ff140af79987a40008548b7cc5f/requirements/2026-07-28.yaml) at commit `c37eec888e1c6ff140af79987a40008548b7cc5f`, server role **37 scenarios**; client role **32 separate scenarios** (not applicable to the Pórtico acting as MCP resource server). Preserve upstream list, runner exit, all `checks.json`, and full raw statuses without expected-failure waivers.

Most recent documented *classification* from real production Gateway: **8 PASS / 2 FAIL / 3 SKIPPED / 24 NOT_TESTED**. Test-only fixture on same baseline: **35 PASS / 1 FAIL / 1 SKIPPED / 0 NOT_TESTED**. Both `release_gate_passed=false`. Do not replace the normal binary's score with fixture results. The fixture compiler build tag `portico_conformance_fixture` deliberately is not part of shipped Community.

The current user decision is **correctness/security of the actual Linux Scoped Community** over artificially passing named `test_*` probes. Do not add diagnostic tools, prompts, resources, fictitious event triggers, or unsupported capability flags to its public catalog.

## All 37 frozen server scenarios: review inventory

Legend: **P**=PASS, **F**=FAIL, **S**=SKIPPED, **N**=NOT_TESTED. Each row retains original status on normal Gateway and test-only fixture; neither the context nor this assessment modifies the official output. `DIRECT` means specific normal-protocol behavior is exercised (not the whole MCP specification). `FIXTURE` means the frozen scenario hard-codes a diagnostic fixture absent from the distributed product. `REVIEW` means a specification/profile applicability decision or additional production-specific evidence is required.

| # | Frozen scenario | Normal | Lab | Context and what remains to justify |
|---:|---|:---:|:---:|---|
| 01 | `server-stateless` | N | S | **REVIEW:** real metadata/version/header/Origin checks pass, but `test_missing_capability`, streaming/log diagnostics and list-change checks are incomplete or skipped |
| 02 | `completion-complete` | F | F | **REVIEW:** `completions` not advertised; real response is -32601/404, allowed for unsupported optional method; frozen runner unconditionally calls completion |
| 03 | `tools-list` | P | P | **DIRECT:** tools/list exercised; new normal-binary probe also rejects synthetic catalog entries |
| 04 | `tools-call-simple-text` | N | P | **FIXTURE:** diagnostic text name; normal system.info tool yields actual content, not the synthetic reference string |
| 05 | `tools-call-image` | N | P | **FIXTURE:** no diagnostic image tool in Community; lab validates content envelope only |
| 06 | `tools-call-audio` | N | P | **FIXTURE:** no diagnostic audio tool in Community |
| 07 | `tools-call-embedded-resource` | N | P | **FIXTURE:** synthetic embedded resource from test tool |
| 08 | `tools-call-mixed-content` | N | P | **FIXTURE:** synthetic text/image/resource mixed envelope |
| 09 | `tools-call-error` | N | P | **FIXTURE:** named artificial error tool; normal policy denial tested separately |
| 10 | `tools-call-with-progress` | N | P | **FIXTURE:** progress token / notifications of synthetic tool; actual production progress capabilities need explicit use-case verification |
| 11 | `server-sse-multiple-streams` | P | P | **DIRECT:** normal MCP transport streaming passed frozen scenario |
| 12 | `resources-list` | P | P | **DIRECT:** normal resources/list; no production `test://` resources |
| 13 | `resources-read-text` | N | P | **FIXTURE:** expected disposable `test://` text resource not in Community |
| 14 | `resources-read-binary` | N | P | **FIXTURE:** expected disposable image resource not in Community |
| 15 | `resources-templates-read` | N | P | **FIXTURE:** named static template `test://template/{id}/data` only in lab |
| 16 | `sep-2164-resource-not-found` | P | P | **DIRECT:** normal missing-resource behavior tested |
| 17 | `prompts-list` | P | P | **DIRECT:** prompts/list works; public list can be empty |
| 18 | `prompts-get-simple` | N | P | **FIXTURE:** simple diagnostic prompt unavailable on production |
| 19 | `prompts-get-with-args` | N | P | **FIXTURE:** fixed named two-argument prompt unavailable on production |
| 20 | `prompts-get-embedded-resource` | N | P | **FIXTURE:** synthetic embedded-resource prompt |
| 21 | `prompts-get-with-image` | N | P | **FIXTURE:** synthetic image prompt |
| 22 | `dns-rebinding-protection` | P | P | **DIRECT WITH CAVEAT:** upstream score alone missed an actual invalid-Origin bypass; #121 independently fixed & tested 403 Origin, cross-scheme/Host confusion |
| 23 | `caching` | S | P | **REVIEW:** conditional cache behavior needs a readable resource; lab only has synthetic reference resource |
| 24 | `input-required-result-basic-elicitation` | N | P | **FIXTURE/REVIEW:** named elicitation test tool; evaluate actual operator-approval flow separately |
| 25 | `input-required-result-basic-sampling` | N | P | **FIXTURE:** diagnostic sampling flow; do not introduce unsupported sampling into Community |
| 26 | `input-required-result-basic-list-roots` | N | P | **FIXTURE:** client-roots diagnostic, not permission to read arbitrary Linux roots |
| 27 | `input-required-result-request-state` | N | P | **FIXTURE/REVIEW:** lab HMAC requestState, check real approval/grant state and anti-replay separately |
| 28 | `input-required-result-multiple-input-requests` | N | P | **FIXTURE:** synthetic multi-input request |
| 29 | `input-required-result-multi-round` | F | P | **FIXTURE/REVIEW:** frozen tool `test_input_required_result_multi_round` absent in product; lab two-round HMAC passes, real ChatGPT/operator UX untested |
| 30 | `input-required-result-missing-input-response` | S | P | **FIXTURE:** test-only missing-response recovery; product client retry coverage separate |
| 31 | `input-required-result-non-tool-request` | N | P | **FIXTURE:** synthetic non-tool input-request diagnostic |
| 32 | `input-required-result-result-type` | N | P | **FIXTURE:** synthetic discriminator and envelope |
| 33 | `input-required-result-unsupported-methods` | P | P | **DIRECT:** unsupported-method behavior tested |
| 34 | `input-required-result-tampered-state` | N | P | **FIXTURE/REVIEW:** synthetic signed requestState; real production replay and operator binding require separate coverage |
| 35 | `input-required-result-capability-check` | N | P | **FIXTURE/REVIEW:** synthetic client capability guard; review actual approval capability negotiation |
| 36 | `input-required-result-ignore-extra-params` | S | P | **FIXTURE:** ignores extra fields for synthetic tool, not yet demonstrated in normal path |
| 37 | `input-required-result-validate-input` | P | P | **DIRECT:** normal input-required validation behavior tested |

Audit checks: normal = **8 P / 2 F / 3 S / 24 N**; isolated = **35 P / 1 F / 1 S / 0 N**. The full frozen suite does **not** pass; fixture success cannot count as normal-product success.

## Normative rules and independent negative tests

1. **Version, stateless HTTP, JSON-RPC, headers:** normal server implements 2026-07-28 discovery, per-request metadata, valid schema, version/header mismatch and unsupported methods. Official `server-stateless` includes direct PASS checks but is not a whole-scenario PASS. Requirements for HTTP transport and per-request `_meta` are normative. A CI test subset that passes does not prove every clause of the complete normative text.
2. **Origin / DNS rebinding:** `guardMCPOrigin` is attached before auth and tool executor. The real Gateway exercises untrusted Host and cross-origin rejection. This check was essential because upstream `dns-rebinding-protection` PASS previously missed a real vulnerability. Maintain the negative tests on exact future candidate.
3. **OAuth resource-server boundary:** normal handler's protected-resource metadata and 401 Bearer challenge; disposable introspection checks issuer, audience, expiry, scope, subject. Separate real OAuth browser authorization-code/PKCE and owner/client acceptance are not shown by the CI. No fake authority should be trusted.
4. **Broker Scoped:** disposable E2E covers authenticated subject propagation, IPC Unix socket, allowed read and denied operation; approvals, operator identity, grant/revoke/replay, stateful credential confidentiality and external effects require their own release gates and operator acceptance. Do not assume the stateless MCP result alone proves owner authorization.
5. **Advertised capabilities:** production currently advertises tools and prompts list, without `completions` or `listChanged`. The official [completion specification](https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/completion) says a server **that supports** completions MUST advertise them. Unsupported `completion/complete` returning -32601 is consistent with that choice. Do not add optional functionality just to satisfy test names. Protocol behavior over synthetic-only content types is demonstrated *only* in the disposable SDK/transport fixture.
6. **Synthetic isolation:** production `tools/list`, `prompts/list`, `resources/list` and resource templates must never expose hard-coded `test_*` / `test://` examples. `TestProductionMCPServerDoesNotExposeConformanceFixtures` and `scripts/mcp_community_profile_probe.py` test the normal binary. Keep fixture builds hermetic.
7. **Test-harness boundary hardening in this audit PR:** the initial profile probe used Python's `urllib.request.urlopen`, which can inherit proxy settings and follow an HTTP redirect even with a numeric loopback starting URL. The audit PR installs `ProxyHandler({})` and `DenyRedirect` for **every** request, rejects 3xx and adds negative tests, plus coverage for `resources/templates/list`. Until its exact SHA CI passes, these improvements remain **proposed**.

Official source: [MCP Streamable HTTP transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http); [MCP transport overview](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports); [Completion](https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/completion). Upstream frozen requirement file and individual `src/scenarios/server/*.ts` describe the exact reference diagnostics. Pórtico proof links: [forensic report](mcp-gate-c-forensic-review.md), [Community profile probe](mcp-community-profile-gate.md), [Scope audit parser](../scripts/mcp_release_scope_audit.py).

## Actual remaining work before Gate C can be approved for release

| Check | Gate now | Required completion evidence |
|---|---|---|
| Frozen official 37/37 | **FAIL** | Remains raw FAIL unless 37 true PASS/exit zero in the frozen runner. No fabricated reclassification |
| Specific advertised-profile normative gate | **NOT TESTED TO COMPLETION** | Independent review of every relevant MUST/SHOULD, not only 37 reference scenarios; explicit accepted scope, negative tests for each server feature; owner engineering signoff |
| New harness safety hardening | **AUDIT PR PENDING** | Merge only after isolated CI + exact integrated-staging SHA CI |
| Actual approval/denial/revocation and UI | **NOT TESTED** | Real supported client connected to Pórtico, operator identity, ask/approve/deny/revoke and audit evidence on supported desktop/mobile as available; fallback validation for non-native clients (#65) |
| Owner/technical reviewer identity | **PENDING** | A second person or genuinely independent auditor must review code, matrix, claims and residual risks; **this author cannot sign their own review as independent** |
| Published signed candidate and promotion | **NOT TESTED** | Gates A license/IP, D real signed RC, F authorized main merge/recovery remain separate |

**Audit recommendation:** do **not** close #79 or set a released/stable Gate C PASS merely because the new real profile subset or 19 GitHub workflows are green. Close only when the advertised-profile acceptance criteria are explicitly approved, reproducible tests and independent reviewer signatures exist, and no mandatory conformance requirement was discounted. The release must retain the frozen official FAIL in its evidence until actually passed.

Owner action now: **none**. Keep changes in isolated staging PR; any real-client test requiring owner interaction must be explained separately with exact clicks and a disposable plan.
