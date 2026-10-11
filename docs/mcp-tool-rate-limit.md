# Community MCP tool invocation rate limits (Gate C A4)

**Applies to:** the normal Linux Scoped Gateway, after authentication identity has been established, for actual MCP `tools/call` requests. This is independent of the existing concurrent-request cap. Non-tool calls such as `server/discover` and `tools/list` are not charged to the tool budget.

## Default limits

- Per authenticated subject: 20 tool calls/second, maximum burst of 60 calls.
- Across this Gateway process: 200 tool calls/second, maximum burst of 600 calls.
- The isolated loopback auth-none test mode uses its single configured static subject, not a bypass.
- Per-subject memory is limited to 4096 tracked subjects with expiry after 10 minutes idle. When full, new subject entries are rejected, not added without bounds.
- When either budget is exhausted, respond HTTP 429, `Retry-After: 1`, JSON-RPC error `-32000` with the original JSON-RPC request ID and no subject or secrets. The next allowed call is governed by natural token replenishment.
- Limits are in-memory per Gateway process. A restart resets counters. Multi-instance/global cross-node rate limiting is not claimed for the Community.
- Configuration knobs for higher-throughput legitimate operator deployments: `VPS_AGENT_TOOL_CALLS_PER_SECOND` and `VPS_AGENT_TOOL_CALL_BURST`, clamped by the runtime to 1000/s and 2000 burst respectively. Do not disable policy authorization to compensate for throttling.

**Security boundary:** limits do not give a tool permission. The request continues through SDK parameter validation, authenticated subject and Broker Scoped policy. Denial, revocation and audit controls remain authoritative. A successful rate-limit regression does not replace real client/operator acceptance or full MCP conformance.

Evidence: `internal/gateway/tool_rate_limit_test.go` tests burst/recovery, independent subjects, cardinality bound, real HTTP 429 and unaffected non-tool discovery. On any release candidate, repeat against the **exact immutable staging SHA** and retain CI artifacts. Related: independent audit [issue #130](https://github.com/josemirmoura/mcp-vps-agent-gateway/issues/130), finding A4.
