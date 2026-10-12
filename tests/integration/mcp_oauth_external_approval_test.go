package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/josemirmoura/mcp-vps-agent-gateway/internal/broker"
	"github.com/josemirmoura/mcp-vps-agent-gateway/internal/gateway"
	"github.com/josemirmoura/mcp-vps-agent-gateway/internal/ipc"
	"github.com/josemirmoura/mcp-vps-agent-gateway/internal/policy"
	"github.com/josemirmoura/mcp-vps-agent-gateway/internal/securefs"
	"github.com/josemirmoura/mcp-vps-agent-gateway/internal/state"
	"github.com/josemirmoura/mcp-vps-agent-gateway/internal/wire"
)

// TestOAuthExternalApprovalRealBrokerRoundTrip adds one continuous, disposable
// contract across OAuth introspection, the HTTP MCP Gateway, Unix IPC and the
// authoritative Broker. The HTTPS operator page itself is exercised separately
// by the browser and real-Broker/portal tests; this test deliberately does not
// impersonate a logged-in browser or claim to be a real ChatGPT acceptance.
func TestOAuthExternalApprovalRealBrokerRoundTrip(t *testing.T) {
	t.Setenv("PORTICO_APPROVAL_SURFACE", "")
	t.Setenv("VPS_AGENT_OPERATOR_PORTAL_URL", "https://operator.example.test/operator")
	t.Setenv("VPS_AGENT_HOST_ROOT", "")
	physical := t.TempDir()
	t.Setenv("VPS_AGENT_PHYSICAL_SCOPE_ROOT", physical)

	approvedRoot := filepath.Join(physical, "approved-project")
	deniedRoot := filepath.Join(physical, "denied-project")
	for _, path := range []string{approvedRoot, deniedRoot} {
		if err := os.MkdirAll(path, 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "proof.txt"), []byte("synthetic-fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	store, err := state.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	fs, err := securefs.New(nil, nil, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &policy.Config{
		Version: 1, Mode: "scoped",
		Filesystem: policy.FilesystemPolicy{
			Actions: []string{"list", "stat", "read", "hash", "write"},
		},
		Network: policy.NetworkPolicy{Mode: "blocked"},
		Privilege: policy.PrivilegePolicy{Admin: "broker-only"},
		Replay: policy.ReplayPolicy{RequireIdempotencyForSafeWrites: true},
		Grant: policy.GrantPolicy{
			MaxTTLMinutes: 60, OutOfBandApproval: true, StepUpAuth: true,
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	const operatorKey = "synthetic-operator-key-not-production"
	const node = "fixture-node"
	b := &broker.Broker{
		Policy: cfg, FS: fs, State: store, AdminToken: operatorKey,
		ExpectedSubject: "alice", InstanceID: node,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	socket := filepath.Join(t.TempDir(), "broker.sock")
	done := make(chan error, 1)
	go func() { done <- ipc.NewServer(socket, b).Serve(ctx) }()
	brokerClient := ipc.Client{Socket: socket, Timeout: 2 * time.Second}
	ready := false
	for i := 0; i < 100; i++ {
		if _, err := brokerClient.Call(context.Background(),
			wireRequest("preflight", "system.info", "", "alice")); err == nil {
			ready = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		t.Fatal("disposable Broker did not start")
	}

	const issuer = "https://issuer.example.invalid"
	const audience = "portico-gate-e-fixture"
	const clientID = "fixture-resource"
	const clientSecret = "fixture-secret"
	introspector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		id, secret, ok := req.BasicAuth()
		if !ok || id != clientID || secret != clientSecret || req.Method != http.MethodPost ||
			req.URL.Path != "/introspect" || req.ParseForm() != nil {
			http.Error(w, "invalid introspection", http.StatusUnauthorized)
			return
		}
		token := req.Form.Get("token")
		active := token == "alice" || token == "bob"
		subject := token
		if !active {
			subject = ""
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"active": active, "sub": subject, "scope": "portico.read",
			"iss": issuer, "aud": []string{audience},
			"exp": time.Now().Add(5 * time.Minute).Unix(),
		})
	}))
	defer introspector.Close()
	verifier, err := gateway.NewIntegratedOIDCVerifier(
		introspector.URL+"/introspect", "", clientID, clientSecret, issuer, audience)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gateway.Handler(
		gateway.BrokerExecutor{Client: brokerClient},
		gateway.AuthConfig{
			Mode: "integrated", Verifier: verifier,
			RequiredScopes: []string{"portico.read"},
			ResourceIdentifier: "https://mcp.example.invalid/mcp",
			ResourceMetadataURL: "https://mcp.example.invalid/.well-known/oauth-protected-resource",
			AuthorizationServers: []string{issuer},
		},
	))
	defer server.Close()

	// Use real stateless 2026-07-28 MCP requests, not a fake tool executor.
	call := func(token, name string, arguments map[string]any) (int, bool, map[string]any) {
		t.Helper()
		body, err := json.Marshal(map[string]any{
			"jsonrpc": "2.0", "id": 42, "method": "tools/call",
			"params": map[string]any{
				"name": name, "arguments": arguments,
				"_meta": map[string]any{
					"io.modelcontextprotocol/protocolVersion": "2026-07-28",
					"io.modelcontextprotocol/clientInfo": map[string]any{
						"name": "oauth-external-approval-fixture", "version": "1",
					},
					"io.modelcontextprotocol/clientCapabilities": map[string]any{},
				},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		req, err := http.NewRequest(http.MethodPost, server.URL+"/mcp", bytes.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("MCP-Protocol-Version", "2026-07-28")
		req.Header.Set("Mcp-Method", "tools/call")
		req.Header.Set("Mcp-Name", name)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return resp.StatusCode, false, nil
		}
		var rpc struct {
			Result struct {
				IsError bool `json:"isError"`
				StructuredContent map[string]any `json:"structuredContent"`
			} `json:"result"`
			Error json.RawMessage `json:"error"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&rpc); err != nil {
			t.Fatal(err)
		}
		if len(rpc.Error) != 0 {
			t.Fatalf("RPC protocol error for %s: %s", name, rpc.Error)
		}
		return resp.StatusCode, rpc.Result.IsError, rpc.Result.StructuredContent
	}
	requireResult := func(token, tool string, args map[string]any, wantToolError bool) map[string]any {
		t.Helper()
		status, isError, result := call(token, tool, args)
		if status != http.StatusOK || isError != wantToolError {
			t.Fatalf("%s status=%d isError=%v, want status=200 isError=%v: %+v",
				tool, status, isError, wantToolError, result)
		}
		return result
	}
	if status, _, _ := call("", "permissions.request_root_access",
		map[string]any{"root": approvedRoot, "access": "read", "ttl_seconds": 300}); status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated access request returned HTTP %d", status)
	}
	if status, _, _ := call("invalid", "permissions.request_root_access",
		map[string]any{"root": approvedRoot, "access": "read", "ttl_seconds": 300}); status != http.StatusUnauthorized {
		t.Fatalf("invalid OAuth token returned HTTP %d", status)
	}
	first := filepath.Join(approvedRoot, "proof.txt")
	second := filepath.Join(deniedRoot, "proof.txt")
	requireResult("alice", "file.read", map[string]any{"path": first}, true)

	requestRoot := func(root string) string {
		t.Helper()
		result := requireResult("alice", "permissions.request_root_access",
			map[string]any{"root": root, "access": "read", "ttl_seconds": 300}, false)
		id, _ := result["request_id"].(string)
		link, _ := result["operator_approval_url"].(string)
		parsed, err := url.Parse(link)
		if id == "" || err != nil || parsed.Scheme != "https" ||
			parsed.Host != "operator.example.test" || parsed.Path != "/operator" ||
			parsed.Query().Get("request") != id ||
			result["approval_method"] != "operator_web" ||
			result["status"] != "pending" || result["status_tool"] != "permissions.approval_status" {
			t.Fatalf("external approval contract mismatch: %+v", result)
		}
		if _, leaked := result["approval_token"]; leaked {
			t.Fatal("Broker approval token leaked into MCP tool output")
		}
		return id
	}
	status := func(id string, token string) map[string]any {
		t.Helper()
		return requireResult(token, "permissions.approval_status",
			map[string]any{"request_id": id}, false)
	}
	decide := func(id, decision string) {
		t.Helper()
		a, err := store.GetApproval(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		args, _ := json.Marshal(map[string]any{
			"request_id": id,
			"snapshot_hash": state.ApprovalFingerprint(a, node),
			"node_id": node,
		})
		resp := b.Handle(ctx, wire.Request{
			ID: "authenticated-operator-" + decision + "-" + id,
			Tool: "admin.approval." + decision,
			AdminToken: operatorKey, Args: args,
		})
		if !resp.OK {
			t.Fatalf("out-of-band operator %s rejected: %+v", decision, resp)
		}
	}

	id := requestRoot(approvedRoot)
	if got := status(id, "alice")["status"]; got != "pending" {
		t.Fatalf("request should remain pending: %v", got)
	}
	requireResult("bob", "permissions.approval_status", map[string]any{"request_id": id}, true)
	requireResult("alice", "file.read", map[string]any{"path": first}, true)
	decide(id, "approve")
	if got := status(id, "alice")["status"]; got != "approved" {
		t.Fatalf("Broker grant not confirmed: %v", got)
	}
	read := requireResult("alice", "file.read", map[string]any{"path": first}, false)
	if read["content"] != "synthetic-fixture" {
		t.Fatalf("approved root did not permit exact file read: %+v", read)
	}
	requireResult("alice", "permissions.revoke_root_access", map[string]any{"root": approvedRoot}, false)
	if got := status(id, "alice")["status"]; got != "revoked" {
		t.Fatalf("Broker revocation not reflected: %v", got)
	}
	requireResult("alice", "file.read", map[string]any{"path": first}, true)

	deniedID := requestRoot(deniedRoot)
	decide(deniedID, "deny")
	if got := status(deniedID, "alice")["status"]; got != "denied" {
		t.Fatalf("Broker denial not reflected: %v", got)
	}
	requireResult("alice", "file.read", map[string]any{"path": second}, true)

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("disposable Broker shutdown failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("disposable Broker did not shut down")
	}
}
