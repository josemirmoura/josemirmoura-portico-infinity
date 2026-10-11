package integration

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/josemirmoura/mcp-vps-agent-gateway/internal/broker"
	"github.com/josemirmoura/mcp-vps-agent-gateway/internal/gateway"
	"github.com/josemirmoura/mcp-vps-agent-gateway/internal/ipc"
	"github.com/josemirmoura/mcp-vps-agent-gateway/internal/policy"
	"github.com/josemirmoura/mcp-vps-agent-gateway/internal/securefs"
	"github.com/josemirmoura/mcp-vps-agent-gateway/internal/state"
)

// TestGateCVerifiedHTTPSIntrospectionToBroker proves the actual TLS-validated
// OAuth introspection -> MCP Streamable HTTP -> Unix IPC -> Scoped Broker path.
// Both TLS endpoints use disposable certificates, both code paths use the
// normal Community Gateway, and no ZITADEL/VPS credential is involved.
// SSL_CERT_FILE is configured in a child before the Go system root pool loads.
func TestGateCVerifiedHTTPSIntrospectionToBroker(t *testing.T) {
	const issuer = "https://issuer.example.invalid"
	const resource = "https://mcp.example.invalid/mcp"
	const audience = "https-resource"
	const clientID = "only-disposable-gate-c"
	const clientSecret = "fixture-not-a-real-secret"

	if os.Getenv("PORTICO_GATE_C_HTTPS_CHILD") == "1" {
		httpsIntrospector := os.Getenv("PORTICO_GATE_C_INTROSPECTION_URL")
		if httpsIntrospector == "" || !strings.HasPrefix(httpsIntrospector, "https://") {
			t.Fatal("child requires TLS introspection")
		}
		root := t.TempDir()
		allowed := filepath.Join(root, "allowed.txt")
		if err := os.WriteFile(allowed, []byte("scoped-proof"), 0600); err != nil {
			t.Fatal(err)
		}
		outside := filepath.Join(t.TempDir(), "outside.txt")
		if err := os.WriteFile(outside, []byte("never-return"), 0600); err != nil {
			t.Fatal(err)
		}
		store, err := state.Open(":memory:")
		if err != nil { t.Fatal(err) }
		defer store.Close()
		fs, err := securefs.New([]string{root}, []string{root}, 1<<20)
		if err != nil { t.Fatal(err) }
		cfg := &policy.Config{
			Version: 1, Mode: "scoped",
			Filesystem: policy.FilesystemPolicy{Read: []string{root}, Write: []string{root}},
			Network: policy.NetworkPolicy{Mode: "blocked"},
			Privilege: policy.PrivilegePolicy{Admin: "broker-only"},
			Replay: policy.ReplayPolicy{RequireIdempotencyForSafeWrites: true},
		}
		if err := cfg.Validate(); err != nil { t.Fatal(err) }
		localBroker := &broker.Broker{Policy: cfg, FS: fs, State: store}
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		socket := filepath.Join(t.TempDir(), "broker.sock")
		done := make(chan error, 1)
		go func() { done <- ipc.NewServer(socket, localBroker).Serve(ctx) }()
		brokerClient := ipc.Client{Socket: socket, Timeout: 2 * time.Second}
		ready := false
		for i := 0; i < 100; i++ {
			if _, err := brokerClient.Call(context.Background(),
				wireRequest("https-gate-c-ready", "system.info", "", "https-fixture")); err == nil {
				ready = true
				break
			}
			time.Sleep(10*time.Millisecond)
		}
		if !ready { t.Fatal("disposable Broker unavailable") }

		verifier, err := gateway.NewIntegratedOIDCVerifier(
			httpsIntrospector, "", clientID, clientSecret, issuer, audience)
		if err != nil { t.Fatal(err) }
		srv := httptest.NewTLSServer(gateway.Handler(
			gateway.BrokerExecutor{Client: brokerClient},
			gateway.AuthConfig{
				Mode: "integrated", Verifier: verifier,
				RequiredScopes: []string{"portico.read"},
				ResourceIdentifier: resource,
				ResourceMetadataURL: "https://mcp.example.invalid/.well-known/oauth-protected-resource",
				AuthorizationServers: []string{issuer},
			}))
		defer srv.Close()
		if !strings.HasPrefix(srv.URL,"https://") { t.Fatal("Gateway edge is not TLS") }

		client := srv.Client() // trusts ONLY this disposable edge certificate
		client.Timeout = 5*time.Second
		request := func(token, path, origin string) (int, bool, http.Header) {
			t.Helper()
			b, err := json.Marshal(map[string]any{
				"jsonrpc":"2.0", "id": 12, "method":"tools/call",
				"params":map[string]any{
					"name":"file.read", "arguments":map[string]any{"path":path},
					"_meta":map[string]any{
						"io.modelcontextprotocol/protocolVersion":"2026-07-28",
						"io.modelcontextprotocol/clientInfo":map[string]string{"name":"https-fixture","version":"1"},
						"io.modelcontextprotocol/clientCapabilities":map[string]any{},
					},
				},
			})
			if err != nil { t.Fatal(err) }
			req, err := http.NewRequest("POST",srv.URL+"/mcp", bytes.NewReader(b))
			if err != nil { t.Fatal(err) }
			req.Header.Set("Accept","application/json, text/event-stream")
			req.Header.Set("Content-Type","application/json")
			req.Header.Set("MCP-Protocol-Version","2026-07-28")
			req.Header.Set("Mcp-Method","tools/call")
			req.Header.Set("Mcp-Name","file.read")
			if token != "" { req.Header.Set("Authorization","Bearer "+token) }
			if origin != "" { req.Header.Set("Origin",origin) }
			resp, err := client.Do(req)
			if err != nil { t.Fatal(err) }
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				_, _ = io.Copy(io.Discard,io.LimitReader(resp.Body,8192))
				return resp.StatusCode, false,resp.Header
			}
			var rpc struct {
				Result struct{ IsError bool `json:"isError"` } `json:"result"`
				Error json.RawMessage `json:"error"`
			}
			if err := json.NewDecoder(io.LimitReader(resp.Body,1<<20)).Decode(&rpc); err != nil {
				t.Fatal(err)
			}
			if len(rpc.Error) != 0 { t.Fatalf("unexpected RPC error: %s",rpc.Error) }
			return resp.StatusCode,rpc.Result.IsError,resp.Header
		}

		if code, _, hdr := request("",allowed,""); code != 401 ||
			!strings.Contains(hdr.Get("WWW-Authenticate"),"resource_metadata=") {
			t.Fatalf("missing bearer did not yield 401 OAuth resource metadata challenge: HTTP=%d",code)
		}
		if code, _, _ := request("inactive",allowed,""); code != 401 {
			t.Fatalf("inactive bearer bypassed HTTPS introspection: HTTP %d",code)
		}
		if code, _, _ := request("wrong-aud",allowed,""); code != 401 {
			t.Fatalf("wrong-audience bearer bypassed resource protection: HTTP %d",code)
		}
		if code, _, hdr := request("wrong-scope",allowed,""); code != http.StatusForbidden ||
			!strings.Contains(hdr.Get("WWW-Authenticate"),"scope=") ||
			!strings.Contains(hdr.Get("WWW-Authenticate"),"portico.read") {
			t.Fatalf("valid bearer with insufficient scope must return 403 and a Bearer scope challenge; HTTP %d",code)
		}
		if code, _, _ := request("valid",allowed,"https://evil.invalid"); code != 403 {
			t.Fatalf("hostile Origin reached authenticated endpoint: HTTP %d",code)
		}
		if code, denied, _ := request("valid",outside,""); code != 200 || !denied {
			t.Fatalf("HTTPS bearer escaped scoped filesystem: HTTP %d denied=%v",code,denied)
		}
		if code, denied, _ := request("valid",allowed,""); code != 200 || denied {
			t.Fatalf("valid HTTPS OAuth -> IPC -> Scoped Broker failed: HTTP %d denied=%v",code,denied)
		}
		meta, err := client.Get(srv.URL+"/.well-known/oauth-protected-resource")
		if err != nil {t.Fatal(err)}
		defer meta.Body.Close()
		if meta.StatusCode != 200 {t.Fatalf("OAuth resource metadata HTTP %d",meta.StatusCode)}
		var document struct {
			Resource string `json:"resource"`
			AuthorizationServers []string `json:"authorization_servers"`
		}
		if err := json.NewDecoder(meta.Body).Decode(&document); err != nil {t.Fatal(err)}
		if document.Resource != resource || len(document.AuthorizationServers) == 0 ||
			document.AuthorizationServers[0] != issuer {
			t.Fatalf("invalid OAuth resource metadata: %+v",document)
		}
		cancel()
		select {
		case err := <-done:
			if err != nil {t.Fatalf("Broker shutdown: %v",err)}
		case <-time.After(2*time.Second):
			t.Fatal("Broker shutdown timeout")
		}
		return
	}

	var seen atomic.Int64
	introspector := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		id, pass, ok := req.BasicAuth()
		if req.URL.Path != "/introspect" || req.Method != "POST" ||
			!ok || id != clientID || pass != clientSecret || req.ParseForm() != nil {
			http.Error(w,"invalid authenticated introspection",401)
			return
		}
		seen.Add(1)
		token := req.PostForm.Get("token")
		result := map[string]any{
			"active": token != "inactive",
			"sub": "https-fixture",
			"iss": issuer,
			"aud": []string{audience},
			"scope": "portico.read",
			"exp": time.Now().Add(5*time.Minute).Unix(),
		}
		if token == "wrong-aud" {result["aud"]=[]string{"unrelated"}}
		if token == "wrong-scope" {result["scope"]="portico.read.other"}
		w.Header().Set("Content-Type","application/json")
		_ = json.NewEncoder(w).Encode(result)
	}))
	defer introspector.Close()
	cert, err := x509.ParseCertificate(introspector.TLS.Certificates[0].Certificate[0])
	if err != nil {t.Fatal(err)}
	trust := filepath.Join(t.TempDir(),"fixture-trust.pem")
	if err := os.WriteFile(trust,pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:cert.Raw}),0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(),15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx,os.Args[0],"-test.run=^TestGateCVerifiedHTTPSIntrospectionToBroker$")
	cmd.Env = append(os.Environ(),
		"PORTICO_GATE_C_HTTPS_CHILD=1",
		"PORTICO_GATE_C_INTROSPECTION_URL="+introspector.URL+"/introspect",
		"SSL_CERT_FILE="+trust,
	)
	output, err := cmd.CombinedOutput()
	if err != nil {t.Fatalf("HTTPS Gateway/Broker subprocess failed: %v; %s",err,output)}
	if n := seen.Load(); n < 3 {
		t.Fatalf("HTTPS introspection endpoint was not exercised by OAuth cases: %d calls",n)
	}
}
