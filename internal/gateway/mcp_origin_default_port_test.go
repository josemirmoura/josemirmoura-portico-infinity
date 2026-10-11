package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A security guard must validate the actual scheme/host/port origin tuple.
// RFC 6454 and RFC 9110 treat an omitted default port and :80/:443 as
// equivalent. Rejection otherwise breaks legitimate browser MCP clients
// behind HTTPS reverse proxies configured with explicit :443.
func TestGateCOriginCanonicalDefaultPortsAtRealHTTPGateway(t *testing.T) {
	cases := []struct {
		name     string
		resource string
		host     string
		origin   string
		want     int
	}{
		{"https explicit 443 config", "https://mcp.example.invalid:443/mcp", "", "https://mcp.example.invalid", 200},
		{"https explicit 443 browser", "https://mcp.example.invalid/mcp", "", "https://mcp.example.invalid:443", 200},
		{"https nondefault exact", "https://mcp.example.invalid:8443/mcp", "", "https://mcp.example.invalid:8443", 200},
		{"https nondefault is not default", "https://mcp.example.invalid:8443/mcp", "", "https://mcp.example.invalid", 403},
		{"https different nondefault", "https://mcp.example.invalid:8443/mcp", "", "https://mcp.example.invalid:8444", 403},
		{"http explicit 80 config", "http://mcp.example.invalid:80/mcp", "", "http://mcp.example.invalid", 200},
		{"http cross scheme forbidden", "https://mcp.example.invalid:443/mcp", "", "http://mcp.example.invalid:80", 403},
		{"https cross host forbidden", "https://mcp.example.invalid:443/mcp", "", "https://evil.example.invalid:443", 403},
		{"loopback explicit 80 host", "", "127.0.0.1:80", "http://127.0.0.1", 200},
		{"loopback explicit 80 origin", "", "127.0.0.1", "http://127.0.0.1:80", 200},
		{"loopback nondefault mismatch", "", "127.0.0.1:18990", "http://127.0.0.1", 403},
		{"rebound Host still forbidden", "", "evil.example.invalid:80", "http://evil.example.invalid", 403},
		{"port zero denied", "https://mcp.example.invalid/mcp", "", "https://mcp.example.invalid:0", 403},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			probe := &oauthResourceProbeExecutor{}
			srv := httptest.NewServer(Handler(probe, AuthConfig{
				Mode: "none", StaticSubject: "alice",
				ResourceIdentifier: tc.resource,
			}))
			defer srv.Close()

			payload, err := json.Marshal(map[string]any{
				"jsonrpc": "2.0", "id": 17, "method": "tools/call",
				"params": map[string]any{
					"name": "system.info", "arguments": map[string]any{},
					"_meta": map[string]any{
						"io.modelcontextprotocol/protocolVersion": "2026-07-28",
						"io.modelcontextprotocol/clientInfo": map[string]any{"name": "origin-port-fixture", "version": "1"},
						"io.modelcontextprotocol/clientCapabilities": map[string]any{},
					},
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			req, err := http.NewRequest("POST", srv.URL+"/mcp", bytes.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			if tc.host != "" {
				req.Host = tc.host
			}
			req.Header.Set("Origin", tc.origin)
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json, text/event-stream")
			req.Header.Set("MCP-Protocol-Version", "2026-07-28")
			req.Header.Set("Mcp-Method", "tools/call")
			req.Header.Set("Mcp-Name", "system.info")

			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != tc.want {
				t.Fatalf("Origin %s Host %s resource %s: HTTP %d, want %d",
					tc.origin, tc.host, tc.resource, resp.StatusCode, tc.want)
			}
			count, _ := probe.snapshot()
			if tc.want == http.StatusForbidden && count != 0 {
				t.Fatal("denied origin reached MCP executor")
			}
			if tc.want == http.StatusOK && count != 1 {
				t.Fatalf("authorized origin executor called %d times, want once", count)
			}
		})
	}
}
