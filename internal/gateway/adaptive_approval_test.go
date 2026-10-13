package gateway

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestApprovalCapabilityNegotiation(t *testing.T) {
	cases := []struct {
		name string
		caps *mcp.ClientCapabilities
		want approvalClientSupport
	}{
		{"absent", nil, approvalClientSupport{}},
		{"legacy-form", &mcp.ClientCapabilities{Elicitation: &mcp.ElicitationCapabilities{}}, approvalClientSupport{Form: true}},
		{"url-only", &mcp.ClientCapabilities{Elicitation: &mcp.ElicitationCapabilities{URL: &mcp.URLElicitationCapabilities{}}}, approvalClientSupport{URL: true}},
		{"wrong-mime", &mcp.ClientCapabilities{Extensions: map[string]any{approvalExtension: map[string]any{"mimeTypes": []string{"text/html"}}}}, approvalClientSupport{}},
		{"malformed", &mcp.ClientCapabilities{Extensions: map[string]any{approvalExtension: "yes"}}, approvalClientSupport{}},
		{"apps", &mcp.ClientCapabilities{Extensions: map[string]any{approvalExtension: map[string]any{"mimeTypes": []string{approvalAppMIME}}}}, approvalClientSupport{Apps: true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := approvalCapabilities(tc.caps); got != tc.want {
				t.Fatalf("got %+v want %+v", got, tc.want)
			}
		})
	}
}

func TestMCPAppsResourceAndTextFallbackSharePersistentRequest(t *testing.T) {
	t.Setenv("PORTICO_APPROVAL_SURFACE", "adaptive")
	t.Setenv("VPS_AGENT_MCP_APPS", "1")
	t.Setenv("VPS_AGENT_OPERATOR_PORTAL_URL", "https://operator.example.test/operator")
	t.Setenv("PORTICO_OPERATOR_FRAME_ANCESTORS", "https://host.example.test")
	ts := httptest.NewServer(Handler(approvalExecutor{}, AuthConfig{Mode: "none", StaticSubject: "alice"}))
	defer ts.Close()
	for _, apps := range []bool{false, true} {
		options := &mcp.ClientOptions{}
		if apps {
			options.Capabilities = &mcp.ClientCapabilities{Extensions: map[string]any{approvalExtension: map[string]any{"mimeTypes": []string{approvalAppMIME}}}}
		}
		client := mcp.NewClient(&mcp.Implementation{Name: "same-name-untrusted-client", Version: "v1"}, options)
		session, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: ts.URL + "/mcp"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "permissions.request_root_access", Arguments: map[string]any{"root": "/opt/project-a", "access": "read", "ttl_seconds": 300}})
		if err != nil || res.IsError {
			t.Fatalf("request failed %v %+v", err, res)
		}
		raw, _ := json.Marshal(res.StructuredContent)
		expected := "operator_web"
		if apps {
			expected = "mcp_apps"
		}
		if !strings.Contains(string(raw), expected) || strings.Contains(string(raw), "approval_token") {
			t.Fatalf("unexpected adaptive output: %s", raw)
		}
		if apps {
			resource, err := session.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: approvalAppURI})
			if err != nil {
				t.Fatal(err)
			}
			if len(resource.Contents) != 1 || resource.Contents[0].MIMEType != approvalAppMIME {
				t.Fatal("invalid resource")
			}
			text := resource.Contents[0].Text
			if strings.Contains(text, "__PORTICO_CONFIG__") || strings.Contains(text, "approval_token") || !strings.Contains(text, "https://operator.example.test") {
				t.Fatal("resource not configured or credential leaked")
			}
		}
		session.Close()
	}
}

func TestCommunityExternalHTTPSIsDefaultEvenWithNativeClientCapabilities(t *testing.T) {
	t.Setenv("PORTICO_APPROVAL_SURFACE", "")
	t.Setenv("VPS_AGENT_MCP_APPS", "1")
	t.Setenv("VPS_AGENT_OPERATOR_PORTAL_URL", "https://operator.example.test/operator")
	ts := httptest.NewServer(Handler(approvalExecutor{}, AuthConfig{Mode: "none", StaticSubject: "alice"}))
	defer ts.Close()

	// This client advertises both MCP Apps and elicitation. Neither should
	// hijack the independently authenticated external operator workflow.
	options := &mcp.ClientOptions{
		Capabilities: &mcp.ClientCapabilities{
			Extensions: map[string]any{approvalExtension: map[string]any{"mimeTypes": []string{approvalAppMIME}}},
			Elicitation: &mcp.ElicitationCapabilities{},
		},
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "portico-external-default-test", Version: "1"}, options)
	session, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: ts.URL + "/mcp"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()

	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "permissions.request_root_access",
		Arguments: map[string]any{"root": "/opt/project-a", "access": "read", "ttl_seconds": 300},
	})
	if err != nil || res.IsError {
		t.Fatalf("request failed err=%v result=%+v", err, res)
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"operator_web", "operator_approval_url", "https://operator.example.test/operator?request=",
		"permissions.approval_status", "retry_after_seconds",
	} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("missing %q from default external approval output: %s", want, raw)
		}
	}
	for _, forbidden := range []string{"approval_token", "\"approval_method\":\"mcp_apps\"", "operator_navigation"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("unsafe or wrong approval channel %q in output: %s", forbidden, raw)
		}
	}
}

// A host-native "Always allow this tool" choice is NEVER a root grant.
// Both the URL and CLI fallbacks must explain the separate operator step.
func TestChatToolConsentDoesNotGrantRootAccess(t *testing.T) {
  for _, portal := range []string{"", "https://operator.example.test/operator"} {
    t.Run(portal, func(t *testing.T) {
      t.Setenv("PORTICO_APPROVAL_SURFACE", "")
      t.Setenv("VPS_AGENT_OPERATOR_PORTAL_URL", portal)
      t.Setenv("VPS_AGENT_MCP_APPS", "1")
      ts := httptest.NewServer(Handler(approvalExecutor{}, AuthConfig{Mode: "none", StaticSubject: "alice"}))
      defer ts.Close()
      options := &mcp.ClientOptions{Capabilities: &mcp.ClientCapabilities{
        Extensions: map[string]any{approvalExtension: map[string]any{"mimeTypes": []string{approvalAppMIME}}},
      }}
      client := mcp.NewClient(&mcp.Implementation{Name: "chat-host-consent", Version: "v1"}, options)
      session, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: ts.URL + "/mcp"}, nil)
      if err != nil { t.Fatal(err) }
      defer session.Close()
      result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
        Name: "permissions.request_root_access",
        Arguments: map[string]any{"root": "/opt/project-a", "access": "read", "ttl_seconds": 600},
      })
      if err != nil || result.IsError { t.Fatalf("request: %v %v", err, result) }
      payload, err := json.Marshal(result.StructuredContent)
      if err != nil { t.Fatal(err) }
      for _, want := range []string{
        `"client_tool_consent_grants_root_access":false`,
        `"operator_authentication_required":true`,
        "Permitir uma vez/Sempre permitir",
        "permissions.approval_status",
      } {
        if !strings.Contains(string(payload), want) { t.Fatalf("missing %s: %s", want, payload) }
      }
      if portal == "" && !strings.Contains(string(payload), `"approval_method":"operator_fallback"`) {
        t.Fatalf("fallback missing: %s", payload)
      }
      if portal != "" && !strings.Contains(string(payload), `"approval_method":"operator_web"`) {
        t.Fatalf("web flow missing: %s", payload)
      }
      if strings.Contains(string(payload), `"status":"approved"`) {
        t.Fatalf("tool consent cannot approve root: %s", payload)
      }
    })
  }
}
