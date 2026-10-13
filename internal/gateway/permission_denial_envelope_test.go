package gateway

import (
    "context"
    "encoding/json"
    "net/http/httptest"
    "strings"
    "testing"

    "github.com/josemirmoura/mcp-vps-agent-gateway/internal/wire"
    "github.com/modelcontextprotocol/go-sdk/mcp"
)

// permissionDenialExecutor simulates a real Broker authorization rejection.
// It does not grant access or touch any host filesystem or remote MCP server.
type permissionDenialExecutor struct{}

func (permissionDenialExecutor) Call(_ context.Context, req wire.Request) (wire.Response, error) {
    switch req.Tool {
    case "file.read", "file.write", "file.read_test", "file.write_test":
        return wire.ErrorResponse(req.ID, "permission_denied", "path outside authorized roots"), nil
    default:
        return wire.ErrorResponse(req.ID, "unexpected_tool", "test rejects unexpected tool"), nil
    }
}

func TestPermissionDeniedIsMCPToolErrorNotProtocolError(t *testing.T) {
    // The server is real Streamable HTTP; only its Broker executor is a
    // disposable stub. No privileged socket, Docker or filesystem is used.
    server := httptest.NewServer(Handler(permissionDenialExecutor{}, AuthConfig{
        Mode: "none", StaticSubject: "synthetic-test-user",
    }))
    defer server.Close()

    client := mcp.NewClient(&mcp.Implementation{Name: "permission-denied-wire-probe", Version: "1"}, nil)
    session, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{
        Endpoint: server.URL + "/mcp",
    }, nil)
    if err != nil {
        t.Fatal(err)
    }
    defer session.Close()

    cases := []struct {
        name string
        args map[string]any
    }{
        {"file.read", map[string]any{"path": "/opt/not-authorized/read.txt"}},
        {"file.write", map[string]any{"path": "/opt/not-authorized/write.txt", "content": "synthetic"}},
    }
    for _, test := range cases {
        t.Run(test.name, func(t *testing.T) {
            result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
                Name: test.name, Arguments: test.args,
            })
            // A normal tool denial must NOT become a JSON-RPC protocol error.
            if err != nil {
                t.Fatalf("denial surfaced as protocol error: %v", err)
            }
            if result == nil || !result.IsError {
                t.Fatalf("denial did not set MCP isError: %+v", result)
            }
            raw, marshalErr := json.Marshal(result)
            if marshalErr != nil {
                t.Fatal(marshalErr)
            }
            if !strings.Contains(string(raw), "permission_denied: path outside authorized roots") {
                t.Fatalf("MCP tool result lost the Broker's denial code: %s", raw)
            }
            // The generic ChatGPT client envelope INVALID_ARGUMENT observed
            // in E2E is not emitted by this Streamable HTTP tool result.
            if strings.Contains(string(raw), "INVALID_ARGUMENT") {
                t.Fatalf("Gateway inserted client-side INVALID_ARGUMENT wrapper: %s", raw)
            }
        })
    }
}

func TestMalformedArgumentsDifferFromPermissionDenial(t *testing.T) {
    server := httptest.NewServer(Handler(permissionDenialExecutor{}, AuthConfig{
        Mode: "none", StaticSubject: "synthetic-test-user",
    }))
    defer server.Close()
    client := mcp.NewClient(&mcp.Implementation{Name: "invalid-argument-probe", Version: "1"}, nil)
    session, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{
        Endpoint: server.URL + "/mcp",
    }, nil)
    if err != nil {
        t.Fatal(err)
    }
    defer session.Close()
    result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
        Name: "file.read", Arguments: map[string]any{"path": 123},
    })
    if err != nil {
        t.Fatalf("argument validation should be a tool result, got: %v", err)
    }
    if result == nil || !result.IsError {
        t.Fatalf("invalid input unexpectedly accepted: %+v", result)
    }
    raw, _ := json.Marshal(result)
    if strings.Contains(string(raw), "permission_denied") {
        t.Fatalf("malformed arguments misclassified as Broker denial: %s", raw)
    }
}
