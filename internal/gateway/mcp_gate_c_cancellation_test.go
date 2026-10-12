package gateway

import (
    "bytes"
    "context"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "sync"
    "testing"
    "time"

    "github.com/josemirmoura/mcp-vps-agent-gateway/internal/wire"
)

// Verifies cancellation on the actual Streamable HTTP Handler -> Executor
// boundary; the test never reaches a privileged Broker or writes to the host.
type gateCBlockingCancellationExecutor struct {
    started chan struct{}
    canceled chan struct{}
    startOnce sync.Once
    cancelOnce sync.Once
}

func (p *gateCBlockingCancellationExecutor) Call(ctx context.Context, req wire.Request) (wire.Response, error) {
    p.startOnce.Do(func(){close(p.started)})
    <-ctx.Done()
    p.cancelOnce.Do(func(){close(p.canceled)})
    return wire.Response{},ctx.Err()
}

func TestGateCRealHandlerRequestContextPropagatesDisconnect(t *testing.T) {
    probe:=&gateCBlockingCancellationExecutor{started:make(chan struct{}),canceled:make(chan struct{})}
    srv:=httptest.NewServer(Handler(probe,AuthConfig{Mode:"none",StaticSubject:"fixture"}))
    defer srv.Close()
    body,err:=json.Marshal(map[string]any{
        "jsonrpc":"2.0", "id":408, "method":"tools/call",
        "params":map[string]any{
            "name":"system.info", "arguments":map[string]any{},
            "_meta":map[string]any{
                "io.modelcontextprotocol/protocolVersion":"2026-07-28",
                "io.modelcontextprotocol/clientInfo":map[string]any{"name":"cancel-test","version":"1"},
                "io.modelcontextprotocol/clientCapabilities":map[string]any{},
            },
        },
    })
    if err!=nil {t.Fatal(err)}
    ctx,cancel:=context.WithCancel(context.Background())
    defer cancel()
    req,err:=http.NewRequestWithContext(ctx,"POST",srv.URL+"/mcp",bytes.NewReader(body))
    if err!=nil {t.Fatal(err)}
    req.Header.Set("Accept","application/json, text/event-stream")
    req.Header.Set("Content-Type","application/json")
    req.Header.Set("MCP-Protocol-Version","2026-07-28")
    req.Header.Set("Mcp-Method","tools/call")
    req.Header.Set("Mcp-Name","system.info")
    client:=&http.Client{Timeout:5*time.Second}
    finished:=make(chan struct{})
    go func() {
        defer close(finished)
        resp,err:=client.Do(req)
        if err==nil {resp.Body.Close()}
    }()
    select {
    case <-probe.started:
    case <-time.After(3*time.Second):
        t.Fatal("request never reached actual MCP Handler/Executor")
    }
    cancel()
    select {
    case <-probe.canceled:
    case <-time.After(3*time.Second):
        t.Fatal("client disconnect did not cancel in-flight real MCP Executor context")
    }
    select {
    case <-finished:
    case <-time.After(3*time.Second):
        t.Fatal("client did not terminate after cancel")
    }
}
