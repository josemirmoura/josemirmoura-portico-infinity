package gateway

import (
    "bytes"
    "encoding/base64"
    "encoding/json"
    "io"
    "net/http"
    "net/http/httptest"
    "testing"

    "github.com/josemirmoura/mcp-vps-agent-gateway/internal/securefs"
)

func gateCTransportFixture(t *testing.T) *httptest.Server {
    t.Helper()
    root := t.TempDir()
    fs, err := securefs.New([]string{root}, []string{root}, 1024)
    if err != nil { t.Fatal(err) }
    return httptest.NewServer(Handler(LocalExecutor{FS: fs}, AuthConfig{
        Mode: "none", StaticSubject: "mcp-audit-fixture",
    }))
}

func gateCTransportRequest(t *testing.T, endpoint, version string) *http.Request {
    t.Helper()
    body, err := json.Marshal(map[string]any{
        "jsonrpc": "2.0", "id": "audit-request", "method": "tools/call",
        "params": map[string]any{
            "name": "system.info", "arguments": map[string]any{},
            "_meta": map[string]any{
                "io.modelcontextprotocol/protocolVersion": version,
                "io.modelcontextprotocol/clientCapabilities": map[string]any{},
            },
        },
    })
    if err != nil { t.Fatal(err) }
    request, err := http.NewRequest(http.MethodPost, endpoint+"/mcp", bytes.NewReader(body))
    if err != nil { t.Fatal(err) }
    request.Header.Set("Content-Type", "application/json")
    request.Header.Set("Accept", "application/json, text/event-stream")
    request.Header.Set("MCP-Protocol-Version", version)
    request.Header.Set("Mcp-Method", "tools/call")
    request.Header.Set("Mcp-Name", "system.info")
    return request
}

func gateCSendTransportRequest(t *testing.T, client *http.Client, req *http.Request) (int, map[string]json.RawMessage) {
    t.Helper()
    resp, err := client.Do(req)
    if err != nil { t.Fatal(err) }
    defer resp.Body.Close()
    payload, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
    if err != nil { t.Fatal(err) }
    var out map[string]json.RawMessage
    if err := json.Unmarshal(payload, &out); err != nil {
        t.Fatalf("expected JSON-RPC, HTTP %d: %q", resp.StatusCode, payload)
    }
    return resp.StatusCode, out
}

func gateCAssertRPCCode(t *testing.T, msg map[string]json.RawMessage, expected int) {
    t.Helper()
    var entry struct { Code int `json:"code"` }
    if err := json.Unmarshal(msg["error"], &entry); err != nil { t.Fatal(err) }
    if entry.Code != expected { t.Fatalf("code=%d want=%d",entry.Code,expected) }
}

func TestGateCA2MCPEncodedNameAgainstRealHandler(t *testing.T) {
    server := gateCTransportFixture(t)
    defer server.Close()
    for _, tc := range []struct{
        name, header string
        wantStatus int
        wantError int
    }{
        {"plain", "system.info", http.StatusOK, 0},
        {"valid-base64", "=?base64?"+base64.StdEncoding.EncodeToString([]byte("system.info"))+"?=", http.StatusOK, 0},
        {"encoded-wrong-tool", "=?base64?"+base64.StdEncoding.EncodeToString([]byte("file.write"))+"?=", http.StatusBadRequest, -32020},
        {"encoded-invalid-base64", "=?base64?%%%%?=", http.StatusBadRequest, -32020},
        {"encoded-invalid-utf8", "=?base64?//8=?=", http.StatusBadRequest, -32020},
        {"encoded-missing-suffix", "=?base64?c3lzdGVtLmluZm8=", http.StatusBadRequest, -32020},
        {"encoded-nonexistent", "=?base64?bm9uZXhpc3RlbnQ=?=", http.StatusBadRequest, -32020},
    } {
        t.Run(tc.name,func(t *testing.T){
            req := gateCTransportRequest(t,server.URL,"2026-07-28")
            req.Header.Set("Mcp-Name",tc.header)
            status,msg := gateCSendTransportRequest(t,server.Client(),req)
            if status != tc.wantStatus { t.Fatalf("HTTP=%d want=%d",status,tc.wantStatus) }
            if tc.wantError != 0 { gateCAssertRPCCode(t,msg,tc.wantError) } else if len(msg["result"])==0 {t.Fatal("successful response missing result")}
        })
    }
}

func TestGateCA3UnknownHistoricalVersionHasStructuredErrorAndID(t *testing.T) {
    server := gateCTransportFixture(t)
    defer server.Close()
    req := gateCTransportRequest(t,server.URL,"1900-01-01")
    status,msg := gateCSendTransportRequest(t,server.Client(),req)
    if status!=400 {t.Fatalf("HTTP=%d",status)}
    gateCAssertRPCCode(t,msg,-32022)
    if string(msg["id"])!=`"audit-request"` {t.Fatalf("lost request ID: %s",msg["id"])}
    var rpcErr struct{ Data struct{
        Supported []string `json:"supported"`
        Requested string `json:"requested"`
    } `json:"data"` }
    if err:=json.Unmarshal(msg["error"],&rpcErr);err!=nil {t.Fatal(err)}
    if rpcErr.Data.Requested!="1900-01-01"||len(rpcErr.Data.Supported)==0 {t.Fatalf("invalid version data: %+v",rpcErr.Data)}
    found:=false
    for _,v:=range rpcErr.Data.Supported {if v=="2026-07-28" {found=true}}
    if !found {t.Fatal("modern supported version missing")}
    // A supported modern request remains functional.
    req=gateCTransportRequest(t,server.URL,"2026-07-28")
    status,msg=gateCSendTransportRequest(t,server.Client(),req)
    if status!=200||len(msg["result"])==0 {t.Fatalf("supported request affected: HTTP=%d",status)}
}

func TestGateCA5DuplicateMCPHeadersRejectedInBothOrders(t *testing.T) {
    server := gateCTransportFixture(t)
    defer server.Close()
    for _, tc:=range []struct{
        header, a, b string
    }{
        {"Mcp-Name","system.info","file.write"},
        {"Mcp-Method","tools/call","tools/list"},
        {"MCP-Protocol-Version","2026-07-28","1900-01-01"},
        {"Mcp-Param-Region","alpha","beta"},
        {"Mcp-Name","system.info","system.info"},
    } {
        for _, reverse:=range []bool{false,true} {
            req:=gateCTransportRequest(t,server.URL,"2026-07-28")
            req.Header.Del(tc.header)
            a,b:=tc.a,tc.b
            if reverse {a,b=b,a}
            req.Header.Add(tc.header,a)
            req.Header.Add(tc.header,b)
            status,msg:=gateCSendTransportRequest(t,server.Client(),req)
            if status!=400 {t.Errorf("%s reversed=%v HTTP=%d",tc.header,reverse,status);continue}
            gateCAssertRPCCode(t,msg,-32020)
        }
    }
}
