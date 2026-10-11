package gateway

import (
    "bytes"
    "encoding/json"
    "io"
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"
)

// A request with an invalid JSON-RPC envelope or invalid tool arguments
// must not dispatch even a read-only method to the actual Executor.
// No synthetic MCP tools or privileged production resources are involved.
func TestGateCRealHTTPMalformedJSONRPCNeverReachesExecutor(t *testing.T) {
    const metadata = `"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientInfo":{"name":"malformed-rpc-audit","version":"1"},"io.modelcontextprotocol/clientCapabilities":{}}`
    goodParams := `"params":{"name":"system.info","arguments":{},` + metadata + "}"
    cases := []struct{
        name string
        body string
    }{
        {"truncated-json", `{"jsonrpc":"2.0","id":41,"method":"tools/call",`},
        {"trailing-garbage", `{"jsonrpc":"2.0","id":41,"method":"tools/call",`+goodParams+"not-json"},
        {"wrong-jsonrpc-revision", `{"jsonrpc":"1.0","id":41,"method":"tools/call",`+goodParams+"}"},
        {"missing-method", `{"jsonrpc":"2.0","id":41,`+goodParams+"}"},
        {"non-string-method", `{"jsonrpc":"2.0","id":41,"method":12,`+goodParams+"}"},
        {"invalid-params-container", `{"jsonrpc":"2.0","id":41,"method":"tools/call","params":[]}`},
        {"invalid-arguments-type", `{"jsonrpc":"2.0","id":41,"method":"tools/call","params":{"name":"system.info","arguments":"not-object",`+metadata+"}}"},
        {"invalid-tool-name-type", `{"jsonrpc":"2.0","id":41,"method":"tools/call","params":{"name":true,"arguments":{},`+metadata+"}}"},
    }
    for _,tc:=range cases {
        t.Run(tc.name,func(t *testing.T){
            probe:=&oauthResourceProbeExecutor{}
            server:=httptest.NewServer(Handler(probe,AuthConfig{Mode:"none",StaticSubject:"malformed-fixture"}))
            defer server.Close()
            req,err:=http.NewRequest("POST",server.URL+"/mcp",bytes.NewBufferString(tc.body))
            if err!=nil {t.Fatal(err)}
            req.Header.Set("Content-Type","application/json")
            req.Header.Set("Accept","application/json, text/event-stream")
            req.Header.Set("MCP-Protocol-Version","2026-07-28")
            req.Header.Set("Mcp-Method","tools/call")
            req.Header.Set("Mcp-Name","system.info")
            response,err:=server.Client().Do(req)
            if err!=nil {t.Fatal(err)}
            defer response.Body.Close()
            if response.StatusCode>=500 || response.StatusCode<200 {
                t.Fatalf("malformed request returned server error HTTP %d",response.StatusCode)
            }
            raw,err:=io.ReadAll(io.LimitReader(response.Body,1<<20))
            if err!=nil {t.Fatal(err)}
            if !strings.Contains(response.Header.Get("Content-Type"),"application/json") {
                t.Fatalf("malformed request returned non-JSON response: HTTP %d Content-Type %q", response.StatusCode,response.Header.Get("Content-Type"))
            }
            var rpc struct {
                JSONRPC string `json:"jsonrpc"`
                ID json.RawMessage `json:"id"`
                Result json.RawMessage `json:"result"`
                Error struct {
                    Code int `json:"code"`
                    Message string `json:"message"`
                } `json:"error"`
            }
            if err:=json.Unmarshal(raw,&rpc);err!=nil {t.Fatalf("non-JSON-RPC response (HTTP %d): %v",response.StatusCode,err)}
            if rpc.JSONRPC!="2.0" || rpc.Error.Code==0 || rpc.Error.Message=="" ||
                (len(rpc.Result)!=0 && string(rpc.Result)!="null") {
                t.Fatalf("malformed request accepted or returned invalid JSON-RPC envelope: HTTP %d response=%s",response.StatusCode,string(raw))
            }
            if response.StatusCode==200 && rpc.Error.Code==0 {t.Fatal("invalid request returned success")}
            calls,_:=probe.snapshot()
            if calls!=0 {t.Fatalf("malformed input reached executor %d times",calls)}
        })
    }
}
