package gateway

import (
    "bytes"
    "encoding/json"
    "io"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"

    "github.com/josemirmoura/mcp-vps-agent-gateway/internal/securefs"
)

func TestGateCA4SubjectRateBurstRecoveryAndIsolation(t *testing.T) {
    limiter:=newToolInvocationLimiter(2,2)
    clock:=time.Now()
    limiter.now=func()time.Time{return clock}
    if !limiter.allow("alice") || !limiter.allow("alice") {t.Fatal("allowed burst denied")}
    if limiter.allow("alice") {t.Fatal("temporal limit missing")}
    if !limiter.allow("bob") {t.Fatal("alice's limit blocked independent authenticated principal")}
    clock=clock.Add(time.Second)
    if !limiter.allow("alice") {t.Fatal("token bucket did not recover")}
    if !limiter.allow("alice") {t.Fatal("second regenerated token missing")}
    if limiter.allow("alice") {t.Fatal("recovered bucket not bounded")}
}

func TestGateCA4BoundedPrincipalMemoryAndFailClosed(t *testing.T) {
    limiter:=newToolInvocationLimiter(1,1)
    clock:=time.Now()
    limiter.now=func()time.Time{return clock}
    for i:=0;i<maxToolSubjects;i++ {
        subject:=string(rune(0x100+i))
        if !limiter.allow(subject) {t.Fatalf("premature max-subject rejection at %d",i)}
    }
    if limiter.allow("new-identity") {t.Fatal("unbounded identity cardinality")}
    clock=clock.Add(toolSubjectIdle+time.Minute)
    if !limiter.allow("new-identity") {t.Fatal("expired subject entries were not reclaimed")}
}

func TestGateCA4RateLimitHTTPRealGatewayAndNonToolsUnaffected(t *testing.T) {
    root:=t.TempDir()
    fs,err:=securefs.New([]string{root},[]string{root},1024)
    if err!=nil {t.Fatal(err)}
    srv:=httptest.NewServer(Handler(LocalExecutor{FS:fs},AuthConfig{
        Mode:"none",StaticSubject:"alice",ToolCallsPerSecond:1,ToolCallBurst:2,
    }))
    defer srv.Close()
    post:=func(method string,id int)(int,map[string]json.RawMessage,http.Header){
        t.Helper()
        params:=map[string]any{"_meta":map[string]any{
            "io.modelcontextprotocol/protocolVersion":"2026-07-28",
            "io.modelcontextprotocol/clientCapabilities":map[string]any{},
        }}
        if method=="tools/call" {params["name"]="system.info";params["arguments"]=map[string]any{}}
        raw,_:=json.Marshal(map[string]any{"jsonrpc":"2.0","id":id,"method":method,"params":params})
        req,err:=http.NewRequest("POST",srv.URL+"/mcp",bytes.NewReader(raw))
        if err!=nil {t.Fatal(err)}
        req.Header.Set("Content-Type","application/json")
        req.Header.Set("Accept","application/json, text/event-stream")
        req.Header.Set("MCP-Protocol-Version","2026-07-28")
        req.Header.Set("Mcp-Method",method)
        if method=="tools/call" {req.Header.Set("Mcp-Name","system.info")}
        resp,err:=srv.Client().Do(req)
        if err!=nil {t.Fatal(err)}
        defer resp.Body.Close()
        b,err:=io.ReadAll(io.LimitReader(resp.Body,1<<20))
        if err!=nil {t.Fatal(err)}
        var out map[string]json.RawMessage
        if err=json.Unmarshal(b,&out);err!=nil {t.Fatalf("HTTP %d non-JSON: %s",resp.StatusCode,b)}
        return resp.StatusCode,out,resp.Header
    }
    for i:=0;i<2;i++ {
        status,body,_:=post("tools/call",i+1)
        if status!=200 || len(body["result"])==0 {t.Fatalf("allowed request %d HTTP=%d",i,status)}
    }
    status,body,hdr:=post("tools/call",3)
    if status!=429 || hdr.Get("Retry-After")=="" {t.Fatalf("no HTTP 429 retry on burst: %d",status)}
    var e struct{Code int `json:"code"`}
    if json.Unmarshal(body["error"],&e)!=nil||e.Code!=-32000 {t.Fatalf("invalid rate-limit RPC error: %s",body["error"])}
    if string(body["id"])!="3" {t.Fatalf("rate-limit lost original JSON-RPC ID: %s",body["id"])}
    status,_,_=post("tools/list",4)
    if status!=200 {t.Fatalf("non-tool discovery was throttled: %d",status)}
}
