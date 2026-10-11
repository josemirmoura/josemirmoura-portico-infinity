package gateway

import (
    "bytes"
    "encoding/json"
    "io"
    "net/http"
    "testing"

    jsonschema "github.com/google/jsonschema-go/jsonschema"
)

// These checks exercise the actual Community Gateway handler and SDK catalog,
// not the synthetic conformance-fixture build tag or a fabricated tools/list.
func gateCProfileRPC(t *testing.T, serverURL, method string, params map[string]any, id int) (int, map[string]json.RawMessage) {
    t.Helper()
    params["_meta"] = map[string]any{
        "io.modelcontextprotocol/protocolVersion": "2026-07-28",
        "io.modelcontextprotocol/clientInfo": map[string]any{"name":"schema-audit","version":"1"},
        "io.modelcontextprotocol/clientCapabilities": map[string]any{},
    }
    data, err := json.Marshal(map[string]any{
        "jsonrpc":"2.0", "id":id, "method":method, "params":params,
    })
    if err != nil { t.Fatal(err) }
    req, err := http.NewRequest("POST",serverURL+"/mcp",bytes.NewReader(data))
    if err != nil { t.Fatal(err) }
    req.Header.Set("Content-Type","application/json")
    req.Header.Set("Accept","application/json, text/event-stream")
    req.Header.Set("MCP-Protocol-Version","2026-07-28")
    req.Header.Set("Mcp-Method",method)
    if method=="tools/call" { req.Header.Set("Mcp-Name",params["name"].(string)) }
    client:=&http.Client{}
    response, err := client.Do(req)
    if err != nil { t.Fatal(err) }
    defer response.Body.Close()
    if got:=response.Header.Get("Content-Type"); got!="application/json" && got!="application/json; charset=utf-8" {
        t.Fatalf("%s returned unexpected content-type %q",method,got)
    }
    wire, err := io.ReadAll(io.LimitReader(response.Body,1<<20))
    if err != nil {t.Fatal(err)}
    var msg map[string]json.RawMessage
    if err:=json.Unmarshal(wire,&msg);err!=nil {t.Fatalf("%s not JSON-RPC: %v",method,err)}
    var gotID int
    if err:=json.Unmarshal(msg["id"],&gotID);err!=nil || gotID!=id {
        t.Fatalf("%s response ID mismatch: %s",method,msg["id"])
    }
    var jsonrpc string
    if err:=json.Unmarshal(msg["jsonrpc"],&jsonrpc);err!=nil || jsonrpc!="2.0" {
        t.Fatalf("%s not JSON-RPC 2.0",method)
    }
    return response.StatusCode,msg
}

func gateCResolveLocalSchema(t *testing.T, tool, direction string, raw json.RawMessage) *jsonschema.Resolved {
    t.Helper()
    if len(raw)==0 || string(raw)=="null" {t.Fatalf("%s has null %s schema",tool,direction)}
    var fields map[string]json.RawMessage
    if err:=json.Unmarshal(raw,&fields);err!=nil || fields==nil {
        t.Fatalf("%s %s must be JSON Schema object: %v",tool,direction,err)
    }
    if dialect,ok:=fields["$schema"];ok {
        var uri string
        if err:=json.Unmarshal(dialect,&uri);err!=nil || uri!="https://json-schema.org/draft/2020-12/schema" {
            t.Fatalf("%s declares unsupported %s dialect %s",tool,direction,dialect)
        }
    }
    var schema jsonschema.Schema
    if err:=json.Unmarshal(raw,&schema);err!=nil {t.Fatalf("%s invalid %s schema: %v",tool,direction,err)}
    // Do NOT fetch external $refs or accept a partial/no-op validation.
    resolved,err:=schema.Resolve(nil)
    if err!=nil {t.Fatalf("%s unresolvable %s schema: %v",tool,direction,err)}
    return resolved
}

func TestGateCRealProductionToolCatalogSchemas202012(t *testing.T) {
    s:=gateCTransportFixture(t)
    defer s.Close()
    var names []string
    outputs:=map[string]*jsonschema.Resolved{}
    var previous []string
    for pass:=0;pass<2;pass++ {
        var passNames []string
        cursor:=""
        cursors:=map[string]bool{}
        for page:=0;page<20;page++ {
            params:=map[string]any{}
            if cursor!="" {params["cursor"]=cursor}
            status,rpc:=gateCProfileRPC(t,s.URL,"tools/list",params,1100+100*pass+page)
            if status!=200 || len(rpc["error"])>0 {t.Fatalf("tools/list HTTP %d: %s",status,rpc["error"])}
            var result struct {
                ResultType string `json:"resultType"`
                Tools []struct {
                    Name string `json:"name"`
                    InputSchema json.RawMessage `json:"inputSchema"`
                    OutputSchema json.RawMessage `json:"outputSchema"`
                } `json:"tools"`
                NextCursor string `json:"nextCursor"`
            }
            if err:=json.Unmarshal(rpc["result"],&result);err!=nil {t.Fatal(err)}
            if result.ResultType!="complete" {t.Fatalf("tools/list resultType=%q",result.ResultType)}
            for _,entry:=range result.Tools {
                if entry.Name=="" || len(entry.Name)>128 {t.Fatalf("invalid exposed tool name %q",entry.Name)}
                for _,prior:=range passNames {if prior==entry.Name {t.Fatalf("duplicate tool %q",entry.Name)}}
                passNames=append(passNames,entry.Name)
                var input map[string]json.RawMessage
                if err:=json.Unmarshal(entry.InputSchema,&input);err!=nil {t.Fatalf("%s inputSchema malformed",entry.Name)}
                if string(input["type"])!=`"object"` {t.Fatalf("%s inputSchema root is not object",entry.Name)}
                gateCResolveLocalSchema(t,entry.Name,"input",entry.InputSchema)
                if len(entry.OutputSchema)>0 && string(entry.OutputSchema)!="null" {
                    outputs[entry.Name]=gateCResolveLocalSchema(t,entry.Name,"output",entry.OutputSchema)
                }
            }
            if result.NextCursor=="" {break}
            if cursors[result.NextCursor] {t.Fatal("tools/list cursor cycle")}
            cursors[result.NextCursor]=true
            cursor=result.NextCursor
            if page==19 {t.Fatal("catalog overflow")}
        }
        if len(passNames)<10 {t.Fatalf("only %d tools in Community catalog",len(passNames))}
        if pass==0 {names=passNames} else {
            if len(names)!=len(passNames) {t.Fatal("catalog changed across stateless calls")}
            for i,v:=range names {if passNames[i]!=v {t.Fatal("unstable tool listing order")}}
        }
        previous=passNames
    }
    _=previous
    found:=false
    for _,n:=range names {if n=="system.info" {found=true}}
    if !found {t.Fatal("safe system.info tool absent")}

    status,rpc:=gateCProfileRPC(t,s.URL,"tools/call",map[string]any{
        "name":"system.info","arguments":map[string]any{},
    },1337)
    if status!=200 || len(rpc["error"])>0 {t.Fatalf("real tool failed HTTP %d: %s",status,rpc["error"])}
    var result struct {
        ResultType string `json:"resultType"`
        IsError bool `json:"isError"`
        Content []json.RawMessage `json:"content"`
        StructuredContent json.RawMessage `json:"structuredContent"`
    }
    if err:=json.Unmarshal(rpc["result"],&result);err!=nil {t.Fatal(err)}
    if result.ResultType!="complete" || result.IsError || len(result.Content)==0 {
        t.Fatalf("invalid complete tool result: %+v",result)
    }
    if output:=outputs["system.info"];output!=nil {
        if len(result.StructuredContent)==0 {t.Fatal("tool outputSchema but no structuredContent")}
        var instance any
        if err:=json.Unmarshal(result.StructuredContent,&instance);err!=nil {t.Fatal(err)}
        if err:=output.Validate(instance);err!=nil {t.Fatalf("system.info structuredContent violates its outputSchema: %v",err)}
    }
}

func TestGateCRealGatewayDoesNotAdvertiseDeprecatedUnusedLogging(t *testing.T) {
    s:=gateCTransportFixture(t)
    defer s.Close()
    status,reply:=gateCProfileRPC(t,s.URL,"server/discover",map[string]any{},2101)
    if status!=200 || len(reply["error"])>0 {t.Fatalf("discovery failed HTTP %d: %s",status,reply["error"])}
    var discovery struct {
        Capabilities map[string]json.RawMessage `json:"capabilities"`
        SupportedVersions []string `json:"supportedVersions"`
    }
    if err:=json.Unmarshal(reply["result"],&discovery);err!=nil {t.Fatal(err)}
    if _,ok:=discovery.Capabilities["logging"];ok {t.Fatal("deprecated unused MCP logging advertised")}
    if _,ok:=discovery.Capabilities["tools"];!ok {t.Fatal("real tools capability missing")}
    ok:=false
    for _,v:=range discovery.SupportedVersions {if v=="2026-07-28" {ok=true}}
    if !ok {t.Fatal("requested revision missing from discovery")}
}
