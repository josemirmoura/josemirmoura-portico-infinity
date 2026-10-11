package gateway

import (
    "context"
    "encoding/json"
    "strings"
    "testing"
    "time"

    "github.com/josemirmoura/mcp-vps-agent-gateway/internal/wire"
    "github.com/modelcontextprotocol/go-sdk/mcp"
)

// A native MCP "accept" conveys navigation intent only. The independently
// authenticated operator and Broker alone may grant access. This fixture
// rejects forged MRTR requestState before Executor and allows only status
// retrieval for a valid continuation.
type gateCNavigationSpy struct { requests []wire.Request }

func (s *gateCNavigationSpy) Call(_ context.Context, req wire.Request) (wire.Response,error) {
    s.requests=append(s.requests,req)
    raw,_:=json.Marshal(map[string]any{"status":"pending","resource":"/opt/fixture-project"})
    return wire.Response{ID:req.ID, OK:true, Result:raw},nil
}

func gateCNavigationRequest(state, action string) *mcp.CallToolRequest {
    return &mcp.CallToolRequest{Params:&mcp.CallToolParamsRaw{
        RequestState:state,
        InputResponses:mcp.InputResponseMap{
            navigationInputKey:&mcp.ElicitResult{Action:action},
        },
    }}
}

func TestGateCMRTRSignedNavigationNeverGrantsAccess(t *testing.T) {
    const root="/opt/fixture-project"
    const other="/opt/other"
    spy:=&gateCNavigationSpy{}
    srv:=&Server{Executor:spy, navigationKey:[]byte("fixture-hmac-key-32-bytes-private!!")}
    alice:=context.WithValue(context.Background(),subjectKey{},"alice")
    bob:=context.WithValue(context.Background(),subjectKey{},"bob")
    state:=operatorNavigationState{
        Version:2, Kind:"root", RequestID:"apr_fixture_proof",
        Target:root, Subject:"alice", Expires:time.Now().Add(5*time.Minute).Unix(),
    }
    signed:=srv.sealNavigation(state)
    if signed=="" {t.Fatal("navigation HMAC signing failed")}
    expired:=state
    expired.Expires=time.Now().Add(-time.Minute).Unix()
    wrongVersion:=state
    wrongVersion.Version=1
    cases:=[]struct{
        name string
        ctx context.Context
        kind,target,token,action string
    }{
        {"invalid-token",alice,"root",root,"not-a-navigation-token","accept"},
        {"tampered-hmac",alice,"root",root,signed+"x","accept"},
        {"cross-subject",bob,"root",root,signed,"accept"},
        {"cross-target",alice,"root",other,signed,"accept"},
        {"cross-kind",alice,"sensitive",root,signed,"accept"},
        {"expired-state",alice,"root",root,srv.sealNavigation(expired),"accept"},
        {"wrong-version",alice,"root",root,srv.sealNavigation(wrongVersion),"accept"},
        {"client-action-cannot-grant",alice,"root",root,signed,"approve"},
    }
    for _,tc:=range cases {
        t.Run(tc.name,func(t *testing.T){
            before:=len(spy.requests)
            result,handled,err:=srv.navigationContinuation(tc.ctx,gateCNavigationRequest(tc.token,tc.action),tc.kind,tc.target)
            if !handled || err==nil || result!=nil {
                t.Fatalf("invalid MRTR state was accepted: handled=%v error=%v result=%v",handled,err,result)
            }
            if len(spy.requests)!=before {t.Fatal("forged navigation reached the Broker")}
        })
    }

    result,handled,err:=srv.navigationContinuation(alice,gateCNavigationRequest(signed,"accept"),"root",root)
    if err!=nil || !handled {t.Fatalf("legitimate navigation continuation failed: %v handled=%v",err,handled)}
    if result["status"]!="pending" || result["operator_authentication_required"]!=true ||
        result["native_action"]!="accept" || result["approval_method"]!="operator_navigation" ||
        result["status_tool"]!="permissions.approval_status" {
        t.Fatalf("client accept was mistaken for independent operator approval: %+v",result)
    }
    if len(spy.requests)!=1 {
        t.Fatalf("native accept made %d broker calls; expected status read only",len(spy.requests))
    }
    if req:=spy.requests[0];req.Tool!="permissions.approval_status" || req.Subject!="alice" ||
        !strings.HasPrefix(req.Resource,"apr_fixture_") {
        t.Fatalf("unsafe Broker operation after native accept: tool=%q subject=%q",req.Tool,req.Subject)
    }
}
