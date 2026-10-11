package main

import (
    "bytes"
    "context"
    "time"
    "os"
    "os/exec"
    "testing"
)

// Independent A1 regression: a distributed Gateway binary never permits
// plaintext introspection, even at localhost. httptest-only exceptions
// belong inside the isolated verifier constructor unit tests.
func TestGateCA1DistributedProcessRejectsPlainHTTPIntrospection(t *testing.T) {
    if os.Getenv("PORTICO_A1_HELPER_PROCESS") == "1" {
        main()
        return
    }
    for _, endpoint := range []string{
        "http://zitadel-auth-internal:8080/oauth/v2/introspect",
        "http://127.0.0.1:18888/oauth/v2/introspect",
    } {
        t.Run(endpoint,func(t *testing.T){
            ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second)
            defer cancel()
            cmd:=exec.CommandContext(ctx,os.Args[0],"-test.run=^TestGateCA1DistributedProcessRejectsPlainHTTPIntrospection$")
            cmd.Env=append(os.Environ(),
                "PORTICO_A1_HELPER_PROCESS=1",
                "VPS_AGENT_LISTEN=127.0.0.1:0",
                "VPS_AGENT_POC_ROOT="+t.TempDir(),
                "VPS_AGENT_BROKER_SOCKET=",
                "VPS_AGENT_PUBLIC_URL=",
                "VPS_AGENT_AUTH_MODE=integrated",
                "VPS_AGENT_OIDC_ISSUER=https://issuer.invalid",
                "VPS_AGENT_OAUTH_RESOURCE=https://mcp.invalid/mcp",
                "VPS_AGENT_INTEGRATED_INTROSPECTION_URL="+endpoint,
            )
            output,err:=cmd.CombinedOutput()
            if err==nil {t.Fatal("insecure introspection unexpectedly allowed normal Gateway startup")}
            if !bytes.Contains(output,[]byte("HTTPS introspection URL required")) {
                t.Fatalf("unexpected startup failure (missing fail-closed reason): %s",output)
            }
        })
    }
}
