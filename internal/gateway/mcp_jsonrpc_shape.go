package gateway

import (
    "bytes"
    "encoding/json"
    "io"
    "net/http"
    "strings"
)

// guardMCPJSONRPCShape runs behind OAuth/rate limiting and before the Go SDK.
// It closes a 2026-07-28 interoperability gap: malformed JSON-RPC should not
// be mistaken for an accepted notification or return unstructured parse text.
// This guard does not authorize tools; the SDK and Broker keep that authority.
func guardMCPJSONRPCShape(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request) {
        if r.Method != http.MethodPost {
            next.ServeHTTP(w,r)
            return
        }
        const maxBody=1<<20 // same bound as StreamableHTTPHandler
        raw,err:=io.ReadAll(io.LimitReader(r.Body,maxBody+1))
        if err!=nil {
            writeMCPTransportError(w,http.StatusBadRequest,json.RawMessage("null"),-32700,"Cannot read JSON-RPC message",nil)
            return
        }
        if len(raw)>maxBody {
            writeMCPTransportError(w,http.StatusRequestEntityTooLarge,json.RawMessage("null"),-32600,"JSON-RPC message too large",nil)
            return
        }
        if !json.Valid(raw) {
            writeMCPTransportError(w,http.StatusBadRequest,json.RawMessage("null"),-32700,"Parse error",nil)
            return
        }
        var envelope map[string]json.RawMessage
        if json.Unmarshal(raw,&envelope)!=nil || envelope==nil {
            writeMCPTransportError(w,http.StatusBadRequest,json.RawMessage("null"),-32600,"Invalid JSON-RPC request object",nil)
            return
        }
        requestID:=json.RawMessage("null")
        if id,ok:=envelope["id"];ok {
            if !validMCPRequestID(id) {
                writeMCPTransportError(w,http.StatusBadRequest,requestID,-32600,"Invalid request id",nil)
                return
            }
            requestID=id
        }
        if string(envelope["jsonrpc"])!=`"2.0"` {
            writeMCPTransportError(w,http.StatusBadRequest,requestID,-32600,"Invalid JSON-RPC version",nil)
            return
        }
        var method string
        if json.Unmarshal(envelope["method"],&method)!=nil || strings.TrimSpace(method)=="" {
            writeMCPTransportError(w,http.StatusBadRequest,requestID,-32600,"Missing or invalid JSON-RPC method",nil)
            return
        }
        if params,ok:=envelope["params"];ok {
            var obj map[string]json.RawMessage
            if json.Unmarshal(params,&obj)!=nil || obj==nil {
                writeMCPTransportError(w,http.StatusBadRequest,requestID,-32602,"JSON-RPC params must be an object",nil)
                return
            }
        }
        r.Body=io.NopCloser(bytes.NewReader(raw))
        next.ServeHTTP(w,r)
    })
}

// MCP 2026-07-28 request IDs must be strings or numbers, never null/bool/object.
func validMCPRequestID(value json.RawMessage) bool {
    if len(value)==0 || bytes.Equal(value,[]byte("null")) {return false}
    var s string
    if json.Unmarshal(value,&s)==nil {return true}
    var n json.Number
    return json.Unmarshal(value,&n)==nil
}
