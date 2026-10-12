package gateway

import (
    "bytes"
    "encoding/base64"
    "encoding/json"
    "io"
    "net/http"
    "slices"
    "strings"
    "unicode/utf8"

    "github.com/modelcontextprotocol/go-sdk/mcp"
)

// guardMCPTransportCompatibility fixes transport gaps in go-sdk v1.8.0.
// These checks sit BEFORE authentication and the SDK; the SDK still performs
// authoritative header/body coherence and Broker policy checks. Never disable
// either layer to accommodate an encoded header value.
func guardMCPTransportCompatibility(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.URL.Path != "/mcp" {
            next.ServeHTTP(w, r)
            return
        }
        for key, values := range r.Header {
            if isMCPScalarHeader(key) && len(values) != 1 {
                writeMCPTransportError(w, http.StatusBadRequest, json.RawMessage("null"), -32020,
                    "MCP header must occur exactly once: "+http.CanonicalHeaderKey(key), nil)
                return
            }
        }
        if r.Method != http.MethodPost {
            next.ServeHTTP(w, r)
            return
        }

        // Normalize only a valid RFC-style Base64 sentinel, never untrusted
        // body data. The SDK checks the decoded Mcp-Name against params.name.
        if raw := r.Header.Get("Mcp-Name"); raw != "" {
            if strings.HasPrefix(raw, "=?base64?") {
                if !strings.HasSuffix(raw, "?=") {
                    writeMCPTransportError(w, 400, json.RawMessage("null"), -32020, "Malformed encoded Mcp-Name header", nil)
                    return
                }
                inner := strings.TrimSuffix(strings.TrimPrefix(raw, "=?base64?"), "?=")
                decoded, err := base64.StdEncoding.Strict().DecodeString(inner)
                if err != nil || !utf8.Valid(decoded) {
                    writeMCPTransportError(w, 400, json.RawMessage("null"), -32020, "Invalid Base64 or UTF-8 in Mcp-Name header", nil)
                    return
                }
                r.Header.Set("Mcp-Name", string(decoded))
            }
        }
        version := r.Header.Get("MCP-Protocol-Version")
        // The SDK returns a text/plain error for unknown OLD versions.
        // Modern MCP requires the same structured -32022 error for both
        // future and historical unsupported versions, preserving request ID.
        if version != "" && !slices.Contains(mcp.SupportedProtocolVersions(), version) &&
            version < "2026-07-28" {
            requestID := json.RawMessage("null")
            body, err := io.ReadAll(io.LimitReader(r.Body, (1<<20)+1))
            if err == nil && len(body) <= 1<<20 {
                var payload struct {
                    JSONRPC string          `json:"jsonrpc"`
                    ID      json.RawMessage `json:"id"`
                }
                if json.Unmarshal(body, &payload) == nil && payload.JSONRPC == "2.0" && json.Valid(payload.ID) {
                    requestID = payload.ID
                }
            }
            writeMCPTransportError(w, http.StatusBadRequest, requestID, -32022,
                "Unsupported protocol version", map[string]any{
                    "supported": mcp.SupportedProtocolVersions(),
                    "requested": version,
                })
            return
        }
        next.ServeHTTP(w, r)
    })
}

func isMCPScalarHeader(name string) bool {
    switch strings.ToLower(name) {
    case "mcp-protocol-version", "mcp-method", "mcp-name":
        return true
    }
    // x-mcp-header fields carry scalar values as well. Rejecting duplicates
    // prevents proxy/SDK first-vs-last-header interpretation differences.
    return strings.HasPrefix(strings.ToLower(name), "mcp-param-")
}

func writeMCPTransportError(w http.ResponseWriter, status int, id json.RawMessage, code int, message string, data any) {
    if len(id) == 0 || !json.Valid(id) {
        id = json.RawMessage("null")
    }
    payload := struct {
        JSONRPC string `json:"jsonrpc"`
        ID json.RawMessage `json:"id"`
        Error struct {
            Code int `json:"code"`
            Message string `json:"message"`
            Data any `json:"data,omitempty"`
        } `json:"error"`
    }{JSONRPC: "2.0", ID: bytes.Clone(id)}
    payload.Error.Code, payload.Error.Message, payload.Error.Data = code, message, data
    w.Header().Set("Content-Type", "application/json")
    w.Header().Set("Cache-Control", "no-store")
    w.WriteHeader(status)
    _ = json.NewEncoder(w).Encode(payload)
}
