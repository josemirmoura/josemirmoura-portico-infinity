package gateway

import (
    "context"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "strings"
    "sync/atomic"
    "testing"
    "time"
)

// Regression for Gate C independent audit A1: an introspection 307 must
// NEVER forward either the bearer under examination or Basic client secrets.
func TestGateCA1IntrospectionRedirectNeverForwardsCredentials(t *testing.T) {
    for _, tc := range []struct {
        name string
        code int
        differentHostname bool
    }{
        {"307-same-host-other-port", http.StatusTemporaryRedirect, false},
        {"302-same-host-other-port", http.StatusFound, false},
        {"307-different-hostname", http.StatusTemporaryRedirect, true},
    } {
        t.Run(tc.name, func(t *testing.T) {
            var forwarded atomic.Int32
            receiver := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                forwarded.Add(1)
                _ = r.ParseForm()
                if r.Form.Get("token") != "" || r.Header.Get("Authorization") != "" {
                    t.Error("redirect reached receiver with sensitive data")
                }
                _ = json.NewEncoder(w).Encode(map[string]any{
                    "active": true, "sub": "alice", "iss": "https://issuer.example.invalid",
                    "aud": []string{"resource-id"}, "scope": "portico.read",
                    "exp": time.Now().Add(time.Minute).Unix(),
                })
            }))
            defer receiver.Close()

            location := receiver.URL + "/redirected"
            if tc.differentHostname {
                location = strings.Replace(location, "127.0.0.1", "localhost", 1)
            }
            initial := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                http.Redirect(w, r, location, tc.code)
            }))
            defer initial.Close()

            verify, err := NewIntegratedOIDCVerifier(initial.URL, "", "client-id", "private-password",
                "https://issuer.example.invalid", "resource-id")
            if err != nil { t.Fatal(err) }
            info, err := verify(context.Background(), "disposable-access-token", nil)
            if err == nil || info != nil {
                t.Fatal("redirect response was accepted as token introspection")
            }
            if got := forwarded.Load(); got != 0 {
                t.Fatalf("redirect was followed (%d receiver hits)", got)
            }
        })
    }
}

func TestGateCA1InsecureIntrospectionConfigurationFailsClosed(t *testing.T) {
    bad := []string{
        "http://zitadel-auth-internal:8080/oauth/v2/introspect",
        "http://localhost:8080/oauth/v2/introspect", // DNS name, not a numeric loopback fixture
        "http://example.invalid/oauth/v2/introspect",
        "https://user:secret@example.invalid/oauth/v2/introspect",
        "https://example.invalid/oauth/v2/introspect?access_token=secret",
        "https://example.invalid/oauth/v2/introspect#fragment",
        "ftp://example.invalid/oauth/v2/introspect",
    }
    for _, endpoint := range bad {
        t.Run(endpoint, func(t *testing.T) {
            _, err := NewIntegratedOIDCVerifier(endpoint, "", "client-id", "test-secret",
                "https://issuer.example.invalid", "resource-id")
            if err == nil { t.Fatalf("accepted unsafe introspection endpoint: %q", endpoint) }
        })
    }
    // Only local numeric fixtures are allowed to use plaintext HTTP. Public
    // integrated-auth configuration must use certificate-verified HTTPS.
    for _, endpoint := range []string{
        "http://127.0.0.1:18888/oauth/v2/introspect",
        "http://[::1]:18888/oauth/v2/introspect",
        "https://issuer.example.invalid/oauth/v2/introspect",
    } {
        t.Run(endpoint, func(t *testing.T) {
            _, err := NewIntegratedOIDCVerifier(endpoint, "", "client-id", "test-secret",
                "https://issuer.example.invalid", "resource-id")
            if err != nil { t.Fatal(err) }
        })
    }
}

func TestGateCA1TLSCertificateVerificationCannotBeBypassed(t *testing.T) {
    untrusted := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        _ = json.NewEncoder(w).Encode(map[string]any{
            "active": true, "sub": "alice", "iss": "https://issuer.example.invalid",
            "aud": []string{"resource-id"}, "scope": "portico.read",
            "exp": time.Now().Add(time.Minute).Unix(),
        })
    }))
    defer untrusted.Close()
    verify, err := NewIntegratedOIDCVerifier(untrusted.URL, "", "client-id", "test-secret",
        "https://issuer.example.invalid", "resource-id")
    if err != nil { t.Fatal(err) }
    info, err := verify(context.Background(), "disposable-access-token", nil)
    if err == nil || info != nil {
        t.Fatal("untrusted TLS certificate was accepted during introspection")
    }
}
