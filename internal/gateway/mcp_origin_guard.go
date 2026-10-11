package gateway

import (
    "net"
    "net/http"
    "net/url"
    "strconv"
    "strings"
)

// guardMCPOrigin enforces the MCP 2026-07-28 Streamable HTTP requirement:
// every present Origin must be validated; invalid origins return HTTP 403.
// Server-to-server clients that omit Origin are unaffected.
//
// For public instances the configured OAuth resource URL is the trust anchor.
// Comparing Origin only with untrusted request.Host would allow DNS rebinding
// (Host and Origin can both be attacker-controlled).
//
// Without a configured public resource, browser Origins are permitted only on
// the local loopback authority. This leaves headless MCP clients working and
// refuses arbitrary DNS names resolving to the locally bound Gateway.
func guardMCPOrigin(resource string, next http.Handler) http.Handler {
    expected := parseMCPResourceOrigin(resource)
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        origins := r.Header.Values("Origin")
        if len(origins) == 0 {
            next.ServeHTTP(w, r)
            return
        }
        valid := false
        if len(origins) == 1 {
            got := parseMCPOrigin(origins[0])
            if got != nil {
                if resource != "" {
                    valid = expected != nil && sameMCPOrigin(got, expected)
                } else {
                    authority, err := url.Parse("http://" + r.Host)
                    if err == nil && authority.Host == r.Host && isMCPOriginLoopback(authority.Hostname()) {
                        scheme := "http"
                        if r.TLS != nil {
                            scheme = "https"
                        }
                        // The Origin wire format omits the default port. Treat
                        // explicit :80/:443 and an omitted default port as
                        // the same origin, without trusting a non-loopback Host.
                        valid = sameMCPOrigin(got, &url.URL{Scheme: scheme, Host: authority.Host})
                    }
                }
            }
        }
        if !valid {
            // No credentials, origin values or request body in the error or logs.
            http.Error(w, "invalid Origin", http.StatusForbidden)
            return
        }
        next.ServeHTTP(w, r)
    })
}

func parseMCPResourceOrigin(raw string) *url.URL {
    u, err := url.Parse(raw)
    if err != nil || u == nil || u.User != nil || u.Host == "" ||
        u.RawQuery != "" || u.Fragment != "" {
        return nil
    }
    // OAuth resource identifiers include a path such as /mcp. The browser
    // Origin header necessarily contains only scheme and authority.
    return parseMCPOrigin(u.Scheme + "://" + u.Host)
}

func parseMCPOrigin(raw string) *url.URL {
    if raw == "" || strings.TrimSpace(raw) != raw {
        return nil
    }
    u, err := url.Parse(raw)
    if err != nil || u == nil || (u.Scheme != "https" && u.Scheme != "http") ||
        u.Host == "" || u.Hostname() == "" || u.Opaque != "" || u.User != nil ||
        u.Path != "" || u.RawPath != "" || u.RawQuery != "" ||
        u.ForceQuery || u.Fragment != "" {
        return nil
    }
    if strings.ContainsAny(u.Host, "@, ") {
        return nil
    }
    // Disallow invalid port numbers before origin comparison. An omitted port
    // means 80 (HTTP) or 443 (HTTPS), not the string "".
    if _, ok := normalizedMCPPort(u); !ok {
        return nil
    }
    return u
}

// normalizedMCPPort follows the scheme/host/port origin triple, rather than
// comparing the textual port spelling. Browsers omit :80 and :443 in Origin;
// proxies and OAuth resource URLs may include them explicitly.
func normalizedMCPPort(u *url.URL) (int, bool) {
    if u == nil {
        return 0, false
    }
    if u.Port() == "" {
        switch u.Scheme {
        case "http":
            return 80, true
        case "https":
            return 443, true
        default:
            return 0, false
        }
    }
    n, err := strconv.Atoi(u.Port())
    return n, err == nil && n >= 1 && n <= 65535
}

func sameMCPOrigin(a, b *url.URL) bool {
    if a == nil || b == nil || a.Scheme != b.Scheme ||
        !strings.EqualFold(a.Hostname(), b.Hostname()) {
        return false
    }
    ap, aok := normalizedMCPPort(a)
    bp, bok := normalizedMCPPort(b)
    return aok && bok && ap == bp
}

func isMCPOriginLoopback(host string) bool {
    if strings.EqualFold(host, "localhost") {
        return true
    }
    ip := net.ParseIP(host)
    return ip != nil && ip.IsLoopback()
}
