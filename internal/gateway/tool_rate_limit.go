package gateway

import (
    "bytes"
    "encoding/json"
    "io"
    "net/http"
    "strings"
    "sync"
    "time"

    "golang.org/x/time/rate"
)

// A4: MCP 2026-07-28 requires servers to rate limit tool invocations.
// This is distinct from in-flight request concurrency. The limiter runs
// AFTER authenticated-subject propagation and BEFORE the MCP tool executor.
const (
    defaultToolPerSecond = 20
    defaultToolBurst = 60
    globalToolPerSecond = 200
    globalToolBurst = 600
    maxToolSubjects = 4096
    toolSubjectIdle = 10 * time.Minute
)

type rateLimitedSubject struct {
    limiter *rate.Limiter
    lastSeen time.Time
}

type toolInvocationLimiter struct {
    mu sync.Mutex
    subjects map[string]*rateLimitedSubject
    global *rate.Limiter
    perSecond int
    burst int
    now func() time.Time
    lastSweep time.Time
}

func newToolInvocationLimiter(perSecond, burst int) *toolInvocationLimiter {
    if perSecond <= 0 { perSecond = defaultToolPerSecond }
    if burst <= 0 { burst = defaultToolBurst }
    // Protect against broken operator configs with uncontrolled memory/CPU.
    if perSecond > 1000 { perSecond = 1000 }
    if burst > 2000 { burst = 2000 }
    return &toolInvocationLimiter{
        subjects: make(map[string]*rateLimitedSubject),
        global: rate.NewLimiter(rate.Limit(globalToolPerSecond), globalToolBurst),
        perSecond: perSecond, burst: burst, now: time.Now,
    }
}

func (l *toolInvocationLimiter) allow(subject string) bool {
    now := l.now()
    if subject == "" { subject = "anonymous" }
    l.mu.Lock()
    defer l.mu.Unlock()
    // Bound the number of tracked principals even if many valid identities
    // arrive; abandoned principals expire without a background goroutine.
    if l.lastSweep.IsZero() || now.Sub(l.lastSweep) >= time.Minute {
        for name, entry := range l.subjects {
            if now.Sub(entry.lastSeen) > toolSubjectIdle { delete(l.subjects,name) }
        }
        l.lastSweep = now
    }
    entry := l.subjects[subject]
    if entry == nil {
        if len(l.subjects) >= maxToolSubjects { return false }
        entry = &rateLimitedSubject{limiter: rate.NewLimiter(rate.Limit(l.perSecond),l.burst)}
        l.subjects[subject] = entry
    }
    entry.lastSeen = now
    // Deny abusive principals before consulting the shared global pool.
    if !entry.limiter.AllowN(now,1) { return false }
    return l.global.AllowN(now,1)
}

func (l *toolInvocationLimiter) wrap(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        if r.Method != http.MethodPost || r.URL.Path != "/mcp" ||
            !strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/json") {
            next.ServeHTTP(w,r)
            return
        }

        // Read at most the SDK's configured 1 MiB body limit. Restore the
        // original byte stream for the SDK, including an oversized stream,
        // so transport/version/header checks remain authoritative.
        const maxBody = 1 << 20
        prefix, err := io.ReadAll(io.LimitReader(r.Body,maxBody+1))
        if err != nil {
            http.Error(w, "invalid request body",http.StatusBadRequest)
            return
        }
        if len(prefix)>maxBody {
            r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(prefix),r.Body))
            next.ServeHTTP(w,r)
            return
        }
        _ = r.Body.Close()
        r.Body = io.NopCloser(bytes.NewReader(prefix))

        var request struct {
            ID json.RawMessage `json:"id"`
            Method string `json:"method"`
        }
        if json.Unmarshal(prefix,&request)!=nil || request.Method!="tools/call" {
            next.ServeHTTP(w,r)
            return
        }
        if !l.allow(SubjectFromContext(r.Context())) {
            w.Header().Set("Retry-After","1")
            writeMCPToolLimitError(w,request.ID)
            return
        }
        next.ServeHTTP(w,r)
    })
}

func writeMCPToolLimitError(w http.ResponseWriter, id json.RawMessage) {
    if len(id)==0 || !json.Valid(id) { id=json.RawMessage("null") }
    out:=struct {
        JSONRPC string `json:"jsonrpc"`
        ID json.RawMessage `json:"id"`
        Error struct {
            Code int `json:"code"`
            Message string `json:"message"`
        } `json:"error"`
    }{JSONRPC:"2.0",ID:bytes.Clone(id)}
    out.Error.Code=-32000
    out.Error.Message="Tool invocation rate limit exceeded"
    w.Header().Set("Content-Type","application/json")
    w.Header().Set("Cache-Control","no-store")
    w.WriteHeader(http.StatusTooManyRequests)
    _=json.NewEncoder(w).Encode(out)
}
