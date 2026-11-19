// net/http middleware that asks an agent-custody door in authz mode ("authz": true) about each request before the
// handler runs, as nginx auth_request does. Standard library only; copy this file into your module.
package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	ReceiptHeader    = "X-Agent-Custody-Receipt"
	ClassHeader      = "X-Agent-Custody-Class"
	LogPendingHeader = "X-Agent-Custody-Log-Pending"
)

// Hop-by-hop and body fields stay off the check, which is its own GET with no body. The three the door decides on
// are set by the middleware, never copied from the client.
var notForwarded = map[string]bool{
	"Connection": true, "Keep-Alive": true, "Proxy-Connection": true, "Te": true, "Trailer": true, "Transfer-Encoding": true,
	"Upgrade": true, "Content-Length": true, "Expect": true,
	"X-Original-Method": true, "X-Original-Uri": true, "X-Forwarded-For": true,
}

// The door's credentials: the door reads them, the handler does not get them.
var doorOnly = []string{"X-Agent-Custody-Grant", "X-Agent-Custody-Agent"}

// Door returns middleware that sends the method, path, query, and headers of each request to the door at doorURL
// and runs next only on the door's 200. Any other answer goes to the client as the door gave it. A door that cannot
// be reached, does not answer within timeout, or allows without a receipt is a 503: the request never runs ungated.
func Door(doorURL string, timeout time.Duration) func(http.Handler) http.Handler {
	client := &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	checkURL := strings.TrimRight(doorURL, "/") + "/_agent_custody"
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			check, err := http.NewRequestWithContext(r.Context(), http.MethodGet, checkURL, nil)
			if err != nil {
				unavailable(w, "the door's address is not a URL")
				return
			}
			for name, values := range r.Header {
				if !notForwarded[name] {
					check.Header[name] = values
				}
			}
			if _, ok := r.Header["User-Agent"]; !ok {
				check.Header.Set("User-Agent", "") // Go would send its own, and the receipt would record it as the client's
			}
			check.Host = r.Host
			check.Header.Set("X-Original-Method", r.Method)
			check.Header.Set("X-Original-Uri", r.URL.RequestURI())
			check.Header.Set("X-Forwarded-For", remoteHost(r.RemoteAddr))
			res, err := client.Do(check)
			if err != nil {
				unavailable(w, "the door could not be reached")
				return
			}
			defer res.Body.Close()
			body, err := io.ReadAll(io.LimitReader(res.Body, 64<<10))
			if err != nil {
				unavailable(w, "the door's answer could not be read")
				return
			}
			receipt := res.Header.Get(ReceiptHeader)
			if res.StatusCode == http.StatusOK && receipt == "" {
				unavailable(w, "the door allowed the request without a receipt")
				return
			}
			for _, h := range []string{ReceiptHeader, ClassHeader, LogPendingHeader} {
				if v := res.Header.Get(h); v != "" {
					w.Header().Set(h, v)
				}
			}
			if res.StatusCode != http.StatusOK {
				for _, h := range []string{"Content-Type", "Retry-After"} {
					if v := res.Header.Get(h); v != "" {
						w.Header().Set(h, v)
					}
				}
				w.WriteHeader(res.StatusCode)
				_, _ = w.Write(body)
				return
			}
			r = r.Clone(r.Context())
			for _, h := range doorOnly {
				r.Header.Del(h)
			}
			r.Header.Set(ReceiptHeader, receipt)
			r.Header.Set(ClassHeader, res.Header.Get(ClassHeader))
			next.ServeHTTP(w, r)
		})
	}
}

func remoteHost(addr string) string {
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	return addr
}

func unavailable(w http.ResponseWriter, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "not passed on: " + reason})
}
