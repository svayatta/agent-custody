// The door middleware in front of a net/http handler, driven as net/http drives it. DOOR_URL points at
// `agent-custody door` with "authz": true; CUSTODY_GRANT is a passport scoped to the refund route.
package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"
)

type seen struct {
	ran                   bool
	receipt, class, grant string
	body                  string
}

func main() {
	doorURL, grant := os.Getenv("DOOR_URL"), os.Getenv("CUSTODY_GRANT")
	if doorURL == "" || grant == "" {
		fail("set DOOR_URL and CUSTODY_GRANT")
	}
	var app seen
	shop := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		app = seen{ran: true, receipt: r.Header.Get(ReceiptHeader), class: r.Header.Get(ClassHeader), grant: r.Header.Get("X-Agent-Custody-Grant"), body: string(b)}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"shop":"answered"}`))
	})
	call := func(handler http.Handler, method, target, body string, headers map[string]string) *httptest.ResponseRecorder {
		app = seen{}
		req := httptest.NewRequest(method, "http://shop.example"+target, strings.NewReader(body))
		req.RemoteAddr = "203.0.113.7:51000"
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	guarded := Door(doorURL, 5*time.Second)(shop)

	// 1. A public read: allowed, and the shop sees the door's receipt in place of the one the client forged.
	res := call(guarded, "GET", "/catalogue/shoes?colour=red", "", map[string]string{ReceiptHeader: "forged", "X-Forwarded-For": "198.51.100.66", "User-Agent": "example-browser"})
	if res.Code != 200 || !app.ran || app.receipt == "" || app.receipt == "forged" || app.receipt != res.Header().Get(ReceiptHeader) || app.class != "unknown" {
		fail(fmt.Sprintf("allowed read: status %d, ran %v, receipt %q, class %q", res.Code, app.ran, app.receipt, app.class))
	}
	fmt.Println("go: GET /catalogue/shoes allowed, class", app.class)
	fmt.Println("receipt allowed", app.receipt)

	// 2. An unknown arrival's refund: refused with the door's 403 and body; the shop never runs. The client's own
	// X-Original-* headers do not change what the door decides on.
	res = call(guarded, "POST", "/refunds", `{"amount":1000}`, map[string]string{"Content-Type": "application/json", "X-Original-Method": "GET", "X-Original-Uri": "/catalogue/free"})
	denied := res.Header().Get(ReceiptHeader)
	if res.Code != 403 || app.ran || denied == "" || !strings.Contains(res.Body.String(), "refused by the door's policy") {
		fail(fmt.Sprintf("refused refund: status %d, ran %v, body %s", res.Code, app.ran, res.Body.String()))
	}
	fmt.Println("go: POST /refunds refused 403")
	fmt.Println("receipt denied", denied)

	// 3. A verified agent's refund: allowed after the door committed it to the log; the shop gets the body, the
	// receipt, and the class, and never the grant.
	res = call(guarded, "POST", "/refunds", `{"amount":1000}`, map[string]string{"Content-Type": "application/json", "X-Agent-Custody-Grant": grant})
	if res.Code != 200 || !app.ran || app.class != "verified" || app.grant != "" || app.body != `{"amount":1000}` || app.receipt != res.Header().Get(ReceiptHeader) {
		fail(fmt.Sprintf("verified refund: status %d, ran %v, class %q, grant passed %v, body %q", res.Code, app.ran, app.class, app.grant != "", app.body))
	}
	fmt.Println("go: POST /refunds with a passport allowed, class", app.class)
	fmt.Println("receipt verified", app.receipt)

	// 4. A door that is down, and one that never answers: 503, and the shop never runs.
	gone, _ := net.Listen("tcp", "127.0.0.1:0")
	goneURL := "http://" + gone.Addr().String()
	gone.Close()
	res = call(Door(goneURL, 2*time.Second)(shop), "GET", "/catalogue/shoes", "", nil)
	if res.Code != 503 || app.ran {
		fail(fmt.Sprintf("unreachable door: status %d, ran %v", res.Code, app.ran))
	}
	fmt.Println("fail-closed unreachable", res.Code)
	silent, _ := net.Listen("tcp", "127.0.0.1:0") // accepts connections and never answers
	defer silent.Close()
	start := time.Now()
	res = call(Door("http://"+silent.Addr().String(), 500*time.Millisecond)(shop), "GET", "/catalogue/shoes", "", nil)
	if res.Code != 503 || app.ran || time.Since(start) > 10*time.Second {
		fail(fmt.Sprintf("silent door: status %d, ran %v", res.Code, app.ran))
	}
	fmt.Println("fail-closed timeout", res.Code)
	fmt.Println("OK")
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, "go:", msg)
	os.Exit(1)
}
