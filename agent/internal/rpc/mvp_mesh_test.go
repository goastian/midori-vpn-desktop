package rpc

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMVPMeshRoutesNeverReachNetworkOperations(t *testing.T) {
	// A zero-value Server has no API client, NAT manager or proxy. These
	// routes must reject requests before touching any of them.
	s := &Server{port: 7071}
	for _, route := range []string{"enable", "exit-node", "full-tunnel/enable", "exit-nodes"} {
		method := http.MethodPost
		if route == "exit-nodes" {
			method = http.MethodGet
		}
		r := httptest.NewRequest(method, "http://127.0.0.1:7071/mesh/"+route, strings.NewReader(`{}`))
		r.RemoteAddr = "127.0.0.1:50000"
		r.Header.Set("X-Agent-Token", "test")
		w := httptest.NewRecorder()
		s.newMux("test").ServeHTTP(w, r)
		if w.Code != http.StatusNotImplemented {
			t.Fatalf("%s: status=%d body=%s", route, w.Code, w.Body)
		}
	}
	// Missing settings and historical opt-in must not trigger startup work.
	s.AutoEnableMesh(context.Background())
}
