package rpc

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goastian/midorivpn-agent/internal/state"
)

func TestNewVPNConnectionIDIsUniqueAndOpaque(t *testing.T) {
	first, err := newVPNConnectionID()
	if err != nil {
		t.Fatal(err)
	}
	second, err := newVPNConnectionID()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 32 || len(second) != 32 {
		t.Fatalf("connection id lengths = %d and %d, want 32", len(first), len(second))
	}
	if first == second {
		t.Fatal("connection identities must be unique")
	}
}

func TestHandleVPNDisconnectRejectsStaleConnectionWithoutTeardown(t *testing.T) {
	agent := state.NewAgent()
	agent.SetVPN(state.VPNStatus{
		Connected: true, ConnectionID: "current-connection", ActiveProtocol: "openvpn",
	})
	server := &Server{agent: agent}
	req := httptest.NewRequest(http.MethodPost, "/vpn/disconnect", strings.NewReader(
		`{"connection_id":"stale-connection","reason":"user_request"}`,
	))
	recorder := httptest.NewRecorder()

	server.handleVPNDisconnect(recorder, req)

	if recorder.Code != http.StatusConflict {
		t.Fatalf("disconnect status = %d, want %d", recorder.Code, http.StatusConflict)
	}
	vpn := agent.Snapshot()["vpn"].(state.VPNStatus)
	if !vpn.Connected || vpn.ConnectionID != "current-connection" {
		t.Fatalf("active tunnel changed after stale request: %#v", vpn)
	}
}

func TestDecodeVPNDisconnectRequestRequiresCurrentIntent(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
		ok   bool
	}{
		{name: "user request", body: `{"connection_id":"0123456789abcdef","reason":"user_request"}`, ok: true},
		{name: "server switch", body: `{"connection_id":"0123456789abcdef","reason":"server_switch"}`, ok: true},
		{name: "missing identity", body: `{"reason":"user_request"}`},
		{name: "unknown reason", body: `{"connection_id":"0123456789abcdef","reason":"navigation"}`},
		{name: "unknown field", body: `{"connection_id":"0123456789abcdef","reason":"user_request","force":true}`},
		{name: "trailing value", body: `{"connection_id":"0123456789abcdef","reason":"user_request"} {}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/vpn/disconnect", strings.NewReader(test.body))
			_, err := decodeVPNDisconnectRequest(req)
			if (err == nil) != test.ok {
				t.Fatalf("decode error = %v, want success %t", err, test.ok)
			}
		})
	}
}
