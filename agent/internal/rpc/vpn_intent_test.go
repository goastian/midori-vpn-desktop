package rpc

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goastian/midorivpn-agent/internal/settings"
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

func TestDecodeVPNConnectRequestSeparatesAutomaticAndManualIntent(t *testing.T) {
	const serverID = "82b130ca-d14d-46a3-ad44-7ccd34dfb842"
	for _, test := range []struct {
		name string
		body string
		mode settings.SelectionMode
		ok   bool
	}{
		{name: "automatic", body: `{"selection_mode":"automatic","protocol":"smart_auto"}`, mode: settings.SelectionModeAutomatic, ok: true},
		{name: "manual", body: `{"selection_mode":"manual","server_id":"` + serverID + `","protocol":"wireguard"}`, mode: settings.SelectionModeManual, ok: true},
		{name: "legacy manual", body: `{"server_id":"` + serverID + `"}`, mode: settings.SelectionModeManual, ok: true},
		{name: "automatic server ambiguity", body: `{"selection_mode":"automatic","server_id":"` + serverID + `"}`},
		{name: "manual without server", body: `{"selection_mode":"manual"}`},
		{name: "unknown mode", body: `{"selection_mode":"nearest"}`},
		{name: "unknown field", body: `{"selection_mode":"automatic","retry":true}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/vpn/connect", strings.NewReader(test.body))
			decoded, err := decodeVPNConnectRequest(req)
			if (err == nil) != test.ok {
				t.Fatalf("decode error = %v, want success %t", err, test.ok)
			}
			if test.ok && decoded.SelectionMode != test.mode {
				t.Fatalf("mode = %q, want %q", decoded.SelectionMode, test.mode)
			}
		})
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
