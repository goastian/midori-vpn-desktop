package rpc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/goastian/midorivpn-agent/internal/apiClient"
	"github.com/goastian/midorivpn-agent/internal/connectioncleanup"
	"github.com/goastian/midorivpn-agent/internal/netguard"
	"github.com/goastian/midorivpn-agent/internal/state"
	"github.com/goastian/midorivpn-agent/internal/wg"
)

func TestDrainConnectionCleanupRetainsFailuresAndRemovesSuccesses(t *testing.T) {
	var succeed atomic.Bool
	peerID := "11111111-1111-4111-8111-111111111111"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete || r.URL.Path != "/api/v1/control/connections/"+peerID {
			http.NotFound(w, r)
			return
		}
		if !succeed.Load() {
			http.Error(w, `{"code":"temporary_failure"}`, http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer backend.Close()

	storePath := filepath.Join(t.TempDir(), "state", "pending.json")
	store, err := connectioncleanup.NewAt(storePath)
	if err != nil {
		t.Fatal(err)
	}
	client := apiClient.New(backend.URL, "", func() string { return "test-token" }, nil)
	server := &Server{
		apiClient:             client,
		connectionCleanup:     store,
		connectionCleanupWake: make(chan struct{}, 1),
	}
	if err := server.queueConnectionCleanup(peerID); err != nil {
		t.Fatal(err)
	}

	if remaining := server.drainConnectionCleanup(context.Background()); remaining != 1 {
		t.Fatalf("pending after backend 500 = %d, want 1", remaining)
	}
	reopened, err := connectioncleanup.NewAt(storePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(reopened.List()) != 1 || reopened.List()[0] != peerID {
		t.Fatalf("failed cleanup was not retained: %v", reopened.List())
	}

	succeed.Store(true)
	if remaining := server.drainConnectionCleanup(context.Background()); remaining != 0 {
		t.Fatalf("pending after backend 202 = %d, want 0", remaining)
	}
}

func TestVPNDisconnectPersistsCleanupBeforeLocalTeardown(t *testing.T) {
	peerID := "22222222-2222-4222-8222-222222222222"
	connectionID := "current-connection"
	store, err := connectioncleanup.NewAt(filepath.Join(t.TempDir(), "state", "pending.json"))
	if err != nil {
		t.Fatal(err)
	}
	agent := state.NewAgent()
	agent.SetVPN(state.VPNStatus{
		Connected: true, Phase: state.VPNPhaseConnected, ConnectionID: connectionID,
		PeerID: peerID, ActiveProtocol: "wireguard",
	})
	server := &Server{
		agent:                 agent,
		wgMgr:                 wg.NewManager(),
		guard:                 netguard.New(),
		connectionCleanup:     store,
		connectionCleanupWake: make(chan struct{}, 1),
	}
	request := httptest.NewRequest(http.MethodPost, "/vpn/disconnect",
		strings.NewReader(`{"connection_id":"`+connectionID+`","reason":"user_request"}`))
	recorder := httptest.NewRecorder()

	server.handleVPNDisconnect(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("disconnect status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var response map[string]bool
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !response["ok"] || !response["cleanup_pending"] {
		t.Fatalf("disconnect response = %v", response)
	}
	if got := store.List(); len(got) != 1 || got[0] != peerID {
		t.Fatalf("durable cleanup = %v, want %s", got, peerID)
	}
	vpn := agent.Snapshot()["vpn"].(state.VPNStatus)
	if vpn.Connected || vpn.Phase != state.VPNPhaseDisconnected {
		t.Fatalf("local tunnel state = %#v", vpn)
	}
}

func TestVPNDisconnectKeepsTunnelWhenCleanupCannotBeRecorded(t *testing.T) {
	peerID := "33333333-3333-4333-8333-333333333333"
	connectionID := "current-connection"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"code":"temporary_failure"}`, http.StatusInternalServerError)
	}))
	defer backend.Close()
	agent := state.NewAgent()
	agent.SetVPN(state.VPNStatus{
		Connected: true, Phase: state.VPNPhaseConnected, ConnectionID: connectionID,
		PeerID: peerID, ActiveProtocol: "wireguard",
	})
	server := &Server{
		agent:     agent,
		apiClient: apiClient.New(backend.URL, "", func() string { return "test-token" }, nil),
	}
	request := httptest.NewRequest(http.MethodPost, "/vpn/disconnect",
		strings.NewReader(`{"connection_id":"`+connectionID+`","reason":"user_request"}`))
	recorder := httptest.NewRecorder()

	server.handleVPNDisconnect(recorder, request)

	if recorder.Code != http.StatusBadGateway {
		t.Fatalf("disconnect status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	vpn := agent.Snapshot()["vpn"].(state.VPNStatus)
	if !vpn.Connected || vpn.ConnectionID != connectionID {
		t.Fatalf("tunnel identity was discarded without durable cleanup: %#v", vpn)
	}
}
