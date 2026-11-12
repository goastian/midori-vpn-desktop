package rpc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/goastian/midorivpn-agent/internal/dns"
	"github.com/goastian/midorivpn-agent/internal/httpx"
)

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	snap := s.agent.Snapshot()
	snap["local_rpc"] = map[string]any{
		"port": s.port,
	}
	snap["local_proxy"] = map[string]any{
		"port":     localFwdPort,
		"active":   s.localFwd.Active(),
		"upstream": s.localFwd.Upstream(),
		"hint":     fmt.Sprintf("Set http_proxy=http://127.0.0.1:%d to route browser/app traffic through the exit node", localFwdPort),
	}
	snap["kill_switch"] = map[string]any{
		"active": s.guard.Active(),
	}
	dnsKind, dnsProtected := s.currentDNSStatus()
	snap["dns_protected"] = dnsProtected
	snap["dns_backend"] = dnsKind.String()
	snap["dns_needs_extra_caps"] = dnsKind.NeedsExtraCaps()
	authBackend := "unknown"
	if s.authMgr != nil {
		authBackend = s.authMgr.Backend()
	}
	snap["security"] = map[string]any{
		"token_store":          authBackend,
		"token_store_degraded": authBackend != "secret-service",
	}
	writeJSON(w, snap)
}

// handleDNSStatus never suggests granting broad filesystem capabilities.
func (s *Server) handleDNSStatus(w http.ResponseWriter, r *http.Request) {
	kind := s.wgMgr.DNSBackendKind()
	supported := kind == dns.KindResolved
	writeJSON(w, map[string]any{
		"backend":          kind.String(),
		"needs_extra_caps": false,
		"caps_missing":     []string{},
		"caps_ok":          supported,
		"supported":        supported,
	})
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	httpx.AllowStreaming(w)
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	data, _ := json.Marshal(s.agent.Snapshot())
	fmt.Fprintf(w, "event: snapshot\ndata: %s\n\n", data)
	flusher.Flush()

	ch, cancel := s.agent.Subscribe()
	defer cancel()

	for {
		select {
		case <-r.Context().Done():
			return
		case ev := <-ch:
			data, _ := json.Marshal(s.agent.Snapshot())
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", ev.Type, data)
			flusher.Flush()
		case <-time.After(30 * time.Second):
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		}
	}
}
