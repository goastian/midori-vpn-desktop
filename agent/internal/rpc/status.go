package rpc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/goastian/midorivpn-agent/internal/caps"
)

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	snap := s.agent.Snapshot()
	snap["local_proxy"] = map[string]any{
		"port":     localFwdPort,
		"active":   s.localFwd.Active(),
		"upstream": s.localFwd.Upstream(),
		"hint":     fmt.Sprintf("Set http_proxy=http://127.0.0.1:%d to route browser/app traffic through the exit node", localFwdPort),
	}
	snap["kill_switch"] = map[string]any{
		"active": s.guard.Active(),
	}
	snap["dns_protected"] = s.wgMgr.DNSProtected()
	snap["dns_backend"] = s.wgMgr.DNSBackendKind().String()
	snap["dns_needs_extra_caps"] = s.wgMgr.DNSBackendKind().NeedsExtraCaps()
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

// handleDNSStatus reports the active DNS backend so the UI can decide whether
// to prompt the user for the extra CAP_DAC_OVERRIDE + CAP_LINUX_IMMUTABLE
// capabilities required by the resolvconf backend.
func (s *Server) handleDNSStatus(w http.ResponseWriter, r *http.Request) {
	kind := s.wgMgr.DNSBackendKind()
	needsExtra := kind.NeedsExtraCaps()
	missing := []string{}
	if needsExtra {
		if !caps.HasDacOverride() {
			missing = append(missing, "cap_dac_override")
		}
		if !caps.HasLinuxImmutable() {
			missing = append(missing, "cap_linux_immutable")
		}
	}
	writeJSON(w, map[string]any{
		"backend":          kind.String(),
		"needs_extra_caps": needsExtra,
		"caps_missing":     missing,
		"caps_ok":          len(missing) == 0,
	})
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "tauri://localhost")

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
