package rpc

import (
	"encoding/json"
	"net/http"
	"time"
)

func (s *Server) handleSystemSecurity(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, inspectSystemSecurity())
}

func (s *Server) handleCapabilitiesStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]bool{"granted": installedCapabilitiesGranted()})
}

func (s *Server) handleCapabilitiesGrant(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Extended bool `json:"extended"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body")
		return
	}
	granted, err := setInstalledCapabilities(req.Extended)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "capability_update_failed")
		return
	}
	writeJSON(w, granted)
}

func (s *Server) handleCapabilitiesRevoke(w http.ResponseWriter, _ *http.Request) {
	revoked, err := revokeInstalledCapabilities()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "capability_revoke_failed")
		return
	}
	writeJSON(w, revoked)
}

func (s *Server) handleAutostartStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]bool{"enabled": autostartEnabled()})
}

func (s *Server) handleAutostartSet(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body")
		return
	}
	if err := setAutostart(req.Enabled, s.port, s.uiDir); err != nil {
		writeError(w, http.StatusInternalServerError, "autostart_update_failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAppRestart(w http.ResponseWriter, _ *http.Request) {
	if s.restart == nil {
		writeError(w, http.StatusNotImplemented, "restart_unavailable")
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
	go func() {
		time.Sleep(250 * time.Millisecond)
		s.gracefulShutdown()
		_ = s.restart()
	}()
}

func (s *Server) handleAppQuit(w http.ResponseWriter, _ *http.Request) {
	if s.quit == nil {
		writeError(w, http.StatusNotImplemented, "quit_unavailable")
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
	go func() {
		time.Sleep(100 * time.Millisecond)
		s.quit()
	}()
}
