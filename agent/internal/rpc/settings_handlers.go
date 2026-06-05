package rpc

import (
	"encoding/json"
	"net/http"

	"github.com/goastian/midorivpn-agent/internal/settings"
)

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	if s.settings == nil {
		writeJSON(w, map[string]any{})
		return
	}
	writeJSON(w, s.settings.Get())
}

func (s *Server) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	if s.settings == nil {
		writeError(w, http.StatusServiceUnavailable, "settings store unavailable")
		return
	}
	var req settings.Settings
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := s.settings.Update(func(c *settings.Settings) { *c = req }); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, s.settings.Get())
}
