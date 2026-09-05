package rpc

import (
	"encoding/json"
	"fmt"
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
	var req struct {
		Mesh *struct {
			StartDisabled *bool `json:"start_disabled"`
		} `json:"mesh"`
		Autostart *struct {
			Enabled *bool `json:"enabled"`
		} `json:"autostart"`
		UI *struct {
			StartMinimized *bool   `json:"start_minimized"`
			Language       *string `json:"language"`
		} `json:"ui"`
		VPN *vpnSettingsPatch `json:"vpn"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	nextVPN, err := mergeVPNSettings(s.settings.Get().VPN, req.VPN)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.settings.Update(func(c *settings.Settings) {
		if req.Mesh != nil && req.Mesh.StartDisabled != nil {
			c.Mesh.StartDisabled = *req.Mesh.StartDisabled
		}
		if req.Autostart != nil && req.Autostart.Enabled != nil {
			c.Autostart.Enabled = *req.Autostart.Enabled
		}
		if req.UI != nil {
			if req.UI.StartMinimized != nil {
				c.UI.StartMinimized = *req.UI.StartMinimized
			}
			if req.UI.Language != nil {
				c.UI.Language = normalizedUILanguage(*req.UI.Language)
			}
		}
		if req.VPN != nil {
			c.VPN = nextVPN
		}
	}); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, s.settings.Get())
}

type vpnSettingsPatch struct {
	SelectionMode  *settings.SelectionMode `json:"selection_mode"`
	ManualServerID *string                 `json:"manual_server_id"`
}

func mergeVPNSettings(current settings.VPNSettings, patch *vpnSettingsPatch) (settings.VPNSettings, error) {
	if patch == nil {
		return current, nil
	}
	if patch.SelectionMode != nil {
		if !patch.SelectionMode.Valid() {
			return current, fmt.Errorf("invalid vpn selection_mode")
		}
		current.SelectionMode = *patch.SelectionMode
	}
	if patch.ManualServerID != nil {
		current.ManualServerID = *patch.ManualServerID
	}
	if current.SelectionMode == settings.SelectionModeAutomatic {
		current.ManualServerID = ""
		return current, nil
	}
	if !isValidUUID(current.ManualServerID) {
		return current, fmt.Errorf("valid manual_server_id required in manual mode")
	}
	return current, nil
}

func normalizedUILanguage(value string) string {
	switch value {
	case "en", "es", "pt", "de", "fr", "ru":
		return value
	default:
		return "en"
	}
}
