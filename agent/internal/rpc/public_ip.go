package rpc

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"
)

// handlePublicIP fetches the current public IP of this machine.
// When VPN is connected (wg0 with AllowedIPs=0.0.0.0/0) the request exits
// through the WireGuard tunnel. If an exit node is active, the response IP
// will match the exit node's public IP.
func (s *Server) handlePublicIP(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://checkip.amazonaws.com", nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	req.Header.Set("User-Agent", "midorivpn-agent/1")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, "cannot reach IP check service: "+err.Error())
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	ip := strings.TrimSpace(string(body))

	writeJSON(w, map[string]any{
		"ip":               ip,
		"exit_node_active": s.localFwd.Active(),
		"exit_node":        s.localFwd.Upstream(),
	})
}
