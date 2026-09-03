package rpc

import (
	"context"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/goastian/midorivpn-agent/internal/httpx"
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

	resp, err := s.publicIPClient.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, "cannot reach IP check service")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		writeError(w, http.StatusBadGateway, "IP check service rejected the request")
		return
	}

	body, err := httpx.ReadBody(resp.Body, 64)
	if err != nil {
		writeError(w, http.StatusBadGateway, "invalid IP check response")
		return
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(string(body)))
	if err != nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() {
		writeError(w, http.StatusBadGateway, "invalid IP check response")
		return
	}

	writeJSON(w, map[string]any{
		"ip":               ip.String(),
		"exit_node_active": s.localFwd.Active(),
		"exit_node":        s.localFwd.Upstream(),
	})
}
