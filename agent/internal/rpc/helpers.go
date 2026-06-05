package rpc

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/goastian/midorivpn-agent/internal/apiClient"
	"github.com/goastian/midorivpn-agent/internal/netguard"
	"github.com/goastian/midorivpn-agent/internal/state"
)

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func splitHost(hostPort string) string {
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		return hostPort
	}
	return host
}

func normalizeAssignedIP(assignedIP string) string {
	for strings.HasSuffix(assignedIP, "/32/32") {
		assignedIP = strings.TrimSuffix(assignedIP, "/32")
	}
	if assignedIP != "" && !strings.Contains(assignedIP, "/") {
		assignedIP += "/32"
	}
	return assignedIP
}

func splitCSV(raw string) []string {
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// isReservedIP returns true for IP addresses that must never be used as DNS
// resolvers supplied by the backend.
func isReservedIP(raw string) bool {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return true
	}
	reserved := []string{
		"0.0.0.0/8",
		"10.0.0.0/8",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"::1/128",
		"fe80::/10",
		"fc00::/7",
	}
	for _, cidr := range reserved {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

// sanitizeDNS removes unsafe DNS resolvers supplied by the backend and falls
// back to public resolvers when filtering leaves no usable entries.
func sanitizeDNS(servers []string) []string {
	safe := make([]string, 0, len(servers))
	for _, s := range servers {
		if isReservedIP(s) {
			slog.Warn("vpn connect: rejecting reserved DNS address from backend", "addr", s)
			continue
		}
		safe = append(safe, s)
	}
	if len(safe) == 0 {
		slog.Warn("vpn connect: all backend DNS entries rejected; falling back to Cloudflare")
		return []string{"1.1.1.1", "1.0.0.1"}
	}
	return safe
}

func isTunPermissionError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "create tun") && strings.Contains(msg, "operation not permitted")
}

func (s *Server) netguardScope(endpoint, assignedIP string) netguard.Scope {
	scope := netguard.Scope{
		TunnelIface: s.wgMgr.InterfaceName(),
		Endpoint:    endpoint,
		APIURL:      s.apiURL,
		AssignedIP:  assignedIP,
	}
	snap := s.agent.Snapshot()
	if meshState, ok := snap["mesh"].(state.MeshStatus); ok && meshState.Active {
		scope.MeshPeerIPs = peerMeshIPs(meshState.Peers)
	}
	return scope
}

func (s *Server) refreshGuardForCurrentVPN() {
	if s.guard == nil || !s.guard.Active() {
		return
	}
	snap := s.agent.Snapshot()
	vpn, ok := snap["vpn"].(state.VPNStatus)
	if !ok || !vpn.Connected {
		return
	}
	if err := s.guard.Enable(s.netguardScope(vpn.ServerEndpoint, vpn.AssignedIP)); err != nil {
		slog.Warn("kill switch refresh failed", "err", err)
		protection, _ := snap["protection"].(state.ProtectionStatus)
		protection.LastError = err.Error()
		s.agent.SetProtection(protection)
	}
}

func peerMeshIPs(peers []apiClient.Peer) []string {
	out := make([]string, 0, len(peers))
	for _, peer := range peers {
		ip := strings.TrimSpace(peer.MeshIP)
		if ip != "" {
			out = append(out, ip)
		}
	}
	return out
}

// isValidUUID returns true if s looks like a canonical UUID
// (8-4-4-4-12 hex digits). This prevents path-injection into backend URLs.
func isValidUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
				return false
			}
		}
	}
	return true
}
