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

type RPCError struct {
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
	Details string `json:"details,omitempty"`
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeStructuredError(w, code, "", msg)
}

func writeStructuredError(w http.ResponseWriter, httpStatus int, errCode string, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus)
	json.NewEncoder(w).Encode(RPCError{
		Error: msg,
		Code:  errCode,
	})
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

// isReservedIP returns true for addresses that cannot identify a unicast DNS
// resolver. Private and carrier-grade NAT addresses remain valid because a VPN
// may deliberately route DNS to an internal resolver.
func isReservedIP(raw string) bool {
	ip := net.ParseIP(strings.TrimSpace(raw))
	if ip == nil {
		return true
	}
	if ipv4 := ip.To4(); ipv4 != nil && (ipv4[0] == 0 || ipv4[0] >= 240) {
		return true
	}
	return ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || !ip.IsGlobalUnicast()
}

// sanitizeDNS removes unsafe DNS resolvers supplied by the backend. An empty
// result is an invalid server contract; callers must fail closed.
func sanitizeDNS(servers []string) []string {
	safe := make([]string, 0, len(servers))
	for _, s := range servers {
		if isReservedIP(s) {
			slog.Warn("vpn connect: rejecting reserved DNS address from backend", "addr", s)
			continue
		}
		safe = append(safe, s)
	}
	return safe
}

func isTunPermissionError(err error) bool {
	msg := strings.ToLower(err.Error())
	return (strings.Contains(msg, "create tun") || strings.Contains(msg, "wireguard")) &&
		(strings.Contains(msg, "operation not permitted") || strings.Contains(msg, "permission denied"))
}

func isDNSPermissionError(err error) bool {
	msg := strings.ToLower(err.Error())
	return (strings.Contains(msg, "dns apply") || strings.Contains(msg, "resolv.conf") || strings.Contains(msg, "resolvconf")) &&
		(strings.Contains(msg, "permission denied") || strings.Contains(msg, "operation not permitted"))
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
