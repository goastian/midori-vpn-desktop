package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/goastian/midorivpn-agent/internal/apiClient"
	"github.com/goastian/midorivpn-agent/internal/caps"
	"github.com/goastian/midorivpn-agent/internal/firewall"
	"github.com/goastian/midorivpn-agent/internal/logredact"
	"github.com/goastian/midorivpn-agent/internal/mesh"
	"github.com/goastian/midorivpn-agent/internal/proxy"
	"github.com/goastian/midorivpn-agent/internal/settings"
	"github.com/goastian/midorivpn-agent/internal/state"
	"github.com/goastian/midorivpn-agent/internal/sysstate"
)

func (s *Server) handleMeshEnable(w http.ResponseWriter, r *http.Request) {
	if err := s.enableMesh(r.Context()); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	// User explicitly enabled mesh — clear any prior "start disabled" pref so
	// future agent restarts auto-enable.
	if s.settings != nil {
		if err := s.settings.Update(func(c *settings.Settings) { c.Mesh.StartDisabled = false }); err != nil {
			slog.Warn("settings: failed to persist mesh.start_disabled=false", "err", err)
		}
	}
	snap := s.agent.Snapshot()
	meshState, _ := snap["mesh"].(state.MeshStatus)
	writeJSON(w, map[string]any{
		"ok":               true,
		"mesh_ip":          meshState.MeshIP,
		"proxy_port":       meshState.ExitNodePort,
		"local_proxy_port": localFwdPort,
		"peers":            meshState.Peers,
		"firewall_warning": "",
	})
}

// enableMesh activates this node as a mesh member + exit node.
// It is idempotent: calling it when mesh is already active is a no-op.
func (s *Server) enableMesh(ctx context.Context) error {
	s.meshMu.Lock()
	defer s.meshMu.Unlock()

	// Already active — nothing to do.
	if snap := s.agent.Snapshot(); func() bool {
		m, _ := snap["mesh"].(state.MeshStatus)
		return m.Active
	}() {
		return nil
	}

	node, err := s.apiClient.ActivateNode(ctx)
	if err != nil {
		return err
	}

	const proxyPort = 1080
	// Enable IP forwarding + iptables NAT so mesh peers can route all their
	// traffic through this node and appear with this node's public IP.
	if err := mesh.EnableNAT(""); err != nil {
		_ = s.apiClient.DeactivateNode(context.Background())
		return fmt.Errorf("mesh NAT setup failed: %w", err)
	}

	if err := s.apiClient.RegisterExitNode(ctx, node.MeshID, "socks5", proxyPort, true, true); err != nil {
		mesh.DisableNATAndRestore(context.Background(), "")
		_ = s.apiClient.DeactivateNode(context.Background())
		return fmt.Errorf("register exit node: %w", err)
	}

	// Start exit proxy for mesh peers if not already running.
	if s.proxyCtx == nil {
		proxyCtx, cancel := context.WithCancel(context.Background())
		s.proxyCtx = cancel
		proxyAddr := fmt.Sprintf(":%d", proxyPort)
		sourceCIDRs := proxy.SourceCIDRsForIPs(peerMeshIPs(node.Peers))
		if len(sourceCIDRs) == 0 {
			sourceCIDRs = proxy.SourceCIDRsForIPs([]string{node.MeshIP})
		}
		p := proxy.NewSOCKS5(
			proxyAddr,
			proxy.WithAllowedSourceCIDRs(sourceCIDRs),
			proxy.WithMaxConnections(256),
		)
		s.socks5Srv = p
		go func() {
			if err := p.Start(proxyCtx); err != nil {
				slog.Error("mesh socks5 exit proxy error", "err", err)
			}
		}()
	}

	s.agent.SetMesh(state.MeshStatus{
		Active:       true,
		MeshID:       node.MeshID,
		MeshIP:       node.MeshIP,
		PublicIP:     node.PublicIP,
		IsExitNode:   true,
		ExitNodePort: proxyPort,
		Peers:        node.Peers,
	})

	s.refreshGuardForCurrentVPN()

	// Apply host firewall rules for mesh traffic + local RPC.
	// This runs inside the mutex to prevent double-application on concurrent
	// enable requests. We use a 2-minute timeout for polkit interactive auth.
	{
		fwCtx, fwCancel := context.WithTimeout(context.Background(), 120*time.Second)
		defer fwCancel()
		iface := "wg0"
		if s.wgMgr != nil && s.wgMgr.InterfaceName() != "" {
			iface = s.wgMgr.InterfaceName()
		}
		if err := firewall.Allow(fwCtx, firewall.Scope{
			Name:              "mesh",
			Interface:         iface,
			RPCPort:           s.port,
			MeshDestinationIP: node.MeshIP,
			MeshPeerIPs:       peerMeshIPs(node.Peers),
			MeshProxyPort:     proxyPort,
			Direct:            caps.HasNetAdmin(),
		}); err != nil {
			slog.Warn("firewall allow failed (mesh still up)", "err", err)
		}
	}

	slog.Info("mesh enabled", "mesh_ip", logredact.IP(node.MeshIP), "peers", len(node.Peers))
	return nil
}

func (s *Server) handleMeshDisable(w http.ResponseWriter, r *http.Request) {
	if err := s.apiClient.DeactivateNode(r.Context()); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	// User explicitly turned mesh off — remember so next agent boot does not
	// auto-re-enable.
	if s.settings != nil {
		if err := s.settings.Update(func(c *settings.Settings) { c.Mesh.StartDisabled = true }); err != nil {
			slog.Warn("settings: failed to persist mesh.start_disabled=true", "err", err)
		}
	}

	if s.proxyCtx != nil {
		s.proxyCtx()
		s.proxyCtx = nil
		s.proxySrv = nil
		s.socks5Srv = nil
	}

	// Remove Mesh NAT and restore ip_forward immediately. Do not wait for
	// app shutdown when the user explicitly disables Mesh.
	mesh.DisableNATAndRestore(r.Context(), "")

	// Roll back firewall rules we installed on enable. Tagged rules only.
	go func() {
		fwCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		iface := "wg0"
		if s.wgMgr != nil && s.wgMgr.InterfaceName() != "" {
			iface = s.wgMgr.InterfaceName()
		}
		sysstate.Global.RevertByPrefix(fwCtx, "firewall:mesh:")
		if err := firewall.Cleanup(fwCtx, iface, caps.HasNetAdmin()); err != nil {
			slog.Debug("firewall cleanup failed", "err", err)
		}
	}()

	// Clear any exit node routing.
	s.localFwd.SetUpstream("", 0)

	s.agent.SetMesh(state.MeshStatus{Active: false})
	s.refreshGuardForCurrentVPN()
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleListExitNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.apiClient.ListExitNodes(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if nodes == nil {
		nodes = []apiClient.ExitNode{}
	}
	writeJSON(w, nodes)
}

func validateExitNodeProxyTarget(meshIP string, port int) error {
	if meshIP == "" {
		return fmt.Errorf("mesh_ip is required")
	}
	if port <= 0 || port > 65535 {
		return fmt.Errorf("proxy_port must be between 1 and 65535")
	}
	ip := net.ParseIP(meshIP)
	if ip == nil {
		return fmt.Errorf("mesh_ip must be an IP address")
	}
	if ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return fmt.Errorf("mesh_ip is not allowed")
	}
	return nil
}

func (s *Server) handleSetExitNode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		MeshIP      string `json:"mesh_ip"`
		ProxyScheme string `json:"proxy_scheme"`
		ProxyPort   int    `json:"proxy_port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if err := validateExitNodeProxyTarget(req.MeshIP, req.ProxyPort); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.ProxyScheme == "" {
		req.ProxyScheme = "socks5"
	}
	if req.ProxyScheme != "socks5" && req.ProxyScheme != "http-connect" {
		writeError(w, http.StatusBadRequest, "unsupported proxy_scheme")
		return
	}
	if err := s.apiClient.SetExitNode(r.Context(), req.MeshIP, req.ProxyScheme, req.ProxyPort); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}

	if req.ProxyScheme == "http-connect" {
		s.localFwd.SetUpstream(req.MeshIP, req.ProxyPort)
	} else {
		s.localFwd.SetUpstream("", 0)
	}

	snap := s.agent.Snapshot()
	meshState, _ := snap["mesh"].(state.MeshStatus)
	meshState.ExitNodeHost = req.MeshIP
	meshState.ExitNodePort = req.ProxyPort
	meshState.ExitNodeScheme = req.ProxyScheme
	meshState.FullTunnel = true
	s.agent.SetMesh(meshState)

	writeJSON(w, map[string]any{
		"ok":               true,
		"local_proxy_port": localFwdPort,
		"proxy_scheme":     req.ProxyScheme,
	})
}

func (s *Server) handleMeshFullTunnelEnable(w http.ResponseWriter, r *http.Request) {
	s.handleSetExitNode(w, r)
}

func (s *Server) handleMeshFullTunnelDisable(w http.ResponseWriter, r *http.Request) {
	s.handleClearExitNode(w, r)
}

func (s *Server) handleClearExitNode(w http.ResponseWriter, r *http.Request) {
	if err := s.apiClient.ClearExitNode(r.Context()); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	s.localFwd.SetUpstream("", 0)
	snap := s.agent.Snapshot()
	meshState, _ := snap["mesh"].(state.MeshStatus)
	meshState.ExitNodeHost = ""
	meshState.ExitNodePort = 0
	meshState.ExitNodeScheme = ""
	meshState.FullTunnel = false
	s.agent.SetMesh(meshState)
	writeJSON(w, map[string]bool{"ok": true})
}
