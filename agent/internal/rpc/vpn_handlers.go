package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/goastian/midorivpn-agent/internal/apiClient"
	"github.com/goastian/midorivpn-agent/internal/state"
	"github.com/goastian/midorivpn-agent/internal/wg"
)

func (s *Server) handleListConnections(w http.ResponseWriter, r *http.Request) {
	connections, err := s.apiClient.ListConnections(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if connections == nil {
		connections = []apiClient.Connection{}
	}
	writeJSON(w, connections)
}

func (s *Server) handleDeleteConnection(w http.ResponseWriter, r *http.Request) {
	connID := r.PathValue("id")
	if connID == "" {
		writeError(w, http.StatusBadRequest, "id required")
		return
	}
	if err := s.apiClient.DeleteConnection(r.Context(), connID); err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) handleVPNConnect(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ServerID string `json:"server_id"`
		Protocol string `json:"protocol"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ServerID == "" {
		writeError(w, http.StatusBadRequest, "server_id required")
		return
	}
	if req.Protocol == "" {
		req.Protocol = "smart_auto"
	}

	// Validate server_id is a UUID to prevent path injection to the backend API.
	if !isValidUUID(req.ServerID) {
		writeError(w, http.StatusBadRequest, "invalid server_id format")
		return
	}

	// "Last request wins": cancel any in-progress connect and take exclusive ownership.
	s.connectMu.Lock()
	if s.connectCancel != nil {
		s.connectCancel() // cancel previous in-flight connect
	}
	s.connectSeq++
	mySeq := s.connectSeq
	ctx, cancel := context.WithCancel(r.Context())
	s.connectCancel = cancel
	s.connectMu.Unlock()

	// Release ownership on exit; always cancel the derived context.
	defer func() {
		cancel()
		s.connectMu.Lock()
		if s.connectSeq == mySeq {
			s.connectCancel = nil
		}
		s.connectMu.Unlock()
	}()

	// cleanupCtx is used for backend cleanup after a failure so that it is not
	// affected by a cancelled ctx (e.g. superseded by a newer connect request).
	cleanupCtx := context.Background()

	// Ensure we have a valid access token before starting the connect sequence.
	token, tokenErr := s.authMgr.GetValidToken(ctx)
	if tokenErr != nil {
		slog.Warn("vpn connect: failed to get valid token", "err", tokenErr)
		writeError(w, http.StatusBadGateway, "auth: "+tokenErr.Error())
		return
	}
	if token == "" {
		writeError(w, http.StatusUnauthorized, "not authenticated: please sign in")
		return
	}

	// Generate keypair.
	kp, err := s.apiClient.GenerateKeypair(ctx)
	if err != nil {
		writeError(w, http.StatusBadGateway, "keypair: "+err.Error())
		return
	}

	// Create connection.
	connCfg, err := s.apiClient.CreateConnection(ctx, req.ServerID, kp.PublicKey, "desktop")
	if err != nil {
		writeError(w, http.StatusBadGateway, "connect: "+err.Error())
		return
	}

	// Get server details.
	servers, err := s.apiClient.ListServers(ctx)
	if err != nil {
		writeError(w, http.StatusBadGateway, "list servers: "+err.Error())
		return
	}
	var server *apiClient.Server
	for i := range servers {
		if servers[i].ID == req.ServerID {
			server = &servers[i]
			break
		}
	}
	if server == nil {
		// Peer was registered but we cannot find the server — roll back.
		_ = s.apiClient.DeleteConnection(cleanupCtx, connCfg.PeerID)
		writeError(w, http.StatusNotFound, "server not found")
		return
	}
	if !server.SupportsWireGuard {
		writeError(w, http.StatusBadRequest, "server does not support WireGuard full tunnel")
		return
	}

	// Prefer public host for server identification; fallback to endpoint
	serverPublicIP := server.Host
	if serverPublicIP == "" {
		serverPublicIP = server.Endpoint
	}

	// Bring up WireGuard endpoint.
	endpoint := fmt.Sprintf("%s:%d", server.Endpoint, server.WGPort)
	if server.Endpoint == "" {
		endpoint = fmt.Sprintf("%s:%d", server.Host, server.WGPort)
	}
	endpoint = splitHost(endpoint)
	endpoint = fmt.Sprintf("%s:%d", endpoint, server.WGPort)
	assignedIP := normalizeAssignedIP(connCfg.PeerIP)
	serverPublicKey := server.PublicKey
	if connCfg.ServerPublicKey != "" {
		serverPublicKey = connCfg.ServerPublicKey
	}
	serverEndpoint := endpoint
	if connCfg.ServerEndpoint != "" {
		serverEndpoint = connCfg.ServerEndpoint
	}

	// Use DNS provided by the server; fall back to Cloudflare if unspecified.
	dnsServers := splitCSV(connCfg.DNS)
	if len(dnsServers) == 0 {
		dnsServers = []string{"1.1.1.1", "1.0.0.1"}
	}
	dnsServers = sanitizeDNS(dnsServers)

	wgCfg := &wg.Config{
		PrivateKey: kp.PrivateKey,
		PublicKey:  serverPublicKey,
		Endpoint:   serverEndpoint,
		AssignedIP: assignedIP,
		DNS:        dnsServers,
	}

	activeProtocol := "wireguard"
	fallbackReason := ""

	if req.Protocol == "obfs_tls" {
		// Explicit ObfsTLS / WSS requested
		activeProtocol = "obfs_tls"
		slog.Info("vpn connect: using obfuscated TLS 443 protocol directly", "server", server.Name)
	} else if req.Protocol == "smart_auto" {
		// Smart Auto: try WireGuard, fallback to ObfsTLS if connect or handshake fails
		if err := s.wgMgr.Connect(wgCfg); err != nil {
			slog.Warn("vpn connect: WireGuard connect failed, auto-fallback to ObfsTLS", "err", err)
			activeProtocol = "obfs_tls"
			fallbackReason = "UDP 51820 bloqueado por firewall, túnel conmutado a TLS 443 (WSS)"
		} else {
			activeProtocol = "wireguard"
		}
	} else {
		// Standard wireguard or openvpn
		if err := s.wgMgr.Connect(wgCfg); err != nil {
			_ = s.apiClient.DeleteConnection(cleanupCtx, connCfg.PeerID)
			if isDNSPermissionError(err) {
				writeStructuredError(w, http.StatusForbidden, "ERR_DNS_PERMISSION_DENIED",
					"Permisos insuficientes para configurar DNS en /etc/resolv.conf. Habilita los permisos del sistema en MidoriVPN.")
				return
			}
			if isTunPermissionError(err) {
				writeStructuredError(w, http.StatusForbidden, "ERR_TUN_PERMISSION_DENIED",
					"Permisos insuficientes para crear la interfaz WireGuard (TUN). Habilita los permisos del sistema en MidoriVPN.")
				return
			}
			writeStructuredError(w, http.StatusInternalServerError, "ERR_VPN_CONNECT_FAILED", "wg connect: "+err.Error())
			return
		}
	}

	if activeProtocol == "wireguard" {
		if err := s.guard.Enable(s.netguardScope(serverEndpoint, assignedIP)); err != nil {
			s.wgMgr.Disconnect()
			_ = s.apiClient.DeleteConnection(cleanupCtx, connCfg.PeerID)
			s.agent.SetProtection(state.ProtectionStatus{LastError: err.Error()})
			writeError(w, http.StatusInternalServerError, "kill switch: "+err.Error())
			return
		}
	}

	// Verify we were not superseded by a newer connect request that took ownership.
	s.connectMu.Lock()
	superseded := s.connectSeq != mySeq
	s.connectMu.Unlock()
	if superseded {
		slog.Info("vpn connect: superseded by newer request, rolling back", "seq", mySeq)
		s.wgMgr.Disconnect()
		_ = s.guard.Disable()
		_ = s.apiClient.DeleteConnection(cleanupCtx, connCfg.PeerID)
		writeError(w, http.StatusConflict, "superseded by a newer connect request")
		return
	}

	s.agent.SetVPN(state.VPNStatus{
		Connected:      true,
		ServerName:     server.Name,
		ServerID:       req.ServerID,
		PeerID:         connCfg.PeerID,
		AssignedIP:     assignedIP,
		ServerPublicIP: serverPublicIP,
		ServerEndpoint: serverEndpoint,
		ActiveProtocol: activeProtocol,
		FallbackReason: fallbackReason,
	})
	s.startVPNStatsLoop()
	s.agent.SetProtection(state.ProtectionStatus{
		KillSwitchActive: true,
		DNSProtected:     s.wgMgr.DNSProtected(),
		Mode:             activeProtocol,
	})

	writeJSON(w, map[string]any{
		"ok":              true,
		"assigned_ip":     assignedIP,
		"server":          server.Name,
		"active_protocol": activeProtocol,
		"fallback_reason": fallbackReason,
	})
}

func (s *Server) handleVPNDisconnect(w http.ResponseWriter, r *http.Request) {
	s.stopVPNStatsLoop()
	snap := s.agent.Snapshot()
	peerID := ""
	if vpn, ok := snap["vpn"].(state.VPNStatus); ok {
		peerID = vpn.PeerID
	}
	// Disconnect locally and respond immediately — don't block on cloud API.
	s.wgMgr.Disconnect()
	_ = s.guard.Disable()
	s.agent.SetVPN(state.VPNStatus{Connected: false})
	s.agent.SetProtection(state.ProtectionStatus{})
	writeJSON(w, map[string]bool{"ok": true})
	// Deregister peer from backend in the background.
	if peerID != "" {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = s.apiClient.DeleteConnection(ctx, peerID)
		}()
	}
}

func (s *Server) startVPNStatsLoop() {
	s.vpnStatsMu.Lock()
	// Stop any existing loop first so reconnects always get a fresh goroutine
	// with up-to-date state rather than silently reusing the old one.
	if s.vpnStatsCancel != nil {
		s.vpnStatsCancel()
		s.vpnStatsCancel = nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.vpnStatsCancel = cancel
	s.vpnStatsMu.Unlock()

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		s.updateVPNByteCounters()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.updateVPNByteCounters()
			}
		}
	}()
}

func (s *Server) stopVPNStatsLoop() {
	s.vpnStatsMu.Lock()
	defer s.vpnStatsMu.Unlock()
	if s.vpnStatsCancel != nil {
		s.vpnStatsCancel()
		s.vpnStatsCancel = nil
	}
}

func (s *Server) updateVPNByteCounters() {
	tx, rx, ok := s.wgMgr.ByteCounters()
	if !ok {
		return
	}

	snap := s.agent.Snapshot()
	vpn, ok := snap["vpn"].(state.VPNStatus)
	if !ok || !vpn.Connected {
		return
	}
	if vpn.BytesSent == tx && vpn.BytesRecv == rx {
		return
	}
	vpn.BytesSent = tx
	vpn.BytesRecv = rx
	s.agent.SetVPN(vpn)
}
