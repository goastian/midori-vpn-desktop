package rpc

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/goastian/midorivpn-agent/internal/apiClient"
	"github.com/goastian/midorivpn-agent/internal/crypto"
	"github.com/goastian/midorivpn-agent/internal/state"
	"github.com/goastian/midorivpn-agent/internal/tunnel"
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

	// Generate WireGuard and ML-KEM-768 keypairs locally. Private key material
	// never leaves the client process.
	kp, err := crypto.GenerateWireGuardKeypair()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "keypair: "+err.Error())
		return
	}
	pqKeypair, pqErr := crypto.GenerateMLKEM768Keypair()
	var pqEncKey string
	if pqErr == nil && pqKeypair != nil {
		pqEncKey = pqKeypair.EncapsulationKeyB64
	}

	// Create connection with optional PQ KEM encapsulation public key.
	connCfg, err := s.apiClient.CreateConnection(ctx, req.ServerID, kp.PublicKey, "desktop", pqEncKey)
	if err != nil {
		writeError(w, http.StatusBadGateway, "connect: "+err.Error())
		return
	}

	// If the server returned an ML-KEM-768 ciphertext, decapsulate the shared secret.
	isPostQuantum := false
	if connCfg.PQKEMCiphertext != "" && pqKeypair != nil {
		sharedKey, decErr := crypto.DecapsulateSharedKey(pqKeypair.DecapsulationKey, connCfg.PQKEMCiphertext)
		if decErr == nil && sharedKey != "" {
			connCfg.PresharedKey = sharedKey
			isPostQuantum = true
			slog.Info("post-quantum ML-KEM-768 key exchange negotiated successfully")
		} else {
			slog.Warn("post-quantum decapsulation failed, using direct PSK", "err", decErr)
		}
	} else if connCfg.PresharedKey != "" {
		isPostQuantum = true
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
		_ = s.apiClient.DeleteConnection(cleanupCtx, connCfg.PeerID)
		writeError(w, http.StatusBadRequest, "server does not support WireGuard full tunnel")
		return
	}
	if req.Protocol != "wireguard" && req.Protocol != "smart_auto" && req.Protocol != "wss" && req.Protocol != "masque" {
		_ = s.apiClient.DeleteConnection(cleanupCtx, connCfg.PeerID)
		writeStructuredError(w, http.StatusBadRequest, "ERR_TRANSPORT_UNAVAILABLE", "El transporte solicitado no está disponible en este servidor.")
		return
	}

	// Prefer public host for server identification; fallback to endpoint
	serverPublicIP := server.Host
	if serverPublicIP == "" {
		serverPublicIP = server.Endpoint
	}

	assignedIP := normalizeAssignedIP(connCfg.PeerIP)
	serverPublicKey := server.PublicKey
	if connCfg.ServerPublicKey != "" {
		serverPublicKey = connCfg.ServerPublicKey
	}

	// DNS is part of the authenticated connection contract. Guessing a public
	// resolver would silently override administrator policy and can create a
	// privacy leak, so an incomplete response is rejected.
	dnsServers := splitCSV(connCfg.DNS)
	if len(dnsServers) == 0 {
		_ = s.apiClient.DeleteConnection(cleanupCtx, connCfg.PeerID)
		writeStructuredError(w, http.StatusBadGateway, "ERR_DNS_CONFIGURATION_MISSING", "El servidor no entregó una configuración DNS válida.")
		return
	}
	dnsServers = sanitizeDNS(dnsServers)
	if len(dnsServers) == 0 {
		_ = s.apiClient.DeleteConnection(cleanupCtx, connCfg.PeerID)
		writeStructuredError(w, http.StatusBadGateway, "ERR_DNS_CONFIGURATION_INVALID", "El servidor entregó una configuración DNS no permitida.")
		return
	}

	baseWGConfig := wg.Config{
		PrivateKey:   kp.PrivateKey,
		PublicKey:    serverPublicKey,
		PresharedKey: connCfg.PresharedKey,
		AssignedIP:   assignedIP,
		DNS:          dnsServers,
		MTU:          1280,
	}

	candidates := selectTransportCandidates(server.Transports, req.Protocol)
	if len(candidates) == 0 {
		_ = s.apiClient.DeleteConnection(cleanupCtx, connCfg.PeerID)
		writeStructuredError(w, http.StatusBadRequest, "ERR_TRANSPORT_UNAVAILABLE", "No hay transportes saludables disponibles en este servidor.")
		return
	}

	activeProtocol := ""
	fallbackReason := ""
	var relay interface{ Close() }
	netguardEndpoint := ""
	serverEndpoint := ""
	connectionStarted := time.Now()
	var connectionErr error
	for index, candidate := range candidates {
		candidateEndpoint := net.JoinHostPort(candidate.host, strconv.Itoa(candidate.port))
		wgConfig := baseWGConfig
		wgConfig.Endpoint = candidateEndpoint
		wgConfig.RouteEndpoint = candidateEndpoint
		var candidateRelay interface{ Close() }
		if candidate.protocol == "wss" {
			credentials, credentialErr := s.apiClient.TunnelCredentials(ctx, connCfg.PeerID)
			if credentialErr != nil || credentials.TunnelToken == "" {
				connectionErr = fmt.Errorf("WSS tunnel credentials unavailable")
				continue
			}
			wssURL := (&url.URL{Scheme: "wss", Host: candidateEndpoint, Path: "/api/v1/tunnel/ws"}).String()
			dialCtx, dialCancel := context.WithTimeout(ctx, 15*time.Second)
			var localEndpoint string
			candidateRelay, localEndpoint, connectionErr = tunnel.StartWSSRelay(dialCtx, wssURL, credentials.TunnelToken)
			dialCancel()
			if connectionErr != nil {
				continue
			}
			wgConfig.Endpoint = localEndpoint
		} else if candidate.protocol == "masque" {
			credentials, credentialErr := s.apiClient.TunnelCredentials(ctx, connCfg.PeerID)
			if credentialErr != nil || credentials.TunnelToken == "" {
				connectionErr = fmt.Errorf("MASQUE tunnel credentials unavailable")
				continue
			}
			uriTemplate, templateOK := metadataString(candidate.metadata, "uri_template")
			target, targetOK := metadataString(candidate.metadata, "target")
			if !templateOK || !targetOK {
				connectionErr = fmt.Errorf("MASQUE transport metadata is incomplete")
				continue
			}
			if target != net.JoinHostPort("127.0.0.1", strconv.Itoa(server.WGPort)) {
				connectionErr = fmt.Errorf("MASQUE target does not match the server WireGuard socket")
				continue
			}
			dialCtx, dialCancel := context.WithTimeout(ctx, 15*time.Second)
			var localEndpoint string
			candidateRelay, localEndpoint, connectionErr = tunnel.StartMasqueRelay(dialCtx, uriTemplate, target, credentials.TunnelToken)
			dialCancel()
			if connectionErr != nil {
				continue
			}
			wgConfig.Endpoint = localEndpoint
			wgConfig.MTU = 1180
		}

		attemptStarted := time.Now()
		connectionErr = s.wgMgr.Connect(&wgConfig)
		if connectionErr == nil {
			handshakeCtx, handshakeCancel := context.WithTimeout(ctx, candidate.timeout)
			connectionErr = s.wgMgr.WaitForHandshake(handshakeCtx)
			handshakeCancel()
		}
		if connectionErr != nil {
			s.wgMgr.Disconnect()
			if candidateRelay != nil {
				candidateRelay.Close()
			}
			if req.Protocol == "smart_auto" && index+1 < len(candidates) {
				fallbackReason = candidate.protocol + "_handshake_failed"
			}
			continue
		}

		slog.Info("vpn transport handshake completed", "protocol", candidate.protocol, "duration", time.Since(attemptStarted))
		activeProtocol = candidate.protocol
		relay = candidateRelay
		netguardEndpoint = candidateEndpoint
		serverEndpoint = candidateEndpoint
		break
	}
	if activeProtocol == "" {
		_ = s.apiClient.DeleteConnection(cleanupCtx, connCfg.PeerID)
		if isDNSPermissionError(connectionErr) {
			writeStructuredError(w, http.StatusForbidden, "ERR_DNS_PERMISSION_DENIED",
				"Permisos insuficientes para configurar DNS en /etc/resolv.conf. Habilita los permisos del sistema en MidoriVPN.")
			return
		}
		if isTunPermissionError(connectionErr) {
			writeStructuredError(w, http.StatusForbidden, "ERR_TUN_PERMISSION_DENIED",
				"Permisos insuficientes para crear la interfaz WireGuard (TUN). Habilita los permisos del sistema en MidoriVPN.")
			return
		}
		writeStructuredError(w, http.StatusBadGateway, "ERR_VPN_HANDSHAKE_FAILED", "No se pudo completar el handshake del túnel: "+connectionErr.Error())
		return
	}
	connectionDurationMS := time.Since(connectionStarted).Milliseconds()

	if err := s.guard.Enable(s.netguardScope(netguardEndpoint, assignedIP)); err != nil {
		s.wgMgr.Disconnect()
		if relay != nil {
			relay.Close()
		}
		_ = s.apiClient.DeleteConnection(cleanupCtx, connCfg.PeerID)
		s.agent.SetProtection(state.ProtectionStatus{LastError: err.Error()})
		writeError(w, http.StatusInternalServerError, "kill switch: "+err.Error())
		return
	}

	// Verify we were not superseded by a newer connect request that took ownership.
	s.connectMu.Lock()
	superseded := s.connectSeq != mySeq
	s.connectMu.Unlock()
	if superseded {
		slog.Info("vpn connect: superseded by newer request, rolling back", "seq", mySeq)
		s.wgMgr.Disconnect()
		if relay != nil {
			relay.Close()
		}
		_ = s.guard.Disable()
		_ = s.apiClient.DeleteConnection(cleanupCtx, connCfg.PeerID)
		writeError(w, http.StatusConflict, "superseded by a newer connect request")
		return
	}
	if relay != nil {
		s.setTransportRelay(relay)
	}

	pqAlgo := ""
	if isPostQuantum {
		pqAlgo = "ML-KEM-768"
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
		ConnectionMS:   connectionDurationMS,
		PostQuantum:    isPostQuantum,
		PQAlgorithm:    pqAlgo,
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
		"connection_ms":   connectionDurationMS,
		"post_quantum":    isPostQuantum,
		"pq_algorithm":    pqAlgo,
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
	s.closeTransportRelay()
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

func findTransport(transports []apiClient.TransportCapability, protocol string) (apiClient.TransportCapability, bool) {
	for _, transport := range transports {
		if transport.Protocol == protocol && transport.Enabled && transport.HealthStatus == "healthy" {
			return transport, true
		}
	}
	return apiClient.TransportCapability{}, false
}

type vpnTransportCandidate struct {
	protocol string
	host     string
	port     int
	priority int
	metadata map[string]interface{}
	timeout  time.Duration
}

func selectTransportCandidates(transports []apiClient.TransportCapability, requested string) []vpnTransportCandidate {
	validCandidate := func(protocol string) (vpnTransportCandidate, bool) {
		transport, ok := findTransport(transports, protocol)
		if !ok || transport.Host == "" || transport.Port < 1 || transport.Port > 65535 {
			return vpnTransportCandidate{}, false
		}
		timeout := 5 * time.Second
		if protocol == "wireguard" {
			timeout = 1500 * time.Millisecond
		}
		return vpnTransportCandidate{protocol: protocol, host: transport.Host, port: transport.Port, priority: transport.Priority, metadata: transport.Metadata, timeout: timeout}, true
	}

	protocols := []string{requested}
	if requested == "smart_auto" {
		protocols = []string{"wireguard", "wss", "masque"}
	}
	candidates := make([]vpnTransportCandidate, 0, len(protocols))
	for _, protocol := range protocols {
		if candidate, ok := validCandidate(protocol); ok {
			candidates = append(candidates, candidate)
		}
	}
	if requested == "smart_auto" {
		sort.SliceStable(candidates, func(i, j int) bool { return candidates[i].priority > candidates[j].priority })
	}
	return candidates
}

func metadataString(metadata map[string]interface{}, key string) (string, bool) {
	value, ok := metadata[key].(string)
	value = strings.TrimSpace(value)
	return value, ok && value != ""
}

func (s *Server) setTransportRelay(relay interface{ Close() }) {
	s.relayMu.Lock()
	previous := s.transportRelay
	s.transportRelay = relay
	s.relayMu.Unlock()
	if previous != nil && previous != relay {
		previous.Close()
	}
}

func (s *Server) closeTransportRelay() {
	s.relayMu.Lock()
	relay := s.transportRelay
	s.transportRelay = nil
	s.relayMu.Unlock()
	if relay != nil {
		relay.Close()
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
