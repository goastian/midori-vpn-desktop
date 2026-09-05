package rpc

import (
	"context"
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
	"github.com/goastian/midorivpn-agent/internal/settings"
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
	req, err := decodeVPNConnectRequest(r)
	if err != nil {
		writeStructuredError(w, http.StatusBadRequest, "ERR_VPN_CONNECT_REQUEST_INVALID", "La solicitud de conexión no es válida.")
		return
	}
	s.runVPNConnect(r.Context(), req, apiClient.ConnectionReasonUser, httpVPNConnectResponder{writer: w}, true)
}

type vpnConnectResponder interface {
	Fail(*vpnConnectFailure)
	Succeed(vpnConnectResult)
}

type httpVPNConnectResponder struct {
	writer http.ResponseWriter
}

func (responder httpVPNConnectResponder) Fail(failure *vpnConnectFailure) {
	if failure.Code == "" {
		writeError(responder.writer, failure.Status, failure.Message)
		return
	}
	writeStructuredError(responder.writer, failure.Status, failure.Code, failure.Message)
}

func (responder httpVPNConnectResponder) Succeed(result vpnConnectResult) {
	writeJSON(responder.writer, map[string]any{
		"ok":              true,
		"assigned_ip":     result.AssignedIP,
		"server":          result.Server,
		"active_protocol": result.ActiveProtocol,
		"fallback_reason": result.FallbackReason,
		"connection_ms":   result.ConnectionMS,
		"post_quantum":    result.PostQuantum,
		"pq_algorithm":    result.PQAlgorithm,
	})
}

func (s *Server) runVPNConnect(ctx context.Context, req vpnConnectRequest, reason apiClient.ConnectionReason, responder vpnConnectResponder, persistSelection bool) {
	if persistSelection {
		if current, ok := s.agent.Snapshot()["vpn"].(state.VPNStatus); ok &&
			(current.Connected || current.Phase == state.VPNPhaseReconnecting) {
			responder.Fail(connectFailure(http.StatusConflict, "ERR_VPN_ALREADY_CONNECTED", "Desconecta el túnel o la recuperación actual antes de iniciar otro."))
			return
		}
		// A direct user action owns the lifecycle from this point onward. Cancel
		// an automatic recovery loop before it can publish a competing tunnel.
		s.stopFailoverMonitor()
		if s.settings == nil {
			responder.Fail(connectFailure(http.StatusServiceUnavailable, "ERR_SETTINGS_UNAVAILABLE", "No se pudo guardar el modo de selección del servidor."))
			return
		}
		if err := s.settings.Update(func(current *settings.Settings) {
			current.VPN.SelectionMode = req.SelectionMode
			current.VPN.ManualServerID = req.ServerID
			if req.SelectionMode == settings.SelectionModeAutomatic {
				current.VPN.ManualServerID = ""
			}
		}); err != nil {
			responder.Fail(connectFailure(http.StatusInternalServerError, "ERR_SETTINGS_UNAVAILABLE", "No se pudo guardar el modo de selección del servidor."))
			return
		}
	}
	connectionID, err := newVPNConnectionID()
	if err != nil {
		responder.Fail(connectFailure(http.StatusInternalServerError, "", "connection identity unavailable"))
		return
	}

	if current, ok := s.agent.Snapshot()["vpn"].(state.VPNStatus); ok && current.Connected {
		responder.Fail(connectFailure(http.StatusConflict, "ERR_VPN_ALREADY_CONNECTED", "Desconecta el túnel actual antes de iniciar otro."))
		return
	}

	// "Last request wins": cancel any in-progress connect and take exclusive ownership.
	s.connectMu.Lock()
	if s.connectCancel != nil {
		s.connectCancel() // cancel previous in-flight connect
	}
	s.connectSeq++
	mySeq := s.connectSeq
	ctx, cancel := context.WithCancel(ctx)
	s.connectCancel = cancel
	if persistSelection {
		s.agent.BeginVPNConnection(connectionID, req.ServerID, req.Protocol)
	} else {
		failedServerID := ""
		if current, ok := s.agent.Snapshot()["vpn"].(state.VPNStatus); ok {
			failedServerID = current.FailoverFrom
			if failedServerID == "" {
				failedServerID = current.ServerID
			}
		}
		s.agent.BeginVPNRecoveryConnection(connectionID, failedServerID, req.Protocol)
	}
	s.connectMu.Unlock()
	slog.Info("vpn connection attempt started", "requested_protocol", req.Protocol, "server_id", req.ServerID)

	// Release ownership on exit; always cancel the derived context.
	defer func() {
		cancel()
		s.connectMu.Lock()
		if s.connectSeq == mySeq {
			s.connectCancel = nil
		}
		s.connectMu.Unlock()
	}()
	if persistSelection {
		defer s.agent.FailVPNConnection(connectionID)
	}

	// Ensure we have a valid access token before starting the connect sequence.
	token, tokenErr := s.authMgr.GetValidToken(ctx)
	if tokenErr != nil {
		slog.Warn("vpn connect: failed to get valid token", "err", tokenErr)
		responder.Fail(connectFailure(http.StatusBadGateway, "", "auth: "+tokenErr.Error()))
		return
	}
	if token == "" {
		responder.Fail(connectFailure(http.StatusUnauthorized, "", "not authenticated: please sign in"))
		return
	}
	// Resolve and validate the requested transport before provisioning any
	// protocol-specific credential. In particular, certificate transports must
	// never create an unrelated WireGuard peer as a side effect.
	server, selection, err := s.resolveVPNServer(ctx, req)
	if err != nil {
		responder.Fail(connectFailure(http.StatusBadGateway, "ERR_NO_REACHABLE_SERVER", "No hay un servidor VPN elegible y accesible para este modo."))
		return
	}
	if server == nil {
		responder.Fail(connectFailure(http.StatusNotFound, "", "server not found"))
		return
	}
	req.ServerID = server.ID
	s.agent.SetVPNSelection(connectionID, server.ID, string(req.SelectionMode))
	candidates := selectTransportCandidates(server.Transports, req.Protocol)
	if len(candidates) == 0 {
		responder.Fail(connectFailure(http.StatusBadRequest, "ERR_TRANSPORT_UNAVAILABLE", "No hay transportes saludables disponibles en este servidor."))
		return
	}
	candidateNames := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		candidateNames = append(candidateNames, candidate.protocol)
	}
	slog.Info("vpn transport candidates selected", "requested_protocol", req.Protocol, "candidates", candidateNames)
	if req.Protocol == "openvpn" {
		s.runOpenVPNConnect(ctx, server, candidates[0], mySeq, connectionID, req.SelectionMode, selection, responder)
		return
	}
	if req.Protocol == "ikev2" {
		s.runIKEv2Connect(ctx, server, candidates[0], mySeq, connectionID, req.SelectionMode, selection, responder)
		return
	}
	if !server.SupportsWireGuard {
		responder.Fail(connectFailure(http.StatusBadRequest, "", "server does not support WireGuard full tunnel"))
		return
	}
	s.agent.UpdateVPNConnection(connectionID, state.VPNPhaseAuthenticating, "", "")
	identity, err := s.deviceIdentity.Current()
	if err != nil {
		slog.Error("persistent device identity unavailable", "err", err)
		responder.Fail(connectFailure(http.StatusInternalServerError, "", "device identity unavailable"))
		return
	}

	// Generate WireGuard and ML-KEM-768 keypairs locally. Private key material
	// never leaves the client process.
	kp, err := crypto.GenerateWireGuardKeypair()
	if err != nil {
		responder.Fail(connectFailure(http.StatusInternalServerError, "", "keypair: "+err.Error()))
		return
	}
	pqKeypair, pqErr := crypto.GenerateMLKEM768Keypair()
	var pqEncKey string
	if pqErr == nil && pqKeypair != nil {
		pqEncKey = pqKeypair.EncapsulationKeyB64
	}

	// Create connection with optional PQ KEM encapsulation public key.
	connCfg, err := s.apiClient.CreateConnection(
		ctx,
		req.ServerID,
		kp.PublicKey,
		deviceRegistration(identity),
		reason,
		pqEncKey,
	)
	if err != nil {
		responder.Fail(connectFailure(http.StatusBadGateway, "", "connect: "+err.Error()))
		return
	}
	if connCfg.DeviceID == "" || !isValidUUID(connCfg.DeviceID) {
		s.cleanupVPNConnection(connCfg.PeerID)
		responder.Fail(connectFailure(http.StatusBadGateway, "", "connect: response is missing a valid device identity"))
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
		s.cleanupVPNConnection(connCfg.PeerID)
		responder.Fail(connectFailure(http.StatusBadGateway, "ERR_DNS_CONFIGURATION_MISSING", "El servidor no entregó una configuración DNS válida."))
		return
	}
	dnsServers = sanitizeDNS(dnsServers)
	if len(dnsServers) == 0 {
		s.cleanupVPNConnection(connCfg.PeerID)
		responder.Fail(connectFailure(http.StatusBadGateway, "ERR_DNS_CONFIGURATION_INVALID", "El servidor entregó una configuración DNS no permitida."))
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

	activeProtocol := ""
	fallbackReason := ""
	var relay interface{ Close() }
	netguardEndpoint := ""
	serverEndpoint := ""
	connectionStarted := time.Now()
	var connectionErr error
	for index, candidate := range candidates {
		s.agent.UpdateVPNConnection(connectionID, state.VPNPhaseNegotiating, "", fallbackReason)
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
				s.agent.UpdateVPNConnection(connectionID, state.VPNPhaseNegotiating, "", fallbackReason)
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
		s.cleanupVPNConnection(connCfg.PeerID)
		if isDNSPermissionError(connectionErr) {
			responder.Fail(connectFailure(http.StatusForbidden, "ERR_DNS_PERMISSION_DENIED",
				"Permisos insuficientes para configurar DNS en /etc/resolv.conf. Habilita los permisos del sistema en MidoriVPN."))
			return
		}
		if isTunPermissionError(connectionErr) {
			responder.Fail(connectFailure(http.StatusForbidden, "ERR_TUN_PERMISSION_DENIED",
				"Permisos insuficientes para crear la interfaz WireGuard (TUN). Habilita los permisos del sistema en MidoriVPN."))
			return
		}
		responder.Fail(connectFailure(http.StatusBadGateway, "ERR_VPN_HANDSHAKE_FAILED", "No se pudo completar el handshake del túnel: "+connectionErr.Error()))
		return
	}
	connectionDurationMS := time.Since(connectionStarted).Milliseconds()
	s.agent.UpdateVPNConnection(connectionID, state.VPNPhaseProtecting, activeProtocol, fallbackReason)

	guardWasActive := s.guard.Active()
	if err := s.guard.Enable(s.netguardScope(netguardEndpoint, assignedIP)); err != nil {
		s.wgMgr.Disconnect()
		if relay != nil {
			relay.Close()
		}
		s.cleanupVPNConnection(connCfg.PeerID)
		if !guardWasActive {
			_ = s.guard.Disable()
		}
		s.agent.SetProtection(state.ProtectionStatus{LastError: err.Error()})
		responder.Fail(connectFailure(http.StatusInternalServerError, "", "kill switch: "+err.Error()))
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
		if !guardWasActive {
			_ = s.guard.Disable()
		}
		s.cleanupVPNConnection(connCfg.PeerID)
		responder.Fail(connectFailure(http.StatusConflict, "", "superseded by a newer connect request"))
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
		Connected:         true,
		Phase:             state.VPNPhaseConnected,
		ConnectionID:      connectionID,
		ServerName:        server.Name,
		ServerID:          req.ServerID,
		PeerID:            connCfg.PeerID,
		AssignedIP:        assignedIP,
		ServerPublicIP:    serverPublicIP,
		ServerEndpoint:    serverEndpoint,
		ActiveProtocol:    activeProtocol,
		RequestedProtocol: req.Protocol,
		SelectionMode:     string(req.SelectionMode),
		FallbackReason:    fallbackReason,
		ConnectionMS:      connectionDurationMS,
		PostQuantum:       isPostQuantum,
		PQAlgorithm:       pqAlgo,
	})
	s.startVPNStatsLoop()
	s.agent.SetProtection(state.ProtectionStatus{
		KillSwitchActive: true,
		DNSProtected:     s.wgMgr.DNSProtected(),
		Mode:             activeProtocol,
	})
	if req.SelectionMode == settings.SelectionModeAutomatic && selection != nil {
		s.startFailoverMonitor(req.Protocol, *selection)
	}
	responder.Succeed(vpnConnectResult{
		AssignedIP: assignedIP, Server: server.Name, ActiveProtocol: activeProtocol,
		FallbackReason: fallbackReason, ConnectionMS: connectionDurationMS,
		PostQuantum: isPostQuantum, PQAlgorithm: pqAlgo,
	})
}

func (s *Server) cleanupVPNConnection(peerID string) {
	if peerID == "" {
		return
	}
	cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := s.apiClient.DeleteConnection(cleanupCtx, peerID); err != nil {
		slog.Warn("vpn connection cleanup deferred by backend", "err", err)
	}
}

func (s *Server) handleVPNDisconnect(w http.ResponseWriter, r *http.Request) {
	req, err := decodeVPNDisconnectRequest(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_disconnect_request")
		return
	}

	snap := s.agent.Snapshot()
	vpn, ok := snap["vpn"].(state.VPNStatus)
	if !ok || (!vpn.Connected && vpn.Phase != state.VPNPhaseReconnecting) {
		writeStructuredError(w, http.StatusConflict, "ERR_VPN_NOT_CONNECTED", "No hay un túnel VPN activo para desconectar.")
		return
	}
	if vpn.ConnectionID == "" || vpn.ConnectionID != req.ConnectionID {
		slog.Warn("stale vpn disconnect rejected", "reason", req.Reason, "protocol", vpn.ActiveProtocol)
		writeStructuredError(w, http.StatusConflict, "ERR_VPN_CONNECTION_CHANGED", "La conexión VPN activa cambió; actualiza el estado antes de desconectarla.")
		return
	}

	slog.Info("vpn disconnect requested", "reason", req.Reason, "protocol", vpn.ActiveProtocol, "server_id", vpn.ServerID)
	vpn.Phase = state.VPNPhaseDisconnecting
	s.agent.SetVPN(vpn)
	s.stopFailoverMonitor()
	// Invalidate a pending connection attempt before tearing down the current
	// transport so it cannot become active after this explicit user action.
	s.connectMu.Lock()
	if s.connectCancel != nil {
		s.connectCancel()
		s.connectCancel = nil
	}
	s.connectSeq++
	s.connectMu.Unlock()

	s.stopVPNStatsLoop()
	peerID := vpn.PeerID
	// Disconnect locally and respond immediately — don't block on cloud API.
	s.closeTransportRelay()
	s.restoreExternalDNS()
	s.wgMgr.Disconnect()
	_ = s.guard.Disable()
	s.setRecoveryEndpoints(nil)
	s.agent.SetVPN(state.VPNStatus{Phase: state.VPNPhaseDisconnected})
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
		} else if protocol == "openvpn" || protocol == "ikev2" {
			timeout = 30 * time.Second
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
		s.relayMu.Lock()
		counter, supportsCounters := s.transportRelay.(interface {
			ByteCounters() (int64, int64, bool)
		})
		s.relayMu.Unlock()
		if supportsCounters {
			tx, rx, ok = counter.ByteCounters()
		}
	}
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
