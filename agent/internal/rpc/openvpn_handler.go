package rpc

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/goastian/midorivpn-agent/internal/apiClient"
	"github.com/goastian/midorivpn-agent/internal/openvpn"
	"github.com/goastian/midorivpn-agent/internal/state"
)

func (s *Server) handleOpenVPNConnect(w http.ResponseWriter, ctx context.Context, server *apiClient.Server, candidate vpnTransportCandidate, sequence uint64, connectionID string) {
	s.agent.UpdateVPNConnection(connectionID, state.VPNPhaseAuthenticating, "", "")
	serverName, ok := metadataString(candidate.metadata, "server_name")
	if !ok {
		writeStructuredError(w, http.StatusBadGateway, "ERR_TRANSPORT_CONFIGURATION_INVALID", "OpenVPN no tiene un nombre de certificado de gateway configurado.")
		return
	}
	credential, err := s.ensureDeviceCredential(ctx, server.ID)
	if err != nil {
		writeStructuredError(w, http.StatusBadGateway, "ERR_DEVICE_CERTIFICATE_FAILED", "No se pudo preparar el certificado privado del dispositivo: "+err.Error())
		return
	}
	endpoint := net.JoinHostPort(candidate.host, strconv.Itoa(candidate.port))
	started := time.Now()
	s.agent.UpdateVPNConnection(connectionID, state.VPNPhaseNegotiating, "", "")
	client, err := openvpn.Start(ctx, openvpn.Config{
		Endpoint: endpoint, ServerName: serverName, Credential: credential, Timeout: candidate.timeout,
	})
	if err != nil {
		writeStructuredError(w, http.StatusBadGateway, "ERR_VPN_HANDSHAKE_FAILED", "No se pudo completar el handshake OpenVPN/DCO: "+err.Error())
		return
	}
	cleanup := func() {
		_ = s.guard.Disable()
		s.restoreExternalDNS()
		client.Close()
	}
	s.agent.UpdateVPNConnection(connectionID, state.VPNPhaseProtecting, "openvpn", "")

	dnsServers := transportDNS(candidate.metadata)
	if len(dnsServers) == 0 {
		dnsServers = client.DNS()
	}
	dnsServers = sanitizeDNS(dnsServers)
	if len(dnsServers) == 0 {
		cleanup()
		writeStructuredError(w, http.StatusBadGateway, "ERR_DNS_CONFIGURATION_MISSING", "El gateway OpenVPN no entregó una configuración DNS válida.")
		return
	}
	assignedIP := client.AssignedIP()
	if assignedIP == "" {
		cleanup()
		writeStructuredError(w, http.StatusBadGateway, "ERR_TRANSPORT_CONFIGURATION_INVALID", "OpenVPN no entregó una dirección de túnel válida.")
		return
	}
	if err := s.applyExternalDNS(client.InterfaceName(), dnsServers); err != nil {
		cleanup()
		if isDNSPermissionError(err) {
			writeStructuredError(w, http.StatusForbidden, "ERR_DNS_PERMISSION_DENIED", "Permisos insuficientes para configurar DNS en el sistema.")
			return
		}
		writeError(w, http.StatusInternalServerError, "OpenVPN DNS: "+err.Error())
		return
	}
	if err := s.guard.Enable(s.netguardScopeForInterface(client.InterfaceName(), endpoint, assignedIP)); err != nil {
		cleanup()
		writeError(w, http.StatusInternalServerError, "kill switch: "+err.Error())
		return
	}

	s.connectMu.Lock()
	superseded := s.connectSeq != sequence
	s.connectMu.Unlock()
	if superseded {
		cleanup()
		writeError(w, http.StatusConflict, "superseded by a newer connect request")
		return
	}
	s.setTransportRelay(client)
	serverPublicIP := server.Host
	if serverPublicIP == "" {
		serverPublicIP = server.Endpoint
	}
	connectionMS := time.Since(started).Milliseconds()
	s.agent.SetVPN(state.VPNStatus{
		Connected: true, Phase: state.VPNPhaseConnected, ConnectionID: connectionID, ServerName: server.Name, ServerID: server.ID,
		AssignedIP: assignedIP, ServerPublicIP: serverPublicIP,
		ServerEndpoint: endpoint, ActiveProtocol: "openvpn", RequestedProtocol: "openvpn", ConnectionMS: connectionMS,
	})
	s.startVPNStatsLoop()
	s.agent.SetProtection(state.ProtectionStatus{KillSwitchActive: true, DNSProtected: true, Mode: "openvpn"})
	writeJSON(w, map[string]any{
		"ok": true, "assigned_ip": assignedIP, "server": server.Name,
		"active_protocol": "openvpn", "connection_ms": connectionMS,
		"post_quantum": false, "pq_algorithm": "",
	})
}

func transportDNS(metadata map[string]interface{}) []string {
	value, exists := metadata["dns"]
	if !exists {
		return nil
	}
	values := []string{}
	switch typed := value.(type) {
	case string:
		values = strings.FieldsFunc(typed, func(r rune) bool { return r == ',' || r == ' ' })
	case []interface{}:
		for _, item := range typed {
			if text, ok := item.(string); ok {
				values = append(values, text)
			}
		}
	}
	return splitCSV(strings.Join(values, ","))
}
