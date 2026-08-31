package rpc

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/goastian/midorivpn-agent/internal/apiClient"
	"github.com/goastian/midorivpn-agent/internal/ikev2"
	"github.com/goastian/midorivpn-agent/internal/state"
)

func (s *Server) handleIKEv2Connect(w http.ResponseWriter, ctx context.Context, server *apiClient.Server, candidate vpnTransportCandidate, sequence uint64, connectionID string) {
	serverName, ok := metadataString(candidate.metadata, "server_name")
	if !ok {
		writeStructuredError(w, http.StatusBadGateway, "ERR_TRANSPORT_CONFIGURATION_INVALID", "IKEv2 no tiene un nombre de certificado de gateway configurado.")
		return
	}
	dnsServers := sanitizeDNS(transportDNS(candidate.metadata))
	if len(dnsServers) == 0 {
		writeStructuredError(w, http.StatusBadGateway, "ERR_DNS_CONFIGURATION_MISSING", "El gateway IKEv2 no entregó una configuración DNS válida.")
		return
	}
	credential, err := s.ensureDeviceCredential(ctx, server.ID)
	if err != nil {
		writeStructuredError(w, http.StatusBadGateway, "ERR_DEVICE_CERTIFICATE_FAILED", "No se pudo preparar el certificado privado del dispositivo: "+err.Error())
		return
	}
	endpoint := net.JoinHostPort(candidate.host, strconv.Itoa(candidate.port))
	started := time.Now()
	client, err := ikev2.Start(ctx, ikev2.Config{
		Endpoint: endpoint, ServerName: serverName, Credential: credential, Timeout: candidate.timeout,
	})
	if err != nil {
		writeStructuredError(w, http.StatusBadGateway, "ERR_VPN_HANDSHAKE_FAILED", "No se pudo completar el handshake IKEv2/EAP-TLS: "+err.Error())
		return
	}
	cleanup := func() {
		_ = s.guard.Disable()
		s.restoreExternalDNS()
		client.Close()
	}
	assignedIP := client.AssignedIP()
	if assignedIP == "" {
		cleanup()
		writeStructuredError(w, http.StatusBadGateway, "ERR_TRANSPORT_CONFIGURATION_INVALID", "IKEv2 no entregó una dirección virtual válida.")
		return
	}
	if err := s.applyExternalDNS(client.InterfaceName(), dnsServers); err != nil {
		cleanup()
		if isDNSPermissionError(err) {
			writeStructuredError(w, http.StatusForbidden, "ERR_DNS_PERMISSION_DENIED", "Permisos insuficientes para configurar DNS en el sistema.")
			return
		}
		writeError(w, http.StatusInternalServerError, "IKEv2 DNS: "+err.Error())
		return
	}
	if err := s.guard.Enable(s.netguardScopeForInterface(client.InterfaceName(), client.Endpoint(), assignedIP)); err != nil {
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
		Connected: true, ConnectionID: connectionID, ServerName: server.Name, ServerID: server.ID,
		AssignedIP: assignedIP, ServerPublicIP: serverPublicIP,
		ServerEndpoint: client.Endpoint(), ActiveProtocol: "ikev2", ConnectionMS: connectionMS,
	})
	s.startVPNStatsLoop()
	s.agent.SetProtection(state.ProtectionStatus{KillSwitchActive: true, DNSProtected: true, Mode: "ikev2"})
	writeJSON(w, map[string]any{
		"ok": true, "assigned_ip": assignedIP, "server": server.Name,
		"active_protocol": "ikev2", "connection_ms": connectionMS,
		"post_quantum": false, "pq_algorithm": "",
	})
}
