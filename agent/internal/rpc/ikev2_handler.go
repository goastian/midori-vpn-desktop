package rpc

import (
	"context"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/goastian/midorivpn-agent/internal/apiClient"
	"github.com/goastian/midorivpn-agent/internal/ikev2"
	"github.com/goastian/midorivpn-agent/internal/settings"
	"github.com/goastian/midorivpn-agent/internal/state"
)

func (s *Server) runIKEv2Connect(ctx context.Context, server *apiClient.Server, candidate vpnTransportCandidate, sequence uint64, connectionID string, selectionMode settings.SelectionMode, selection *automaticSelection, responder vpnConnectResponder) {
	guardWasActive := s.guard.Active()
	s.agent.UpdateVPNConnection(connectionID, state.VPNPhaseAuthenticating, "", "")
	serverName, ok := metadataString(candidate.metadata, "server_name")
	if !ok {
		responder.Fail(connectFailure(http.StatusBadGateway, "ERR_TRANSPORT_CONFIGURATION_INVALID", "IKEv2 no tiene un nombre de certificado de gateway configurado."))
		return
	}
	dnsServers := sanitizeDNS(transportDNS(candidate.metadata))
	if len(dnsServers) == 0 {
		responder.Fail(connectFailure(http.StatusBadGateway, "ERR_DNS_CONFIGURATION_MISSING", "El gateway IKEv2 no entregó una configuración DNS válida."))
		return
	}
	credential, err := s.ensureDeviceCredential(ctx, server.ID)
	if err != nil {
		responder.Fail(connectFailure(http.StatusBadGateway, "ERR_DEVICE_CERTIFICATE_FAILED", "No se pudo preparar el certificado privado del dispositivo: "+err.Error()))
		return
	}
	endpoint := net.JoinHostPort(candidate.host, strconv.Itoa(candidate.port))
	started := time.Now()
	s.agent.UpdateVPNConnection(connectionID, state.VPNPhaseNegotiating, "", "")
	client, err := ikev2.Start(ctx, ikev2.Config{
		Endpoint: endpoint, ServerName: serverName, Credential: credential, Timeout: candidate.timeout,
	})
	if err != nil {
		responder.Fail(connectFailure(http.StatusBadGateway, "ERR_VPN_HANDSHAKE_FAILED", "No se pudo completar el handshake IKEv2/EAP-TLS: "+err.Error()))
		return
	}
	cleanup := func() {
		if !guardWasActive {
			_ = s.guard.Disable()
		}
		s.restoreExternalDNS()
		client.Close()
	}
	s.agent.UpdateVPNConnection(connectionID, state.VPNPhaseProtecting, "ikev2", "")
	assignedIP := client.AssignedIP()
	if assignedIP == "" {
		cleanup()
		responder.Fail(connectFailure(http.StatusBadGateway, "ERR_TRANSPORT_CONFIGURATION_INVALID", "IKEv2 no entregó una dirección virtual válida."))
		return
	}
	if err := s.applyExternalDNS(client.InterfaceName(), dnsServers); err != nil {
		cleanup()
		if isDNSPermissionError(err) {
			responder.Fail(connectFailure(http.StatusForbidden, "ERR_DNS_PERMISSION_DENIED", "Permisos insuficientes para configurar DNS en el sistema."))
			return
		}
		responder.Fail(connectFailure(http.StatusInternalServerError, "", "IKEv2 DNS: "+err.Error()))
		return
	}
	if err := s.guard.Enable(s.netguardScopeForInterface(client.InterfaceName(), client.Endpoint(), assignedIP)); err != nil {
		cleanup()
		responder.Fail(connectFailure(http.StatusInternalServerError, "", "kill switch: "+err.Error()))
		return
	}

	s.connectMu.Lock()
	superseded := s.connectSeq != sequence
	s.connectMu.Unlock()
	if superseded {
		cleanup()
		responder.Fail(connectFailure(http.StatusConflict, "", "superseded by a newer connect request"))
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
		ServerEndpoint: client.Endpoint(), ActiveProtocol: "ikev2", RequestedProtocol: "ikev2",
		SelectionMode: string(selectionMode), ConnectionMS: connectionMS,
	})
	s.startVPNStatsLoop()
	s.agent.SetProtection(state.ProtectionStatus{KillSwitchActive: true, DNSProtected: true, Mode: "ikev2"})
	if selectionMode == settings.SelectionModeAutomatic && selection != nil {
		s.startFailoverMonitor("ikev2", *selection)
	}
	responder.Succeed(vpnConnectResult{
		AssignedIP: assignedIP, Server: server.Name, ActiveProtocol: "ikev2",
		ConnectionMS: connectionMS,
	})
}
