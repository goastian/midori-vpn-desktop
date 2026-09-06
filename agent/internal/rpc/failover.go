package rpc

import (
	"context"
	"errors"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/goastian/midorivpn-agent/internal/apiClient"
	"github.com/goastian/midorivpn-agent/internal/failover"
	"github.com/goastian/midorivpn-agent/internal/httpx"
	"github.com/goastian/midorivpn-agent/internal/settings"
	"github.com/goastian/midorivpn-agent/internal/state"
)

const failoverHealthInterval = 10 * time.Second

type automaticSelection struct {
	Current    apiClient.ServerCandidate
	Candidates []apiClient.ServerCandidate
	Catalog    []apiClient.Server
}

func placementProtocol(requested string) string {
	if requested == "smart_auto" {
		return "wireguard"
	}
	return requested
}

func (s *Server) resolveVPNServer(ctx context.Context, request vpnConnectRequest) (*apiClient.Server, *automaticSelection, error) {
	servers, err := s.apiClient.ListServers(ctx)
	if err != nil {
		return nil, nil, err
	}
	if request.SelectionMode == settings.SelectionModeManual {
		s.setRecoveryEndpoints(nil)
		for index := range servers {
			if servers[index].ID == request.ServerID {
				return &servers[index], nil, nil
			}
		}
		return nil, nil, errors.New("manually selected server is unavailable")
	}

	protocol := placementProtocol(request.Protocol)
	candidates, err := s.apiClient.ListServerCandidates(ctx, protocol)
	if err != nil {
		return nil, nil, err
	}
	measurable := make([]failover.Candidate, 0, len(candidates))
	for _, candidate := range candidates {
		if candidate.Protocol != protocol || !isValidUUID(candidate.ID) ||
			strings.TrimSpace(candidate.Endpoint) == "" || candidate.Port < 1 || candidate.Port > 65535 {
			continue
		}
		measurable = append(measurable, failover.Candidate{
			ID: candidate.ID, ProbeURL: candidate.ProbeURL, Priority: candidate.Priority,
		})
	}
	selected, err := s.edgeProber.Select(ctx, measurable)
	if err != nil {
		return nil, nil, err
	}
	var selectedCandidate apiClient.ServerCandidate
	for _, candidate := range candidates {
		if candidate.ID == selected.Candidate.ID {
			selectedCandidate = candidate
			break
		}
	}
	for index := range servers {
		if servers[index].ID == selectedCandidate.ID {
			selection := &automaticSelection{
				Current: selectedCandidate, Candidates: cloneServerCandidates(candidates), Catalog: cloneServers(servers),
			}
			s.setRecoveryEndpoints(buildRecoveryEndpoints(selection.Candidates, selection.Catalog))
			return &servers[index], selection, nil
		}
	}
	return nil, nil, errors.New("selected server is absent from the server catalog")
}

func cloneServerCandidates(values []apiClient.ServerCandidate) []apiClient.ServerCandidate {
	return append([]apiClient.ServerCandidate(nil), values...)
}

func buildRecoveryEndpoints(candidates []apiClient.ServerCandidate, servers []apiClient.Server) []string {
	eligible := make(map[string]struct{}, len(candidates))
	values := make([]string, 0, len(candidates)*3)
	for _, candidate := range candidates {
		eligible[candidate.ID] = struct{}{}
		if parsed, err := url.Parse(candidate.ProbeURL); err == nil && parsed.Host != "" {
			values = append(values, parsed.Host)
		}
		values = append(values, endpointWithPort(candidate.Endpoint, candidate.Port))
	}
	for _, server := range servers {
		if _, ok := eligible[server.ID]; !ok {
			continue
		}
		for _, transport := range server.Transports {
			if transport.Enabled && transport.HealthStatus == "healthy" &&
				transport.Host != "" && transport.Port > 0 && transport.Port <= 65535 {
				values = append(values, net.JoinHostPort(transport.Host, strconv.Itoa(transport.Port)))
			}
		}
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func endpointWithPort(host string, port int) string {
	host = strings.TrimSpace(host)
	if parsedHost, parsedPort, err := net.SplitHostPort(host); err == nil {
		if parsedPort == strconv.Itoa(port) {
			return net.JoinHostPort(parsedHost, parsedPort)
		}
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func (s *Server) setRecoveryEndpoints(endpoints []string) {
	s.recoveryMu.Lock()
	s.recoveryEndpoints = append([]string(nil), endpoints...)
	s.recoveryMu.Unlock()
}

func (s *Server) currentRecoveryEndpoints() []string {
	s.recoveryMu.Lock()
	defer s.recoveryMu.Unlock()
	return append([]string(nil), s.recoveryEndpoints...)
}

func (s *Server) startFailoverMonitor(protocol string, selection automaticSelection) {
	s.failoverMu.Lock()
	if s.failoverCancel != nil {
		s.failoverCancel()
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.failoverCancel = cancel
	s.failoverMu.Unlock()
	go s.monitorFailover(ctx, protocol, selection)
}

func (s *Server) stopFailoverMonitor() {
	s.failoverMu.Lock()
	if s.failoverCancel != nil {
		s.failoverCancel()
		s.failoverCancel = nil
	}
	s.failoverMu.Unlock()
}

func (s *Server) monitorFailover(ctx context.Context, protocol string, selection automaticSelection) {
	ticker := time.NewTicker(failoverHealthInterval)
	defer ticker.Stop()
	var failures failover.FailureTracker
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_, healthy := s.edgeProber.Probe(ctx, failover.Candidate{
				ID: selection.Current.ID, ProbeURL: selection.Current.ProbeURL,
			})
			if !failures.Observe(healthy) {
				continue
			}
			slog.Warn("vpn edge failed three consecutive health probes; starting automatic failover",
				"server_id", selection.Current.ID, "protocol", protocol)
			s.runAutomaticFailover(ctx, protocol, selection.Current.ID)
			return
		}
	}
}

type backgroundVPNConnectResponder struct {
	failure *vpnConnectFailure
	success bool
}

func (responder *backgroundVPNConnectResponder) Fail(failure *vpnConnectFailure) {
	responder.failure = failure
}

func (responder *backgroundVPNConnectResponder) Succeed(vpnConnectResult) {
	responder.success = true
}

func (s *Server) runAutomaticFailover(ctx context.Context, protocol, failedServerID string) {
	snapshot := s.agent.Snapshot()
	current, ok := snapshot["vpn"].(state.VPNStatus)
	if !ok || !current.Connected || current.SelectionMode != string(settings.SelectionModeAutomatic) {
		return
	}
	recoveryID := current.ConnectionID
	oldPeerID := current.PeerID
	if oldPeerID != "" {
		if err := s.queueConnectionCleanup(oldPeerID); err != nil {
			slog.Error("automatic failover refused to lose previous peer cleanup", "error", err)
			return
		}
	}
	current.Phase = state.VPNPhaseReconnecting
	current.FailoverFrom = failedServerID
	s.agent.SetVPN(current)

	s.stopVPNStatsLoop()
	s.closeTransportRelay()
	s.restoreExternalDNS()
	s.wgMgr.Disconnect()
	s.agent.SetVPN(state.VPNStatus{
		Phase: state.VPNPhaseReconnecting, ConnectionID: recoveryID,
		ServerID: failedServerID, RequestedProtocol: protocol,
		SelectionMode: string(settings.SelectionModeAutomatic), FailoverFrom: failedServerID,
	})
	s.agent.SetProtection(state.ProtectionStatus{
		KillSwitchActive: s.guard.Active(), DNSProtected: false, Mode: protocol,
	})
	for attempt := 0; ; attempt++ {
		if ctx.Err() != nil || !s.authMgr.LoggedIn() {
			return
		}
		responder := &backgroundVPNConnectResponder{}
		attemptCtx, cancel := context.WithTimeout(ctx, 50*time.Second)
		s.runVPNConnect(attemptCtx, vpnConnectRequest{
			Protocol: protocol, SelectionMode: settings.SelectionModeAutomatic,
		}, apiClient.ConnectionReasonAutomaticFailover, responder, false)
		cancel()
		if responder.success {
			slog.Info("automatic VPN failover completed", "from_server_id", failedServerID, "attempt", attempt+1)
			return
		}
		if ctx.Err() != nil {
			return
		}
		s.agent.SetVPN(state.VPNStatus{
			Phase: state.VPNPhaseReconnecting, ConnectionID: recoveryID,
			ServerID: failedServerID, RequestedProtocol: protocol,
			SelectionMode: string(settings.SelectionModeAutomatic), FailoverFrom: failedServerID,
		})
		delay := failover.RetryDelay(attempt, rand.Float64())
		status := 0
		code := ""
		if responder.failure != nil {
			status = responder.failure.Status
			code = responder.failure.Code
		}
		slog.Warn("automatic VPN failover attempt failed", "attempt", attempt+1,
			"status", status, "code", code, "retry_in", delay)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func newEdgeProbeClient() *http.Client {
	return httpx.NewClient(failover.DefaultProbeTimeout)
}
