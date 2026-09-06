package rpc

import (
	"testing"
	"time"

	"github.com/goastian/midorivpn-agent/internal/apiClient"
)

func TestFindTransportRequiresEnabledHealthyCapability(t *testing.T) {
	transports := []apiClient.TransportCapability{
		{Protocol: "wss", Host: "unknown.example.test", Port: 443, Enabled: true, HealthStatus: "unknown"},
		{Protocol: "wss", Host: "disabled.example.test", Port: 443, Enabled: false, HealthStatus: "healthy"},
	}
	if _, ok := findTransport(transports, "wss"); ok {
		t.Fatal("unverified or disabled transport must not be selected")
	}

	transports = append(transports, apiClient.TransportCapability{
		Protocol: "wss", Host: "healthy.example.test", Port: 443, Enabled: true, HealthStatus: "healthy",
	})
	transport, ok := findTransport(transports, "wss")
	if !ok || transport.Host != "healthy.example.test" {
		t.Fatalf("healthy transport not selected: %#v, %t", transport, ok)
	}
}

func TestSelectTransportCandidatesSmartUsesOnlyHealthyOrder(t *testing.T) {
	transports := []apiClient.TransportCapability{
		{Protocol: "wss", Host: "vpn.example.test", Port: 443, Enabled: true, HealthStatus: "healthy"},
		{Protocol: "wireguard", Host: "vpn.example.test", Port: 51820, Enabled: true, HealthStatus: "healthy"},
		{Protocol: "openvpn", Host: "vpn.example.test", Port: 1194, Enabled: true, HealthStatus: "healthy"},
	}
	candidates := selectTransportCandidates(transports, "smart_auto")
	if len(candidates) != 2 {
		t.Fatalf("candidate count = %d, want 2", len(candidates))
	}
	if candidates[0].protocol != "wireguard" || candidates[0].timeout != smartWireGuardHandshakeTimeout {
		t.Fatalf("first candidate = %#v, want direct WireGuard", candidates[0])
	}
	if candidates[1].protocol != "wss" || candidates[1].timeout != 5*time.Second {
		t.Fatalf("second candidate = %#v, want WSS", candidates[1])
	}
}

func TestSelectTransportCandidatesExplicitWireGuardAllowsHandshakeRetries(t *testing.T) {
	candidates := selectTransportCandidates([]apiClient.TransportCapability{{
		Protocol: "wireguard", Host: "vpn.example.test", Port: 51820, Enabled: true, HealthStatus: "healthy",
	}}, "wireguard")
	if len(candidates) != 1 || candidates[0].timeout != 15*time.Second {
		t.Fatalf("WireGuard candidates = %#v", candidates)
	}
	if candidates[0].timeout <= smartWireGuardHandshakeTimeout {
		t.Fatalf("explicit WireGuard timeout = %s, must exceed Smart fallback budget", candidates[0].timeout)
	}
}

func TestSelectTransportCandidatesRejectsDegradedAndInvalidEndpoints(t *testing.T) {
	transports := []apiClient.TransportCapability{
		{Protocol: "wireguard", Host: "vpn.example.test", Port: 51820, Enabled: true, HealthStatus: "degraded"},
		{Protocol: "wss", Host: "", Port: 443, Enabled: true, HealthStatus: "healthy"},
	}
	if candidates := selectTransportCandidates(transports, "smart_auto"); len(candidates) != 0 {
		t.Fatalf("unexpected candidates: %#v", candidates)
	}
}

func TestTransportDNSAcceptsStringAndArray(t *testing.T) {
	for _, metadata := range []map[string]interface{}{
		{"dns": "10.8.0.1, 10.8.0.2"},
		{"dns": []interface{}{"10.8.0.1", "10.8.0.2"}},
	} {
		got := transportDNS(metadata)
		if len(got) != 2 || got[0] != "10.8.0.1" || got[1] != "10.8.0.2" {
			t.Fatalf("transportDNS(%#v) = %#v", metadata, got)
		}
	}
}

func TestOpenVPNCandidateUsesHandshakeTimeout(t *testing.T) {
	candidates := selectTransportCandidates([]apiClient.TransportCapability{{
		Protocol: "openvpn", Host: "vpn.example.test", Port: 1194, Enabled: true, HealthStatus: "healthy",
	}}, "openvpn")
	if len(candidates) != 1 || candidates[0].timeout != 30*time.Second {
		t.Fatalf("OpenVPN candidates = %#v", candidates)
	}
}

func TestIKEv2CandidateUsesHandshakeTimeout(t *testing.T) {
	candidates := selectTransportCandidates([]apiClient.TransportCapability{{
		Protocol: "ikev2", Host: "vpn.example.test", Port: 500, Enabled: true, HealthStatus: "healthy",
	}}, "ikev2")
	if len(candidates) != 1 || candidates[0].timeout != 30*time.Second {
		t.Fatalf("IKEv2 candidates = %#v", candidates)
	}
}
