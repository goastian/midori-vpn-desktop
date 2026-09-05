package rpc

import (
	"reflect"
	"testing"

	"github.com/goastian/midorivpn-agent/internal/apiClient"
)

func TestBuildRecoveryEndpointsCoversEligibleTransports(t *testing.T) {
	candidates := []apiClient.ServerCandidate{
		{ID: "one", ProbeURL: "https://edge-one.example/.well-known/midorivpn/edge-health", Endpoint: "edge-one.example:51820", Port: 51820},
		{ID: "two", ProbeURL: "https://edge-two.example:8443/.well-known/midorivpn/edge-health", Endpoint: "edge-two.example", Port: 51820},
	}
	servers := []apiClient.Server{{
		ID: "two",
		Transports: []apiClient.TransportCapability{
			{Host: "edge-two.example", Port: 443, Enabled: true, HealthStatus: "healthy"},
			{Host: "disabled.example", Port: 443, Enabled: false, HealthStatus: "healthy"},
		},
	}}
	want := []string{
		"edge-one.example", "edge-one.example:51820",
		"edge-two.example:8443", "edge-two.example:51820", "edge-two.example:443",
	}
	if got := buildRecoveryEndpoints(candidates, servers); !reflect.DeepEqual(got, want) {
		t.Fatalf("buildRecoveryEndpoints() = %#v, want %#v", got, want)
	}
}

func TestPlacementProtocolUsesWireGuardForSmartAuto(t *testing.T) {
	if got := placementProtocol("smart_auto"); got != "wireguard" {
		t.Fatalf("placementProtocol(smart_auto) = %q", got)
	}
	if got := placementProtocol("openvpn"); got != "openvpn" {
		t.Fatalf("placementProtocol(openvpn) = %q", got)
	}
}
