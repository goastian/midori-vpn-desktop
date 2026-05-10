package proxy

import (
	"net"
	"testing"
)

func TestMeshSourceCIDRs(t *testing.T) {
	cases := []struct {
		meshIP string
		want   string
	}{
		{"100.64.10.20", "100.64.0.0/10"},
		{"10.20.30.40", "10.0.0.0/8"},
		{"172.16.5.10", "172.16.0.0/12"},
		{"192.168.12.3", "192.168.0.0/16"},
		{"fd7a:115c:a1e0::1", "fd00::/8"},
		{"203.0.113.10", "203.0.113.10/32"},
	}
	for _, tc := range cases {
		got := MeshSourceCIDRs(tc.meshIP)
		if len(got) != 1 || got[0] != tc.want {
			t.Fatalf("MeshSourceCIDRs(%q) = %v, want [%q]", tc.meshIP, got, tc.want)
		}
	}
}

func TestSOCKS5SourceFilter(t *testing.T) {
	s := NewSOCKS5(
		"100.64.10.20:1080",
		WithAllowedSourceCIDRs([]string{"100.64.0.0/10", "fd00::/8"}),
	)

	if !s.allowIP(net.ParseIP("100.64.1.2")) {
		t.Fatal("expected mesh IPv4 source to pass")
	}
	if !s.allowIP(net.ParseIP("fd7a:115c:a1e0::2")) {
		t.Fatal("expected mesh IPv6 source to pass")
	}
	if s.allowIP(net.ParseIP("192.0.2.10")) {
		t.Fatal("expected non-mesh source to be rejected")
	}
	if s.allowIP(nil) {
		t.Fatal("expected nil source to be rejected")
	}
}

func TestSourceCIDRsForIPsUsesExactHosts(t *testing.T) {
	got := SourceCIDRsForIPs([]string{"100.64.1.2", "fd7a:115c:a1e0::2", "bogus"})
	want := []string{"100.64.1.2/32", "fd7a:115c:a1e0::2/128"}
	if len(got) != len(want) {
		t.Fatalf("SourceCIDRsForIPs length = %d, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("SourceCIDRsForIPs[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestSOCKS5UDPListenAddrUsesBoundMeshIP(t *testing.T) {
	s := NewSOCKS5("[fd7a:115c:a1e0::1]:1080")
	got := s.udpListenAddr()
	if got.IP.String() != "fd7a:115c:a1e0::1" || got.Port != 0 {
		t.Fatalf("unexpected UDP listen addr: %v", got)
	}
}
