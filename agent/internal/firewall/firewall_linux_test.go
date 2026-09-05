//go:build linux

package firewall

import (
	"reflect"
	"testing"
)

func TestNormalizeScopeDefaultsAndFiltersMeshIPs(t *testing.T) {
	scope := normalizeScope(Scope{
		MeshDestinationIP: " 10.20.0.8/32 ",
		MeshPeerIPs:       []string{" 10.20.0.2 ", "invalid", "10.20.0.2", "2001:db8::2"},
	})

	if scope.Name != "default" || scope.Interface != "wg0" || scope.RPCPort != 7071 {
		t.Fatalf("unexpected defaults: %+v", scope)
	}
	if scope.MeshDestinationIP != "10.20.0.8/32" {
		t.Fatalf("destination = %q", scope.MeshDestinationIP)
	}
	if want := []string{"10.20.0.2", "2001:db8::2"}; !reflect.DeepEqual(scope.MeshPeerIPs, want) {
		t.Fatalf("mesh peers = %v, want %v", scope.MeshPeerIPs, want)
	}
}

func TestNormalizeScopeDropsPeersWithoutValidDestination(t *testing.T) {
	scope := normalizeScope(Scope{MeshDestinationIP: "not-an-ip", MeshPeerIPs: []string{"10.20.0.2"}})
	if scope.MeshDestinationIP != "" || scope.MeshPeerIPs != nil {
		t.Fatalf("invalid destination was retained: %+v", scope)
	}
}

func TestFirewalldRichRulesKeepsAddressFamiliesSeparate(t *testing.T) {
	rules := firewalldRichRules(Scope{
		RPCPort:           7071,
		MeshDestinationIP: "2001:db8::10/128",
		MeshPeerIPs:       []string{"10.20.0.2", "2001:db8::2"},
		MeshProxyPort:     8443,
	})

	want := []string{
		"rule family=ipv4 source address=127.0.0.1 destination address=127.0.0.1 port port=7071 protocol=tcp accept",
		"rule family=ipv6 source address=2001:db8::2 destination address=2001:db8::10/128 port port=8443 protocol=tcp accept",
	}
	if !reflect.DeepEqual(rules, want) {
		t.Fatalf("rules = %#v, want %#v", rules, want)
	}
}

func TestScopeIdentifiersAreStableAndSanitized(t *testing.T) {
	if got := scopeTag(" Office / LAN "); got != "midorivpn-managed-office_lan" {
		t.Fatalf("scope tag = %q", got)
	}
	if got := nftTableName("***"); got != "midorivpn_fw_default" {
		t.Fatalf("table name = %q", got)
	}
	if nftFamily("192.0.2.1/32") != "ip" || nftFamily("2001:db8::1/128") != "ip6" {
		t.Fatal("unexpected nft address family")
	}
}

func BenchmarkSanitizeName(b *testing.B) {
	for b.Loop() {
		_ = sanitizeName(" Office / LAN (Primary) ")
	}
}
