//go:build linux

package ikev2

import (
	"strings"
	"testing"

	"github.com/goastian/midorivpn-agent/internal/devicepki"
)

func TestBuildSwanctlConfigUsesEAPTLSAndXFRM(t *testing.T) {
	config := Config{
		Endpoint: "vpn.example.test:500", ServerName: "vpn.example.test",
		Credential: &devicepki.Credential{Identity: "urn:midorivpn:device:12345678-1234-1234-1234-123456789abc"},
	}
	generated := buildSwanctlConfig(config)
	for _, required := range []string{
		"auth = eap-tls", "eap_id = urn:midorivpn:device:12345678-1234-1234-1234-123456789abc",
		"remote_ts = 0.0.0.0/0", "if_id_in = 42", "if_id_out = 42",
		"aes256gcm16", "cacerts = client-ca.pem", "id = vpn.example.test",
	} {
		if !strings.Contains(generated, required) {
			t.Errorf("swanctl configuration omits %q", required)
		}
	}
	for _, forbidden := range []string{"eap-mschapv2", "3des", "modp1024", "password"} {
		if strings.Contains(strings.ToLower(generated), forbidden) {
			t.Errorf("swanctl configuration contains forbidden value %q", forbidden)
		}
	}
}

func TestBuildStrongSwanConfigUsesRandomPortsAndPrivateVICI(t *testing.T) {
	generated := buildStrongSwanConfig("/run/user/1000/test/charon.vici", "/run/user/1000/test/swanctl")
	for _, required := range []string{
		"initiator_only = yes", "port = 0", "port_nat_t = 0",
		"install_routes_xfrmi = yes", "install_virtual_ip_on = midorivpn-ike",
		"unix:///run/user/1000/test/charon.vici",
	} {
		if !strings.Contains(generated, required) {
			t.Errorf("strongSwan configuration omits %q", required)
		}
	}
}

func TestValidateConfigRejectsIPCertificateName(t *testing.T) {
	credential := &devicepki.Credential{Identity: "urn:midorivpn:device:12345678-1234-1234-1234-123456789abc"}
	if err := validateConfig(Config{Endpoint: "vpn.example.test:500", ServerName: "192.0.2.1", Credential: credential}); err == nil {
		t.Fatal("IP server certificate identity was accepted")
	}
	if err := validateConfig(Config{Endpoint: "vpn.example.test:500", ServerName: "vpn.example.test", Credential: credential}); err != nil {
		t.Fatalf("valid IKEv2 configuration rejected: %v", err)
	}
}
