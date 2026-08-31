//go:build linux

package ikev2

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/goastian/midorivpn-agent/internal/devicepki"
)

func TestBuildSwanctlConfigUsesEAPClientAuthAndXFRM(t *testing.T) {
	config := Config{
		Endpoint: "vpn.example.test:500", ServerName: "vpn.example.test",
		Credential: &devicepki.Credential{CertificateID: "12345678-1234-1234-1234-123456789abc", Identity: "urn:midorivpn:device:12345678-1234-1234-1234-123456789abc"},
	}
	generated := buildSwanctlConfig(config)
	for _, required := range []string{
		"auth = eap", `eap_id = "O=MidoriVPN, CN=device:12345678-1234-1234-1234-123456789abc"`,
		"remote_ts = 0.0.0.0/0", "if_id_in = 42", "if_id_out = 42",
		"aes256gcm16", "cacerts = client-ca.pem", "id = vpn.example.test",
	} {
		if !strings.Contains(generated, required) {
			t.Errorf("swanctl configuration omits %q", required)
		}
	}
	if strings.Contains(generated, "auth = eap-tls") {
		t.Fatal("client configuration selects the responder-side EAP-TLS auth keyword")
	}
	if strings.Contains(generated, "urn:midorivpn:device:") {
		t.Fatal("URI SAN identity was reused as an incompatible strongSwan KEY_ID")
	}
	for _, forbidden := range []string{"eap-mschapv2", "3des", "modp1024", "password"} {
		if strings.Contains(strings.ToLower(generated), forbidden) {
			t.Errorf("swanctl configuration contains forbidden value %q", forbidden)
		}
	}
}

func TestBuildStrongSwanConfigUsesRandomPortsAndPrivateVICI(t *testing.T) {
	generated := buildStrongSwanConfig("/run/user/1000/test/charon.vici")
	for _, required := range []string{
		"initiator_only = yes", "port = 0", "port_nat_t = 0",
		"install_routes_xfrmi = yes", "install_virtual_ip_on = midorivpn-ike",
		"unix:///run/user/1000/test/charon.vici", "charon-systemd {",
		"filelog {", "stderr {", "flush_line = yes",
	} {
		if !strings.Contains(generated, required) {
			t.Errorf("strongSwan configuration omits %q", required)
		}
	}
}

func TestRequireVersionUsesPrivateConfiguration(t *testing.T) {
	directory := t.TempDir()
	configPath := filepath.Join(directory, "strongswan.conf")
	if err := os.WriteFile(configPath, []byte("charon {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("EXPECTED_CONFIG", configPath)
	binary := filepath.Join(directory, "charon")
	script := "#!/bin/sh\n[ \"$STRONGSWAN_CONF\" = \"$EXPECTED_CONFIG\" ] || exit 2\n[ -r \"$STRONGSWAN_CONF\" ] || exit 3\necho 'strongSwan 6.0.7'\n"
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := requireVersion(context.Background(), binary, configPath); err != nil {
		t.Fatalf("requireVersion() error = %v", err)
	}
}

func TestValidateConfigRejectsIPCertificateName(t *testing.T) {
	credential := &devicepki.Credential{CertificateID: "12345678-1234-1234-1234-123456789abc", Identity: "urn:midorivpn:device:12345678-1234-1234-1234-123456789abc"}
	if err := validateConfig(Config{Endpoint: "vpn.example.test:500", ServerName: "192.0.2.1", Credential: credential}); err == nil {
		t.Fatal("IP server certificate identity was accepted")
	}
	if err := validateConfig(Config{Endpoint: "vpn.example.test:500", ServerName: "vpn.example.test", Credential: credential}); err != nil {
		t.Fatalf("valid IKEv2 configuration rejected: %v", err)
	}
}

func TestResolveEndpointIPv4sNormalizesLiteralAddress(t *testing.T) {
	addresses, err := resolveEndpointIPv4s(context.Background(), "192.0.2.40")
	if err != nil {
		t.Fatalf("resolveEndpointIPv4s() error = %v", err)
	}
	if len(addresses) != 1 || addresses[0] != "192.0.2.40" {
		t.Fatalf("resolveEndpointIPv4s() = %v", addresses)
	}
	if _, err := resolveEndpointIPv4s(context.Background(), "2001:db8::1"); err == nil {
		t.Fatal("IPv6 endpoint was accepted for the IPv4-only full tunnel")
	}
}

func TestResolveEndpointReturnsLiteralSocketAndAllRouteExclusions(t *testing.T) {
	endpoint, addresses, err := resolveEndpoint(context.Background(), "192.0.2.40:500")
	if err != nil {
		t.Fatalf("resolveEndpoint() error = %v", err)
	}
	if endpoint != "192.0.2.40:500" {
		t.Fatalf("resolveEndpoint() endpoint = %q", endpoint)
	}
	if len(addresses) != 1 || addresses[0] != "192.0.2.40" {
		t.Fatalf("resolveEndpoint() addresses = %v", addresses)
	}
}

func TestBoundedOutputRetainsLatestDiagnostics(t *testing.T) {
	output := newBoundedOutput(8)
	for _, value := range []string{"12345", "678", "90"} {
		written, err := output.Write([]byte(value))
		if err != nil || written != len(value) {
			t.Fatalf("Write(%q) = (%d, %v)", value, written, err)
		}
	}
	if got := output.String(); got != "34567890" {
		t.Fatalf("String() = %q, want latest bounded output", got)
	}
	if _, err := output.Write([]byte("abcdefghijk")); err != nil {
		t.Fatal(err)
	}
	if got := output.String(); got != "defghijk" {
		t.Fatalf("String() after oversized write = %q", got)
	}
}

func TestWithCharonDiagnosticPreservesCause(t *testing.T) {
	client := &Client{charonOutput: newBoundedOutput(64)}
	_, _ = client.charonOutput.Write([]byte("IKE_SA retransmit 3"))
	err := client.withCharonDiagnostic(context.DeadlineExceeded)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("diagnostic error no longer wraps deadline: %v", err)
	}
	if !strings.Contains(err.Error(), "IKE_SA retransmit 3") {
		t.Fatalf("diagnostic missing from error: %v", err)
	}
}
