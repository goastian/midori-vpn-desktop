//go:build linux

package openvpn

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/goastian/midorivpn-agent/internal/devicepki"
)

func TestFindOpenVPNExecutableIgnoresGraphicalSessionPath(t *testing.T) {
	temporary := t.TempDir()
	executable := filepath.Join(temporary, "openvpn")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", filepath.Join(temporary, "empty"))
	path, err := findExecutable([]string{filepath.Join(temporary, "missing"), executable}, "openvpn")
	if err != nil {
		t.Fatal(err)
	}
	if path != executable {
		t.Fatalf("OpenVPN path = %q, want %q", path, executable)
	}
}

func TestBuildArgsEnforcesModernDCOCompatibleProfile(t *testing.T) {
	credential := &devicepki.Credential{}
	config := Config{Endpoint: "vpn.example.test:1194", ServerName: "vpn.example.test", Credential: credential}
	if err := validateConfig(config); err != nil {
		t.Fatal(err)
	}
	files := &devicepki.RuntimeFiles{CAPath: "/run/ca", CertificatePath: "/run/cert", PrivateKeyPath: "/run/key"}
	args := buildArgs(config, files, "/run/management")
	joined := strings.Join(args, " ")
	for _, required := range []string{"--client", "--proto udp", "--topology subnet", "--allow-compression no", "--remote vpn.example.test 1194", "--remote-cert-tls server", "--verify-x509-name vpn.example.test name", "--tls-version-min 1.3", "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"} {
		if !strings.Contains(joined, required) {
			t.Errorf("OpenVPN arguments omit %q: %s", required, joined)
		}
	}
	for _, forbidden := range []string{"--disable-dco", "--persist-key", "--no-replay", "--data-ciphers-fallback"} {
		if slices.Contains(args, forbidden) {
			t.Errorf("OpenVPN arguments contain forbidden option %q", forbidden)
		}
	}
}

func TestValidateConfigRejectsIPCertificateNameAndBadEndpoint(t *testing.T) {
	credential := &devicepki.Credential{}
	for _, config := range []Config{
		{Endpoint: "missing-port", ServerName: "vpn.example.test", Credential: credential},
		{Endpoint: "vpn.example.test:1194", ServerName: "192.0.2.1", Credential: credential},
		{Endpoint: "vpn.example.test:1194", ServerName: "bad/name", Credential: credential},
	} {
		if err := validateConfig(config); err == nil {
			t.Fatalf("validateConfig(%+v) accepted unsafe configuration", config)
		}
	}
}
