//go:build linux

package wg

import (
	"errors"
	"net"
	"testing"
)

func TestResolveEndpointHostname(t *testing.T) {
	resolved, ip, err := resolveEndpoint("de.vpn.astian.org:51820", func(host string) ([]net.IP, error) {
		if host != "de.vpn.astian.org" {
			t.Fatalf("lookup host mismatch: got %q", host)
		}
		return []net.IP{net.ParseIP("203.0.113.10")}, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved != "203.0.113.10:51820" {
		t.Fatalf("resolved endpoint mismatch: got %q", resolved)
	}
	if got := ip.String(); got != "203.0.113.10" {
		t.Fatalf("resolved ip mismatch: got %q", got)
	}
}

func TestResolveEndpointLiteralIPv4SkipsLookup(t *testing.T) {
	lookupCalled := false
	resolved, ip, err := resolveEndpoint("198.51.100.7:51820", func(string) ([]net.IP, error) {
		lookupCalled = true
		return nil, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if lookupCalled {
		t.Fatal("expected literal IPv4 endpoint to skip DNS lookup")
	}
	if resolved != "198.51.100.7:51820" {
		t.Fatalf("resolved endpoint mismatch: got %q", resolved)
	}
	if got := ip.String(); got != "198.51.100.7" {
		t.Fatalf("resolved ip mismatch: got %q", got)
	}
}

func TestResolveEndpointRejectsIPv6OnlyEndpoint(t *testing.T) {
	_, _, err := resolveEndpoint("[2001:db8::1]:51820", func(string) ([]net.IP, error) {
		return nil, nil
	})
	if err == nil {
		t.Fatal("expected IPv6-only endpoint to fail")
	}
	if err.Error() != "endpoint \"2001:db8::1\" has no IPv4 address" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveEndpointLookupError(t *testing.T) {
	wantErr := errors.New("dns failed")
	_, _, err := resolveEndpoint("de.vpn.astian.org:51820", func(string) ([]net.IP, error) {
		return nil, wantErr
	})
	if err == nil {
		t.Fatal("expected lookup error")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("expected wrapped lookup error, got %v", err)
	}
}

func TestIPCHasHandshake(t *testing.T) {
	state := "private_key=redacted\npublic_key=redacted\nlast_handshake_time_sec=1787443200\nlast_handshake_time_nsec=1\n"
	if !ipcHasHandshake(state) {
		t.Fatal("expected a positive handshake timestamp to be accepted")
	}
}

func TestIPCHasHandshakeRejectsMissingInvalidAndZeroTimestamps(t *testing.T) {
	for _, state := range []string{
		"public_key=redacted\n",
		"last_handshake_time_sec=0\n",
		"last_handshake_time_sec=invalid\n",
	} {
		if ipcHasHandshake(state) {
			t.Fatalf("unexpected handshake in state %q", state)
		}
	}
}
