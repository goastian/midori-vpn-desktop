package rpc

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Agent RPC token gate
// ---------------------------------------------------------------------------

func TestResolveAgentTokenRequiresTokenByDefault(t *testing.T) {
	t.Setenv("MIDORIVPN_AGENT_TOKEN", "")
	_, err := resolveAgentToken(false)
	if err == nil || !strings.Contains(err.Error(), "MIDORIVPN_AGENT_TOKEN") {
		t.Fatalf("expected missing token error, got %v", err)
	}
}

func TestResolveAgentTokenAllowsExplicitDevMode(t *testing.T) {
	t.Setenv("MIDORIVPN_AGENT_TOKEN", "")
	token, err := resolveAgentToken(true)
	if err != nil {
		t.Fatalf("expected dev mode to allow missing token: %v", err)
	}
	if token != "" {
		t.Fatalf("expected empty token in dev mode, got %q", token)
	}
}

func TestResolveAgentTokenReturnsConfiguredToken(t *testing.T) {
	t.Setenv("MIDORIVPN_AGENT_TOKEN", "secret")
	token, err := resolveAgentToken(false)
	if err != nil {
		t.Fatalf("expected configured token to pass: %v", err)
	}
	if token != "secret" {
		t.Fatalf("expected token, got %q", token)
	}
}

func TestConstantTimeTokenEqual(t *testing.T) {
	if !constantTimeTokenEqual("secret", "secret") {
		t.Fatal("expected equal tokens to match")
	}
	if constantTimeTokenEqual("secret", "wrong") {
		t.Fatal("expected different same-length tokens not to match")
	}
	if constantTimeTokenEqual("secret", "secret-with-extra-bytes") {
		t.Fatal("expected different length tokens not to match")
	}
}

// ---------------------------------------------------------------------------
// DNS validation
// ---------------------------------------------------------------------------

func TestIsReservedIP(t *testing.T) {
	reserved := []string{
		"127.0.0.1",
		"10.0.0.1",
		"10.255.255.255",
		"172.16.0.1",
		"172.31.255.255",
		"192.168.1.1",
		"169.254.0.1",
		"100.64.0.1", // CGNAT
		"100.127.255.255",
		"0.0.0.1",
		"::1",
		"fe80::1",
		"fc00::1",
		"fd00::1",
		"not-an-ip", // unparseable → reserved
		"",
	}
	for _, ip := range reserved {
		if !isReservedIP(ip) {
			t.Errorf("expected %q to be reserved, but isReservedIP returned false", ip)
		}
	}
}

func TestIsReservedIP_Public(t *testing.T) {
	public := []string{
		"1.1.1.1",
		"8.8.8.8",
		"9.9.9.9",
		"208.67.222.222",
		"2606:4700:4700::1111", // Cloudflare IPv6
	}
	for _, ip := range public {
		if isReservedIP(ip) {
			t.Errorf("expected %q to be public, but isReservedIP returned true", ip)
		}
	}
}

func TestSanitizeDNS_FiltersReserved(t *testing.T) {
	input := []string{"1.1.1.1", "192.168.1.1", "8.8.8.8", "10.0.0.1"}
	got := sanitizeDNS(input)
	for _, addr := range got {
		if isReservedIP(addr) {
			t.Errorf("sanitizeDNS kept reserved address %q", addr)
		}
	}
	if len(got) != 2 {
		t.Errorf("expected 2 safe entries, got %d: %v", len(got), got)
	}
}

func TestSanitizeDNS_FallbackWhenAllReserved(t *testing.T) {
	input := []string{"192.168.1.1", "10.0.0.1", "127.0.0.1"}
	got := sanitizeDNS(input)
	if len(got) == 0 {
		t.Fatal("sanitizeDNS returned empty slice; expected Cloudflare fallback")
	}
	for _, addr := range got {
		if isReservedIP(addr) {
			t.Errorf("fallback address %q is reserved", addr)
		}
	}
}

func TestSanitizeDNS_Empty(t *testing.T) {
	got := sanitizeDNS(nil)
	if len(got) == 0 {
		t.Fatal("sanitizeDNS(nil) returned empty; expected Cloudflare fallback")
	}
}

func TestSanitizeDNS_AlreadyClean(t *testing.T) {
	input := []string{"1.1.1.1", "1.0.0.1"}
	got := sanitizeDNS(input)
	if len(got) != 2 || got[0] != "1.1.1.1" || got[1] != "1.0.0.1" {
		t.Errorf("sanitizeDNS mutated clean list: %v", got)
	}
}

// ---------------------------------------------------------------------------
// UUID validation
// ---------------------------------------------------------------------------

func TestIsValidUUID(t *testing.T) {
	valid := []string{
		"550e8400-e29b-41d4-a716-446655440000",
		"00000000-0000-0000-0000-000000000000",
		"FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF",
	}
	for _, u := range valid {
		if !isValidUUID(u) {
			t.Errorf("expected %q to be a valid UUID", u)
		}
	}

	invalid := []string{
		"",
		"not-a-uuid",
		"550e8400-e29b-41d4-a716",              // too short
		"550e8400-e29b-41d4-a716-44665544000g", // invalid char
		"550e8400e29b41d4a716446655440000",     // missing hyphens
		"../../etc/passwd",
		"550e8400-e29b-41d4-a716-446655440000X", // too long
	}
	for _, u := range invalid {
		if isValidUUID(u) {
			t.Errorf("expected %q to be an invalid UUID", u)
		}
	}
}

// ---------------------------------------------------------------------------
// splitCSV
// ---------------------------------------------------------------------------

func TestSplitCSV(t *testing.T) {
	cases := []struct {
		raw  string
		want []string
	}{
		{"", nil},
		{"1.1.1.1", []string{"1.1.1.1"}},
		{"1.1.1.1,8.8.8.8", []string{"1.1.1.1", "8.8.8.8"}},
		{" 1.1.1.1 , 8.8.8.8 ", []string{"1.1.1.1", "8.8.8.8"}},
		{"1.1.1.1,,8.8.8.8", []string{"1.1.1.1", "8.8.8.8"}},
	}
	for _, c := range cases {
		got := splitCSV(c.raw)
		if len(got) != len(c.want) {
			t.Errorf("splitCSV(%q): got %v, want %v", c.raw, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("splitCSV(%q)[%d]: got %q, want %q", c.raw, i, got[i], c.want[i])
			}
		}
	}
}
