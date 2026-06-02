package logredact

import (
	"strings"
	"testing"
)

func TestIPMasksHostPortion(t *testing.T) {
	if Verbose() {
		t.Skip("verbose mode enabled via env; skipping masking test")
	}
	if got := IP("10.20.30.40"); got != "10.x.x.x" {
		t.Fatalf("IP(10.20.30.40) = %q, want 10.x.x.x", got)
	}
	if got := IP("2001:db8::1"); !strings.HasSuffix(got, ":x:x:x:x:x:x:x") {
		t.Fatalf("IP(IPv6) = %q, want IPv6 masked form", got)
	}
	if got := IP("not-an-ip"); !strings.HasPrefix(got, "len=") {
		t.Fatalf("IP(non-IP) = %q, want generic fingerprint", got)
	}
	if got := IP(""); got != "" {
		t.Fatalf("IP(empty) = %q, want empty", got)
	}
}

func TestIPsAppliesElementwise(t *testing.T) {
	if Verbose() {
		t.Skip("verbose mode enabled via env; skipping masking test")
	}
	in := []string{"1.2.3.4", "5.6.7.8"}
	out := IPs(in)
	if len(out) != 2 || out[0] != "1.x.x.x" || out[1] != "5.x.x.x" {
		t.Fatalf("IPs = %v", out)
	}
}

func TestUserMasksLocalPart(t *testing.T) {
	if Verbose() {
		t.Skip("verbose mode enabled via env; skipping masking test")
	}
	if got := User("alice@example.com"); got != "a***@example.com" {
		t.Fatalf("User(email) = %q, want a***@example.com", got)
	}
	if got := User("plainuser"); !strings.HasPrefix(got, "p***#") {
		t.Fatalf("User(plain) = %q, want masked form", got)
	}
	if got := User(""); got != "" {
		t.Fatalf("User(empty) = %q", got)
	}
}

func TestHostPortKeepsPort(t *testing.T) {
	if Verbose() {
		t.Skip("verbose mode enabled via env; skipping masking test")
	}
	got := HostPort("api.example.com:443")
	if !strings.HasSuffix(got, ":443") {
		t.Fatalf("HostPort lost port: %q", got)
	}
	if !strings.Contains(got, ".com") {
		t.Fatalf("HostPort lost suffix: %q", got)
	}
}

func TestBodySummary(t *testing.T) {
	if Verbose() {
		t.Skip("verbose mode enabled via env; skipping masking test")
	}
	got := Body([]byte("hello world"))
	if !strings.HasPrefix(got, "11B sha256:") {
		t.Fatalf("Body summary = %q", got)
	}
}
