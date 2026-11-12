//go:build linux

package dns

import "testing"

func TestResolvconfRefusesPrivilegedFileMutation(t *testing.T) {
	// Invalid DNS is enough to exercise the legacy backend without writing
	// the runner's resolver. A safe backend must explain the unsupported mode,
	// not try to acquire broader filesystem capabilities.
	err := newResolvconfBackend().Apply("wg0", []string{"not-an-ip"})
	if err == nil || err.Error() != "DNS protection requires systemd-resolved managing /etc/resolv.conf; direct resolver writes are disabled" {
		t.Fatalf("unsafe fallback not disabled: %v", err)
	}
}
