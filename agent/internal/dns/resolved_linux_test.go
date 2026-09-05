//go:build linux

package dns

import "testing"

func TestResolvedBackendRejectsInvalidConfigurationBeforeMutation(t *testing.T) {
	backend := newResolvedBackend()
	if err := backend.Apply("", []string{"1.1.1.1"}); err == nil {
		t.Fatal("expected empty interface to fail")
	}
	if err := backend.Apply("wg0", []string{"not-an-ip"}); err == nil {
		t.Fatal("expected invalid DNS server to fail")
	}
	if backend.applied {
		t.Fatal("invalid configuration must not mark DNS as applied")
	}
}

func TestResolvedBackendIgnoresEmptyServerListAndRestoresIdempotently(t *testing.T) {
	backend := newResolvedBackend()
	if err := backend.Apply("wg0", []string{" ", "\t"}); err != nil {
		t.Fatalf("empty server list: %v", err)
	}
	if backend.applied {
		t.Fatal("empty server list must not mark DNS as applied")
	}
	if err := backend.Restore(); err != nil {
		t.Fatalf("restore without apply: %v", err)
	}
}
