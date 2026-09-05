//go:build linux

package mesh

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/sys/unix"
)

func TestFindBinReturnsFirstExistingCandidate(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "missing")
	second := filepath.Join(dir, "nft")
	if err := os.WriteFile(second, []byte("test"), 0o700); err != nil {
		t.Fatal(err)
	}

	if got := findBin(first, second); got != second {
		t.Fatalf("findBin = %q, want %q", got, second)
	}
	if got := findBin(first); got != "" {
		t.Fatalf("missing findBin = %q", got)
	}
}

func TestNetAdminCommandPreservesArgumentsAndCapability(t *testing.T) {
	command := netAdminCommand("/bin/true", "add", "table", "ip", "midorivpn")
	if want := []string{"/bin/true", "add", "table", "ip", "midorivpn"}; !reflect.DeepEqual(command.Args, want) {
		t.Fatalf("command args = %v, want %v", command.Args, want)
	}
	if command.SysProcAttr == nil || !reflect.DeepEqual(command.SysProcAttr.AmbientCaps, []uintptr{unix.CAP_NET_ADMIN}) {
		t.Fatalf("ambient capabilities = %+v", command.SysProcAttr)
	}
}
