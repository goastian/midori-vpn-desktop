//go:build linux

package rpc

import (
	"os"
	"strings"
	"testing"
)

func TestCapabilitySetUsesLeastPrivilegeByDefault(t *testing.T) {
	if got, want := capabilitySet(false), "cap_net_admin,cap_net_raw=ep"; got != want {
		t.Fatalf("default capability set = %q, want %q", got, want)
	}
}

func TestCapabilitySetNeverGrantsFilesystemPowers(t *testing.T) {
	if got, want := capabilitySet(true), "cap_net_admin,cap_net_raw=ep"; got != want {
		t.Fatalf("legacy extended request = %q, want %q", got, want)
	}
}

func TestFileCapabilitiesRejectsAnyAdditionalPowers(t *testing.T) {
	for _, value := range []string{"", "cap_net_admin=ep", "cap_net_admin,cap_net_raw,cap_dac_override=ep", "cap_net_admin,cap_net_raw,cap_sys_admin=ep", "cap_net_admin,cap_net_raw=eip"} {
		if fileCapabilitiesSafe("/usr/libexec/midorivpn-agent " + value) {
			t.Fatalf("accepted %q", value)
		}
	}
	if !fileCapabilitiesSafe("/usr/libexec/midorivpn-agent cap_net_admin,cap_net_raw=ep\n") {
		t.Fatal("minimal file capabilities rejected")
	}
}

func TestAutostartLaunchesDesktopShell(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	if err := setAutostart(true, 7071, "/usr/share/midorivpn/ui"); err != nil {
		t.Fatalf("enable autostart: %v", err)
	}
	path, err := autostartPath()
	if err != nil {
		t.Fatalf("resolve autostart path: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read autostart file: %v", err)
	}
	if !strings.Contains(string(body), "Exec=\"/usr/bin/midorivpn-desktop\" --port 7071 --ui-dir \"/usr/share/midorivpn/ui\" --autostart") {
		t.Fatalf("autostart must launch desktop shell, got:\n%s", body)
	}
}
