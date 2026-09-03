package deviceidentity

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIdentityPersistsPrivateInstallationState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state", "midorivpn")
	mac := mustMAC(t, "02:11:22:33:44:55")
	deps := testDependencies("Tecno 09", []net.Interface{{
		Name:         "enp1s0",
		Flags:        net.FlagUp,
		HardwareAddr: mac,
	}}, []string{"enp1s0"}, map[string]AdapterKind{"enp1s0": AdapterKindEthernet})

	firstStore, err := open(dir, deps)
	if err != nil {
		t.Fatalf("open first identity: %v", err)
	}
	first, err := firstStore.Current()
	if err != nil {
		t.Fatalf("read first identity: %v", err)
	}
	if !validUUIDv4(first.ClientInstanceID) {
		t.Fatalf("client instance ID is not UUIDv4: %q", first.ClientInstanceID)
	}
	if first.ReportedName != "Tecno-09" {
		t.Fatalf("reported name = %q, want Tecno-09", first.ReportedName)
	}
	if first.DeviceType != DeviceTypeDesktop {
		t.Fatalf("device type = %q, want desktop", first.DeviceType)
	}
	if first.AdapterKind != AdapterKindEthernet || !strings.HasPrefix(first.AdapterReference, "net-v1:") {
		t.Fatalf("unexpected adapter identity: %#v", first)
	}

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("identity directory mode = %o, want 700", got)
	}
	statePath := filepath.Join(dir, stateFilename)
	fileInfo, err := os.Stat(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("identity file mode = %o, want 600", got)
	}
	stateData, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stateData, []byte(mac)) || bytes.Contains(stateData, []byte(mac.String())) || bytes.Contains(stateData, []byte(first.AdapterReference)) {
		t.Fatalf("persisted state contains adapter material: %s", stateData)
	}

	secondStore, err := open(dir, deps)
	if err != nil {
		t.Fatalf("reopen identity: %v", err)
	}
	second, err := secondStore.Current()
	if err != nil {
		t.Fatalf("read reopened identity: %v", err)
	}
	if second.ClientInstanceID != first.ClientInstanceID || second.AdapterReference != first.AdapterReference {
		t.Fatalf("identity changed after reopen: first=%#v second=%#v", first, second)
	}
}

func TestHostnameChangesDoNotOverwriteAlias(t *testing.T) {
	hostname := "Old Host"
	deps := testDependencies(hostname, nil, nil, nil)
	deps.hostname = func() (string, error) { return hostname, nil }
	store, err := open(t.TempDir(), deps)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetAlias("  Equipo\tPrincipal  "); err != nil {
		t.Fatal(err)
	}
	before, err := store.Current()
	if err != nil {
		t.Fatal(err)
	}

	hostname = "New Host"
	after, err := store.Current()
	if err != nil {
		t.Fatal(err)
	}
	if after.ClientInstanceID != before.ClientInstanceID {
		t.Fatal("hostname change rotated the client instance ID")
	}
	if after.ReportedName != "New-Host" {
		t.Fatalf("updated reported name = %q, want New-Host", after.ReportedName)
	}
	if after.Alias != "Equipo Principal" || after.DisplayName() != "Equipo Principal" {
		t.Fatalf("alias was not preserved: %#v", after)
	}

	reopened, err := open(filepath.Dir(store.path), deps)
	if err != nil {
		t.Fatal(err)
	}
	persisted, err := reopened.Current()
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Alias != after.Alias || persisted.ReportedName != after.ReportedName {
		t.Fatalf("updated identity was not persisted: %#v", persisted)
	}
}

func TestInvalidStateFailsClosed(t *testing.T) {
	t.Run("corrupt", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, stateFilename), []byte("not-json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := open(dir, testDependencies("host", nil, nil, nil)); err == nil {
			t.Fatal("open succeeded with corrupt state")
		}
	})

	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(t.TempDir(), "identity.json")
		if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, stateFilename)); err != nil {
			t.Fatal(err)
		}
		if _, err := open(dir, testDependencies("host", nil, nil, nil)); err == nil {
			t.Fatal("open followed a symlinked identity file")
		}
	})
}

func TestAdapterSelectionPrefersPhysicalDefaultRoute(t *testing.T) {
	interfaces := []net.Interface{
		{Name: "lo", Flags: net.FlagUp | net.FlagLoopback, HardwareAddr: mustMAC(t, "00:00:00:00:00:00")},
		{Name: "wg0", Flags: net.FlagUp, HardwareAddr: mustMAC(t, "02:00:00:00:00:01")},
		{Name: "enp9s0", Flags: net.FlagUp, HardwareAddr: mustMAC(t, "02:10:20:30:40:50")},
		{Name: "wlp2s0", Flags: net.FlagUp, HardwareAddr: mustMAC(t, "06:10:20:30:40:50")},
		{Name: "enp0s1", Flags: 0, HardwareAddr: mustMAC(t, "0a:10:20:30:40:50")},
	}
	deps := testDependencies("host", interfaces, []string{"wg0", "wlp2s0"}, map[string]AdapterKind{
		"enp9s0": AdapterKindEthernet,
		"wlp2s0": AdapterKindWiFi,
	})
	selected, ok := selectAdapter(deps)
	if !ok || selected.name != "wlp2s0" || selected.kind != AdapterKindWiFi {
		t.Fatalf("selected adapter = %#v, %v", selected, ok)
	}

	deps.defaultRoutes = func() []string { return []string{"missing0"} }
	selected, ok = selectAdapter(deps)
	if !ok || selected.name != "enp9s0" {
		t.Fatalf("stable fallback adapter = %#v, %v", selected, ok)
	}
}

func TestAdapterChangesReferenceButNotInstallationIdentity(t *testing.T) {
	active := []net.Interface{{
		Name:         "wlp2s0",
		Flags:        net.FlagUp,
		HardwareAddr: mustMAC(t, "02:11:22:33:44:55"),
	}}
	deps := testDependencies("host", active, []string{"wlp2s0"}, map[string]AdapterKind{
		"wlp2s0": AdapterKindWiFi,
		"enp1s0": AdapterKindEthernet,
	})
	deps.interfaces = func() ([]net.Interface, error) { return active, nil }
	deps.defaultRoutes = func() []string { return []string{active[0].Name} }
	store, err := open(t.TempDir(), deps)
	if err != nil {
		t.Fatal(err)
	}
	wifi, err := store.Current()
	if err != nil {
		t.Fatal(err)
	}

	active = []net.Interface{{
		Name:         "enp1s0",
		Flags:        net.FlagUp,
		HardwareAddr: mustMAC(t, "0a:aa:bb:cc:dd:ee"),
	}}
	ethernet, err := store.Current()
	if err != nil {
		t.Fatal(err)
	}
	if ethernet.ClientInstanceID != wifi.ClientInstanceID {
		t.Fatal("adapter change rotated the client instance ID")
	}
	if ethernet.AdapterReference == wifi.AdapterReference || ethernet.AdapterReference == "" {
		t.Fatalf("adapter reference did not change: wifi=%q ethernet=%q", wifi.AdapterReference, ethernet.AdapterReference)
	}
	if ethernet.AdapterKind != AdapterKindEthernet {
		t.Fatalf("adapter kind = %q, want ethernet", ethernet.AdapterKind)
	}
}

func TestMissingPhysicalAdapterOmitsReference(t *testing.T) {
	deps := testDependencies("host", []net.Interface{{
		Name:         "veth0",
		Flags:        net.FlagUp,
		HardwareAddr: mustMAC(t, "02:11:22:33:44:55"),
	}}, []string{"veth0"}, map[string]AdapterKind{"veth0": AdapterKindEthernet})
	store, err := open(t.TempDir(), deps)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := store.Current()
	if err != nil {
		t.Fatal(err)
	}
	if identity.AdapterReference != "" || identity.AdapterKind != "" {
		t.Fatalf("virtual adapter produced a reference: %#v", identity)
	}
}

func TestAdapterReferenceUsesContextualHMAC(t *testing.T) {
	key := bytes.Repeat([]byte{0x41}, 32)
	address := mustMAC(t, "02:11:22:33:44:55")
	calculated := adapterReference(key, address)

	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(fingerprintContext))
	_, _ = mac.Write(address)
	want := "net-v1:" + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if calculated != want {
		t.Fatalf("adapter reference = %q, want %q", calculated, want)
	}
}

func TestSanitizeReportedName(t *testing.T) {
	if got := sanitizeReportedName("  Técno / 09  "); got != "T-cno-09" {
		t.Fatalf("sanitized name = %q, want T-cno-09", got)
	}
	if got := sanitizeReportedName("___"); got != "linux-desktop" {
		t.Fatalf("empty sanitized name = %q, want fallback", got)
	}
	if got := sanitizeReportedName(strings.Repeat("a", 80)); len(got) != 64 {
		t.Fatalf("sanitized name length = %d, want 64", len(got))
	}
}

func testDependencies(hostname string, interfaces []net.Interface, routes []string, kinds map[string]AdapterKind) dependencies {
	return dependencies{
		hostname: func() (string, error) { return hostname, nil },
		interfaces: func() ([]net.Interface, error) {
			return interfaces, nil
		},
		defaultRoutes: func() []string { return routes },
		classify: func(name string) (AdapterKind, bool) {
			kind, ok := kinds[name]
			return kind, ok
		},
		random: bytes.NewReader(bytes.Repeat([]byte{0x5a}, 128)),
	}
}

func mustMAC(t *testing.T, value string) net.HardwareAddr {
	t.Helper()
	address, err := net.ParseMAC(value)
	if err != nil {
		t.Fatal(err)
	}
	return address
}
