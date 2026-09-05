package settings

import "testing"

func TestUIStartMinimizedPersists(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	store, err := New()
	if err != nil {
		t.Fatalf("create settings store: %v", err)
	}
	if store.Get().UI.StartMinimized {
		t.Fatal("start minimized must default to false")
	}
	if err := store.Update(func(value *Settings) { value.UI.StartMinimized = true }); err != nil {
		t.Fatalf("persist UI setting: %v", err)
	}

	reloaded, err := New()
	if err != nil {
		t.Fatalf("reload settings store: %v", err)
	}
	if !reloaded.Get().UI.StartMinimized {
		t.Fatal("start minimized was not persisted")
	}
}

func TestVPNSelectionDefaultsAutomaticAndPersistsManualPin(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	store, err := New()
	if err != nil {
		t.Fatalf("create settings store: %v", err)
	}
	if store.Get().VPN.SelectionMode != SelectionModeAutomatic {
		t.Fatalf("selection mode = %q, want automatic", store.Get().VPN.SelectionMode)
	}
	const serverID = "82b130ca-d14d-46a3-ad44-7ccd34dfb842"
	if err := store.Update(func(value *Settings) {
		value.VPN.SelectionMode = SelectionModeManual
		value.VPN.ManualServerID = serverID
	}); err != nil {
		t.Fatalf("persist VPN selection: %v", err)
	}

	reloaded, err := New()
	if err != nil {
		t.Fatalf("reload settings store: %v", err)
	}
	if got := reloaded.Get().VPN; got.SelectionMode != SelectionModeManual || got.ManualServerID != serverID {
		t.Fatalf("persisted VPN settings = %#v", got)
	}
}
