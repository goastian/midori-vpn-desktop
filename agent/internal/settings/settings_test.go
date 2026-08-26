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
