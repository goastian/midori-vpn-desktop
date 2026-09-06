package connectioncleanup

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestStorePersistsPrivateDeterministicSet(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state", "midorivpn")
	path := filepath.Join(dir, "pending.json")
	store, err := NewAt(path)
	if err != nil {
		t.Fatal(err)
	}
	first := "ffffffff-ffff-4fff-8fff-ffffffffffff"
	second := "11111111-1111-4111-8111-111111111111"
	if first < second {
		first, second = second, first
	}
	if err := store.Add(first); err != nil {
		t.Fatal(err)
	}
	if err := store.Add(second); err != nil {
		t.Fatal(err)
	}
	if err := store.Add(first); err != nil {
		t.Fatalf("idempotent add: %v", err)
	}

	reopened, err := NewAt(path)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := reopened.List(), []string{second, first}; !reflect.DeepEqual(got, want) {
		t.Fatalf("pending IDs = %v, want %v", got, want)
	}
	if err := reopened.Remove(second); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Remove(second); err != nil {
		t.Fatalf("idempotent remove: %v", err)
	}
	if got := reopened.List(); !reflect.DeepEqual(got, []string{first}) {
		t.Fatalf("pending IDs after remove = %v", got)
	}

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o700 || fileInfo.Mode().Perm() != 0o600 {
		t.Fatalf("modes = dir %o file %o, want 700/600", dirInfo.Mode().Perm(), fileInfo.Mode().Perm())
	}
}

func TestStoreRejectsInvalidOrCorruptState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "pending.json")
	store, err := NewAt(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Add("not-a-uuid"); err == nil {
		t.Fatal("invalid peer ID accepted")
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"peer_ids":["bad"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewAt(path); err == nil {
		t.Fatal("corrupt pending state accepted")
	}
}

func TestStoreRejectsSymlinkTarget(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte(`{"version":1,"peer_ids":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "pending.json")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := NewAt(path); err == nil {
		t.Fatal("symlink pending state accepted")
	}
}
