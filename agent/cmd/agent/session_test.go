package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func privateRuntimeDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestBrowserTokenIsFreshAndNotCallerControlled(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", privateRuntimeDir(t))
	t.Setenv("MIDORIVPN_AGENT_TOKEN", "caller-controlled")
	first, path, err := ensureBrowserToken()
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := ensureBrowserToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 64 || first == "caller-controlled" || first == second {
		t.Fatal("RPC sessions must use fresh 256-bit random tokens")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("token permissions: %v %v", info, err)
	}
}

func TestSessionWritesNeverFollowSymlinks(t *testing.T) {
	dir := privateRuntimeDir(t)
	t.Setenv("XDG_RUNTIME_DIR", dir)
	outside := filepath.Join(t.TempDir(), "untouched")
	if err := os.WriteFile(outside, []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "midorivpn-agent.token")); err != nil {
		t.Fatal(err)
	}
	_, _, _ = ensureBrowserToken()
	data, err := os.ReadFile(outside)
	if err != nil || string(data) != "original" {
		t.Fatalf("symlink target modified: %q %v", data, err)
	}
	info, err := os.Stat(outside)
	if err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("symlink target permissions changed: %v %v", info, err)
	}
}

func TestRuntimeDirectoryMustBePrivateAndAbsolute(t *testing.T) {
	for _, path := range []string{"", "relative", t.TempDir()} {
		if strings.HasPrefix(path, "/") {
			if err := os.Chmod(path, 0o777); err != nil {
				t.Fatal(err)
			}
		}
		t.Setenv("XDG_RUNTIME_DIR", path)
		if _, _, err := ensureBrowserToken(); err == nil {
			t.Errorf("accepted unsafe runtime directory %q", path)
		}
	}
}

func TestSingleInstanceLockRejectsSymlinks(t *testing.T) {
	dir := privateRuntimeDir(t)
	t.Setenv("XDG_RUNTIME_DIR", dir)
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "midorivpn-agent.lock")); err != nil {
		t.Fatal(err)
	}
	release, err := acquireSingleInstanceLock()
	if err == nil {
		release()
		t.Fatal("accepted symlink lock")
	}
}

func TestSessionTokenCanBeResumedButNotReadThroughLinks(t *testing.T) {
	dir := privateRuntimeDir(t)
	t.Setenv("XDG_RUNTIME_DIR", dir)
	want, path, err := ensureBrowserToken()
	if err != nil {
		t.Fatal(err)
	}
	if got, err := readRuntimeToken(); err != nil || got != want {
		t.Fatalf("resume failed: %v", err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readRuntimeToken(); err == nil {
		t.Fatal("accepted a non-private token file")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".other"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(path+".other", path); err != nil {
		t.Fatal(err)
	}
	if _, err := readRuntimeToken(); err == nil {
		t.Fatal("accepted a symlink token read")
	}
}

func TestInstanceLockIsStableAcrossRelease(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", privateRuntimeDir(t))
	release, err := acquireSingleInstanceLock()
	if err != nil {
		t.Fatal(err)
	}
	if second, err := acquireSingleInstanceLock(); err == nil {
		second()
		release()
		t.Fatal("two agents acquired one lock")
	}
	path := filepath.Join(os.Getenv("XDG_RUNTIME_DIR"), "midorivpn-agent.lock")
	before, err := os.Stat(path)
	if err != nil {
		release()
		t.Fatal(err)
	}
	release()
	after, err := os.Stat(path)
	if err != nil || !os.SameFile(before, after) {
		t.Fatal("lock inode was removed or replaced")
	}
	third, err := acquireSingleInstanceLock()
	if err != nil {
		t.Fatal(err)
	}
	third()
}

func TestParentSupervisionRejectsMissingOrUnrelatedProcess(t *testing.T) {
	for _, pid := range []int{0, 1, -1, os.Getpid()} {
		if err := superviseParent(pid); err == nil {
			t.Fatalf("accepted unrelated parent %d", pid)
		}
	}
}
