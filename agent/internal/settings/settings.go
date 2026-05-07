// Package settings persists user-controlled agent preferences to a JSON file
// at $XDG_CONFIG_HOME/midorivpn/settings.json.
//
// Used today for two switches the user explicitly requested:
//   - Mesh.StartDisabled: when true, the agent does NOT auto-enable the
//     mesh node on startup. Default false (mesh is always-on).
//   - Autostart.Enabled: tracks whether the user opted out of XDG autostart.
//     The actual XDG entry is managed by the Tauri side; we keep the bit
//     here so the agent can mirror it through SSE for the UI.
package settings

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// Settings is the persisted preferences set.
type Settings struct {
	Mesh      MeshSettings      `json:"mesh"`
	Autostart AutostartSettings `json:"autostart"`
}

type MeshSettings struct {
	// StartDisabled, when true, prevents auto-enable of the mesh on agent
	// startup. The default (false) honours the product decision: "always ON
	// unless explicit opt-out".
	StartDisabled bool `json:"start_disabled"`
}

type AutostartSettings struct {
	// Enabled mirrors the actual XDG autostart presence. Default true.
	Enabled bool `json:"enabled"`
}

// defaults returns the product-mandated defaults.
func defaults() Settings {
	return Settings{
		Mesh:      MeshSettings{StartDisabled: false},
		Autostart: AutostartSettings{Enabled: true},
	}
}

// Store reads/writes settings.json with atomic semantics.
type Store struct {
	mu   sync.RWMutex
	path string
	cur  Settings
}

// New constructs a Store rooted at the user's config dir. It creates the
// parent directory (mode 0700) if missing and loads existing settings — or
// writes defaults if none exist.
func New() (*Store, error) {
	dir, err := userConfigDir()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create settings dir: %w", err)
	}
	s := &Store{path: filepath.Join(dir, "settings.json"), cur: defaults()}
	if err := s.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	// Persist defaults on first run so admins can see the file format.
	if _, err := os.Stat(s.path); errors.Is(err, os.ErrNotExist) {
		if werr := s.save(); werr != nil {
			return nil, werr
		}
	}
	return s, nil
}

// Get returns a snapshot of the current settings.
func (s *Store) Get() Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cur
}

// Update applies fn to a copy of the settings under the lock and persists
// the result atomically. fn must not block on I/O.
func (s *Store) Update(fn func(*Settings)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next := s.cur
	fn(&next)
	s.cur = next
	return s.save()
}

func (s *Store) load() error {
	f, err := os.Open(s.path) //nolint:gosec // user-config path
	if err != nil {
		return err
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, 64*1024))
	if err != nil {
		return err
	}
	cur := defaults()
	if jerr := json.Unmarshal(body, &cur); jerr != nil {
		return fmt.Errorf("parse settings: %w", jerr)
	}
	s.cur = cur
	return nil
}

func (s *Store) save() error {
	body, err := json.MarshalIndent(s.cur, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".settings-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) //nolint:errcheck
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpPath, s.path)
}

func userConfigDir() (string, error) {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "midorivpn"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "midorivpn"), nil
}
