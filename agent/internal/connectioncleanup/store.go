// Package connectioncleanup persists backend peers that still need an exact,
// idempotent DELETE after the local VPN transport has been torn down.
package connectioncleanup

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

const (
	storeVersion      = 1
	maxPendingPeers   = 256
	maxStoreFileBytes = 64 * 1024
)

type diskState struct {
	Version int      `json:"version"`
	PeerIDs []string `json:"peer_ids"`
}

// Store is a crash-safe, per-user set of peer IDs awaiting backend cleanup.
type Store struct {
	mu      sync.Mutex
	path    string
	pending map[string]struct{}
}

// New opens the production store under XDG_STATE_HOME (or ~/.local/state).
func New() (*Store, error) {
	dir, err := stateDir()
	if err != nil {
		return nil, err
	}
	return NewAt(filepath.Join(dir, "pending-connection-cleanup.json"))
}

// NewAt opens a store at path. It is exported to keep filesystem behavior
// directly testable without changing process-wide user directories.
func NewAt(path string) (*Store, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("connection cleanup path must be absolute")
	}
	dir := filepath.Dir(path)
	if err := ensurePrivateDir(dir); err != nil {
		return nil, fmt.Errorf("prepare connection cleanup directory: %w", err)
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, errors.New("pending connection cleanup path is not a regular file")
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return nil, fmt.Errorf("protect pending connection cleanup file: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect pending connection cleanup file: %w", err)
	}
	s := &Store{path: path, pending: make(map[string]struct{})}
	if err := s.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return s, nil
}

// Add durably records peerID before local tunnel teardown.
func (s *Store) Add(peerID string) error {
	if !validUUID(peerID) {
		return errors.New("pending connection cleanup peer ID must be a UUID")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.pending[peerID]; exists {
		return nil
	}
	if len(s.pending) >= maxPendingPeers {
		return fmt.Errorf("pending connection cleanup limit %d reached", maxPendingPeers)
	}
	next := cloneSet(s.pending)
	next[peerID] = struct{}{}
	if err := s.save(next); err != nil {
		return err
	}
	s.pending = next
	return nil
}

// Remove forgets peerID only after the backend accepted its idempotent DELETE.
func (s *Store) Remove(peerID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.pending[peerID]; !exists {
		return nil
	}
	next := cloneSet(s.pending)
	delete(next, peerID)
	if err := s.save(next); err != nil {
		return err
	}
	s.pending = next
	return nil
}

// List returns pending IDs in deterministic order.
func (s *Store) List() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return sortedIDs(s.pending)
}

func (s *Store) load() error {
	file, err := os.Open(s.path) //nolint:gosec // fixed per-user state path
	if err != nil {
		return err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, maxStoreFileBytes+1))
	if err != nil {
		return fmt.Errorf("read pending connection cleanup: %w", err)
	}
	if len(body) > maxStoreFileBytes {
		return errors.New("pending connection cleanup file exceeds size limit")
	}
	var state diskState
	if err := json.Unmarshal(body, &state); err != nil {
		return fmt.Errorf("parse pending connection cleanup: %w", err)
	}
	if state.Version != storeVersion {
		return fmt.Errorf("unsupported pending connection cleanup version %d", state.Version)
	}
	if len(state.PeerIDs) > maxPendingPeers {
		return errors.New("pending connection cleanup file exceeds entry limit")
	}
	for _, peerID := range state.PeerIDs {
		if !validUUID(peerID) {
			return errors.New("pending connection cleanup contains an invalid peer ID")
		}
		s.pending[peerID] = struct{}{}
	}
	return nil
}

func (s *Store) save(pending map[string]struct{}) error {
	body, err := json.MarshalIndent(diskState{Version: storeVersion, PeerIDs: sortedIDs(pending)}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode pending connection cleanup: %w", err)
	}
	body = append(body, '\n')
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".pending-connection-cleanup-*")
	if err != nil {
		return fmt.Errorf("create pending connection cleanup temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) //nolint:errcheck // rename removes it on success
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return fmt.Errorf("write pending connection cleanup: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("protect pending connection cleanup: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync pending connection cleanup: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close pending connection cleanup: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("replace pending connection cleanup: %w", err)
	}
	dirHandle, err := os.Open(dir) //nolint:gosec // fixed per-user state path
	if err != nil {
		return fmt.Errorf("open pending connection cleanup directory: %w", err)
	}
	defer dirHandle.Close()
	if err := dirHandle.Sync(); err != nil {
		return fmt.Errorf("sync pending connection cleanup directory: %w", err)
	}
	return nil
}

func stateDir() (string, error) {
	if stateHome := os.Getenv("XDG_STATE_HOME"); stateHome != "" {
		if !filepath.IsAbs(stateHome) {
			return "", errors.New("XDG_STATE_HOME must be an absolute path")
		}
		return filepath.Join(stateHome, "midorivpn"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve user home directory: %w", err)
	}
	return filepath.Join(home, ".local", "state", "midorivpn"), nil
}

func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("connection cleanup path is not a directory")
	}
	return os.Chmod(dir, 0o700)
}

func cloneSet(source map[string]struct{}) map[string]struct{} {
	result := make(map[string]struct{}, len(source))
	for value := range source {
		result[value] = struct{}{}
	}
	return result
}

func sortedIDs(source map[string]struct{}) []string {
	result := make([]string, 0, len(source))
	for value := range source {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func validUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	compact := value[:8] + value[9:13] + value[14:18] + value[19:23] + value[24:]
	decoded := make([]byte, 16)
	_, err := hex.Decode(decoded, []byte(compact))
	return err == nil
}
