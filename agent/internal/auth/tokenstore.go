// Package auth implements persistent OAuth token storage and refresh.
//
// Tokens are persisted with a hybrid strategy:
//   - First attempt: freedesktop Secret Service (libsecret / GNOME Keyring /
//     KWallet) via D-Bus. This is the GNOME/KDE standard and provides
//     session-locked encryption tied to the user's login.
//   - Fallback: AES-GCM encrypted file at $XDG_CONFIG_HOME/midorivpn/tokens.enc
//     with the per-install key at .keystore (mode 0600). Used when Secret
//     Service is unavailable (headless, sway+greetd, container, locked
//     keyring, etc).
//
// The fallback intentionally keeps the key alongside the ciphertext: it does
// not protect against a local attacker with read access to the user's home
// directory, but it does prevent leaking tokens through casual disk access
// (e.g. backups, shared dotfile sync) the same way the browser extension
// approach does in chrome.storage.local.
package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Tokens is the persisted credential set.
type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresAt    int64  `json:"expires_at"` // Unix seconds.
	Username     string `json:"username,omitempty"`
}

// IsZero reports whether t carries no credentials.
func (t Tokens) IsZero() bool { return t.AccessToken == "" && t.RefreshToken == "" }

// Store persists tokens across agent restarts.
type Store interface {
	Save(t Tokens) error
	Load() (Tokens, error)
	Clear() error
	Backend() string // human-readable backend name, for logs/UI
}

// ErrNotFound is returned by Load when no tokens are persisted.
var ErrNotFound = errors.New("auth: no tokens stored")

// NewStore returns the best available Store. It tries Secret Service first
// and falls back to FileStore on failure.
func NewStore() Store {
	// Secret Service is plugged in via secretservice_linux.go (build-tagged).
	// On platforms without it, secretServiceStore returns nil.
	if ss := newSecretServiceStore(); ss != nil {
		// Probe with a no-op load to ensure the daemon responds. If the user
		// just hasn't unlocked their keyring yet we still return SS — the
		// caller will see ErrNotFound and a later Save will succeed.
		if _, perr := ss.Load(); perr == nil || errors.Is(perr, ErrNotFound) {
			slog.Info("auth: using Secret Service for token storage")
			return ss
		} else {
			slog.Warn("auth: Secret Service unavailable, falling back to file store",
				"err", perr)
		}
	}
	fs, ferr := newFileStore()
	if ferr != nil {
		slog.Error("auth: file store init failed", "err", ferr)
		// Last resort: in-memory store. Tokens won't persist across restarts
		// but the agent stays functional for the current session.
		return &memoryStore{}
	}
	slog.Info("auth: using encrypted file store for token storage",
		"path", fs.path)
	return fs
}

// ── Memory store (last-resort fallback) ──────────────────────────────────────

type memoryStore struct {
	mu sync.RWMutex
	t  Tokens
}

func (m *memoryStore) Save(t Tokens) error { m.mu.Lock(); m.t = t; m.mu.Unlock(); return nil }
func (m *memoryStore) Load() (Tokens, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.t.IsZero() {
		return Tokens{}, ErrNotFound
	}
	return m.t, nil
}
func (m *memoryStore) Clear() error  { m.mu.Lock(); m.t = Tokens{}; m.mu.Unlock(); return nil }
func (*memoryStore) Backend() string { return "memory" }

// ── File store (AES-GCM, key file colocated) ─────────────────────────────────

type fileStore struct {
	mu      sync.Mutex
	path    string
	keyPath string
	key     []byte // 32 bytes once initialised
}

func newFileStore() (*fileStore, error) {
	dir, err := userStateDir()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create config dir: %w", err)
	}
	fs := &fileStore{
		path:    filepath.Join(dir, "tokens.enc"),
		keyPath: filepath.Join(dir, ".keystore"),
	}
	if err := fs.loadOrCreateKey(); err != nil {
		return nil, err
	}
	return fs, nil
}

func userStateDir() (string, error) {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "midorivpn"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "midorivpn"), nil
}

func (f *fileStore) loadOrCreateKey() error {
	if data, err := os.ReadFile(f.keyPath); err == nil {
		// Accept existing base64 key material regardless of line ending style.
		key, derr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
		if derr == nil && len(key) == 32 {
			f.key = key
			return nil
		}
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("rand: %w", err)
	}
	enc := base64.StdEncoding.EncodeToString(key)
	if err := writeFileAtomic(f.keyPath, []byte(enc), 0o600); err != nil {
		return fmt.Errorf("write keystore: %w", err)
	}
	f.key = key
	return nil
}

func (f *fileStore) Save(t Tokens) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	plaintext, err := json.Marshal(t)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(f.key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return writeFileAtomic(f.path, out, 0o600)
}

func (f *fileStore) Load() (Tokens, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	data, err := os.ReadFile(f.path)
	if err != nil {
		if os.IsNotExist(err) {
			return Tokens{}, ErrNotFound
		}
		return Tokens{}, err
	}
	block, err := aes.NewCipher(f.key)
	if err != nil {
		return Tokens{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Tokens{}, err
	}
	ns := gcm.NonceSize()
	if len(data) < ns+1 {
		return Tokens{}, fmt.Errorf("ciphertext too short")
	}
	nonce, ct := data[:ns], data[ns:]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return Tokens{}, fmt.Errorf("decrypt: %w", err)
	}
	var t Tokens
	if err := json.Unmarshal(plaintext, &t); err != nil {
		return Tokens{}, err
	}
	if t.IsZero() {
		return Tokens{}, ErrNotFound
	}
	return t, nil
}

func (f *fileStore) Clear() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := os.Remove(f.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (*fileStore) Backend() string { return "file" }

// writeFileAtomic writes b to path via a temp+rename so a crash mid-write
// can never leave a corrupted file behind.
func writeFileAtomic(path string, b []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) //nolint:errcheck // best-effort cleanup if rename succeeded
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
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
	return os.Rename(tmpPath, path)
}
