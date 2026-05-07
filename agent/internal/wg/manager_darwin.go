//go:build darwin

// Package wg — stub for macOS until a platform-specific WireGuard manager is implemented.
package wg

import "errors"

type Config struct {
	PrivateKey string
	PublicKey  string
	Endpoint   string
	AssignedIP string
	DNS        []string
	MeshIPs    []string
}

type Manager struct{}

func NewManager() *Manager { return &Manager{} }

func (m *Manager) Connect(_ *Config) error {
	return errors.New("WireGuard not supported on macOS yet")
}

func (m *Manager) Disconnect() {}

func (m *Manager) IsConnected() bool { return false }

func (m *Manager) DNSProtected() bool { return false }

func (m *Manager) InterfaceName() string { return "" }

func (m *Manager) ByteCounters() (tx int64, rx int64, ok bool) {
	return 0, 0, false
}
