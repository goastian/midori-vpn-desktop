//go:build windows

// Package wg — stub for Windows (WireGuard kernel driver not yet implemented).
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
	return errors.New("WireGuard not supported on Windows yet")
}

func (m *Manager) Disconnect() error { return nil }

func (m *Manager) IsConnected() bool { return false }
