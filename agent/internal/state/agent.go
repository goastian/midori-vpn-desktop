// Package state holds the agent's shared runtime state, accessible by all
// subsystems (WireGuard manager, proxy, RPC server).
package state

import (
	"sync"

	"github.com/goastian/midorivpn-agent/internal/apiClient"
)

// VPNStatus represents the current VPN connection state.
type VPNStatus struct {
	Connected  bool   `json:"connected"`
	ServerName string `json:"server_name"`
	ServerID   string `json:"server_id"`
	AssignedIP string `json:"assigned_ip"`
	MeshIP     string `json:"mesh_ip"`
	BytesSent  int64  `json:"bytes_sent"`
	BytesRecv  int64  `json:"bytes_recv"`
}

// MeshStatus represents the current mesh node state.
type MeshStatus struct {
	Active       bool              `json:"active"`
	MeshID       string            `json:"mesh_id"`
	MeshIP       string            `json:"mesh_ip"`
	PublicIP     string            `json:"public_ip"`
	IsExitNode   bool              `json:"is_exit_node"`
	ExitNodeHost string            `json:"exit_node_host,omitempty"`
	ExitNodePort int               `json:"exit_node_port,omitempty"`
	Peers        []apiClient.Peer  `json:"peers"`
}

// AuthStatus represents the authentication state.
type AuthStatus struct {
	LoggedIn    bool   `json:"logged_in"`
	Username    string `json:"username,omitempty"`
	AccessToken string `json:"-"` // never serialized
	RefreshToken string `json:"-"`
	ExpiresAt   int64  `json:"expires_at,omitempty"`
}

// Agent is the central shared state container.
type Agent struct {
	mu sync.RWMutex

	Auth   AuthStatus
	VPN    VPNStatus
	Mesh   MeshStatus

	// Channels for SSE broadcasts.
	events chan Event
}

// Event is a state-change notification sent over SSE.
type Event struct {
	Type string `json:"type"` // "auth", "vpn", "mesh"
}

// NewAgent creates a new Agent with default state.
func NewAgent() *Agent {
	return &Agent{
		events: make(chan Event, 64),
	}
}

// Snapshot returns a safe copy of all state for JSON serialization.
func (a *Agent) Snapshot() map[string]any {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return map[string]any{
		"auth": AuthStatus{
			LoggedIn:  a.Auth.LoggedIn,
			Username:  a.Auth.Username,
			ExpiresAt: a.Auth.ExpiresAt,
		},
		"vpn":  a.VPN,
		"mesh": a.Mesh,
	}
}

// SetAuth atomically updates auth state and broadcasts an event.
func (a *Agent) SetAuth(s AuthStatus) {
	a.mu.Lock()
	a.Auth = s
	a.mu.Unlock()
	a.broadcast(Event{Type: "auth"})
}

// SetVPN atomically updates VPN state and broadcasts.
func (a *Agent) SetVPN(s VPNStatus) {
	a.mu.Lock()
	a.VPN = s
	a.mu.Unlock()
	a.broadcast(Event{Type: "vpn"})
}

// SetMesh atomically updates mesh state and broadcasts.
func (a *Agent) SetMesh(s MeshStatus) {
	a.mu.Lock()
	a.Mesh = s
	a.mu.Unlock()
	a.broadcast(Event{Type: "mesh"})
}

// GetAccessToken returns the current access token (safe for concurrent use).
func (a *Agent) GetAccessToken() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.Auth.AccessToken
}

// Subscribe returns a channel that receives state-change events.
// The caller must call the returned cancel function when done.
func (a *Agent) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 16)
	go func() {
		for e := range a.events {
			select {
			case ch <- e:
			default:
			}
		}
	}()
	return ch, func() { close(ch) }
}

func (a *Agent) broadcast(e Event) {
	select {
	case a.events <- e:
	default:
	}
}
