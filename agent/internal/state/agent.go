// Package state holds the agent's shared runtime state, accessible by all
// subsystems (WireGuard manager, proxy, RPC server).
package state

import (
	"sync"

	"github.com/goastian/midorivpn-agent/internal/apiClient"
)

// VPNStatus represents the current VPN connection state.
type VPNStatus struct {
	Connected      bool   `json:"connected"`
	ServerName     string `json:"server_name"`
	ServerID       string `json:"server_id"`
	PeerID         string `json:"peer_id,omitempty"`
	AssignedIP     string `json:"assigned_ip"`
	ServerPublicIP string `json:"server_public_ip"`
	ServerEndpoint string `json:"server_endpoint,omitempty"`
	MeshIP         string `json:"mesh_ip"`
	BytesSent      int64  `json:"bytes_sent"`
	BytesRecv      int64  `json:"bytes_recv"`
}

// MeshStatus represents the current mesh node state.
type MeshStatus struct {
	Active         bool             `json:"active"`
	MeshID         string           `json:"mesh_id"`
	MeshIP         string           `json:"mesh_ip"`
	PublicIP       string           `json:"public_ip"`
	IsExitNode     bool             `json:"is_exit_node"`
	FullTunnel     bool             `json:"full_tunnel"`
	ExitNodeHost   string           `json:"exit_node_host,omitempty"`
	ExitNodePort   int              `json:"exit_node_port,omitempty"`
	ExitNodeScheme string           `json:"exit_node_scheme,omitempty"`
	Peers          []apiClient.Peer `json:"peers"`
}

type ProtectionStatus struct {
	KillSwitchActive bool   `json:"kill_switch_active"`
	DNSProtected     bool   `json:"dns_protected"`
	Mode             string `json:"mode,omitempty"`
	LastError        string `json:"last_error,omitempty"`
}

// AuthStatus represents the authentication state.
type AuthStatus struct {
	LoggedIn     bool   `json:"logged_in"`
	Username     string `json:"username,omitempty"`
	AccessToken  string `json:"-"` // never serialized
	RefreshToken string `json:"-"`
	ExpiresAt    int64  `json:"expires_at,omitempty"`
}

// Agent is the central shared state container.
type Agent struct {
	mu sync.RWMutex

	Auth       AuthStatus
	VPN        VPNStatus
	Mesh       MeshStatus
	Protection ProtectionStatus

	// Pub/sub for SSE broadcasts: each subscriber gets its own channel so that
	// a slow or reconnecting client never starves other subscribers.
	subMu sync.Mutex
	subs  []chan Event
}

// Event is a state-change notification sent over SSE.
type Event struct {
	Type string `json:"type"` // "auth", "vpn", "mesh"
}

// NewAgent creates a new Agent with default state.
func NewAgent() *Agent {
	return &Agent{}
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
		"vpn":        a.VPN,
		"mesh":       a.Mesh,
		"protection": a.Protection,
	}
}

// SetAuth atomically updates auth state and broadcasts an event.
func (a *Agent) SetAuth(s AuthStatus) {
	a.mu.Lock()
	a.Auth = s
	a.mu.Unlock()
	a.broadcast(Event{Type: "auth_status"})
}

// SetVPN atomically updates VPN state and broadcasts.
func (a *Agent) SetVPN(s VPNStatus) {
	a.mu.Lock()
	a.VPN = s
	a.mu.Unlock()
	a.broadcast(Event{Type: "vpn_status"})
}

// SetMesh atomically updates mesh state and broadcasts.
func (a *Agent) SetMesh(s MeshStatus) {
	a.mu.Lock()
	a.Mesh = s
	a.mu.Unlock()
	a.broadcast(Event{Type: "mesh_status"})
}

func (a *Agent) SetProtection(s ProtectionStatus) {
	a.mu.Lock()
	a.Protection = s
	a.mu.Unlock()
	a.broadcast(Event{Type: "protection_status"})
}

// GetAccessToken returns the current access token (safe for concurrent use).
func (a *Agent) GetAccessToken() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.Auth.AccessToken
}

// GetAuth returns a copy of the current auth state, including non-serialized
// fields such as access and refresh tokens.
func (a *Agent) GetAuth() AuthStatus {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.Auth
}

// Subscribe returns a channel that receives state-change events.
// Every subscriber gets its own buffered channel so each SSE connection
// receives all events independently (proper fan-out).
// The caller MUST call the returned cancel function when done.
func (a *Agent) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 32)
	a.subMu.Lock()
	a.subs = append(a.subs, ch)
	a.subMu.Unlock()

	var once sync.Once
	return ch, func() {
		once.Do(func() {
			a.subMu.Lock()
			for i, c := range a.subs {
				if c == ch {
					a.subs = append(a.subs[:i], a.subs[i+1:]...)
					break
				}
			}
			a.subMu.Unlock()
			close(ch)
		})
	}
}

func (a *Agent) broadcast(e Event) {
	a.subMu.Lock()
	for _, ch := range a.subs {
		select {
		case ch <- e:
		default: // subscriber too slow; drop rather than block
		}
	}
	a.subMu.Unlock()
}
