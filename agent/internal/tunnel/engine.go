package tunnel

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	ErrNoSuitableDriver = errors.New("no suitable tunnel driver available")
	ErrAlreadyConnected = errors.New("tunnel session is already active")
	ErrNotConnected     = errors.New("no active tunnel session")
)

type Protocol string

const (
	ProtocolSmart     Protocol = "smart"
	ProtocolWireGuard Protocol = "wireguard"
	ProtocolObfsTLS   Protocol = "obfs_tls"
	ProtocolMASQUE    Protocol = "masque_h3"
	ProtocolOpenVPN   Protocol = "openvpn_dco"
)

type DriverCapabilities struct {
	SupportsIPv6       bool
	SupportsObfuscation bool
	SupportsDCO        bool
	HardwareAccel      bool
}

type TunnelConfig struct {
	ServerID        string            `json:"server_id"`
	ServerHost      string            `json:"server_host"`
	ServerPort      int               `json:"server_port"`
	ServerPublicKey string            `json:"server_public_key"`
	ClientPrivateKey string           `json:"client_private_key"`
	AssignedIP      string            `json:"assigned_ip"`
	DNS             []string          `json:"dns"`
	AllowedIPs      []string          `json:"allowed_ips"`
	MTU             int               `json:"mtu"`
	CustomHeaders   map[string]string `json:"custom_headers,omitempty"`
}

type Session struct {
	ID        string    `json:"id"`
	Protocol  Protocol  `json:"protocol"`
	Driver    string    `json:"driver"`
	ConnectedAt time.Time `json:"connected_at"`
	LocalIP   string    `json:"local_ip"`
	Endpoint  string    `json:"endpoint"`
}

type Stats struct {
	BytesIn       uint64        `json:"bytes_in"`
	BytesOut      uint64        `json:"bytes_out"`
	LastHandshake time.Time     `json:"last_handshake"`
	RTT           time.Duration `json:"rtt"`
	PacketLoss    float64       `json:"packet_loss"`
}

type ProbeResult struct {
	Protocol  Protocol      `json:"protocol"`
	Available bool          `json:"available"`
	Latency   time.Duration `json:"latency"`
	Error     string        `json:"error,omitempty"`
}

// Driver defines the common interface required for all tunnel protocol adapters
type Driver interface {
	Name() string
	Protocol() Protocol
	Capabilities() DriverCapabilities
	Connect(ctx context.Context, cfg *TunnelConfig) (*Session, error)
	Disconnect(ctx context.Context) error
	Stats(ctx context.Context) (*Stats, error)
	Probe(ctx context.Context, endpoint string) (*ProbeResult, error)
}

// Registry manages registered tunnel protocol drivers
type Registry struct {
	mu      sync.RWMutex
	drivers map[Protocol]Driver
}

func NewRegistry() *Registry {
	return &Registry{
		drivers: make(map[Protocol]Driver),
	}
}

func (r *Registry) Register(d Driver) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.drivers[d.Protocol()] = d
}

func (r *Registry) Get(p Protocol) (Driver, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.drivers[p]
	return d, ok
}

func (r *Registry) List() []Driver {
	r.mu.RLock()
	defer r.mu.RUnlock()
	list := make([]Driver, 0, len(r.drivers))
	for _, d := range r.drivers {
		list = append(list, d)
	}
	return list
}
