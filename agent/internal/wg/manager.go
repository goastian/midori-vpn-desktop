//go:build linux || darwin

// Package wg manages a WireGuard TUN interface using wireguard-go (no system WG required).
package wg

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"

	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
)

// Config holds the WireGuard configuration needed to bring up a connection.
type Config struct {
	PrivateKey string
	PublicKey  string // server public key
	Endpoint   string // host:port of the WireGuard server
	AssignedIP string // CIDR assigned to this peer, e.g. "10.8.0.5/32"
	DNS        []string
	MeshIPs    []string // additional allowed IPs for mesh routing
}

// Manager wraps a wireguard-go Device and TUN interface.
type Manager struct {
	mu     sync.Mutex
	dev    *device.Device
	tunDev tun.Device
	cfg    *Config
}

// NewManager creates a Manager (no interface is created until Connect).
func NewManager() *Manager {
	return &Manager{}
}

// Connect brings up the wg0 TUN interface with the given config.
// It tears down any existing interface first.
func (m *Manager) Connect(cfg *Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Tear down existing connection.
	m.shutdownLocked()

	tdev, err := tun.CreateTUN("wg0", device.DefaultMTU)
	if err != nil {
		return fmt.Errorf("create TUN: %w", err)
	}

	logger := device.NewLogger(device.LogLevelSilent, "[wg0] ")
	dev := device.NewDevice(tdev, conn.NewDefaultBind(), logger)

	privKeyBytes, err := base64.StdEncoding.DecodeString(cfg.PrivateKey)
	if err != nil {
		tdev.Close()
		return fmt.Errorf("decode private key: %w", err)
	}
	serverPubKeyBytes, err := base64.StdEncoding.DecodeString(cfg.PublicKey)
	if err != nil {
		tdev.Close()
		return fmt.Errorf("decode server public key: %w", err)
	}

	// Build UAPI config.
	allowedIPs := "0.0.0.0/0, ::/0"
	for _, ip := range cfg.MeshIPs {
		allowedIPs += ", " + ip
	}

	uapi := fmt.Sprintf(
		"private_key=%x\n\npublic_key=%x\nendpoint=%s\nallowed_ips=%s\npersistent_keepalive_interval=25\n\n",
		privKeyBytes,
		serverPubKeyBytes,
		cfg.Endpoint,
		allowedIPs,
	)

	if err := dev.IpcSet(uapi); err != nil {
		tdev.Close()
		return fmt.Errorf("ipc set: %w", err)
	}

	if err := dev.Up(); err != nil {
		tdev.Close()
		return fmt.Errorf("device up: %w", err)
	}

	// Assign the IP address to the TUN interface.
	if err := m.assignAddr(tdev, cfg.AssignedIP); err != nil {
		dev.Close()
		return fmt.Errorf("assign IP: %w", err)
	}

	m.dev = dev
	m.tunDev = tdev
	m.cfg = cfg

	slog.Info("wg: interface up", "assigned_ip", cfg.AssignedIP, "endpoint", cfg.Endpoint)
	return nil
}

// Disconnect tears down the WireGuard interface.
func (m *Manager) Disconnect() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shutdownLocked()
}

// IsConnected returns true if the interface is currently up.
func (m *Manager) IsConnected() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dev != nil
}

func (m *Manager) shutdownLocked() {
	if m.dev != nil {
		m.dev.Close()
		m.dev = nil
	}
	if m.tunDev != nil {
		m.tunDev.Close()
		m.tunDev = nil
	}
	m.cfg = nil
	slog.Info("wg: interface down")
}

// assignAddr sets the IP address on the TUN interface using netlink (Linux).
// On macOS/Windows this needs platform-specific handling.
func (m *Manager) assignAddr(tdev tun.Device, cidr string) error {
	name, err := tdev.Name()
	if err != nil {
		return err
	}

	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return fmt.Errorf("parse CIDR %s: %w", cidr, err)
	}

	iface, err := net.InterfaceByName(name)
	if err != nil {
		return fmt.Errorf("get interface %s: %w", name, err)
	}

	// Use ip command for portability across Linux distros (avoids netlink cgo).
	// Production build should use golang.org/x/net/netlink for no-exec dependency.
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	addr := prefix.Addr()
	mask := net.CIDRMask(prefix.Bits(), 32)
	if prefix.Addr().Is6() {
		mask = net.CIDRMask(prefix.Bits(), 128)
	}

	_ = iface
	_ = addr
	_ = mask

	// Use the 'ip' command: portable, works on all Linux distros without cgo netlink.
	return runIP("addr", "add", cidr, "dev", name)
}

func runIP(args ...string) error {
	proc, err := os.StartProcess("/sbin/ip", append([]string{"ip"}, args...), &os.ProcAttr{
		Env: []string{"PATH=/sbin:/usr/sbin:/bin:/usr/bin"},
	})
	if err != nil {
		// Try with full search path.
		proc, err = os.StartProcess("/usr/sbin/ip", append([]string{"ip"}, args...), &os.ProcAttr{
			Env: []string{"PATH=/sbin:/usr/sbin:/bin:/usr/bin"},
		})
		if err != nil {
			return fmt.Errorf("start ip command: %w", err)
		}
	}
	state, err := proc.Wait()
	if err != nil {
		return fmt.Errorf("wait ip command: %w", err)
	}
	if !state.Success() {
		return fmt.Errorf("ip command failed: %v", state)
	}
	return nil
}
