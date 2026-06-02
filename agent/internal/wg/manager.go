//go:build linux

// Package wg manages a WireGuard TUN interface using wireguard-go (no system WG required).
package wg

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/goastian/midorivpn-agent/internal/dns"
	"github.com/goastian/midorivpn-agent/internal/logredact"
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
	mu            sync.Mutex
	dev           *device.Device
	tunDev        tun.Device
	cfg           *Config
	defaultRoutes []string
	dnsBackend    dns.Backend
	dnsApplied    bool
	// saved sysctl values restored on disconnect
	rpFilterSaved map[string]string
}

// NewManager creates a Manager (no interface is created until Connect).
// The DNS backend is auto-detected on the first Connect call.
func NewManager() *Manager {
	return &Manager{}
}

// DNSBackendKind returns the kind of DNS backend the manager will use.
// If no backend has been initialised yet it triggers detection once.
func (m *Manager) DNSBackendKind() dns.Kind {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.dnsBackend == nil {
		m.dnsBackend = dns.Detect()
	}
	return m.dnsBackend.Kind()
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
	// wireguard-go's IpcSetOperation treats a blank line as "terminate
	// operation", so there must be NO blank lines in the middle of the
	// config.  Each AllowedIP must be on its own "allowed_ip=<CIDR>" line
	// (singular key, not a comma-separated "allowed_ips=…" list).
	var uapiBuilder strings.Builder
	fmt.Fprintf(&uapiBuilder, "private_key=%x\n", privKeyBytes)
	fmt.Fprintf(&uapiBuilder, "public_key=%x\n", serverPubKeyBytes)
	fmt.Fprintf(&uapiBuilder, "endpoint=%s\n", cfg.Endpoint)
	fmt.Fprintf(&uapiBuilder, "persistent_keepalive_interval=25\n")
	fmt.Fprintf(&uapiBuilder, "allowed_ip=0.0.0.0/0\n")
	fmt.Fprintf(&uapiBuilder, "allowed_ip=::/0\n")
	for _, ip := range cfg.MeshIPs {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		if _, err := netip.ParsePrefix(ip); err != nil {
			slog.Warn("wg: skipping invalid mesh IP", "ip", ip, "err", err)
			continue
		}
		fmt.Fprintf(&uapiBuilder, "allowed_ip=%s\n", ip)
	}
	// Blank line terminates the UAPI set operation.
	uapiBuilder.WriteByte('\n')
	uapi := uapiBuilder.String()

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

	if err := m.configureSystemTunnel(tdev, cfg); err != nil {
		dev.Close()
		tdev.Close()
		return fmt.Errorf("configure full tunnel: %w", err)
	}

	m.dev = dev
	m.tunDev = tdev
	m.cfg = cfg

	slog.Info("wg: interface up", "assigned_ip", logredact.IP(cfg.AssignedIP), "endpoint", logredact.HostPort(cfg.Endpoint))
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
	m.restoreSystemTunnel()
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

func (m *Manager) DNSProtected() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.dnsApplied
}

func (m *Manager) InterfaceName() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tunDev == nil {
		return ""
	}
	name, _ := m.tunDev.Name()
	return name
}

// ByteCounters returns tx/rx byte counters from kernel interface stats.
func (m *Manager) ByteCounters() (tx int64, rx int64, ok bool) {
	m.mu.Lock()
	if m.tunDev == nil {
		m.mu.Unlock()
		return 0, 0, false
	}
	name, err := m.tunDev.Name()
	m.mu.Unlock()
	if err != nil || name == "" {
		return 0, 0, false
	}

	base := "/sys/class/net/" + name + "/statistics/"
	tx, err = readInt64File(base + "tx_bytes")
	if err != nil {
		return 0, 0, false
	}
	rx, err = readInt64File(base + "rx_bytes")
	if err != nil {
		return 0, 0, false
	}
	return tx, rx, true
}

func readInt64File(path string) (int64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	v, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, err
	}
	return v, nil
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

	// Bring the link up explicitly before assigning the address. device.Up()
	// starts the WireGuard engine, but Linux routing tools still expect the
	// netdev itself to be UP.
	// MTU 1280 for stability over throughput; reduces packet fragmentation
	// and improves compatibility with constrained network paths.
	if err := runIP("link", "set", "dev", name, "up", "mtu", "1280"); err != nil {
		return fmt.Errorf("set link up: %w", err)
	}

	// Use replace instead of add so reconnects recover from a stale address left
	// by a previous agent crash or failed attempt.
	return runIP("addr", "replace", cidr, "dev", name)
}

func (m *Manager) configureSystemTunnel(tdev tun.Device, cfg *Config) error {
	name, err := tdev.Name()
	if err != nil {
		return err
	}

	defaults, err := outputIP("route", "show", "default")
	if err != nil {
		return fmt.Errorf("save default route: %w", err)
	}
	m.defaultRoutes = splitNonEmptyLines(defaults)

	if err := m.pinEndpointRoute(cfg.Endpoint); err != nil {
		return err
	}

	// Set rp_filter to loose (2) so that reply packets arriving on wg0 are not
	// dropped by the kernel's reverse-path filter. wg-quick does the same.
	m.rpFilterSaved = make(map[string]string)
	rpKeys := []string{
		"net.ipv4.conf.all.rp_filter",
		"net.ipv4.conf.default.rp_filter",
		"net.ipv4.conf." + name + ".rp_filter",
	}
	for _, key := range rpKeys {
		if cur, e := sysctlGet(key); e == nil {
			m.rpFilterSaved[key] = cur
			_ = sysctlSet(key, "2")
		}
	}

	for _, line := range m.defaultRoutes {
		args := append([]string{"route", "del"}, strings.Fields(line)...)
		_ = runIP(args...)
	}
	if err := runIP("route", "replace", "default", "dev", name); err != nil {
		m.restoreSystemTunnel()
		return fmt.Errorf("replace default route: %w", err)
	}
	// Best-effort IPv6 default via tunnel (suppresses AAAA leaks outside tunnel).
	_ = runIP("-6", "route", "replace", "default", "dev", name)

	slog.Info("dns: config has DNS servers", "count", len(cfg.DNS), "servers", logredact.IPs(cfg.DNS))
	if len(cfg.DNS) > 0 {
		if err := m.applyDNS(name, cfg.DNS); err != nil {
			m.restoreSystemTunnel()
			return err
		}
	} else {
		slog.Warn("dns: no DNS servers provided by server")
	}
	return nil
}

func (m *Manager) applyDNS(iface string, servers []string) error {
	if m.dnsBackend == nil {
		m.dnsBackend = dns.Detect()
	}
	if err := m.dnsBackend.Apply(iface, servers); err != nil {
		return fmt.Errorf("dns apply (%s): %w", m.dnsBackend.Kind(), err)
	}
	m.dnsApplied = true
	return nil
}

func (m *Manager) pinEndpointRoute(endpoint string) error {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		host = endpoint
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return fmt.Errorf("resolve endpoint %q: %w", host, err)
	}
	var endpointIP net.IP
	for _, ip := range ips {
		if ip4 := ip.To4(); ip4 != nil {
			endpointIP = ip4
			break
		}
	}
	if endpointIP == nil {
		return fmt.Errorf("endpoint %q has no IPv4 address", host)
	}

	route, err := outputIP("route", "get", endpointIP.String())
	if err != nil {
		return fmt.Errorf("discover endpoint route: %w", err)
	}
	fields := strings.Fields(route)
	dev := ""
	via := ""
	for i := 0; i+1 < len(fields); i++ {
		switch fields[i] {
		case "dev":
			dev = fields[i+1]
		case "via":
			via = fields[i+1]
		}
	}
	if dev == "" {
		return fmt.Errorf("could not parse endpoint route %q", route)
	}
	args := []string{"route", "replace", endpointIP.String() + "/32"}
	if via != "" {
		args = append(args, "via", via)
	}
	args = append(args, "dev", dev)
	return runIP(args...)
}

func (m *Manager) restoreSystemTunnel() {
	if m.dnsApplied && m.dnsBackend != nil {
		if err := m.dnsBackend.Restore(); err != nil {
			slog.Warn("wg: failed to restore DNS", "err", err)
		}
	}
	m.dnsApplied = false

	if m.tunDev != nil {
		if name, err := m.tunDev.Name(); err == nil && name != "" {
			_ = runIP("route", "del", "default", "dev", name)
			_ = runIP("-6", "route", "del", "default", "dev", name)
		}
	}
	for _, line := range m.defaultRoutes {
		args := append([]string{"route", "replace"}, strings.Fields(line)...)
		if err := runIP(args...); err != nil {
			slog.Warn("wg: failed to restore default route", "route", line, "err", err)
		}
	}
	m.defaultRoutes = nil

	// Restore rp_filter values saved before tunnel setup.
	for key, val := range m.rpFilterSaved {
		_ = sysctlSet(key, val)
	}
	m.rpFilterSaved = nil
}

func splitNonEmptyLines(s string) []string {
	var lines []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func runIP(args ...string) error {
	ipBin := findIPBin()
	if ipBin == "" {
		return fmt.Errorf("ip command not found")
	}

	setNetAdminInheritable()

	cmd := exec.Command(ipBin, args...)
	cmd.Env = []string{"PATH=/sbin:/usr/sbin:/bin:/usr/bin"}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		AmbientCaps: []uintptr{unix.CAP_NET_ADMIN},
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip command failed: %w: %s", err, string(out))
	}
	return nil
}

func outputIP(args ...string) (string, error) {
	ipBin := findIPBin()
	if ipBin == "" {
		return "", fmt.Errorf("ip command not found")
	}
	cmd := exec.Command(ipBin, args...)
	cmd.Env = []string{"PATH=/sbin:/usr/sbin:/bin:/usr/bin"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("ip command failed: %w: %s", err, string(out))
	}
	return string(out), nil
}

func findIPBin() string {
	for _, path := range []string{"/sbin/ip", "/usr/sbin/ip", "/bin/ip", "/usr/bin/ip"} {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

func setNetAdminInheritable() {
	var hdr unix.CapUserHeader
	hdr.Version = unix.LINUX_CAPABILITY_VERSION_3
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return
	}
	data[0].Inheritable |= 1 << unix.CAP_NET_ADMIN
	unix.Capset(&hdr, &data[0]) //nolint:errcheck
}

// sysctlGet reads a sysctl value from /proc/sys.
// key is dot-separated (e.g. "net.ipv4.conf.all.rp_filter").
func sysctlGet(key string) (string, error) {
	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// sysctlSet writes a sysctl value to /proc/sys (requires CAP_NET_ADMIN).
func sysctlSet(key, value string) error {
	path := "/proc/sys/" + strings.ReplaceAll(key, ".", "/")
	return os.WriteFile(path, []byte(value+"\n"), 0o644)
}
