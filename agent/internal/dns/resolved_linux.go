//go:build linux

package dns

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"sync"

	"github.com/goastian/midorivpn-agent/internal/logredact"
)

// resolvedBackend configures DNS for the WireGuard interface through
// systemd-resolved using resolvectl. systemd-resolved owns /etc/resolv.conf
// and rewrites it as needed, so this backend never touches the file directly.
type resolvedBackend struct {
	mu      sync.Mutex
	applied bool
	iface   string
}

func newResolvedBackend() *resolvedBackend { return &resolvedBackend{} }

func (b *resolvedBackend) Kind() Kind { return KindResolved }

func (b *resolvedBackend) Apply(iface string, servers []string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if iface == "" {
		return fmt.Errorf("resolved backend: empty interface name")
	}
	cleaned := make([]string, 0, len(servers))
	for _, s := range servers {
		s = trimSpace(s)
		if s == "" {
			continue
		}
		if net.ParseIP(s) == nil {
			return fmt.Errorf("invalid DNS server %q", s)
		}
		cleaned = append(cleaned, s)
	}
	if len(cleaned) == 0 {
		return nil
	}

	resolvectl := findResolvectl()
	if resolvectl == "" {
		return fmt.Errorf("resolvectl binary not found")
	}

	slog.Info("dns: configuring via resolved", "iface", iface, "servers", logredact.IPs(cleaned))

	dnsArgs := append([]string{"dns", iface}, cleaned...)
	if err := runResolvectl(resolvectl, dnsArgs...); err != nil {
		return fmt.Errorf("resolvectl dns: %w", err)
	}
	// "~." marks the link as the default route for all DNS queries so that
	// system-wide resolution goes through the VPN-provided servers.
	if err := runResolvectl(resolvectl, "domain", iface, "~."); err != nil {
		return fmt.Errorf("resolvectl domain: %w", err)
	}
	// DNSSEC=allow-downgrade matches systemd-resolved's safe default and
	// avoids breaking captive portals / corporate splits.
	_ = runResolvectl(resolvectl, "dnssec", iface, "allow-downgrade")

	b.applied = true
	b.iface = iface
	return nil
}

func (b *resolvedBackend) Restore() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.applied {
		return nil
	}
	resolvectl := findResolvectl()
	if resolvectl == "" {
		b.applied = false
		return nil
	}
	// `resolvectl revert` clears per-link DNS, domain and DNSSEC settings.
	if err := runResolvectl(resolvectl, "revert", b.iface); err != nil {
		slog.Warn("dns: resolvectl revert failed", "err", err)
	}
	b.applied = false
	b.iface = ""
	return nil
}

func findResolvectl() string {
	for _, path := range []string{"/usr/bin/resolvectl", "/bin/resolvectl"} {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

func runResolvectl(bin string, args ...string) error {
	cmd := exec.Command(bin, args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, string(out))
	}
	return nil
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}
