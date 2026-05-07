//go:build linux

// Package netguard manages the Linux kill switch used by the desktop agent.
package netguard

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/goastian/midorivpn-agent/internal/sysstate"
	"golang.org/x/sys/unix"
)

const (
	tableName = "midorivpn_guard"
)

type Guard struct {
	active bool
}

type Scope struct {
	TunnelIface string
	Endpoint    string
	APIURL      string
	AssignedIP  string
	MeshPeerIPs []string
}

func New() *Guard {
	return &Guard{}
}

func (g *Guard) Active() bool {
	return g.active
}

func (g *Guard) Enable(scope Scope) error {
	if scope.TunnelIface == "" {
		return fmt.Errorf("tunnel interface required")
	}
	nft := findNFT()
	if nft == "" {
		return fmt.Errorf("nft command not found")
	}

	_ = runNFT(nft, "delete", "table", "inet", tableName)
	if out, err := runNFTOut(nft, "add", "table", "inet", tableName); err != nil {
		return fmt.Errorf("nft add table: %w: %s", err, strings.TrimSpace(string(out)))
	}
	if out, err := runNFTOut(nft, "add", "chain", "inet", tableName, "output", "{", "type", "filter", "hook", "output", "priority", "0", ";", "policy", "drop", ";", "}"); err != nil {
		_ = g.Disable()
		return fmt.Errorf("nft add output chain: %w: %s", err, strings.TrimSpace(string(out)))
	}
	// INPUT chain: accept established/related replies (WireGuard handshake responses
	// and encrypted UDP replies arrive on the physical interface before decryption;
	// decrypted packets arrive via the tunnel interface) so systems with strict
	// INPUT DROP policies don't silently drop incoming tunnel traffic.
	if out, err := runNFTOut(nft, "add", "chain", "inet", tableName, "input", "{", "type", "filter", "hook", "input", "priority", "0", ";", "policy", "accept", ";", "}"); err != nil {
		_ = g.Disable()
		return fmt.Errorf("nft add input chain: %w: %s", err, strings.TrimSpace(string(out)))
	}

	rules := [][]string{
		// OUTPUT rules
		{"add", "rule", "inet", tableName, "output", "oifname", "lo", "accept"},
		{"add", "rule", "inet", tableName, "output", "ct", "state", "established,related", "accept"},
		// INPUT rules: allow established/related (WireGuard UDP replies from server)
		// and scoped decrypted packets arriving on the tunnel interface.
		{"add", "rule", "inet", tableName, "input", "ct", "state", "established,related", "accept"},
		{"add", "rule", "inet", tableName, "input", "iifname", "lo", "accept"},
	}
	rules = append(rules, tunnelRules(scope)...)
	for _, rule := range rules {
		if out, err := runNFTOut(nft, rule...); err != nil {
			_ = g.Disable()
			return fmt.Errorf("nft rule %q: %w: %s", strings.Join(rule, " "), err, strings.TrimSpace(string(out)))
		}
	}

	for _, hostPort := range []string{scope.Endpoint, apiHostPort(scope.APIURL)} {
		if hostPort == "" {
			continue
		}
		host, port, err := splitHostPortDefault(hostPort, "443")
		if err != nil {
			continue
		}
		ips, _ := net.LookupIP(host)
		for _, ip := range ips {
			family := "ip"
			addrKey := "daddr"
			if ip.To4() == nil {
				family = "ip6"
			}
			args := []string{"add", "rule", "inet", tableName, "output", family, addrKey, ip.String(), "tcp", "dport", port, "accept"}
			if out, err := runNFTOut(nft, args...); err != nil {
				_ = g.Disable()
				return fmt.Errorf("nft allow endpoint %s:%s: %w: %s", ip, port, err, strings.TrimSpace(string(out)))
			}
			args = []string{"add", "rule", "inet", tableName, "output", family, addrKey, ip.String(), "udp", "dport", port, "accept"}
			_, _ = runNFTOut(nft, args...)
		}
	}

	g.active = true
	// Record a cleanup entry so sysstate.RevertAll() can remove the kill-switch
	// table even if Guard.Disable() is never called explicitly (e.g. on crash).
	sysstate.Global.Record("netguard:inet:"+tableName, func(_ context.Context) {
		_ = g.Disable()
	})
	return nil
}

func tunnelRules(scope Scope) [][]string {
	assigned := strings.TrimSpace(scope.AssignedIP)
	if assigned == "" {
		return [][]string{
			{"add", "rule", "inet", tableName, "output", "oifname", scope.TunnelIface, "accept"},
			{"add", "rule", "inet", tableName, "input", "iifname", scope.TunnelIface, "accept"},
		}
	}

	family := nftFamily(assigned)
	rules := [][]string{
		{"add", "rule", "inet", tableName, "output", "oifname", scope.TunnelIface, family, "saddr", assigned, "accept"},
	}
	for _, peerIP := range normalizedIPs(scope.MeshPeerIPs) {
		if nftFamily(peerIP) != family {
			continue
		}
		rules = append(rules,
			[]string{"add", "rule", "inet", tableName, "output", "oifname", scope.TunnelIface, family, "saddr", assigned, family, "daddr", peerIP, "accept"},
			[]string{"add", "rule", "inet", tableName, "input", "iifname", scope.TunnelIface, family, "saddr", peerIP, family, "daddr", assigned, "accept"},
		)
	}
	return rules
}

func normalizedIPs(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func nftFamily(addr string) string {
	host := addr
	if slash := strings.IndexByte(host, '/'); slash >= 0 {
		host = host[:slash]
	}
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		return "ip6"
	}
	return "ip"
}

func (g *Guard) Disable() error {
	nft := findNFT()
	if nft == "" {
		g.active = false
		return nil
	}
	_ = runNFT(nft, "delete", "table", "inet", tableName)
	g.active = false
	return nil
}

func findNFT() string {
	for _, path := range []string{"/sbin/nft", "/usr/sbin/nft", "/usr/bin/nft", "/bin/nft"} {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	return ""
}

func runNFT(nft string, args ...string) error {
	_, err := runNFTOut(nft, args...)
	return err
}

func runNFTOut(nft string, args ...string) ([]byte, error) {
	setNetAdminInheritable()
	cmd := exec.Command(nft, args...)
	cmd.Env = []string{"PATH=/sbin:/usr/sbin:/bin:/usr/bin"}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		AmbientCaps: []uintptr{unix.CAP_NET_ADMIN},
	}
	return cmd.CombinedOutput()
}

func setNetAdminInheritable() {
	var hdr unix.CapUserHeader
	hdr.Version = unix.LINUX_CAPABILITY_VERSION_3
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return
	}
	data[0].Inheritable |= 1 << unix.CAP_NET_ADMIN
	_ = unix.Capset(&hdr, &data[0])
}

func apiHostPort(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	if u.Port() != "" {
		return u.Host
	}
	if u.Scheme == "http" {
		return net.JoinHostPort(u.Hostname(), "80")
	}
	return net.JoinHostPort(u.Hostname(), "443")
}

func splitHostPortDefault(raw, defaultPort string) (string, string, error) {
	host, port, err := net.SplitHostPort(raw)
	if err == nil {
		return host, port, nil
	}
	if strings.Contains(raw, ":") && net.ParseIP(raw) == nil {
		return "", "", err
	}
	return raw, defaultPort, nil
}
