// Package firewall integrates MidoriVPN with the host's active firewall so
// the WireGuard mesh interface (wg0) and the loopback RPC port aren't
// silently dropped on systems with strict default policies (Fedora /
// firewalld, Ubuntu / ufw, Arch / nftables).
//
// All rules we install carry the comment / set name "midorivpn-managed" so
// they can be cleanly removed on uninstall via:
//
//	midorivpn-agent --firewall-cleanup
//
// Detection order:
//  1. firewall-cmd  (firewalld, RHEL/Fedora/SUSE)
//  2. ufw           (Debian/Ubuntu)
//  3. nft           (Arch / minimal systems)
//
// If none are present the function is a no-op — the user runs no firewall
// and we have nothing to do.
package firewall

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/goastian/midorivpn-agent/internal/sysstate"
)

const ManagedTag = "midorivpn-managed"

type Scope struct {
	Name              string
	Interface         string
	RPCPort           int
	MeshDestinationIP string
	MeshPeerIPs       []string
	MeshProxyPort     int
}

// Backend reports which firewall (if any) was detected.
type Backend string

const (
	BackendNone      Backend = "none"
	BackendFirewalld Backend = "firewalld"
	BackendUFW       Backend = "ufw"
	BackendNftables  Backend = "nftables"
)

// Detect returns the first available firewall backend on $PATH.
func Detect() Backend {
	if _, err := exec.LookPath("firewall-cmd"); err == nil {
		// Verify the daemon is actually running, not just installed.
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		defer cancel()
		if err := exec.CommandContext(ctx, "firewall-cmd", "--state").Run(); err == nil {
			return BackendFirewalld
		}
	}
	if _, err := exec.LookPath("ufw"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		defer cancel()
		out, _ := exec.CommandContext(ctx, "ufw", "status").Output()
		if strings.Contains(strings.ToLower(string(out)), "active") {
			return BackendUFW
		}
	}
	if _, err := exec.LookPath("nft"); err == nil {
		return BackendNftables
	}
	return BackendNone
}

// Allow installs the rules required by MidoriVPN: trust the wg0 interface
// (mesh peer traffic) and accept the loopback RPC port from local UID.
//
// All commands are idempotent — re-running Allow is safe.
// On success, a cleanup entry is recorded in sysstate.Global so that
// RevertAll() can remove the rules on agent shutdown.
func Allow(ctx context.Context, scope Scope) error {
	scope = normalizeScope(scope)
	backend := Detect()
	var err error
	switch backend {
	case BackendFirewalld:
		err = allowFirewalld(ctx, scope)
	case BackendUFW:
		err = allowUFW(ctx, scope)
	case BackendNftables:
		err = allowNftables(ctx, scope)
	default:
		slog.Debug("firewall: no active backend detected, skipping")
		return nil
	}
	if err != nil {
		return err
	}
	// Record cleanup so shutdown can revert even if Cleanup() is never called
	// explicitly via the mesh-disable RPC path.
	capturedScope := scope
	capturedBackend := backend
	sysstate.Global.Record("firewall:"+scope.Name+":"+string(capturedBackend), func(ctx context.Context) {
		_ = cleanup(ctx, capturedBackend, capturedScope)
	})
	return nil
}

// Cleanup removes every rule tagged ManagedTag. Called on uninstall and on
// agent shutdown via SIGTERM (best-effort).
func Cleanup(ctx context.Context, wgIface string) error {
	switch Detect() {
	case BackendFirewalld:
		return cleanupFirewalldLegacy(ctx, wgIface)
	case BackendUFW:
		return cleanupUFW(ctx, ManagedTag)
	case BackendNftables:
		return cleanupNftables(ctx, ManagedTag)
	default:
		return nil
	}
}

func cleanup(ctx context.Context, backend Backend, scope Scope) error {
	switch backend {
	case BackendFirewalld:
		return cleanupFirewalld(ctx, scope)
	case BackendUFW:
		return cleanupUFW(ctx, scopeTag(scope.Name))
	case BackendNftables:
		return cleanupNftables(ctx, nftTableName(scope.Name))
	default:
		return nil
	}
}

// ─── firewalld ──────────────────────────────────────────────────────────────

func allowFirewalld(ctx context.Context, scope Scope) error {
	_ = cleanupFirewalld(ctx, scope)
	rules := firewalldRichRules(scope)
	for _, zone := range firewalldTargetZones(ctx) {
		for _, rule := range rules {
			args := []string{"--permanent"}
			if zone != "" {
				args = append(args, "--zone="+zone)
			}
			args = append(args, "--add-rich-rule="+rule)
			if err := run(ctx, "firewall-cmd", args...); err != nil {
				return fmt.Errorf("firewalld add-rich-rule (zone=%s): %w", zone, err)
			}
		}
	}
	return run(ctx, "firewall-cmd", "--reload")
}

func cleanupFirewalld(ctx context.Context, scope Scope) error {
	rules := firewalldRichRules(scope)
	for _, zone := range firewalldTargetZones(ctx) {
		for _, rule := range rules {
			args := []string{"--permanent"}
			if zone != "" {
				args = append(args, "--zone="+zone)
			}
			args = append(args, "--remove-rich-rule="+rule)
			_ = run(ctx, "firewall-cmd", args...)
		}
	}
	_ = run(ctx, "firewall-cmd", "--reload")
	return nil
}

func firewalldTargetZones(ctx context.Context) []string {
	out, err := exec.CommandContext(ctx, "firewall-cmd", "--get-active-zones").Output()
	if err == nil {
		zones := make([]string, 0)
		seen := make(map[string]struct{})
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.Contains(line, ":") {
				continue
			}
			zone := strings.Fields(line)[0]
			if _, ok := seen[zone]; ok {
				continue
			}
			seen[zone] = struct{}{}
			zones = append(zones, zone)
		}
		if len(zones) > 0 {
			return zones
		}
	}

	if out, err := exec.CommandContext(ctx, "firewall-cmd", "--get-default-zone").Output(); err == nil {
		zone := strings.TrimSpace(string(out))
		if zone != "" {
			return []string{zone}
		}
	}

	// Fallback to no explicit zone, equivalent to firewalld default behavior.
	return []string{""}
}

func cleanupFirewalldLegacy(ctx context.Context, iface string) error {
	_ = run(ctx, "firewall-cmd", "--permanent", "--zone=trusted", "--remove-interface="+iface)
	_ = run(ctx, "firewall-cmd", "--reload")
	return nil
}

// ─── ufw ────────────────────────────────────────────────────────────────────

func allowUFW(ctx context.Context, scope Scope) error {
	_ = cleanupUFW(ctx, scopeTag(scope.Name))
	if err := run(ctx, "ufw", "allow", "from", "127.0.0.1", "to", "127.0.0.1",
		"port", fmt.Sprint(scope.RPCPort), "proto", "tcp", "comment", scopeTag(scope.Name)); err != nil {
		return fmt.Errorf("ufw allow rpc: %w", err)
	}
	for _, peerIP := range scope.MeshPeerIPs {
		args := []string{"allow", "in", "on", scope.Interface, "from", peerIP, "to", scope.MeshDestinationIP}
		if scope.MeshProxyPort > 0 {
			args = append(args, "port", fmt.Sprint(scope.MeshProxyPort), "proto", "tcp")
		}
		args = append(args, "comment", scopeTag(scope.Name))
		if err := run(ctx, "ufw", args...); err != nil {
			return fmt.Errorf("ufw allow mesh peer: %w", err)
		}
	}
	return nil
}

func cleanupUFW(ctx context.Context, tag string) error {
	// Iterate numbered rules and delete those whose "# comment" contains the tag.
	out, err := exec.CommandContext(ctx, "ufw", "status", "numbered").Output()
	if err != nil {
		return err
	}
	// Delete from the bottom up so indices stay valid.
	lines := strings.Split(string(out), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if !strings.Contains(lines[i], tag) {
			continue
		}
		// Format: "[ N] ..."
		open := strings.IndexByte(lines[i], '[')
		close := strings.IndexByte(lines[i], ']')
		if open < 0 || close < 0 || close <= open {
			continue
		}
		idx := strings.TrimSpace(lines[i][open+1 : close])
		// `ufw delete N` requires a confirmation; --force skips it.
		_ = run(ctx, "ufw", "--force", "delete", idx)
	}
	return nil
}

// ─── nftables (manual / Arch) ───────────────────────────────────────────────

func allowNftables(ctx context.Context, scope Scope) error {
	// Create a dedicated table+set so cleanup is a single drop.
	table := nftTableName(scope.Name)
	_ = cleanupNftables(ctx, table)
	var b strings.Builder
	fmt.Fprintf(&b, "add table inet %s\n", table)
	fmt.Fprintf(&b, "add chain inet %s input { type filter hook input priority 0; policy accept; }\n", table)
	fmt.Fprintf(&b, "add rule inet %s input iifname \"lo\" ip saddr 127.0.0.1 ip daddr 127.0.0.1 tcp dport %d accept\n", table, scope.RPCPort)
	for _, peerIP := range scope.MeshPeerIPs {
		family := nftFamily(peerIP)
		fmt.Fprintf(&b, "add rule inet %s input iifname \"%s\" %s saddr %s %s daddr %s",
			table, scope.Interface, family, peerIP, family, scope.MeshDestinationIP)
		if scope.MeshProxyPort > 0 {
			fmt.Fprintf(&b, " tcp dport %d", scope.MeshProxyPort)
		}
		b.WriteString(" accept\n")
	}

	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(b.String())
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft load: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func cleanupNftables(ctx context.Context, table string) error {
	_ = run(ctx, "nft", "delete", "table", "inet", table)
	return nil
}

// ─── helpers ────────────────────────────────────────────────────────────────

func normalizeScope(scope Scope) Scope {
	if scope.Name == "" {
		scope.Name = "default"
	}
	if scope.Interface == "" {
		scope.Interface = "wg0"
	}
	scope.MeshDestinationIP = strings.TrimSpace(scope.MeshDestinationIP)
	scope.MeshPeerIPs = uniqueIPs(scope.MeshPeerIPs)
	if scope.MeshDestinationIP == "" || net.ParseIP(stripCIDR(scope.MeshDestinationIP)) == nil {
		scope.MeshDestinationIP = ""
		scope.MeshPeerIPs = nil
	}
	if scope.RPCPort <= 0 {
		scope.RPCPort = 7071
	}
	return scope
}

func firewalldRichRules(scope Scope) []string {
	rules := []string{
		fmt.Sprintf("rule family=ipv4 source address=127.0.0.1 destination address=127.0.0.1 port port=%d protocol=tcp accept", scope.RPCPort),
	}
	destFamily := nftFamily(scope.MeshDestinationIP)
	for _, peerIP := range scope.MeshPeerIPs {
		if nftFamily(peerIP) != destFamily {
			continue
		}
		family := "ipv4"
		if destFamily == "ip6" {
			family = "ipv6"
		}
		rule := fmt.Sprintf("rule family=%s source address=%s destination address=%s", family, peerIP, scope.MeshDestinationIP)
		if scope.MeshProxyPort > 0 {
			rule += fmt.Sprintf(" port port=%d protocol=tcp", scope.MeshProxyPort)
		}
		rules = append(rules, rule+" accept")
	}
	return rules
}

func uniqueIPs(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || net.ParseIP(stripCIDR(value)) == nil {
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

func stripCIDR(value string) string {
	if slash := strings.IndexByte(value, '/'); slash >= 0 {
		return value[:slash]
	}
	return value
}

func nftFamily(addr string) string {
	if ip := net.ParseIP(stripCIDR(addr)); ip != nil && ip.To4() == nil {
		return "ip6"
	}
	return "ip"
}

func scopeTag(name string) string {
	return ManagedTag + "-" + sanitizeName(name)
}

func nftTableName(name string) string {
	return "midorivpn_fw_" + sanitizeName(name)
}

func sanitizeName(name string) string {
	name = strings.ToLower(name)
	re := regexp.MustCompile(`[^a-z0-9_]+`)
	name = re.ReplaceAllString(name, "_")
	name = strings.Trim(name, "_")
	if name == "" {
		return "default"
	}
	return name
}

func run(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "),
			err, strings.TrimSpace(string(out)))
	}
	slog.Debug("firewall cmd", "cmd", name, "args", args)
	return nil
}
