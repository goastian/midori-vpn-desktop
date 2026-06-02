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
	// Direct instructs Allow to use the nftables backend directly, bypassing
	// D-Bus firewall managers (firewalld, ufw) that require polkit
	// authentication for every rule change. Set this when the caller already
	// holds CAP_NET_ADMIN and can write nft rules without privilege escalation.
	Direct bool
}

// Backend reports which firewall (if any) was detected.
type Backend string

const (
	BackendNone      Backend = "none"
	BackendFirewalld Backend = "firewalld"
	BackendUFW       Backend = "ufw"
	BackendNftables  Backend = "nftables"
)

// findExe resolves a command name to an absolute path. It first consults
// $PATH (exec.LookPath) and then falls back to well-known sbin directories
// that desktop-session processes often lack in their PATH.
func findExe(name string) string {
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	for _, dir := range []string{"/usr/sbin", "/sbin", "/usr/bin", "/bin"} {
		p := dir + "/" + name
		if _, err := exec.LookPath(p); err == nil {
			return p
		}
	}
	return ""
}

// Detect returns the first available firewall backend on $PATH or common sbin
// directories (the agent may run with a restricted PATH from Tauri).
func Detect() Backend {
	if fwCmd := findExe("firewall-cmd"); fwCmd != "" {
		// Verify the daemon is actually running, not just installed.
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		defer cancel()
		if err := exec.CommandContext(ctx, fwCmd, "--state").Run(); err == nil {
			return BackendFirewalld
		}
	}
	if ufwCmd := findExe("ufw"); ufwCmd != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		defer cancel()
		out, _ := exec.CommandContext(ctx, ufwCmd, "status").Output()
		if strings.Contains(strings.ToLower(string(out)), "active") {
			return BackendUFW
		}
	}
	if findExe("nft") != "" {
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
	slog.Info("firewall: Allow called", "direct", scope.Direct, "detected_backend", backend)
	// When the caller has CAP_NET_ADMIN it can write nft rules directly without
	// going through firewalld or ufw's D-Bus interfaces (which require polkit
	// authentication for every individual rule and cause cascading cancelled
	// dialogs in desktop polkit agents). Fall through to nftables in that case.
	if scope.Direct && (backend == BackendFirewalld || backend == BackendUFW) {
		if findExe("nft") != "" {
			backend = BackendNftables
			slog.Info("firewall: Direct mode — redirecting to nftables")
		} else {
			// nft not available — nothing we can do silently; skip.
			slog.Info("firewall: Direct mode requested but nft not found, skipping")
			return nil
		}
	}
	var err error
	slog.Info("firewall: Allow using backend", "backend", backend)
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
// When direct is true and the active backend is firewalld or ufw, cleanup
// targets nftables directly (no polkit prompt required when CAP_NET_ADMIN
// is held), mirroring the same bypass used in Allow.
func Cleanup(ctx context.Context, wgIface string, direct bool) error {
	backend := Detect()
	slog.Info("firewall: Cleanup called", "direct", direct, "detected_backend", backend)
	if direct && (backend == BackendFirewalld || backend == BackendUFW) {
		if findExe("nft") != "" {
			backend = BackendNftables
			slog.Info("firewall: Cleanup Direct mode — redirecting to nftables")
		} else {
			return nil
		}
	}
	slog.Info("firewall: Cleanup using backend", "backend", backend)
	switch backend {
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
	fwCmd := findExe("firewall-cmd")
	if fwCmd == "" {
		return []string{""}
	}
	out, err := exec.CommandContext(ctx, fwCmd, "--get-active-zones").Output()
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

	if out, err := exec.CommandContext(ctx, fwCmd, "--get-default-zone").Output(); err == nil {
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
	ufwCmd := findExe("ufw")
	if ufwCmd == "" {
		return nil
	}
	// Iterate numbered rules and delete those whose "# comment" contains the tag.
	out, err := exec.CommandContext(ctx, ufwCmd, "status", "numbered").Output()
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
	// Create a dedicated table+chain so cleanup is a single drop.
	// Use individual nft subcommands rather than "nft -f -" (stdin batch mode),
	// because batch mode triggers a full netlink cache init that fails when the
	// process runs with file capabilities instead of full root privileges.
	table := nftTableName(scope.Name)
	_ = cleanupNftables(ctx, table)

	if err := run(ctx, "nft", "add", "table", "inet", table); err != nil {
		return fmt.Errorf("nft add table: %w", err)
	}
	if err := run(ctx, "nft", "add", "chain", "inet", table, "input",
		"{ type filter hook input priority 0 ; policy accept ; }"); err != nil {
		return fmt.Errorf("nft add chain: %w", err)
	}
	if err := run(ctx, "nft", "add", "rule", "inet", table, "input",
		"iifname", "lo",
		"ip", "saddr", "127.0.0.1", "ip", "daddr", "127.0.0.1",
		"tcp", "dport", fmt.Sprint(scope.RPCPort), "accept"); err != nil {
		return fmt.Errorf("nft add rpc rule: %w", err)
	}
	for _, peerIP := range scope.MeshPeerIPs {
		family := nftFamily(peerIP)
		args := []string{
			"add", "rule", "inet", table, "input",
			"iifname", scope.Interface,
			family, "saddr", peerIP,
			family, "daddr", scope.MeshDestinationIP,
		}
		if scope.MeshProxyPort > 0 {
			args = append(args, "tcp", "dport", fmt.Sprint(scope.MeshProxyPort))
		}
		args = append(args, "accept")
		if err := run(ctx, "nft", args...); err != nil {
			return fmt.Errorf("nft add mesh peer rule: %w", err)
		}
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
	exe := findExe(name)
	if exe == "" {
		return fmt.Errorf("%s: command not found", name)
	}
	cmd := exec.CommandContext(ctx, exe, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w (%s)", name, strings.Join(args, " "),
			err, strings.TrimSpace(string(out)))
	}
	slog.Debug("firewall cmd", "cmd", name, "args", args)
	return nil
}
