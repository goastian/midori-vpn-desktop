//go:build linux

// Package mesh provides helpers for mesh network configuration on Linux.
package mesh

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/goastian/midorivpn-agent/internal/sysstate"
	"golang.org/x/sys/unix"
)

// nftBin is the nftables binary path (nftables is the default on modern distros).
// iptables is tried as a fallback if nft is not available.
const (
	nftBin      = "/sbin/nft"
	iptablesBin = "/sbin/iptables"
)

// nftTable / nftChain used for our NAT rules.
const (
	nftTable = "midorivpn"
	nftChain = "postrouting"
)

func findBin(paths ...string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// enableIPForward enables IPv4 forwarding by writing directly to /proc.
// This does not require sysctl binary.
func enableIPForward() error {
	return os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0644)
}

// setNetAdminInheritable adds CAP_NET_ADMIN to this process's inheritable
// capability set. This is required before ambient caps can be raised in child
// processes (nft), because ambient caps require the cap to be in BOTH the
// permitted AND inheritable sets.
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

// nftRun runs the nft binary with CAP_NET_ADMIN set as an ambient capability
// in the child process, so nft can use netlink without being root.
// setNetAdminInheritable() must have been called first in the parent.
func nftRun(nft string, args ...string) ([]byte, error) {
	cmd := exec.Command(nft, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		AmbientCaps: []uintptr{unix.CAP_NET_ADMIN},
	}
	return cmd.CombinedOutput()
}

// EnableNAT enables IPv4 forwarding and sets up MASQUERADE for the given WAN
// interface using nft (nftables). Falls back to iptables if nft is not available.
// Mutations (ip_forward value + NAT table) are recorded in sysstate.Global for
// automatic revert on agent shutdown.
func EnableNAT(outIface string) error {
	if outIface == "" {
		var err error
		outIface, err = defaultRouteIface()
		if err != nil {
			return fmt.Errorf("detect WAN interface: %w", err)
		}
	}

	// Save the current ip_forward value so we can restore it on shutdown.
	prevIPFwd, _ := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	prevVal := strings.TrimSpace(string(prevIPFwd))

	// Enable IPv4 forwarding via /proc (no sysctl binary needed).
	if err := enableIPForward(); err != nil {
		slog.Warn("mesh: could not enable ip_forward", "err", err)
		// non-fatal: continue
	} else if prevVal != "1" {
		// Only record a revert entry if we actually changed the value.
		sysstate.Global.Record("ip_forward:restore:"+prevVal, func(_ context.Context) {
			_ = os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte(prevVal+"\n"), 0644)
		})
	}

	// Ensure CAP_NET_ADMIN is in the inheritable set so child processes
	// (nft) can receive it as an ambient capability.
	setNetAdminInheritable()

	// Try nft first, then iptables.
	nft := findBin(nftBin, "/usr/sbin/nft", "/usr/bin/nft")
	ipt := findBin(iptablesBin, "/usr/sbin/iptables", "/usr/sbin/iptables-legacy", "/usr/bin/iptables")

	capturedIface := outIface
	if nft != "" {
		err := enableNATnft(nft, capturedIface)
		if err == nil {
			sysstate.Global.Record("nat:nft:"+capturedIface, func(_ context.Context) {
				DisableNAT(capturedIface)
			})
		}
		return err
	}
	if ipt != "" {
		err := enableNATiptables(ipt, capturedIface)
		if err == nil {
			sysstate.Global.Record("nat:iptables:"+capturedIface, func(_ context.Context) {
				DisableNAT(capturedIface)
			})
		}
		return err
	}
	slog.Warn("mesh: neither nft nor iptables found; NAT not configured (mesh egress may not work)")
	return nil
}

func enableNATnft(nft, outIface string) error {
	// Create a dedicated table (idempotent).
	cmds := [][]string{
		{"add", "table", "ip", nftTable},
		{"add", "chain", "ip", nftTable, nftChain, "{ type nat hook postrouting priority 100 ; }"},
		{"add", "rule", "ip", nftTable, nftChain, "oifname", outIface, "masquerade"},
	}
	for _, args := range cmds {
		out, err := nftRun(nft, args...)
		if err != nil {
			// "File exists" is ok (table/chain already present).
			if !strings.Contains(string(out), "File exists") {
				slog.Warn("mesh: nft cmd failed", "args", args, "out", strings.TrimSpace(string(out)))
			}
		}
	}
	slog.Info("mesh: NAT enabled via nft", "iface", outIface)
	return nil
}

func enableNATiptables(ipt, outIface string) error {
	if exec.Command(ipt, "-t", "nat", "-C", "POSTROUTING", "-o", outIface, "-j", "MASQUERADE").Run() != nil {
		if out, err := exec.Command(ipt, "-t", "nat", "-A", "POSTROUTING", "-o", outIface, "-j", "MASQUERADE").CombinedOutput(); err != nil {
			return fmt.Errorf("iptables MASQUERADE: %w (%s)", err, strings.TrimSpace(string(out)))
		}
	}
	if exec.Command(ipt, "-C", "FORWARD", "-j", "ACCEPT").Run() != nil {
		if out, err := exec.Command(ipt, "-A", "FORWARD", "-j", "ACCEPT").CombinedOutput(); err != nil {
			return fmt.Errorf("iptables FORWARD: %w (%s)", err, strings.TrimSpace(string(out)))
		}
	}
	slog.Info("mesh: NAT enabled via iptables", "iface", outIface)
	return nil
}

// DisableNAT removes the NAT rules added by EnableNAT (best-effort).
func DisableNAT(outIface string) {
	nft := findBin(nftBin, "/usr/sbin/nft", "/usr/bin/nft")
	if nft != "" {
		exec.Command(nft, "delete", "table", "ip", nftTable).Run() //nolint:errcheck
		slog.Info("mesh: NAT disabled (nft table removed)")
		return
	}
	if ipt := findBin(iptablesBin, "/usr/sbin/iptables", "/usr/sbin/iptables-legacy"); ipt != "" {
		if outIface == "" {
			outIface, _ = defaultRouteIface()
		}
		exec.Command(ipt, "-t", "nat", "-D", "POSTROUTING", "-o", outIface, "-j", "MASQUERADE").Run() //nolint:errcheck
		slog.Info("mesh: NAT disabled (iptables rules removed)")
	}
}

// DisableNATAndRestore removes mesh NAT and restores system values changed by
// EnableNAT, including net.ipv4.ip_forward, immediately when Mesh is disabled.
func DisableNATAndRestore(ctx context.Context, outIface string) {
	DisableNAT(outIface)
	sysstate.Global.RevertByPrefix(ctx, "nat:", "ip_forward:restore:")
}

// defaultRouteIface returns the name of the interface used for the default route.
func defaultRouteIface() (string, error) {
	ip := findBin("/sbin/ip", "/usr/sbin/ip", "/bin/ip", "/usr/bin/ip")
	if ip == "" {
		return "", fmt.Errorf("ip command not found")
	}
	out, err := exec.Command(ip, "route", "get", "8.8.8.8").Output()
	if err != nil {
		return "", fmt.Errorf("ip route get: %w", err)
	}
	parts := strings.Fields(string(out))
	for i, p := range parts {
		if p == "dev" && i+1 < len(parts) {
			return parts[i+1], nil
		}
	}
	return "", fmt.Errorf("cannot parse default route output: %q", string(out))
}
