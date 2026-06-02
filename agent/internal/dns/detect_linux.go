//go:build linux

package dns

import (
	"log/slog"
	"os"
	"os/exec"
	"strings"
)

// Detect picks the DNS backend to use on this Linux host. It prefers the
// resolved backend when *all three* signals are positive — that avoids
// using resolvectl on systems where systemd-resolved is installed but not
// actually managing /etc/resolv.conf (e.g. Debian server with manual config).
func Detect() Backend {
	if resolvedActive() && resolvConfManagedByResolved() && hasResolvectl() {
		slog.Info("dns: using resolved backend")
		return newResolvedBackend()
	}
	slog.Info("dns: using resolvconf backend")
	return newResolvconfBackend()
}

func resolvedActive() bool {
	for _, path := range []string{"/usr/bin/systemctl", "/bin/systemctl"} {
		if _, err := os.Stat(path); err != nil {
			continue
		}
		cmd := exec.Command(path, "is-active", "--quiet", "systemd-resolved")
		if cmd.Run() == nil {
			return true
		}
		return false
	}
	return false
}

// resolvConfManagedByResolved is true when /etc/resolv.conf is a symlink
// pointing at one of systemd-resolved's stub files. We deliberately *do not*
// trust a regular file even if it lists 127.0.0.53 — manual edits should be
// honoured rather than overwritten via resolvectl.
func resolvConfManagedByResolved() bool {
	target, err := os.Readlink("/etc/resolv.conf")
	if err != nil {
		return false
	}
	for _, prefix := range []string{
		"/run/systemd/resolve/",
		"../run/systemd/resolve/",
	} {
		if strings.HasPrefix(target, prefix) {
			return true
		}
	}
	return false
}

func hasResolvectl() bool {
	for _, path := range []string{"/usr/bin/resolvectl", "/bin/resolvectl"} {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}
	return false
}
