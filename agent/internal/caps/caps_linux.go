//go:build linux

// Package caps inspects the agent process's effective Linux capabilities so
// other components can gate behaviour (e.g. auto-mesh activation) on whether
// the user has actually granted CAP_NET_ADMIN to the agent binary.
package caps

import (
	"bufio"
	"io"
	"log/slog"
	"os"
	"strconv"
	"strings"
)

// Capability bit numbers from capabilities(7).
const (
	capDacOverride    = 1
	capLinuxImmutable = 9
	capNetAdmin       = 12
)

// HasNetAdmin reports whether the current process has CAP_NET_ADMIN in its
// effective capability set. Returns false on any parsing error so callers
// fail closed (do not auto-enable privileged features).
func HasNetAdmin() bool { return hasCap(capNetAdmin) }

// HasDacOverride reports whether CAP_DAC_OVERRIDE is in the effective set.
// Needed by the resolvconf DNS backend to write /etc/resolv.conf.
func HasDacOverride() bool { return hasCap(capDacOverride) }

// HasLinuxImmutable reports whether CAP_LINUX_IMMUTABLE is in the effective
// set. Needed by the resolvconf DNS backend to chattr +i /etc/resolv.conf.
func HasLinuxImmutable() bool { return hasCap(capLinuxImmutable) }

func hasCap(bit uint) bool {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return false
	}
	defer f.Close()
	return hasCapFromStatus(f, bit)
}

// hasNetAdminFromStatus is kept for backwards-compat with existing tests.
func hasNetAdminFromStatus(r io.Reader) bool { return hasCapFromStatus(r, capNetAdmin) }

func hasCapFromStatus(r io.Reader, bit uint) bool {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		hex := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		mask, err := strconv.ParseUint(hex, 16, 64)
		if err != nil {
			slog.Info("caps: failed to parse CapEff", "hex", hex, "err", err)
			return false
		}
		result := mask&(1<<bit) != 0
		slog.Info("caps: checked capability", "capeff_hex", hex, "bit", bit, "result", result)
		return result
	}
	slog.Info("caps: CapEff line not found in /proc/self/status")
	return false
}
