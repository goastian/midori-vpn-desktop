//go:build linux

// Package caps inspects the agent process's effective Linux capabilities so
// other components can gate behaviour (e.g. auto-mesh activation) on whether
// the user has actually granted CAP_NET_ADMIN to the agent binary.
package caps

import (
	"bufio"
	"io"
	"os"
	"strconv"
	"strings"
)

// CAP_NET_ADMIN is bit 12 of the capability bitmask (see capabilities(7)).
const capNetAdmin = 12

// HasNetAdmin reports whether the current process has CAP_NET_ADMIN in its
// effective capability set. Returns false on any parsing error so callers
// fail closed (do not auto-enable privileged features).
func HasNetAdmin() bool {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return false
	}
	defer f.Close()

	return hasNetAdminFromStatus(f)
}

func hasNetAdminFromStatus(r io.Reader) bool {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		hex := strings.TrimSpace(strings.TrimPrefix(line, "CapEff:"))
		mask, err := strconv.ParseUint(hex, 16, 64)
		if err != nil {
			return false
		}
		return mask&(1<<capNetAdmin) != 0
	}
	return false
}
