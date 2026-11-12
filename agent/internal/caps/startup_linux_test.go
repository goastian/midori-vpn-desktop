//go:build linux

package caps

import (
	"golang.org/x/sys/unix"
	"testing"
)

func TestStartupAllowsOnlyNetworkPrivileges(t *testing.T) {
	for bit := uint(0); bit < 64; bit++ {
		for _, set := range []string{"effective", "permitted", "inheritable"} {
			var data [2]unix.CapUserData
			mask := uint32(1) << (bit % 32)
			switch set {
			case "effective":
				data[bit/32].Effective = mask
			case "permitted":
				data[bit/32].Permitted = mask
			case "inheritable":
				data[bit/32].Inheritable = mask
			}
			allowed := bit == unix.CAP_NET_ADMIN || bit == unix.CAP_NET_RAW
			if err := validateCapabilityMasks(data); (err == nil) != allowed {
				t.Fatalf("capability %d in %s: allowed=%v error=%v", bit, set, allowed, err)
			}
		}
	}
	if err := validateCapabilityMasks([2]unix.CapUserData{}); err != nil {
		t.Fatal(err)
	}
}
