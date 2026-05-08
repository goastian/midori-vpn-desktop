//go:build linux

package caps

import (
	"strings"
	"testing"
)

func TestHasNetAdminFromStatus(t *testing.T) {
	withNetAdmin := "Name:\tagent\nCapEff:\t0000000000001000\n"
	if !hasNetAdminFromStatus(strings.NewReader(withNetAdmin)) {
		t.Fatal("expected CAP_NET_ADMIN bit to be detected")
	}

	withoutNetAdmin := "Name:\tagent\nCapEff:\t0000000000000000\n"
	if hasNetAdminFromStatus(strings.NewReader(withoutNetAdmin)) {
		t.Fatal("expected missing CAP_NET_ADMIN bit to be rejected")
	}
}

func TestHasNetAdminFromStatusFailsClosed(t *testing.T) {
	cases := []string{
		"",
		"Name:\tagent\n",
		"CapEff:\tnot-hex\n",
	}
	for _, tc := range cases {
		if hasNetAdminFromStatus(strings.NewReader(tc)) {
			t.Fatalf("expected %q to fail closed", tc)
		}
	}
}
