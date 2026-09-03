package deviceidentity

import (
	"strings"
	"testing"
)

func TestParseDefaultRoutes(t *testing.T) {
	ipv4 := strings.NewReader(`Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
enp1s0 00000000 0102A8C0 0003 0 0 200 00000000 0 0 0
wlp2s0 00000000 0102A8C0 0003 0 0 100 00000000 0 0 0
down0 00000000 0102A8C0 0000 0 0 1 00000000 0 0 0
`)
	routes := parseIPv4DefaultRoutes(ipv4)
	if len(routes) != 2 || routes[0].name != "enp1s0" || routes[0].metric != 200 || routes[1].name != "wlp2s0" {
		t.Fatalf("parsed IPv4 routes = %#v", routes)
	}

	ipv6 := strings.NewReader(`00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe800000000000000000000000000001 00000064 00000000 00000000 00000001 wlp2s0
20010db8000000000000000000000000 40 00000000000000000000000000000000 00 00000000000000000000000000000000 00000001 00000000 00000000 00000001 enp1s0
`)
	routes = parseIPv6DefaultRoutes(ipv6)
	if len(routes) != 1 || routes[0].name != "wlp2s0" || routes[0].metric != 100 {
		t.Fatalf("parsed IPv6 routes = %#v", routes)
	}
}
