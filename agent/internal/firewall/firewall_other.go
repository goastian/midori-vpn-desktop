//go:build !linux

package firewall

import "context"

type Backend string

type Scope struct {
	Name              string
	Interface         string
	RPCPort           int
	MeshDestinationIP string
	MeshPeerIPs       []string
	MeshProxyPort     int
}

const (
	BackendNone Backend = "none"
	ManagedTag          = "midorivpn-managed"
)

func Detect() Backend                                   { return BackendNone }
func Allow(_ context.Context, _ Scope) error            { return nil }
func Cleanup(_ context.Context, _ string, _ bool) error { return nil }
