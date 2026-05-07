//go:build !linux

package netguard

type Guard struct{}

type Scope struct {
	TunnelIface string
	Endpoint    string
	APIURL      string
	AssignedIP  string
	MeshPeerIPs []string
}

func New() *Guard                   { return &Guard{} }
func (g *Guard) Active() bool       { return false }
func (g *Guard) Enable(Scope) error { return nil }
func (g *Guard) Disable() error     { return nil }
