// Package dns abstracts the platform-specific way the agent installs and
// restores DNS configuration while the VPN tunnel is active.
//
// Two Linux backends are provided:
//   - "resolved":  talks to systemd-resolved via resolvectl. Requires no extra
//     Linux capabilities beyond CAP_NET_ADMIN/CAP_NET_RAW already used to
//     configure the WireGuard interface.
//   - "resolvconf": writes /etc/resolv.conf directly and marks it immutable
//     with chattr +i to defeat NetworkManager / resolvconf overwrites.
//     Requires CAP_DAC_OVERRIDE and CAP_LINUX_IMMUTABLE.
//
// Detect() picks the safest available backend at runtime. The wg manager
// only cares about the Backend interface.
package dns

// Kind enumerates the DNS configuration strategies.
type Kind int

const (
	// KindNone means no DNS protection will be applied (non-Linux builds).
	KindNone Kind = iota
	// KindResolved uses systemd-resolved via resolvectl (no extra caps).
	KindResolved
	// KindResolvconf edits /etc/resolv.conf + chattr +i (needs extra caps).
	KindResolvconf
)

// String returns a stable identifier suitable for logs and RPC payloads.
func (k Kind) String() string {
	switch k {
	case KindResolved:
		return "resolved"
	case KindResolvconf:
		return "resolvconf"
	default:
		return "none"
	}
}

// NeedsExtraCaps reports whether the backend requires CAP_DAC_OVERRIDE and
// CAP_LINUX_IMMUTABLE on the agent binary to function correctly.
func (k Kind) NeedsExtraCaps() bool {
	return k == KindResolvconf
}

// Backend installs and restores DNS configuration for the active tunnel.
type Backend interface {
	// Kind reports the backend's identity for logging / UI gating.
	Kind() Kind
	// Apply installs the given DNS servers (IPv4/IPv6 literals) for the
	// tunnel interface. Must be safe to call when no tunnel is active for
	// the resolved backend; resolvconf only uses iface for logging.
	Apply(iface string, servers []string) error
	// Restore reverts any DNS state Apply changed. Safe to call when no
	// state was installed (returns nil).
	Restore() error
}
