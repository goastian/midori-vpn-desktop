//go:build !linux

package caps

// HasNetAdmin always returns true on non-Linux platforms; capability gating
// is a Linux-only concern.
func HasNetAdmin() bool { return true }
