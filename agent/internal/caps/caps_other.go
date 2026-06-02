//go:build !linux

package caps

// HasNetAdmin always returns true on non-Linux platforms; capability gating
// is a Linux-only concern.
func HasNetAdmin() bool { return true }

// HasDacOverride is a no-op on non-Linux platforms.
func HasDacOverride() bool { return true }

// HasLinuxImmutable is a no-op on non-Linux platforms.
func HasLinuxImmutable() bool { return true }
