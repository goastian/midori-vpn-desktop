//go:build !linux

// Package mesh provides mesh network helpers (stub for non-Linux platforms).
package mesh

import (
	"context"
	"log/slog"
)

// EnableNAT is a no-op on non-Linux platforms.
func EnableNAT(_ string) error {
	slog.Warn("mesh: NAT setup is only supported on Linux")
	return nil
}

// DisableNAT is a no-op on non-Linux platforms.
func DisableNAT(_ string) {}

// DisableNATAndRestore is a no-op on non-Linux platforms.
func DisableNATAndRestore(_ context.Context, _ string) {}
