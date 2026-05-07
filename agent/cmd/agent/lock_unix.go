//go:build linux || darwin

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

func acquireSingleInstanceLock() (func(), error) {
	lockDir := os.Getenv("XDG_RUNTIME_DIR")
	if lockDir == "" {
		lockDir = os.TempDir()
	}
	lockPath := filepath.Join(lockDir, "midorivpn-agent.lock")
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lockFile.Close()
		fmt.Fprintln(os.Stderr, "midorivpn-agent: already running (lock held by another process)")
		os.Exit(0)
	}
	return func() {
		unix.Flock(int(lockFile.Fd()), unix.LOCK_UN) //nolint:errcheck
		lockFile.Close()
		os.Remove(lockPath)
	}, nil
}