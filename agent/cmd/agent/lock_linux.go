//go:build linux

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func acquireSingleInstanceLock() (func(), error) {
	root, err := openRuntimeDir()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	lockFile, err := root.OpenFile("midorivpn-agent.lock", os.O_CREATE|os.O_RDWR|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0o600)
	if err != nil {
		return nil, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(int(lockFile.Fd()), &stat); err != nil {
		lockFile.Close()
		return nil, err
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Uid != uint32(os.Getuid()) || stat.Nlink != 1 || stat.Mode&0o777 != 0o600 {
		lockFile.Close()
		return nil, fmt.Errorf("invalid agent lock file")
	}
	if err := unix.Flock(int(lockFile.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		lockFile.Close()
		return nil, fmt.Errorf("%w: lock held by another process", errAlreadyRunning)
	}
	return func() {
		unix.Flock(int(lockFile.Fd()), unix.LOCK_UN) //nolint:errcheck
		lockFile.Close()
		// Keep the inode: unlinking a lock lets concurrent starters lock two
		// different inodes and both believe they own the instance.
	}, nil
}
