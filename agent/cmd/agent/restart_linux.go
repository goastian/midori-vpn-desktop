//go:build linux

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func restartSelf() error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}
	return unix.Exec(executable, restartArgs(os.Args), os.Environ())
}

func superviseParent(pid int) error {
	if pid <= 1 || os.Getppid() != pid {
		return fmt.Errorf("desktop shell has exited")
	}
	// exec of a file-capability binary clears the shell's PDEATHSIG. Rearm
	// it here, then close the race where the parent exited before prctl.
	if err := unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGTERM), 0, 0, 0); err != nil {
		return err
	}
	if os.Getppid() != pid {
		return fmt.Errorf("desktop shell has exited")
	}
	return nil
}
