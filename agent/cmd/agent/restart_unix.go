//go:build linux || darwin

package main

import (
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
