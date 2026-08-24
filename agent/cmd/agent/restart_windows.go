//go:build windows

package main

import "fmt"

func restartSelf() error {
	return fmt.Errorf("in-process restart is unavailable on Windows")
}
