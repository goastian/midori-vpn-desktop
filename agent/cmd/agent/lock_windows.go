//go:build windows

package main

func acquireSingleInstanceLock() (func(), error) {
	return func() {}, nil
}