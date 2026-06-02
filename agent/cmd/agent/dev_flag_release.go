//go:build !dev

package main

// devNoToken is a no-op in release builds. The "-insecure-dev-no-token"
// command-line flag is only registered when the binary is built with the
// "dev" build tag (see dev_flag_dev.go). This ensures release binaries
// cannot be coaxed into running without RPC token enforcement.
func devNoToken() bool { return false }
