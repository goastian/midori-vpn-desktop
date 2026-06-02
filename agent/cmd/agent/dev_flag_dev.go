//go:build dev

package main

import "flag"

// devNoTokenFlag is only registered in development builds. In release builds
// (default), the corresponding stub in dev_flag_release.go is used and the
// command-line flag is not registered at all, so an operator cannot
// accidentally disable token enforcement on a production binary.
var devNoTokenFlag = flag.Bool(
	"insecure-dev-no-token",
	false,
	"allow loopback RPC without MIDORIVPN_AGENT_TOKEN (development only; requires -tags dev)",
)

func devNoToken() bool { return *devNoTokenFlag }
