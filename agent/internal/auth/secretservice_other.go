//go:build !linux

package auth

func newSecretServiceStore() Store { return nil }
