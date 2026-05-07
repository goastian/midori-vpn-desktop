// Secret Service backend stub.
//
// This file provides the `newSecretServiceStore()` symbol used by NewStore().
// A real D-Bus integration with org.freedesktop.secrets (libsecret /
// gnome-keyring / kwallet) belongs here. It is intentionally a stub today so
// the agent can ship the file-based encrypted store immediately without
// pulling in a heavy D-Bus dependency tree.
//
// To enable Secret Service:
//
//   - Add `github.com/godbus/dbus/v5` to go.mod.
//   - Implement Save/Load/Clear against the org.freedesktop.Secret.Service
//     interface (CreateItem on the default collection with attributes
//     {service: "midorivpn", username: "<user>"}).
//   - Return the implementation from newSecretServiceStore() when the daemon
//     is reachable; nil otherwise.
//
// Until then we always fall through to the file store, which is fine for
// Phase 1 — credentials are encrypted at rest and the agent never logs them.

//go:build linux

package auth

func newSecretServiceStore() Store {
	// TODO(phase-1+): real Secret Service integration.
	return nil
}
