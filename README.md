# MidoriVPN Desktop 2.0.0

The production Linux client is a native Go 1.27 agent plus a Vue UI served on authenticated loopback. The RPM does not compile or ship Tauri, GTK3 or WebKitGTK. Windows and macOS source remains in `src-tauri` and platform files, but those targets are blocked from CI and release until certified.

## Linux transports

- Direct kernel WireGuard.
- WireGuard over authenticated WSS.
- WireGuard over authenticated RFC 9298 MASQUE/HTTP3 CONNECT-UDP.
- Smart selection ordered by server priority and accepted only after a real WireGuard handshake.

The client never invents endpoints or marks a requested protocol connected without its handshake. OpenVPN and IKEv2 are not selectable until their real gateways and Linux adapters are available.

## Security model

- OAuth 2.0 Authorization Code + PKCE through the local agent.
- Local RPC listens only on loopback and requires the per-session `X-Agent-Token` in every build.
- Tokens use the OS secret service where available; permissions and degraded storage are visible to the UI.
- WireGuard private keys are generated locally.
- Kill switch, route pinning and DNS state are installed only for the selected endpoint and are restored on disconnect.
- WSS/MASQUE use short-lived tokens bound to the active peer and server.

## Build and test

All tools run in rootless Podman from the workspace root:

```bash
cd midori-vpn-desktop
bash ../scripts/pod.sh npm run check

cd agent
bash ../../scripts/pod.sh go test -race ./...
bash ../../scripts/pod.sh go vet ./...
bash ../../scripts/pod.sh staticcheck ./...
bash ../../scripts/pod.sh govulncheck ./...
```

Build the signed RPM:

```bash
cd midori-vpn-desktop
RPM_SIGNING_KEY_ID=<local-key-fingerprint> bash scripts/build-rpm.sh
```

The builder compiles the Linux Vue bundle and Go agent, creates the RPM and signs it. Output is written only to `dist-packages/`.

## Verify and install

```bash
rpmkeys --checksig --verbose dist-packages/midori-vpn-2.0.0-1.x86_64.rpm
sudo rpm --import dist-packages/RPM-GPG-KEY-midorivpn

# openSUSE
sudo zypper --no-refresh install ./dist-packages/midori-vpn-2.0.0-1.x86_64.rpm

# Fedora family
sudo dnf install ./dist-packages/midori-vpn-2.0.0-1.x86_64.rpm
```

Use the distribution package manager for the actual install so runtime dependencies are resolved. Do not bypass a failed RPM signature.

Runtime dependencies are declared in `packaging/midori-vpn.spec` and include WireGuard tools, nftables, policy kit, capabilities, IP routing utilities and browser launch support. There are no GTK/WebKit dependencies.

## Runtime checks

```bash
systemctl status midorivpn-agent.service
getcap /usr/libexec/midorivpn-agent
curl -i http://127.0.0.1:7071/status
```

An unauthenticated local status request must return `403`. The installed launcher opens the agent-served UI in the default browser and supplies the session through the protected bootstrap flow.

## Benchmarks

`scripts/benchmark-transports.sh` records real connection p50/p95 and download throughput for `wireguard`, `wss`, `masque` or `smart_auto`. It requires a logged-in running agent, a server UUID and an HTTPS throughput object. Results are measurements, not estimates.

## Source layout

```text
agent/                 privileged Go networking agent
src/                   Vue browser-shell UI
packaging/             RPM spec, policy, MAC and maintainer files
scripts/build-rpm.sh   rootless production package pipeline
src-tauri/             retained non-Linux source; excluded from Linux RPM
```

## License

AGPL-3.0-or-later; see the workspace `LICENSE`.
