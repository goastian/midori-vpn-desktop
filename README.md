# MidoriVPN Desktop 2.0.0

The production client is a native Linux Go 1.27 agent plus a Qt 6 tray integration. The dashboard is the same authenticated Vue UI served by the local agent at `127.0.0.1`, so the Linux experience matches the existing client instead of maintaining a second UI. It works across X11 and Wayland desktops, offers a tray menu when the desktop exposes one, and does not link GTK3 or WebKitGTK. Linux x86_64 RPM is the only supported release target.

## Linux transports

- Direct kernel WireGuard.
- WireGuard over authenticated WSS.
- WireGuard over authenticated RFC 9298 MASQUE/HTTP3 CONNECT-UDP.
- Smart selection ordered by server priority and accepted only after a real WireGuard handshake.
- OpenVPN 2.7 with an AEAD-only profile and mandatory verification that the established Linux interface uses DCO. It is exposed only for a server capability marked healthy.
- IKEv2 EAP-TLS through a private strongSwan 6 client, with an isolated runtime,
  XFRM interface, DNS/kill-switch integration and deterministic cleanup. It is
  exposed only for a server capability marked healthy.

The client never invents endpoints or marks a requested protocol connected
without its native handshake. Smart Auto intentionally selects only among the
healthy WireGuard family (`wireguard`, `wss`, `masque`); OpenVPN and IKEv2 are
explicit choices because they have different connection and recovery costs.

## Security model

- OAuth 2.0 Authorization Code + PKCE through the local agent.
- Local RPC listens only on loopback and requires the per-session `X-Agent-Token` in every build.
- Tokens use the OS secret service where available; permissions and degraded storage are visible to the UI.
- WireGuard private keys are generated locally.
- OpenVPN device keys are generated locally as ECDSA P-256 keys and persisted only in Secret Service. Core receives a CSR, never the private key; native client files exist only in the mode-`0700` user runtime directory and are removed on disconnect.
- Kill switch, route pinning and DNS state are installed only for the selected endpoint and are restored on disconnect.
- WSS/MASQUE use short-lived tokens bound to the active peer and server.

## Build and test

The pinned rootless runner mounts the Core checkout as one coordinated source
tree. Place this repository at `<core>/midori-vpn-desktop`, then run:

```bash
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

The builder compiles the Qt tray shell, the Go agent and the authenticated Vue loopback UI, creates the RPM and signs it. Output is written only to `dist-packages/`.

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

Runtime dependencies are declared in `packaging/midori-vpn.spec` and include WireGuard tools, OpenVPN 2.7, nftables, policy kit, capabilities, IP routing utilities and browser launch support. There are no GTK/WebKit dependencies.

## Runtime checks

```bash
# The launcher starts the native tray integration, which owns one local agent,
# keeps RPC on loopback, and opens the Vue dashboard in the default browser.
midorivpn-desktop
```

While the launcher is running, an unauthenticated local status request must
return `403`:

```bash
curl -i http://127.0.0.1:7071/status
```

The dashboard and OAuth flow open in the default browser. The tray integration
reads the per-session local token from a `0600` runtime file; the agent must not
bind outside `127.0.0.1`. Its “Salir y desconectar” action restores the network
state. The start-minimized option uses the system tray when it is available;
without a tray the dashboard opens normally.

## Benchmarks

`scripts/benchmark-transports.sh` records real connection p50/p95 and download throughput for `wireguard`, `wss`, `masque` or `smart_auto`. It requires a logged-in running agent, a server UUID and an HTTPS throughput object. Results are measurements, not estimates.

## Source layout

```text
agent/                 privileged Go networking agent
desktop-qt/            Qt 6 native Linux tray integration
src/                   retained authenticated loopback UI
packaging/             RPM spec, policy, MAC and maintainer files
scripts/build-rpm.sh   rootless production package pipeline
```

## License

AGPL-3.0-or-later; see the
[project license](https://github.com/goastian/midori-vpn-core/blob/main/LICENSE).
