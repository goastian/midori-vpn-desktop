# MidoriVPN Desktop

[![CI](https://github.com/goastian/midori-vpn-desktop/actions/workflows/ci.yml/badge.svg)](https://github.com/goastian/midori-vpn-desktop/actions/workflows/ci.yml)

Desktop client for the **MidoriVPN** private network (mesh + full-tunnel VPN), built with **Tauri 2 + Vue 3** and a native **Go 1.26** background agent that manages WireGuard, obfuscated WSS TLS tunnels, and local proxy routing.

---

## Features

- 🔐 **OAuth 2.0 PKCE Login** via Authentik (`accounts.astian.org`) with AES-GCM 256-bit encrypted token storage.
- 🌐 **WireGuard Mesh Network** with automatic node discovery and dynamic routing.
- 🛡️ **Hardened Linux Security Architecture**:
  - Unprivileged execution by default with dynamic Polkit capability elevation (`setcap cap_net_admin,cap_net_raw=ep`).
  - AppArmor profile (complain mode default) and SELinux module support.
  - Native FirewallD and UFW zone integration for `wg0`.
- 🌙 **Modern Dark UI**: Native Obsidian/Slate theme with emerald pulse indicators and country emoji flags.
- 🚀 **Multi-Platform Support**: Linux (RPM, DEB, AppImage), macOS (DMG, APP), and Windows (MSI, NSIS).
- 🔄 **Proactive Token Refresh**: Seamless session renewal directly with identity providers without disconnects.

---

## Repository Structure

```
midori-vpn-desktop/
├── agent/              # Go 1.26 Agent (WireGuard + mesh + local RPC on 127.0.0.1:7071)
├── src/                # Vue 3 Frontend (Dark theme UI)
├── src-tauri/          # Tauri 2 Rust wrapper & OS integration
├── packaging/          # Maintainer scriptlets, AppArmor, SELinux, and Polkit rules
├── dist-packages/      # Clean production distribution packages (.rpm, .deb)
└── scripts/            # Automated build and packaging scripts
```

---

## Prerequisites & Dependencies

### Build Tools
- **Go** ≥ 1.26
- **Rust** (stable) + `cargo`
- **Node.js** ≥ 22 + `npm`

### Runtime Dependencies
MidoriVPN Desktop directly requires only **3 shared libraries** on Linux:
- `libwebkit2gtk-4.1.so.0` (Tauri WebView renderer)
- `libgtk-3.so.0` (GTK3 windowing system)
- `libayatana-appindicator3.so.1` (System tray integration)

---

## Installation Guide (Linux)

### openSUSE / SUSE (RPM)

> [!TIP]
> **Minimal Installation Recommended**: By default, `zypper` installs all *recommended* packages of `libwebkit2gtk-4_1-0` (pulling in ~60 optional packages such as GStreamer multimedia plugins, audio synthesizers, and gamepad drivers). 
>
> To install **only the minimal essential packages** required by MidoriVPN, pass the `--no-recommends` flag:

```bash
# Minimal installation without optional multimedia bloat
sudo zypper in --no-recommends ./dist-packages/MidoriVPN-2.0.0-1.x86_64.rpm
```

### Fedora / RHEL (RPM)

```bash
sudo dnf install ./dist-packages/MidoriVPN-2.0.0-1.x86_64.rpm
```

### Debian / Ubuntu (DEB)

```bash
sudo apt install --no-install-recommends ./dist-packages/MidoriVPN_2.0.0_amd64.deb
```

---

## Building from Source

### 1. Install Frontend Dependencies
```bash
npm install
```

### 2. Compile the Go Agent
```bash
bash scripts/build-agent.sh host
```
*Generates a stripped static binary at `agent/target/release/agent`.*

### 3. Run Development Mode (HMR)
```bash
npm run tauri:dev
```

### 4. Build Production RPM Package
```bash
bash scripts/build-rpm.sh
```
*Outputs the clean RPM package to `dist-packages/MidoriVPN-2.0.0-1.x86_64.rpm`.*

---

## Post-Installation Verification (Linux)

```bash
# 1. Verify that the agent process listens on loopback:
curl -i http://127.0.0.1:7071/status
# Expected: 403 Forbidden (Protected by session token)

# 2. Check capabilities granted to the agent:
getcap /usr/local/bin/midorivpn-agent

# 3. Check AppArmor status:
sudo aa-status | grep midorivpn
```

---

## Uninstallation

```bash
# openSUSE / Fedora / RHEL
sudo rpm -e midori-vpn

# Debian / Ubuntu
sudo apt remove midori-vpn
```

---

## Troubleshooting

| Symptom | Probable Cause | Solution |
| :--- | :--- | :--- |
| **Permissions Button Fails** | Polkit canceled or `setcap` missing | Check terminal output: `midorivpn-desktop`. Ensure `libcap-progs` / `setcap` is installed. |
| **Zypper wants 60+ packages** | Zypper installs recommended packages by default | Run `sudo zypper in --no-recommends ./MidoriVPN-*.rpm` |
| **Local Status 403** | Local RPC requires token | Expected behavior; UI communicates via authenticated header. |
| **SELinux Denials** | Confined user domain | Run `sudo setsebool -P midorivpn_use_tun on`. |

---

## License

Astian, Inc. & Midori Project. See [LICENSE](LICENSE) for details.
