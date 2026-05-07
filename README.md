# MidoriVPN Desktop

[![CI](https://github.com/goastian/midori-vpn-desktop/actions/workflows/ci.yml/badge.svg)](https://github.com/goastian/midori-vpn-desktop/actions/workflows/ci.yml)

Cliente de escritorio para la red privada **MidoriVPN** (mesh + VPN), construido con **Tauri 2 + Vue 3** y un agente en **Go** que gestiona WireGuard, el mesh y los proxies locales.

## Características

- 🔐 **Login OAuth** seguro con Authentik — tokens cifrados en reposo con AES-GCM 256-bit.
- 🌐 **Red mesh WireGuard** — conecta automáticamente los nodos tras el login.
- 🛡️ **Hardening de seguridad en Linux** — integración con SELinux, AppArmor, firewalld/ufw y polkit.
- 🚀 **Autostart XDG** — arranca con la sesión de escritorio en Linux.
- 🖥️ **Multiplataforma** — Linux (DEB, RPM, AppImage), macOS (DMG, APP) y Windows (MSI, NSIS).
- 🔄 **Refresh proactivo de tokens** — sin interrupciones de sesión.

## Estado

- ✅ **Phase 1** — Mesh + login OAuth con seguridad completa para Linux.
- 🚧 **Phase 2** — Full-Tunnel VPN (próximamente).

## Estructura del repositorio

```
midorivpn-desktop/
├── agent/              # Agente Go (WireGuard + mesh + RPC en 127.0.0.1:7071)
├── src/                # Frontend Vue 3
├── src-tauri/          # Wrapper Tauri (Rust)
├── packaging/          # AppArmor, SELinux, autostart, scripts del paquete
└── scripts/            # Helpers de build
```

## Requisitos

### Herramientas comunes (todas las plataformas)

- [Go](https://go.dev/dl/) ≥ 1.26.2
- [Rust](https://rustup.rs/) (stable) + `cargo`
- [Node.js](https://nodejs.org/) ≥ 22 + `npm`

### Linux (DEB — Debian/Ubuntu)

```bash
sudo apt install libwebkit2gtk-4.1-dev libssl-dev libayatana-appindicator3-dev \
                 librsvg2-dev policykit-1 build-essential curl wget file
```

### Linux (RPM — Fedora/RHEL/openSUSE)

```bash
# Fedora / RHEL
sudo dnf install webkit2gtk4.1-devel openssl-devel libappindicator-gtk3-devel \
                 librsvg2-devel polkit gcc gcc-c++ make

# openSUSE / SUSE
sudo zypper install webkit2gtk4.1-devel libopenssl-devel libappindicator3-devel \
                    librsvg2-devel polkit gcc gcc-c++ make
```

### macOS

Instala las Xcode Command Line Tools:

```bash
xcode-select --install
```

### Windows

- [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) (componente MSVC)
- [WebView2 Runtime](https://developer.microsoft.com/en-us/microsoft-edge/webview2/) (preinstalado en Windows 11)

## Cómo compilar y probar

### 1. Instalar dependencias del frontend

```bash
npm install
```

### 2. Compilar el agente Go

```bash
bash scripts/build-agent.sh host
```

Genera `agent/target/release/agent` (o `agent.exe` en Windows) — binario estático, stripped, listo para que Tauri lo empaquete como recurso.

> Para compilar para otras plataformas, usa uno de los targets disponibles: `linux-amd64`, `linux-arm64`, `darwin-arm64`, `darwin-amd64`, `windows-amd64` o `all`.

### 3. Modo desarrollo (HMR)

```bash
npm run tauri:dev
```

- Abre la ventana con Hot Module Replacement del frontend.
- El agente Go se lanza automáticamente.
- En Linux, la primera vez pedirá contraseña vía `pkexec` para hacer `setcap cap_net_admin,cap_net_raw=ep` sobre el binario; tras eso no se vuelve a pedir.

### 4. Validar el frontend (typecheck + lint + tests + build)

```bash
npm run check
```

### 5. Build de release + paquetes

```bash
npm run tauri:build
```

Los artefactos quedan en `src-tauri/target/release/bundle/`:

| Plataforma | Formato    | Ruta de ejemplo |
|------------|------------|-----------------|
| Linux      | Debian     | `bundle/deb/MidoriVPN_1.0.0_amd64.deb` |
| Linux      | AppImage   | `bundle/appimage/MidoriVPN_1.0.0_amd64.AppImage` |
| Linux      | RPM        | `bundle/rpm/MidoriVPN-1.0.0-1.x86_64.rpm` |
| macOS      | DMG        | `bundle/dmg/MidoriVPN_1.0.0_aarch64.dmg` |
| macOS      | APP        | `bundle/macos/MidoriVPN.app` |
| Windows    | MSI        | `bundle/msi/MidoriVPN_1.0.0_x64_en-US.msi` |
| Windows    | NSIS       | `bundle/nsis/MidoriVPN_1.0.0_x64-setup.exe` |

### 6. Instalar el paquete en Linux (incluye post-install)

```bash
# Debian / Ubuntu
sudo dpkg -i src-tauri/target/release/bundle/deb/MidoriVPN_*_amd64.deb

# Fedora / RHEL / openSUSE / SUSE
sudo rpm -i src-tauri/target/release/bundle/rpm/MidoriVPN-*.x86_64.rpm

# Lánzalo
midorivpn
```

El script `postinst` hace, de forma idempotente y *best-effort*:

1. Copiar el agente a `/usr/local/bin/midorivpn-agent`.
2. Aplicar `setcap cap_net_admin,cap_net_raw=ep` (ya no necesita pkexec en cada arranque).
3. Recargar polkit para que la nueva acción esté disponible.
4. Cargar el perfil AppArmor en modo *complain* (revisa `aa-status` y pasa a *enforce* cuando no haya denegaciones).
5. Compilar e instalar el módulo SELinux (`midorivpn`) si `semodule` está presente.

## Verificar que arrancó bien (Linux)

```bash
# El agente escucha en localhost:7071
curl -s http://127.0.0.1:7071/status | jq

# Las file capabilities deberían estar puestas
getcap /usr/local/bin/midorivpn-agent
# → /usr/local/bin/midorivpn-agent cap_net_admin,cap_net_raw=ep

# El perfil AppArmor cargado
sudo aa-status | grep midorivpn

# El módulo SELinux instalado
semodule -l | grep midorivpn
```

## Configuración

El agente lee variables de entorno en este orden (la última tiene precedencia):

1. Defaults de build (Authentik en `accounts.astian.org`, API en `vpn.astian.org`).
2. `/etc/midorivpn/config.env` (overrides del sistema).
3. `$XDG_CONFIG_HOME/midorivpn/config.env` (overrides del usuario).
4. Variables del proceso.

Variables soportadas: `API_URL`, `AUTHENTIK_ISSUER`, `AUTHENTIK_CLIENT_ID`, `AUTHENTIK_AUTH_URL`, `AUTHENTIK_TOKEN_URL`, `AUTHENTIK_USERINFO_URL`, `AUTHENTIK_JWKS_URL`, `AUTHENTIK_REDIRECT_URI`, `ACCOUNT_URL`.

## Datos del usuario

Los archivos viven en `~/.config/midorivpn/` (modo `0700`):

| Archivo          | Contenido                                     |
|------------------|-----------------------------------------------|
| `tokens.enc`     | Tokens OAuth cifrados con AES-GCM (256-bit)   |
| `.keystore`      | Clave de cifrado aleatoria de 32 bytes        |
| `settings.json`  | Preferencias (mesh auto-start, autostart)     |

## Desinstalar

```bash
# Debian / Ubuntu
sudo apt remove midorivpn

# Fedora / RHEL / openSUSE / SUSE
sudo rpm -e midorivpn
```

El script `prerm` limpia: file capabilities, perfil AppArmor, módulo SELinux y reglas de firewall etiquetadas como `midorivpn-managed`.

## Solución de problemas

| Síntoma | Causa probable | Solución |
|---|---|---|
| Agente pide pkexec en cada arranque | `setcap` no se aplicó | `sudo setcap cap_net_admin,cap_net_raw=ep /usr/local/bin/midorivpn-agent` |
| `aa-status` muestra denegaciones | Perfil AppArmor estricto | Mantén `aa-complain`, recopila logs con `journalctl -k`, abre un issue |
| SELinux bloquea `/dev/net/tun` | Boolean apagado | `sudo setsebool -P midorivpn_use_tun on` |
| Mesh no levanta tras login | Firewall bloqueando wg0 | Revisa `firewall-cmd --list-interfaces` o `sudo ufw status` |

## Contribuir

1. Haz un fork del repositorio y crea una rama descriptiva.
2. Ejecuta `npm run check` para verificar typecheck, lint, tests y build del frontend.
3. Ejecuta `cargo fmt --check` y `cargo clippy --no-deps -- -D warnings` en `src-tauri/`.
4. Ejecuta `go vet ./...` y `go test -race ./...` en `agent/`.
5. Abre un Pull Request describiendo los cambios.

## Licencia

Ver [LICENSE](LICENSE).
