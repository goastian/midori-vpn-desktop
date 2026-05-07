# MidoriVPN Desktop

Cliente de escritorio para la red privada **MidoriVPN** (mesh + VPN), construido con Tauri 2 + Vue 3 y un agente en Go que gestiona WireGuard, el mesh y los proxies locales.

## Estado

- ✅ **Phase 1** — Mesh + login OAuth con seguridad completa para Linux (SELinux/AppArmor/firewalld/ufw, autostart XDG, tokens cifrados con AES-GCM, refresh proactivo).
- 🚧 **Phase 2** — Full-Tunnel VPN (próximamente).

## Estructura

```
midorivpn-desktop/
├── agent/              # Agente Go (WireGuard + mesh + RPC en 127.0.0.1:7071)
├── src/                # Frontend Vue 3
├── src-tauri/          # Wrapper Tauri (Rust)
├── packaging/          # AppArmor, SELinux, autostart, scripts del paquete
└── scripts/            # Helpers de build
```

## Requisitos

### Linux (Debian / Ubuntu)
```bash
sudo apt install libwebkit2gtk-4.1-dev libssl-dev libayatana-appindicator3-dev \
                 librsvg2-dev policykit-1 build-essential curl wget file
```

### Linux (Fedora / RHEL)
```bash
sudo dnf install webkit2gtk4.1-devel openssl-devel libappindicator-gtk3-devel \
                 librsvg2-devel polkit gcc gcc-c++ make
```

### Toolchains
- Go ≥ 1.26
- Rust (stable) + `cargo`
- Node.js ≥ 20 + `npm`

## Cómo compilar y probar

### 1. Instalar dependencias del frontend (solo la primera vez)
```bash
cd midorivpn-desktop
npm install
```

### 2. Compilar el agente Go
```bash
./scripts/build-agent.sh
```
Genera `agent/target/release/agent` (binario estático, stripped, listo para que Tauri lo empaquete como recurso).

### 3. Modo desarrollo (recomendado para iterar)
```bash
npm run tauri dev
```
- Abre la ventana con HMR del frontend.
- El agente se lanza automáticamente.
- La primera vez pedirá contraseña vía `pkexec` para hacer `setcap cap_net_admin,cap_net_raw=ep` sobre el binario; tras eso no se vuelve a pedir.

### 4. Build de release + paquetes
```bash
npm run tauri build
```
Los artefactos quedan en `src-tauri/target/release/bundle/`:

| Formato   | Ruta |
|-----------|------|
| Debian    | `bundle/deb/MidoriVPN_1.0.0_amd64.deb` |
| AppImage  | `bundle/appimage/MidoriVPN_1.0.0_amd64.AppImage` |
| RPM       | `bundle/rpm/MidoriVPN-1.0.0-1.x86_64.rpm` |

### 5. Instalar el paquete real (incluye postinst)
```bash
# Debian / Ubuntu
sudo dpkg -i src-tauri/target/release/bundle/deb/MidoriVPN_*_amd64.deb

# Fedora / RHEL
sudo rpm -i src-tauri/target/release/bundle/rpm/MidoriVPN-*.x86_64.rpm

# Lánzalo
midorivpn
```

El script post-instalación hace, de forma idempotente y *best-effort*:

1. Copiar el agente a `/usr/local/bin/midorivpn-agent`.
2. Aplicar `setcap cap_net_admin,cap_net_raw=ep` (ya no necesita pkexec en cada arranque).
3. Recargar polkit para que la nueva acción esté disponible.
4. Cargar el perfil AppArmor en modo *complain* (revisa `aa-status` y pasa a *enforce* cuando no haya denegaciones).
5. Compilar e instalar el módulo SELinux (`midorivpn`) si `semodule` está presente.

## Verificar que arrancó bien

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

El agente lee variables de entorno en este orden (gana la última):

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
sudo apt remove midorivpn       # o sudo rpm -e midorivpn
```
El script `prerm` limpia: file capabilities, perfil AppArmor, módulo SELinux y reglas de firewall etiquetadas como `midorivpn-managed`.

## Solución de problemas

| Síntoma | Causa probable | Solución |
|---|---|---|
| Agente pide pkexec en cada arranque | `setcap` no se aplicó | `sudo setcap cap_net_admin,cap_net_raw=ep /usr/local/bin/midorivpn-agent` |
| `aa-status` muestra denegaciones | Perfil AppArmor estricto | Mantén `aa-complain`, recopila logs con `journalctl -k`, abre issue |
| SELinux bloquea `/dev/net/tun` | Boolean apagado | `sudo setsebool -P midorivpn_use_tun on` |
| Mesh no levanta tras login | Firewall bloqueando wg0 | Revisa `firewall-cmd --list-interfaces` o `sudo ufw status` |

## Licencia

Ver [LICENSE](../LICENSE).
