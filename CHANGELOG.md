# Changelog

All notable MidoriVPN Desktop changes are documented here.

## v2.0.0 - 2026-08-24

Major Release with a verified WireGuard transport contract, native Go 1.27 agent, and hardened Linux RPM package.

- Linux RPM is the sole production artifact. Windows and macOS builds are disabled while their platform agents remain experimental source only.
- The RPM now declares AGPL-3.0-or-later licensing, publisher, homepage and descriptive metadata; its rootless build workspace is cleared of non-Linux binary artifacts before packaging.
- The Linux RPM serves the Vue application from the authenticated loopback Go agent and contains no Tauri/WebKitGTK runtime.
- A Qt 6 tray integration opens that same Vue dashboard, avoiding a second Linux interface. OAuth uses one browser tab: dashboard, Authentik, loopback callback, then dashboard again with the per-tab local session restored.
- The packaged agent carries the public PKCE identity used by MidoriVPN Control, so normal installations do not require an Authentik configuration file or client secret.
- Auto-Mesh recognizes Core's `origin_country_unavailable` degraded state, stops retrying permanent failures, and reports the condition in the Vue dashboard instead of logging once per minute forever.
- Device certificate private keys are generated as ECDSA P-256 keys in the agent, stored only in Secret Service and submitted to Core exclusively as CSRs. Invalid or unpersistable enrollments fail closed and are revoked.
- The Linux agent includes a real OpenVPN 2.7 adapter with an AEAD-only TLS 1.3 profile, certificate-name validation, handshake detection, DNS/kill-switch integration, runtime credential cleanup and mandatory DCO interface verification. It remains server-health gated until the gateway E2E is certified.
- The Linux agent includes a private strongSwan 6 client for IKEv2 EAP-TLS. It reuses the device-owned certificate, creates an isolated VICI runtime and XFRM interface, loads `swanctl.conf` and credentials explicitly from that private directory, validates the gateway DNS identity, and integrates assigned IP, DNS, kill switch, counters and deterministic cleanup without creating a persistent system profile.
- The private IKE client now launches `charon-systemd`, avoiding the global `/run/strongswan/charon.pid` used by a host daemon. Child capabilities are prepared fail-closed and a bounded stderr diagnostic tail exposes startup failures without allowing daemon output to grow memory indefinitely.
- WireGuard full-tunnel teardown now removes its temporary endpoint `/32` route and restores any route that existed before connection, preventing stale host-route state after disconnect or failed setup.
- MASQUE now supplies the implicit HTTPS port `443` to the QUIC dialer when a standards-compliant URI template omits it, allowing external CONNECT-UDP sessions to start correctly.
- The Qt tray now follows the lifecycle of its owned agent, so closing MidoriVPN from the Vue dashboard cannot leave an orphaned desktop shell running.
- Device-certificate validation accepts only the subsecond precision loss inherent to X.509 time encoding, while continuing to reject material expiry mismatches.
- Settings exposes explicit OpenVPN and IKEv2 choices only for already healthy/certified server capabilities; Smart Auto remains limited to the currently certified WireGuard family until transport E2E is complete.

### Build and validation

- Regenerated `Cargo.lock` from the manifest and made the Podman Rust runner use an executable target volume; `cargo check --locked` is now reproducible.
- RPM builds use Node 24.19.0 and npm 12.0.2 inside a rootless multistage builder; an incompatible Node 22 build is rejected rather than distributed.
- The packaged status UI reads its local RPC and proxy ports from the agent response instead of embedding them in the Vue view.

### Major Changes
- **Go 1.27 Native Agent**: Compilación y ejecución nativa sobre Go 1.27 para la gestión del kernel WireGuard (`wg0`).
- **Shell Linux local**: interfaz Vue servida por el agente Go en loopback; el código Tauri queda bloqueado para Windows y macOS.
- **Empaquetado RPM Blindado para openSUSE Tumbleweed**: Scripts de post-instalación y desinstalación (`postinst`, `prerm`) estrictos con aislamiento Polkit y AppArmor en modo complain.
- **WSS autenticado y verificable**: WireGuard puede usar un relay WSS con token efímero ligado a usuario, dispositivo y servidor; solo se ofrece cuando el servidor lo anuncia explícitamente.
- **MASQUE RFC 9298 real**: el agente usa HTTP/3 CONNECT-UDP, TLS 1.3 y datagramas QUIC para transportar WireGuard, con MTU y ruta pública específicos.
- **Smart con handshakes reales**: la selección automática prueba WireGuard, WSS y MASQUE por prioridad y solo acepta un transporte después del handshake WireGuard.
- **Protocolos honestos**: OpenVPN e IKEv2 solo aparecen con capacidad saludable y certificada, y ambos completan un handshake nativo real antes de declarar conexión.
- **Código simulado retirado**: Se eliminaron los adaptadores internos no conectados de OpenVPN DCO, IKEv2, MASQUE, TLS ofuscado, selector Smart y benchmarks estimados; ya no pueden confundirse con soporte de producción.
- **Seguridad de agente**: el token local es obligatorio en todas las compilaciones; se retiró el build tag de bypass de desarrollo y se corrigió el cierre concurrente de relays.

## v1.1.5 - MidoriVPN Desktop 1.1.5

Patch release for Linux desktop permission recovery and release-pipeline
reliability.

### Fixes

- **agent permissions** — Require the full Linux capability set needed by
  WireGuard, including DNS updates, and report incomplete legacy permissions
  as actionable setup failures instead of allowing a connection to fail later.
- **frontend/error** — Turn resolvconf permission-denied failures into a
  clear desktop permission recovery message.
- **dependencies** — Updated locked frontend, Go, and Rust transitive
  dependencies to their supported security releases.

### Build

- Aligned desktop package metadata with release version `1.1.5`.
- Updated the Go toolchain requirement to `1.26.6` for the agent security
  fixes.

## v1.1.3 - MidoriVPN Desktop 1.1.3

Patch release focused on desktop safety, DNS protection visibility, and
release metadata alignment.

### Fixes

- **tauri/bridge** — Allowed `GET /dns/status` through the local RPC
  allowlist so the DNS protection UI can read the agent status endpoint.
- **build-agent** — `scripts/build-agent.sh` now preserves MidoriVPN user
  data by default. Local tokens, keystore data, and settings are removed only
  when `RESET_MIDORIVPN_USER_DATA=1` is set explicitly.
- **frontend/protection** — Added a protection store and Dashboard status
  card for kill switch and DNS protection state from agent snapshots and SSE
  events.
- **settings** — Mesh settings load/save errors are rendered in Settings
  instead of being swallowed silently.

### Improvements

- Moved permission and mesh firewall warning strings into i18n.
- Added missing DNS protection and protection status translations for
  supported locales.
- Updated release artifact examples to `1.1.3`.

### Tests

- Added frontend coverage for DNS status bridge calls and the protection store.
- Extended the Tauri bridge allowlist test for `dns/status`.

## v1.1.2 - MidoriVPN Desktop 1.1.2

Stability and hardening patch focused on VPN connection reliability,
the local Tauri↔agent bridge, and operational configuration.

### Fixes

- **agent/wg** — Linux agent now resolves WireGuard endpoint hostnames to
  IPv4 before calling wireguard-go `IpcSet`. Servers that publish a hostname
  (e.g. `de.vpn.astian.org:51820`) no longer produce the `ParseAddr`
  IPC error -22. Route pinning is updated to reuse the same pre-resolved IP,
  keeping the pinned route consistent with the effective tunnel endpoint.
  ([c4d818a](../../commit/c4d818a))
- **agent/api** — Agent now derives an `Origin` header from `API_URL` and
  attaches it to every backend request, aligning with vpn-core CSRF/CORS
  validation and fixing 403 origin-not-allowed rejections on stricter
  deployments.
  ([55fad09](../../commit/55fad09))
- **tauri/bridge** — Local RPC bridge now rejects any path not in an explicit
  allowlist before making a network call. A 403 caused by an in-memory token
  rotation during a supervisor restart is transparently retried once with the
  latest token, eliminating transient auth failures after agent restarts.
  Origin-rejection 403s are prefixed with `auth_origin_rejected:` so the
  frontend can show a targeted message.
  ([cc66fc0](../../commit/cc66fc0))
- **frontend/error** — `toErrorMessage()` normalises origin-rejection and
  server-provisioning error strings to user-readable constants
  (`AUTH_ORIGIN_REJECTED_MESSAGE`, `VPN_SERVER_UNAVAILABLE_MESSAGE`),
  preventing raw 502/403 JSON bodies from surfacing in the UI. VPN store
  `connect()` gains a re-entry guard so double-clicks cannot fire two
  concurrent connections.
  ([ac5422b](../../commit/ac5422b))

### Features

- **agent/config** — Layered configuration loading: production defaults →
  `/etc/midorivpn/config.env` → `$XDG_CONFIG_HOME/midorivpn/config.env` →
  process environment. All Authentik OIDC endpoints and `API_URL` can be
  overridden without recompiling.
  ([9b966e5](../../commit/9b966e5))
- **agent/rpc** — RPC server init reads `Config` for all OIDC fields.
  `VPNStatus` exposes `ServerPublicIP` after a successful connect so the
  Dashboard can display the real server IP.
  ([1a0d28d](../../commit/1a0d28d))
- **frontend/ui** — Dashboard shows server public IP when connected and
  deduplicates picker items. App retries snapshots during supervisor
  restarts and keeps sessions alive with an 8-minute token keep-alive.
  Settings displays DNS token-store type and degraded status.
  `__APP_VERSION__` is exposed as a typed Vite build constant.
  ([7591b6a](../../commit/7591b6a))

### Tests

- `agent/internal/wg`: hostname resolution, literal IPv4 passthrough, IPv6
  rejection, DNS failure propagation.
- `agent/internal/apiClient`: `originFromBaseURL` URL forms; end-to-end
  check that `Origin` header equals `scheme+host` of `API_URL`.
- `src/lib/error.test.ts`: origin-rejection and provisioning-failure
  normalisation, legacy pattern detection.
- `src/__tests__/vpn.store.test.ts`: connect() keeps session state on auth
  failure; shows correct readable message for each error class.
  ([f3ce7db](../../commit/f3ce7db))

### Build

- Version bumped to `1.1.2` across `package.json`, `Cargo.toml`, `Cargo.lock`
  and `tauri.conf.json`.
- `scripts/build-local-appimage.sh`: auto-downloads `appimagetool` from
  `github.com/AppImage/appimagetool` continuous release when neither a system
  install nor a cached copy is found. Override via `APPIMAGETOOL_PATH` /
  `APPIMAGETOOL_URL` env vars.
- Artifact path examples in README updated to `1.1.2`.
  ([2e27fa2](../../commit/2e27fa2))

## v1.1.1 - MidoriVPN Desktop 1.1.1

Patch de mantenimiento sobre `v1.1.0` para alinear el versionado del desktop, actualizar dependencias y recoger los commits recientes.

### Fixes

- Version de la aplicacion actualizada a `1.1.1` en npm, Cargo y Tauri.
- Managers DNS de macOS y Windows ahora exponen `DNSBackendKind`, manteniendo consistente la identificacion del backend DNS entre plataformas.
- Imports DNS reorganizados en el agent para mantener builds multiplataforma mas limpios.

### Dependencies

- `getrandom` actualizado de `0.3.4` a `0.4.2` en Tauri/Rust.
- GitHub Actions actualizadas: `actions/checkout` v6, `actions/setup-node` v6, `actions/upload-artifact` v7 y `actions/download-artifact` v8.

### Build

- Fallback del script local de AppImage actualizado para buscar `MidoriVPN_1.1.1_amd64.AppImage`.
- Ejemplos de artefactos en README actualizados a la version `1.1.1`.

## v1.1.0 - MidoriVPN Desktop 1.1.0

Release centrado en permisos, proteccion DNS y limpieza del dashboard.

### Features

- Nuevo `PermissionsTriggerCard` para solicitar permisos desde la UI de forma guiada.
- Nuevo `DnsProtectionCard` para mostrar estado/capacidades del backend DNS y su control desde dashboard.
- Nueva composable `useDnsProtection` para encapsular estado y operaciones de proteccion DNS.
- Dashboard refactorizado para usar componentes dedicados y mejorar organizacion del codigo.

### Tests

- Agregados tests unitarios para `PermissionsTriggerCard`.
- Agregados tests para la utilidad `formatBytes`.

### Improvements

- Actualizados textos i18n para cadenas nuevas de permisos y proteccion DNS.
- Mejorado lazy-loading de rutas y chunking de dependencias para optimizar el build.

## v1.0.2 - MidoriVPN Desktop 1.0.2

Mini patch para corregir el AppImage en escritorios Linux donde `v1.0.1` seguia fallando en maquinas sin instalacion previa del agente.

### Fixes

- AppImage ahora resuelve el binario `agent` empaquetado en sus recursos en vez de asumir `/usr/local/bin/midorivpn-agent`.
- Fallback grafico de AppImage aplicado desde el entrypoint principal antes de iniciar Tauri/WebKitGTK.
- AppImage desactiva tambien el modo de composicion de WebKitGTK y fuerza backend X11 cuando no hay override del usuario.

## v1.0.1 - MidoriVPN Desktop 1.0.1

Mini patch para corregir el AppImage de Linux y pulir la identificacion de paquetes del release.

### Fixes

- AppImage configura un fallback grafico para WebKitGTK cuando se ejecuta desde entorno AppImage, evitando el aborto `EGL_BAD_PARAMETER` antes de pintar la ventana.

### Build

- Agregados comandos locales para compilar y probar el AppImage fuera del CI:
  - `npm run appimage:build:local`
  - `npm run appimage:run:local`
- Version de la aplicacion actualizada a `1.0.1` en npm, Cargo y Tauri.

### Release

- Nombres de assets publicos normalizados con tokens ordenables y consistentes:
  - `linux-x86_64`
  - `linux-arm64`
  - `macos-arm64`
  - `macos-x86_64`
  - `windows-x86_64`
- Artifacts internos del workflow ahora incluyen la version en el nombre para facilitar auditoria.

### Packages

- Linux x86_64: DEB, RPM y AppImage.
- Linux arm64: DEB, RPM y AppImage.
- macOS Apple Silicon arm64: DMG y APP.
- macOS Intel x86_64: DMG y APP.
- Windows x86_64: MSI y NSIS.

## v1.0.0 - MidoriVPN Desktop 1.0.0

Primera version publica de MidoriVPN Desktop.

### Highlights

- Cliente de escritorio multiplataforma para MidoriVPN.
- Login OAuth con Astian Accounts y almacenamiento cifrado de tokens en reposo.
- Conexion automatica a la red mesh WireGuard despues del login.
- Full-tunnel VPN y controles de permisos desde la aplicacion.
- Hardening Linux con integracion AppArmor, SELinux, polkit, firewalld/ufw y autostart XDG.

### Packages

- Linux x86_64: DEB, RPM y AppImage.
- Linux arm64: DEB, RPM y AppImage.
- macOS Apple Silicon arm64: DMG y APP.
- macOS Intel x86_64: DMG y APP.
- Windows x86_64: MSI y NSIS.
