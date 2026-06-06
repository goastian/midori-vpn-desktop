# Changelog

All notable MidoriVPN Desktop changes are documented here.

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
