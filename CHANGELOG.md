# Changelog

All notable MidoriVPN Desktop changes are documented here.

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
