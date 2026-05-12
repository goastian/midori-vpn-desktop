# Changelog

All notable MidoriVPN Desktop changes are documented here.

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

### Release Verification

- Checksums SHA-256 incluidos en la descripcion del release para copiar y pegar facilmente.
- SBOM de codigo fuente y SBOM de artefactos conservados como artifacts internos del workflow.
- Firma GPG de checksums conservada como artifact interno cuando `GPG_SIGN_ENABLED` esta configurado.
