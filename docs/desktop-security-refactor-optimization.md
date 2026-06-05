# Evaluacion de seguridad, refactorizacion y optimizacion de MidoriVPN Desktop

Fecha: 2026-06-04

Alcance: solo `midorivpn-desktop`, incluyendo Vue/Tauri, shell Rust, agente Go, empaquetado y workflows. No cubre backend raiz, control web ni extension.

## Resumen ejecutivo

La postura actual no muestra vulnerabilidades explotables nuevas en Node, Rust o Go con los scanners del proyecto. Las excepciones restantes pertenecen al stack GTK/WebKitGTK heredado de Tauri/wry en Linux y estan documentadas en `src-tauri/audit.toml`; no se intentan fixes parciales porque `glib` no puede subirse a la rama no vulnerable sin que Tauri/wry migren fuera de gtk-rs `0.18`.

Se aplicaron cambios de bajo riesgo para reducir superficie operacional:

- Auditoria npm alineada con CI: `moderate+` por defecto y prod+dev, con `NPM_AUDIT_OMIT=dev` como excepcion temporal.
- Updates menores: `eslint-plugin-vue` `10.9.2`, `happy-dom` `20.10.1`, `yoke` `0.8.3`.
- RPC Go dividido por responsabilidad sin cambiar rutas, metodos ni payloads.
- Shell Rust dividido por responsabilidad sin cambiar comandos Tauri expuestos.
- i18n optimizado para cargar `en` al inicio y locales secundarios bajo demanda.

## Hallazgos y remediacion

| Severidad | Evidencia | Impacto | Recomendacion | Estado |
| --- | --- | --- | --- | --- |
| Alta aceptada | `src-tauri/audit.toml` ignora explicitamente advisories GTK/WebKitGTK heredados, incluyendo `RUSTSEC-2024-0429` para `glib`. Dependabot reporto que la version segura empieza en `glib` `0.20.0`, pero el stack actual resuelve `0.18.x`. | Dependabot no puede crear un PR resoluble para `glib`; forzar `0.20.x` romperia la familia gtk-rs usada por Tauri/wry. | Mantener `cargo-audit` fallando ante cualquier advisory nuevo y documentar el ignore de Dependabot para `glib` hasta que upstream libere una ruta compatible. | Aceptado y documentado en `.github/dependabot.yml` y `src-tauri/audit.toml`. |
| Media | `scripts/npm-audit.sh` auditaba solo prod y `high+`, mientras CI y el baseline operativo usan `moderate+`. | Riesgo de drift entre auditoria local y CI; dev tooling vulnerable puede quedar sin senal local. | Auditar prod+dev por defecto con `--audit-level=moderate`; permitir prod-only solo por variable. | Remediado en `scripts/npm-audit.sh`. |
| Media | `agent/internal/rpc/server.go` concentraba rutas, middleware, VPN, mesh, settings, cache, status y shutdown. | Archivo grande con mayor riesgo de regresiones al tocar seguridad local o handlers de red. | Separar por responsabilidad y cubrir middleware/cache/DNS con tests. | Remediado con `routing.go`, `vpn_handlers.go`, `mesh_handlers.go`, `servers_cache.go`, `status.go`, `settings_handlers.go`, `helpers.go`, `public_ip.go` y `shutdown.go`. |
| Media | Middleware local RPC dependia de token, loopback y Origin; la cobertura previa no aislaba todos los casos criticos. | Cambios futuros podrian abrir rutas locales a origenes no permitidos o aceptar token query fuera de SSE. | Agregar tests para loopback, Origin permitido/denegado, token header/query SSE y callback OAuth exento. | Remediado en `agent/internal/rpc/security_test.go`. |
| Baja | `src-tauri/src/agent.rs` mezclaba token, permisos, proceso, supervisor y relay SSE. | Mantenimiento mas dificil y mayor probabilidad de tocar comandos Tauri al cambiar supervisor/proceso. | Dividir en submodulos internos y re-exportar la misma interfaz publica. | Remediado en `src-tauri/src/agent/`. |
| Baja | `src/i18n/index.ts` importaba todos los JSON de locale en el bundle inicial. | Bundle inicial mayor y trabajo de parseo innecesario para usuarios que usan solo un idioma. | Cargar `en` al inicio y locales secundarios con dynamic import; `setLocale` debe ser async. | Remediado; `LanguageSelect.vue` maneja estado async y hay test dedicado. |
| Baja | Minor drift en tooling: `eslint-plugin-vue`, `happy-dom`, `yoke`. | Fija bugs menores sin cambiar major ni contratos. | Aplicar updates compatibles y repetir baseline. | Remediado. |

## Interfaces publicas verificadas

No se cambiaron rutas del agente:

- `/status`, `/events`, `/servers`, `/connections`, `/connections/{id}`
- `/vpn/connect`, `/vpn/disconnect`
- `/mesh/enable`, `/mesh/disable`, `/mesh/exit-nodes`, `/mesh/exit-node`, `/mesh/full-tunnel/enable`, `/mesh/full-tunnel/disable`
- `/settings`
- `/oauth/start`, `/oauth/callback`
- `/public-ip`, `/dns/status`

No se cambiaron comandos Tauri expuestos:

- `agent_get`, `agent_post`, `agent_delete`
- `start_agent_cmd`, `stop_agent_cmd`, `restart_agent_cmd`
- `agent_has_caps`, `grant_agent_permissions`, `grant_dns_protection_caps`, `revert_agent_permissions`
- comandos de autostart existentes

El unico cambio de contrato interno es frontend: `setLocale(lang)` ahora retorna `Promise<void>`.

## Comandos de evaluacion

Resultado de la verificacion de 2026-06-04: todos los comandos siguientes pasaron. `cargo clippy` y `govulncheck` se reintentaron fuera del sandbox porque necesitaban descargar crates o consultar `vuln.go.dev`; `scripts/cargo-audit.sh` tambien se ejecuto fuera del sandbox para poder escribir el lock de RustSec en `~/.cargo`.

Baseline de seguridad y calidad:

```bash
npm run check
npm audit --audit-level=moderate
bash scripts/npm-audit.sh
bash scripts/cargo-audit.sh
bash scripts/govulncheck.sh
(cd src-tauri && cargo test)
(cd src-tauri && cargo clippy --no-deps -- -D warnings)
(cd agent && go test ./...)
(cd agent && go vet ./...)
git diff --check
```

Checks focalizados agregados durante la remediacion:

```bash
(cd agent && go test ./internal/rpc)
(cd src-tauri && cargo check)
npm run typecheck
npm test -- src/__tests__/i18n.test.ts
```

## Seguimiento

- Revisar el ignore de `glib` cuando Tauri/wry publiquen una migracion compatible fuera de gtk-rs `0.18`.
- Mantener `src-tauri/audit.toml` como lista cerrada: cualquier advisory nuevo debe fallar `scripts/cargo-audit.sh`.
- Evitar upgrades major de Tauri, Vue, Vite o reqwest sin una rama dedicada y pruebas de empaquetado por plataforma.
