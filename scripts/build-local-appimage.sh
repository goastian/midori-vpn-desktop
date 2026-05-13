#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG_CONFIG_DIR="${TMPDIR:-/tmp}/midorivpn-pkgconfig"
AYATANA_PC_SOURCE="/usr/lib64/pkgconfig/ayatana-appindicator3-0.1.pc"
AYATANA_PC_LOCAL="$PKG_CONFIG_DIR/ayatana-appindicator3-0.1.pc"

cd "$ROOT_DIR"

if [[ -f "$AYATANA_PC_SOURCE" ]]; then
  mkdir -p "$PKG_CONFIG_DIR"
  cp "$AYATANA_PC_SOURCE" "$AYATANA_PC_LOCAL"
  sed -i '/^Requires:/d' "$AYATANA_PC_LOCAL"
  export PKG_CONFIG_PATH="$PKG_CONFIG_DIR${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
fi

npm run build-agent:host

set +e
npm run tauri -- build --bundles appimage
status=$?
set -e

appimage="$(find "$ROOT_DIR/src-tauri/target/release/bundle/appimage" -maxdepth 1 -type f -name '*.AppImage' | sort | tail -n 1)"
appdir="$ROOT_DIR/src-tauri/target/release/bundle/appimage/MidoriVPN.AppDir"

if [[ -n "$appimage" ]]; then
  chmod +x "$appimage"
  printf 'AppImage listo:\n%s\n' "$appimage"
  exit 0
fi

if [[ -d "$appdir" ]]; then
  printf 'No se pudo crear el .AppImage final, pero el AppDir quedo listo:\n%s\n\n' "$appdir" >&2
fi

if [[ $status -ne 0 ]]; then
  cat >&2 <<'MESSAGE'
El build de Tauri fallo antes de generar el .AppImage final.

Si el error menciona github.com/runtime-x86_64, appimagetool no pudo descargar
el runtime AppImage desde GitHub en esta maquina. Puedes seguir probando el fix
grafico local con:

  npm run appimage:run:local
MESSAGE
  exit "$status"
fi

exit 1
