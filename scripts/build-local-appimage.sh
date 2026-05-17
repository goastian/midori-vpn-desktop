#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG_CONFIG_DIR="${TMPDIR:-/tmp}/midorivpn-pkgconfig"
AYATANA_PC_SOURCE="/usr/lib64/pkgconfig/ayatana-appindicator3-0.1.pc"
AYATANA_PC_LOCAL="$PKG_CONFIG_DIR/ayatana-appindicator3-0.1.pc"
APPIMAGE_RUNTIME="${APPIMAGE_RUNTIME:-${TMPDIR:-/tmp}/runtime-x86_64}"

cd "$ROOT_DIR"

find_appimagetool() {
  if command -v appimagetool >/dev/null 2>&1; then
    local system_appimagetool
    system_appimagetool="$(command -v appimagetool)"
    if "$system_appimagetool" --version >/dev/null 2>&1; then
      printf '%s\n' "$system_appimagetool"
      return 0
    fi
  fi

  local candidate
  while IFS= read -r candidate; do
    if "$candidate" --version >/dev/null 2>&1; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done < <(find /tmp -type f -name appimagetool -perm -111 2>/dev/null | sort)
}

ensure_appimage_runtime() {
  if [[ -s "$APPIMAGE_RUNTIME" ]]; then
    return 0
  fi

  curl -L \
    https://github.com/AppImage/type2-runtime/releases/download/continuous/runtime-x86_64 \
    -o "$APPIMAGE_RUNTIME"
}

patch_appdir() {
  local appdir="$1"
  local app_run="$appdir/AppRun"
  local webkit_libexec=""

  if [[ -d /usr/libexec/libwebkit2gtk-4_1-0 ]]; then
    webkit_libexec="/usr/libexec/libwebkit2gtk-4_1-0"
  else
    webkit_libexec="$(find /usr -path '*/libwebkit2gtk-4_1-0' -type d 2>/dev/null | sort | head -n 1)"
  fi

  if [[ -n "$webkit_libexec" && -d "$webkit_libexec" ]]; then
    mkdir -p "$appdir/libexec"
    cp -a "$webkit_libexec" "$appdir/libexec/"
  fi

  if [[ -d "$appdir/usr/lib64" ]]; then
    ln -sfn usr/lib64 "$appdir/lib64"
  fi

  if [[ -f "$app_run" ]]; then
    if ! grep -q 'cd "$this_dir"' "$app_run"; then
      perl -0pi -e 's|(source "\$this_dir"/apprun-hooks/"linuxdeploy-plugin-gtk\.sh"\n)|$1\ncd "\$this_dir"\n|s' "$app_run"
    fi
    perl -0pi -e 's|exec "\$this_dir"/AppRun\.wrapped "\$@"|exec "\$this_dir"/usr/bin/midorivpn-desktop "\$@"|' "$app_run"
  fi
}

repack_appimage() {
  local appdir="$1"
  local appimage="$2"
  local appimagetool

  appimagetool="$(find_appimagetool)"
  if [[ -z "$appimagetool" || ! -x "$appimagetool" ]]; then
    printf 'No se encontro appimagetool para reempaquetar %s\n' "$appimage" >&2
    return 1
  fi

  ensure_appimage_runtime
  "$appimagetool" --runtime-file "$APPIMAGE_RUNTIME" "$appdir" "$appimage"
  chmod +x "$appimage"
}

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

if [[ -d "$appdir" ]]; then
  patch_appdir "$appdir"
fi

if [[ -n "$appimage" ]]; then
  if [[ -d "$appdir" ]]; then
    repack_appimage "$appdir" "$appimage"
  fi
  chmod +x "$appimage"
  printf 'AppImage listo:\n%s\n' "$appimage"
  exit 0
fi

if [[ -d "$appdir" ]]; then
  appimage="$ROOT_DIR/src-tauri/target/release/bundle/appimage/MidoriVPN_$(node -p "require('./package.json').version")_amd64.AppImage"
  if repack_appimage "$appdir" "$appimage"; then
    printf 'AppImage listo:\n%s\n' "$appimage"
    exit 0
  fi

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
