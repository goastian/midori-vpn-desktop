#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RELEASE_BIN="$ROOT_DIR/src-tauri/target/release/midorivpn-desktop"
APPIMAGE_PATH="$(find "$ROOT_DIR/src-tauri/target/release/bundle/appimage" -maxdepth 1 -type f -name '*.AppImage' | sort | tail -n 1)"

cd "$ROOT_DIR"

if [[ ! -x "$RELEASE_BIN" ]]; then
  npm run build-agent:host
  npm run build
  npm run tauri -- build --bundles appimage || true
fi

if [[ ! -x "$RELEASE_BIN" ]]; then
  printf 'No existe el binario release: %s\n' "$RELEASE_BIN" >&2
  printf 'Ejecuta primero: npm run appimage:build:local\n' >&2
  exit 1
fi

if [[ -z "$APPIMAGE_PATH" ]]; then
  APPIMAGE_PATH="$ROOT_DIR/src-tauri/target/release/bundle/appimage/MidoriVPN_1.1.1_amd64.AppImage"
fi

export APPIMAGE="$APPIMAGE_PATH"
export WEBKIT_DISABLE_DMABUF_RENDERER="${WEBKIT_DISABLE_DMABUF_RENDERER:-1}"

exec "$RELEASE_BIN" "$@"
