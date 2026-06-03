#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG_CONFIG_DIR="${TMPDIR:-/tmp}/midorivpn-pkgconfig"
AYATANA_PC_LOCAL="$PKG_CONFIG_DIR/ayatana-appindicator3-0.1.pc"

find_ayatana_pc() {
  local candidate
  for candidate in \
    /usr/lib64/pkgconfig/ayatana-appindicator3-0.1.pc \
    /usr/lib/pkgconfig/ayatana-appindicator3-0.1.pc
  do
    if [[ -f "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  candidate="$(find /usr -type f -path '*/pkgconfig/ayatana-appindicator3-0.1.pc' 2>/dev/null | sort | head -n 1)"
  if [[ -n "$candidate" ]]; then
    printf '%s\n' "$candidate"
    return 0
  fi

  return 1
}

apply_ayatana_pkgconfig_shim() {
  local source_pc
  if ! source_pc="$(find_ayatana_pc)"; then
    return 0
  fi

  mkdir -p "$PKG_CONFIG_DIR"
  cp "$source_pc" "$AYATANA_PC_LOCAL"

  # On some distros (e.g. openSUSE with zlib-ng compatibility paths),
  # transitive Requires entries can make the AppImage bundler parse a mixed
  # path/flag token as a file path. Keep only direct library flags.
  sed -i '/^Requires:/d;/^Requires.private:/d' "$AYATANA_PC_LOCAL"

  export PKG_CONFIG_PATH="$PKG_CONFIG_DIR${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
}

cd "$ROOT_DIR"
apply_ayatana_pkgconfig_shim
npm run build-agent:host
tauri build
