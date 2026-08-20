#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> Construyendo imagen midorivpn-rpm-builder..."
podman build -t midorivpn-rpm-builder -f "$ROOT_DIR/packaging/Containerfile.rpm" "$ROOT_DIR/packaging"

echo "==> Compilando paquete RPM con Tauri 2..."
podman run --rm -v "$ROOT_DIR:/src:rw" midorivpn-rpm-builder bash -c "\
  cp -r /src /app && \
  cd /app && \
  npm install && \
  npm run build && \
  npm run build-agent:host && \
  npm run tauri -- build --bundles rpm && \
  mkdir -p /src/src-tauri/target/release/bundle/rpm /src/dist-packages && \
  cp -r /app/src-tauri/target/release/bundle/rpm/* /src/src-tauri/target/release/bundle/rpm/ && \
  cp -r /app/src-tauri/target/release/bundle/rpm/* /src/dist-packages/"

echo "==> Paquete RPM generado con éxito en dist-packages/ y src-tauri/target/release/bundle/rpm/"
