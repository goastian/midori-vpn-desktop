#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LICENSE_FILE="${MIDORIVPN_LICENSE_FILE:-${ROOT_DIR}/../LICENSE}"

if [ "$(id -u)" -eq 0 ]; then
  echo "error: RPM builds must run through rootless Podman" >&2
  exit 1
fi

[ -f "${LICENSE_FILE}" ] || {
  echo "error: project license not found: ${LICENSE_FILE}" >&2
  exit 1
}

# Release output is generated material. A clean directory prevents an older
# RPM from being distributed when the current build fails or changes version.
rm -rf -- "$ROOT_DIR/dist-packages" "$ROOT_DIR/desktop-qt/build"
mkdir -p "$ROOT_DIR/dist-packages"

echo "==> Construyendo imagen midorivpn-rpm-builder..."
podman build -t midorivpn-rpm-builder -f "$ROOT_DIR/packaging/Containerfile.rpm" "$ROOT_DIR/packaging"

echo "==> Compilando agente Go, UI Vue y paquete RPM Linux..."
podman run --rm --userns=keep-id:uid=0,gid=0 \
  -v "$ROOT_DIR:/src:Z" \
  -v "$LICENSE_FILE:/project-license:ro,Z" \
  -v midori_rpm_npm_cache:/root/.npm:Z \
  -v midori_rpm_go_cache:/root/.cache/go-build:Z \
  -v midori_rpm_go_mod:/root/go/pkg/mod:Z \
  midorivpn-rpm-builder bash -c "\
  cp -r /src /app && \
  rm -rf /app/agent/target /app/dist /app/dist-packages && \
  cd /app && \
  npm ci && \
  npm run build:linux && \
  npm run build:qt-shell && \
  npm run build-agent:host && \
  mkdir -p /tmp/rpmbuild/RPMS /tmp/rpmbuild/BUILD /tmp/rpmbuild/BUILDROOT /tmp/rpmbuild/SOURCES /tmp/rpmbuild/SPECS /tmp/rpmbuild/SRPMS && \
  rpmbuild -bb --define '_topdir /tmp/rpmbuild' --define 'source_dir /app' --define 'license_file /project-license' /app/packaging/midori-vpn.spec && \
  cp -a /tmp/rpmbuild/RPMS/x86_64/. /src/dist-packages/"

echo "==> Firmando paquete RPM generado..."
bash "$ROOT_DIR/scripts/sign-rpm.sh"

echo "==> Paquete RPM Linux sin GTK3 generado y firmado en dist-packages/"
