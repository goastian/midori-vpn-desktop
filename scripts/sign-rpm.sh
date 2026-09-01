#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DESKTOP_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$DESKTOP_DIR/dist-packages"
KEY_ID="${RPM_SIGNING_KEY_ID:-}"

if [ -z "$KEY_ID" ]; then
    echo "error: RPM_SIGNING_KEY_ID is required" >&2
    exit 1
fi

echo "==> Firmando paquetes RPM con clave Ed25519 (EdDSA): $KEY_ID..."

for command_name in rpmsign gpg podman; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "error: $command_name is required to sign and verify the RPM" >&2
        exit 1
    fi
done

if ! gpg --batch --list-secret-keys "$KEY_ID" >/dev/null 2>&1; then
    echo "error: RPM signing secret key $KEY_ID is unavailable" >&2
    exit 1
fi

rpm_files=("$DIST_DIR"/*.rpm)
if [ ! -e "${rpm_files[0]}" ]; then
    echo "error: no RPM packages found in $DIST_DIR" >&2
    exit 1
fi

public_key="$DIST_DIR/RPM-GPG-KEY-midorivpn"
gpg --batch --armor --export "$KEY_ID" > "$public_key"
if [ ! -s "$public_key" ]; then
    echo "error: exported RPM public key is empty" >&2
    exit 1
fi

for rpm_file in "${rpm_files[@]}"; do
    echo "Firmando $rpm_file..."
    rpmsign --define "_gpg_name ${KEY_ID}" --addsign "$rpm_file"
    echo "✅ Firmado: $rpm_file"
done

podman run --rm --userns=keep-id:uid=0,gid=0 \
    -v "$DIST_DIR:/artifacts:ro,Z" \
    docker.io/library/fedora:44@sha256:be9d65e2344d805cc11114319c685ecaa96b6d9b4350a0a6460cdb931babbd19 \
    bash -c 'set -Eeuo pipefail
      rpm --dbpath /tmp/rpmdb --initdb
      rpm --dbpath /tmp/rpmdb --import /artifacts/RPM-GPG-KEY-midorivpn
      for rpm_file in /artifacts/*.rpm; do
        rpmkeys --dbpath /tmp/rpmdb --checksig --verbose "$rpm_file"
      done'

echo "==> Exportando clave pública OpenPGP verificada..."
cp "$public_key" "$DESKTOP_DIR/RPM-GPG-KEY-midorivpn"
echo "✅ Clave pública guardada en $DIST_DIR/RPM-GPG-KEY-midorivpn"
