#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DESKTOP_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$DESKTOP_DIR/dist-packages"
KEY_ID="BE000EFBCD8F4CDA53FC1A9F13FC1FEEE3315359"

echo "==> Firmando paquetes RPM con clave Ed25519 (EdDSA): $KEY_ID..."

if ! command -v rpmsign &> /dev/null; then
    echo "⚠️ rpmsign no está instalado. Saltando firmado."
    exit 0
fi

for rpm_file in "$DIST_DIR"/*.rpm; do
    if [ -f "$rpm_file" ]; then
        echo "Firmando $rpm_file..."
        rpmsign --addsign "$rpm_file"
        echo "✅ Firmado exitoso: $rpm_file"
    fi
done

echo "==> Exportando clave pública OpenPGP..."
gpg --armor --export "$KEY_ID" > "$DIST_DIR/RPM-GPG-KEY-midorivpn"
cp "$DIST_DIR/RPM-GPG-KEY-midorivpn" "$DESKTOP_DIR/RPM-GPG-KEY-midorivpn"
echo "✅ Clave pública guardada en $DIST_DIR/RPM-GPG-KEY-midorivpn"
