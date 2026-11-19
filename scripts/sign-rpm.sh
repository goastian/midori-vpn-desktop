#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DESKTOP_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DIST_DIR="$DESKTOP_DIR/dist-packages"
KEY_ID="${RPM_SIGNING_KEY_ID:-}"
EXPECTED_PRIMARY_FINGERPRINT="F848EF47481B45DA34469E6BAF9D3E9CF7E34163"
EXPECTED_SIGNING_FINGERPRINT="C6833E4CA9141C07AD1564FCB5382507F46384A6"

if [ -z "$KEY_ID" ]; then
    echo "error: RPM_SIGNING_KEY_ID is required" >&2
    exit 1
fi

echo "==> Firmando paquetes RPM con clave Ed25519 (EdDSA): $KEY_ID..."

for command_name in rpmsign gpg gpgconf podman; do
    if ! command -v "$command_name" >/dev/null 2>&1; then
        echo "error: $command_name is required to sign and verify the RPM" >&2
        exit 1
    fi
done

normalized_key_id="${KEY_ID^^}"
if [[ "${normalized_key_id}" != "${EXPECTED_PRIMARY_FINGERPRINT}" && \
      "${normalized_key_id}" != "${EXPECTED_SIGNING_FINGERPRINT}" ]]; then
    echo "error: RPM_SIGNING_KEY_ID does not match the established MidoriVPN trust identity" >&2
    exit 1
fi

RPM_SIGNING_KEY_ID="${normalized_key_id}" bash "$SCRIPT_DIR/check-rpm-signing-identity.sh"

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
gpg --batch --armor --export "$EXPECTED_PRIMARY_FINGERPRINT" > "$public_key"
if [ ! -s "$public_key" ]; then
    echo "error: exported RPM public key is empty" >&2
    exit 1
fi

gnupg_home="$(gpgconf --list-dirs homedir)"
[[ "${gnupg_home}" != *'%'* && "${gnupg_home}" != *$'\n'* && "${gnupg_home}" != *$'\r'* ]] || {
  echo "error: unsupported GnuPG home path for RPM macros" >&2
  exit 1
}
sign_options=(
  --define "_gpg_name ${EXPECTED_SIGNING_FINGERPRINT}!"
  --define "_gpg_path ${gnupg_home}"
)
signing_temp=""
cleanup_signing() {
  if [[ -n "${signing_temp}" ]]; then
    rm -f -- "${signing_temp}/passphrase"
    rmdir -- "${signing_temp}"
  fi
}
trap cleanup_signing EXIT
if [[ -n "${RPM_SIGNING_PASSPHRASE:-}" ]]; then
  signing_temp="$(mktemp -d "${TMPDIR:-/tmp}/midorivpn-rpmsign.XXXXXX")"
  [[ "${signing_temp}" != *'%'* && "${signing_temp}" != *$'\n'* && "${signing_temp}" != *$'\r'* ]]
  chmod 0700 "${signing_temp}"
  (umask 077; printf '%s' "${RPM_SIGNING_PASSPHRASE}" > "${signing_temp}/passphrase")
  sign_options+=(--define "_gpg_sign_cmd_extra_args --batch --pinentry-mode loopback --passphrase-file %{shescape:${signing_temp}/passphrase}")
fi

for rpm_file in "${rpm_files[@]}"; do
    echo "Firmando $rpm_file..."
    rpmsign "${sign_options[@]}" --addsign "$rpm_file"
    echo "✅ Firmado: $rpm_file"
done

podman run --rm --userns=keep-id:uid=0,gid=0 \
    -v "$DIST_DIR:/artifacts:ro,Z" \
    docker.io/library/fedora:44@sha256:15da97ed9aa94dd3d92c3925eb89520f6c80e07ea7ee24cba848d1f8b6912b3e \
    bash -c 'set -Eeuo pipefail
      rpm --dbpath /tmp/rpmdb --initdb
      rpm --dbpath /tmp/rpmdb --import /artifacts/RPM-GPG-KEY-midorivpn
      for rpm_file in /artifacts/*.rpm; do
        rpmkeys --dbpath /tmp/rpmdb --checksig --verbose "$rpm_file"
      done'

echo "✅ Clave pública guardada en $DIST_DIR/RPM-GPG-KEY-midorivpn"
