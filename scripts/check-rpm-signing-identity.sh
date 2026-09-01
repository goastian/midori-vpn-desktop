#!/usr/bin/env bash
set -Eeuo pipefail

EXPECTED_PRIMARY_FINGERPRINT="BE000EFBCD8F4CDA53FC1A9F13FC1FEEE3315359"
EXPECTED_SIGNING_FINGERPRINT="84218F95A58E644EDB6947336CF4082EE316F221"

command -v gpg >/dev/null || { echo "error: gpg is required" >&2; exit 1; }

if ! secret_listing="$(gpg --batch --with-colons --fingerprint --fingerprint \
  --list-secret-keys "${EXPECTED_PRIMARY_FINGERPRINT}" 2>/dev/null)"; then
  echo "error: the existing MidoriVPN RPM secret identity is unavailable" >&2
  echo "expected primary fingerprint: ${EXPECTED_PRIMARY_FINGERPRINT}" >&2
  exit 1
fi

mapfile -t fingerprints < <(awk -F: '$1 == "fpr" {print toupper($10)}' <<<"${secret_listing}")
contains_fingerprint() {
  local expected="$1"
  local fingerprint
  for fingerprint in "${fingerprints[@]}"; do
    [[ "${fingerprint}" == "${expected}" ]] && return 0
  done
  return 1
}

contains_fingerprint "${EXPECTED_PRIMARY_FINGERPRINT}" || {
  echo "error: RPM primary fingerprint does not match the established trust anchor" >&2
  exit 1
}
contains_fingerprint "${EXPECTED_SIGNING_FINGERPRINT}" || {
  echo "error: the established RPM signing subkey is unavailable" >&2
  exit 1
}

requested_key="${RPM_SIGNING_KEY_ID:-${EXPECTED_PRIMARY_FINGERPRINT}}"
requested_key="${requested_key^^}"
if [[ "${requested_key}" != "${EXPECTED_PRIMARY_FINGERPRINT}" && \
      "${requested_key}" != "${EXPECTED_SIGNING_FINGERPRINT}" ]]; then
  echo "error: RPM_SIGNING_KEY_ID is not the established MidoriVPN identity" >&2
  exit 1
fi

echo "RPM signing identity available: ${EXPECTED_PRIMARY_FINGERPRINT}"
echo "RPM signing subkey available: ${EXPECTED_SIGNING_FINGERPRINT}"
