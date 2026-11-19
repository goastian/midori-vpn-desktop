#!/usr/bin/env bash
set -Eeuo pipefail

EXPECTED_PRIMARY_FINGERPRINT="F848EF47481B45DA34469E6BAF9D3E9CF7E34163"
EXPECTED_SIGNING_FINGERPRINT="C6833E4CA9141C07AD1564FCB5382507F46384A6"

command -v gpg >/dev/null || { echo "error: gpg is required" >&2; exit 1; }

if ! secret_listing="$(gpg --batch --with-colons --fingerprint --fingerprint \
  --list-secret-keys "${EXPECTED_PRIMARY_FINGERPRINT}" 2>/dev/null)"; then
  echo "error: the existing MidoriVPN RPM secret identity is unavailable" >&2
  echo "expected primary fingerprint: ${EXPECTED_PRIMARY_FINGERPRINT}" >&2
  exit 1
fi

if ! awk -F: \
  -v primary="${EXPECTED_PRIMARY_FINGERPRINT}" \
  -v signing="${EXPECTED_SIGNING_FINGERPRINT}" \
  -v now="$(date +%s)" '
  function active() {
    return validity !~ /^(r|e|d|i)$/ && index(capabilities, "D") == 0 &&
      (expires == "" || expires == "0" || (expires ~ /^[0-9]+$/ && expires > now))
  }
  $1 == "sec" || $1 == "ssb" {
    kind = $1; validity = $2; expires = $7; capabilities = $12; available = $15
  }
  $1 == "fpr" && kind == "sec" && toupper($10) == primary {
    primary_ok = active() && index(capabilities, "c") > 0
  }
  $1 == "fpr" && kind == "ssb" && toupper($10) == signing {
    signing_ok = active() && index(capabilities, "s") > 0 &&
      available != "" && available != "#"
  }
  END { exit !(primary_ok && signing_ok) }
' <<<"${secret_listing}"; then
  echo "error: the trusted RPM identity and an active, available signing subkey are required" >&2
  exit 1
fi

requested_key="${RPM_SIGNING_KEY_ID:-${EXPECTED_PRIMARY_FINGERPRINT}}"
requested_key="${requested_key^^}"
if [[ "${requested_key}" != "${EXPECTED_PRIMARY_FINGERPRINT}" && \
      "${requested_key}" != "${EXPECTED_SIGNING_FINGERPRINT}" ]]; then
  echo "error: RPM_SIGNING_KEY_ID is not the established MidoriVPN identity" >&2
  exit 1
fi

echo "RPM signing identity available: ${EXPECTED_PRIMARY_FINGERPRINT}"
echo "RPM signing subkey available: ${EXPECTED_SIGNING_FINGERPRINT}"
