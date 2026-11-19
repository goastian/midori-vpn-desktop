#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CHECKER="${ROOT_DIR}/scripts/check-rpm-signing-identity.sh"
PRIMARY="$(awk -F '"' '/^EXPECTED_PRIMARY_FINGERPRINT=/ { print $2 }' "${CHECKER}")"
SIGNING="$(awk -F '"' '/^EXPECTED_SIGNING_FINGERPRINT=/ { print $2 }' "${CHECKER}")"
[[ "${PRIMARY}" =~ ^[A-F0-9]{40}$ && "${SIGNING}" =~ ^[A-F0-9]{40}$ ]]

fixture="$(mktemp -d "${TMPDIR:-/tmp}/midorivpn-signing-policy.XXXXXX")"
trap 'rm -rf -- "${fixture}"' EXIT
mkdir -p "${fixture}/bin"
cat > "${fixture}/bin/gpg" <<'GPG'
#!/usr/bin/env bash
set -eu
if [[ "${GPG_TEST_STATUS:-0}" != 0 ]]; then exit "${GPG_TEST_STATUS}"; fi
cat "${GPG_TEST_LISTING:?}"
GPG
chmod 0700 "${fixture}/bin/gpg"

record() {
  local fields=("$1" "$2" 255 22 FIXTURE 1 "$3" "" "" "" "" "$4" "" "" "$5" "" "" "" "" "")
  (IFS=:; printf '%s\n' "${fields[*]}")
}

listing() {
  {
    record sec "${1:-u}" "${2:-0}" cSC '#'
    printf 'fpr:::::::::%s:\n' "${PRIMARY}"
    record ssb "${3:-u}" "${4:-0}" "${5:-s}" "${6:-+}"
    printf 'fpr:::::::::%s:\n' "${SIGNING}"
  } > "${fixture}/listing"
}

failures=0
assert_case() {
  local name="$1" expected="$2" status=0
  PATH="${fixture}/bin:${PATH}" GPG_TEST_LISTING="${fixture}/listing" \
    bash "${CHECKER}" > "${fixture}/output" 2>&1 || status=$?
  if [[ "${status}" != "${expected}" ]]; then
    printf 'FAIL %s: status %s, expected %s\n' "${name}" "${status}" "${expected}" >&2
    failures=$((failures + 1))
  else
    printf 'PASS %s\n' "${name}"
  fi
}

listing
assert_case 'CI signing subkey with stub primary' 0
RPM_SIGNING_KEY_ID="${SIGNING}" assert_case 'explicit signing subkey' 0
RPM_SIGNING_KEY_ID="${PRIMARY,,}" assert_case 'normalized primary fingerprint' 0
RPM_SIGNING_KEY_ID=0000000000000000000000000000000000000000 assert_case 'untrusted requested identity' 1
GPG_TEST_STATUS=1 assert_case 'GnuPG listing failure' 1

listing e
assert_case 'expired primary' 1
listing u 1
assert_case 'primary expiration timestamp' 1
listing u 0 r
assert_case 'revoked signing subkey' 1
listing u 0 e
assert_case 'expired signing subkey' 1
listing u 0 u 1
assert_case 'signing expiration timestamp' 1
listing u 0 u 0 e
assert_case 'non-signing subkey' 1
listing u 0 u 0 s '#'
assert_case 'unavailable signing secret' 1
listing u 0 u 0 sD +
assert_case 'disabled signing subkey' 1

printf 'fpr:::::::::%s:\nfpr:::::::::%s:\n' "${PRIMARY}" "${SIGNING}" > "${fixture}/listing"
assert_case 'fingerprints without key records' 1
listing
sed -i "s/${SIGNING}/0000000000000000000000000000000000000000/" "${fixture}/listing"
assert_case 'different signing fingerprint' 1

[[ "${failures}" == 0 ]] || exit 1
mkdir -m 0700 "${fixture}/public-keyring"
public_listing="$(gpg --homedir "${fixture}/public-keyring" --batch --with-colons \
  --fingerprint --fingerprint --show-keys "${ROOT_DIR}/RPM-GPG-KEY-midorivpn" 2> "${fixture}/public-key.log")"
mapfile -t public_fingerprints < <(awk -F: '$1 == "fpr" { print $10 }' <<<"${public_listing}")
[[ "${#public_fingerprints[@]}" == 2 &&
  "${public_fingerprints[0]}" == "${PRIMARY}" &&
  "${public_fingerprints[1]}" == "${SIGNING}" ]] || {
  echo "error: the tracked public key does not match the pinned signing identity" >&2
  exit 1
}
printf 'Signing identity policy: PASS\n'
