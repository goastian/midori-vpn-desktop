#!/usr/bin/env bash
set -Eeuo pipefail

DESKTOP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${DESKTOP_DIR}/dist-packages"
FEDORA_IMAGE="docker.io/library/fedora:44@sha256:be9d65e2344d805cc11114319c685ecaa96b6d9b4350a0a6460cdb931babbd19"
SYFT_IMAGE="ghcr.io/anchore/syft@sha256:41f8289664101d6ebab30a97ac8df6b6f86b92d8343285ca90f428e2bc353106"
PUBLIC_KEY="${DIST_DIR}/RPM-GPG-KEY-midorivpn"

for command_name in date git jq podman sha256sum; do
  command -v "${command_name}" >/dev/null || { echo "error: ${command_name} is required" >&2; exit 1; }
done

rpm_files=("${DIST_DIR}"/*.rpm)
[[ -e "${rpm_files[0]}" ]] || { echo "error: no RPM packages found in ${DIST_DIR}" >&2; exit 1; }
[[ -s "${PUBLIC_KEY}" ]] || { echo "error: RPM public key is missing" >&2; exit 1; }

epoch="${SOURCE_DATE_EPOCH:-$(git -C "${DESKTOP_DIR}" show -s --format=%ct HEAD)}"
[[ "${epoch}" =~ ^[0-9]+$ ]] || { echo "error: SOURCE_DATE_EPOCH must be an integer" >&2; exit 1; }
commit="$(git -C "${DESKTOP_DIR}" rev-parse HEAD)"
created="$(date --utc --date="@${epoch}" +'%Y-%m-%dT%H:%M:%SZ')"

podman run --rm --userns=keep-id:uid=0,gid=0 \
  -v "${DIST_DIR}:/artifacts:ro,Z" \
  "${FEDORA_IMAGE}" \
  bash -c 'set -Eeuo pipefail
    rpm --dbpath /tmp/rpmdb --initdb
    rpm --dbpath /tmp/rpmdb --import /artifacts/RPM-GPG-KEY-midorivpn
    for rpm_file in /artifacts/*.rpm; do
      rpmkeys --dbpath /tmp/rpmdb --checksig --verbose "$rpm_file"
    done'

for rpm_file in "${rpm_files[@]}"; do
  artifact_name="$(basename "${rpm_file}")"
  artifact_sha="$(sha256sum "${rpm_file}" | awk '{print $1}')"
  sbom_file="${rpm_file}.spdx.json"
  sbom_raw="${sbom_file}.raw"
  provenance_file="${rpm_file}.provenance.json"

  podman run --rm --userns=keep-id:uid=0,gid=0 \
    -v "${DIST_DIR}:/artifacts:z" \
    -e SYFT_CACHE_DIR=/tmp/syft-cache \
    "${SYFT_IMAGE}" \
    scan "file:/artifacts/${artifact_name}" -o "spdx-json=/artifacts/${artifact_name}.spdx.json.raw"

  jq \
    --arg name "${artifact_name}" \
    --arg sha "${artifact_sha}" \
    --arg created "${created}" \
    --arg namespace "https://astian.org/spdx/midorivpn-desktop/2.0.0/${artifact_sha}" \
    '.name=$name | .documentNamespace=$namespace | .creationInfo.created=$created |
     .packages[0].name=$name | .packages[0].checksums=[{algorithm:"SHA256",checksumValue:$sha}]' \
    "${sbom_raw}" > "${sbom_file}"
  rm -f -- "${sbom_raw}"

  jq -n \
    --arg name "${artifact_name}" \
    --arg sha "${artifact_sha}" \
    --arg commit "${commit}" \
    --argjson epoch "${epoch}" \
    '{
      _type:"https://in-toto.io/Statement/v1",
      subject:[{name:$name,digest:{sha256:$sha}}],
      predicateType:"https://slsa.dev/provenance/v1",
      predicate:{
        buildDefinition:{
          buildType:"https://astian.org/midorivpn/rpm-build/v1",
          externalParameters:{version:"2.0.0",source_date_epoch:$epoch},
          resolvedDependencies:[{uri:"git+https://github.com/goastian/midorivpn-desktop",digest:{gitCommit:$commit}}]
        },
        runDetails:{builder:{id:"https://astian.org/midorivpn/rootless-podman-release/v1"}}
      }
    }' > "${provenance_file}"

  [[ -s "${sbom_file}" && -s "${provenance_file}" ]] || { echo "error: incomplete evidence for ${artifact_name}" >&2; exit 1; }
done

(
  cd "${DIST_DIR}"
  sha256sum -- *.rpm RPM-GPG-KEY-midorivpn *.spdx.json *.provenance.json > SHA256SUMS
  sha256sum -c SHA256SUMS
)

echo "Release evidence generated in ${DIST_DIR}"
