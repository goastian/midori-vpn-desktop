#!/usr/bin/env bash
# Install pinned security scanners used by CI and local release checks.
set -euo pipefail

tool="${1:-all}"

: "${GOVULNCHECK_VERSION:=v1.3.0}"

install_govulncheck() {
  go install "golang.org/x/vuln/cmd/govulncheck@$GOVULNCHECK_VERSION"
}

case "$tool" in
  all)
    install_govulncheck
    ;;
  govulncheck)
    install_govulncheck
    ;;
  *)
    echo "usage: $0 [all|govulncheck]" >&2
    exit 2
    ;;
esac
