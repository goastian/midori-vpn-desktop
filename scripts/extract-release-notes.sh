#!/usr/bin/env bash
set -euo pipefail

release_tag="${1:?release tag is required}"
changelog_path="${2:-CHANGELOG.md}"
body_path="${3:-release-body.md}"

if [ ! -f "$changelog_path" ]; then
  echo "Missing changelog file: ${changelog_path}" >&2
  exit 1
fi

heading="$(
  awk -v tag="$release_tag" '
    function heading_tag(line, normalized, parts) {
      normalized = line
      sub(/^##[[:space:]]+/, "", normalized)
      sub(/^\[/, "", normalized)
      sub(/\].*$/, "", normalized)
      split(normalized, parts, /[[:space:]]+/)
      return parts[1]
    }

    /^##[[:space:]]+/ {
      if (heading_tag($0) == tag) {
        sub(/^##[[:space:]]+/, "")
        print
        exit
      }
    }
  ' "$changelog_path"
)"

if [ -z "$heading" ]; then
  echo "No changelog entry found for ${release_tag} in ${changelog_path}" >&2
  exit 1
fi

awk -v tag="$release_tag" '
  function heading_tag(line, normalized, parts) {
    normalized = line
    sub(/^##[[:space:]]+/, "", normalized)
    sub(/^\[/, "", normalized)
    sub(/\].*$/, "", normalized)
    split(normalized, parts, /[[:space:]]+/)
    return parts[1]
  }

  /^##[[:space:]]+/ {
    current_tag = heading_tag($0)
    if (found) {
      exit
    }
    if (current_tag == tag) {
      found = 1
      next
    }
  }

  found {
    print
  }

  END {
    if (!found) {
      exit 1
    }
  }
' "$changelog_path" > "$body_path"

if ! grep -q '[^[:space:]]' "$body_path"; then
  echo "Changelog entry for ${release_tag} has no release body." >&2
  exit 1
fi

release_title="$heading"
case "$heading" in
  *" - "*) release_title="${heading#* - }" ;;
esac

if [ -z "$release_title" ]; then
  release_title="MidoriVPN Desktop ${release_tag}"
fi

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "release-title=${release_title}" >> "$GITHUB_OUTPUT"
  echo "release-body-path=${body_path}" >> "$GITHUB_OUTPUT"
  {
    echo "release-body<<EOF"
    cat "$body_path"
    echo "EOF"
  } >> "$GITHUB_OUTPUT"
fi

echo "Release title: ${release_title}"
echo "Release body: ${body_path}"
