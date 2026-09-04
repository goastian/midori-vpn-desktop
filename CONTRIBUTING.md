# Contributing to MidoriVPN Desktop

MidoriVPN Desktop 2.0.0 is unreleased. Linux x86_64 RPM is the only release
target. Contributions must not reintroduce retired Tauri, Rust, AppImage or
non-Linux product paths.

## Before starting

- Use a public issue for bugs and behavior proposals.
- Report vulnerabilities privately according to [SECURITY.md](SECURITY.md).
- Keep credentials, device state, private endpoints, logs, package keys and
  local evidence out of commits and issue attachments.
- Explain changes to privilege, tunnel, DNS, kill-switch, cleanup or package
  behavior explicitly.

## Development and checks

Use the pinned rootless runner from a Core checkout:

```bash
CORE_REPO=/absolute/path/to/midori-vpn-core
bash "$CORE_REPO/scripts/pod.sh" npm ci
bash "$CORE_REPO/scripts/pod.sh" npm run check

cd agent
bash "$CORE_REPO/scripts/pod.sh" go test -race ./...
bash "$CORE_REPO/scripts/pod.sh" go vet ./...
bash "$CORE_REPO/scripts/pod.sh" staticcheck ./...
bash "$CORE_REPO/scripts/pod.sh" govulncheck ./...
```

Run the relevant RPM packaging checks when changing `packaging/`, the native
tray or build scripts. Building an RPM does not authorize signing,
installation or publication.

Preserve stable installation identity, local-only private keys, authenticated
loopback RPC and deterministic network cleanup. Use the newest compatible
dependency release and update `v2.0.0 - Unreleased` in `CHANGELOG.md` for
visible, security or operational changes. Before submitting, run
`git diff --check` and describe behavior, tests, supported distributions and
risk in the pull request.

## License

By contributing, you agree that your contribution is licensed under
AGPL-3.0-or-later, as described in [LICENSE](LICENSE).
