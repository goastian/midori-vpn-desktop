# Security policy

## Supported versions

MidoriVPN Desktop 2.0.0 is currently unreleased. Security fixes are applied to
the 2.0.0 development line, but that source must not be treated as a supported
production release. Earlier release lines are no longer maintained by this
repository.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use the
[private GitHub security advisory form](https://github.com/goastian/midori-vpn-desktop/security/advisories/new).
Report a Core API or cross-component issue in the
[Core repository](https://github.com/goastian/midori-vpn-core/security/advisories/new)
and identify Desktop as affected.

Include the affected version or commit, Linux distribution, transport, a
minimal reproduction and impact. Sanitize agent output and remove access
tokens, private keys, certificate material, host addresses, device identity
and user data. Never send live credentials or production data.

## Response and disclosure

The maintainers aim to acknowledge a complete report within three business
days and provide an initial triage within seven business days. Please keep the
report private until a fix and disclosure date are agreed. Validated fixes must
pass agent, UI, networking, cleanup and package-integrity gates before a release
is announced.

Reports involving local RPC, privilege boundaries, tunnel routing, DNS, kill
switches, credential storage, package signing or update integrity are in scope.
