# RPM signing

Desktop signing runs manually in `goastian/midori-vpn-desktop`, using the
`release-signing` environment, a human approval and the annotated `v2.0.0` tag.
The private development repository runs checks without access to signing keys.
The workflow does not create tags, GitHub Releases, deployments or store uploads.
It also requires the environment variable `RELEASE_SIGNING_ENABLED=true`.
Keep that switch disabled until the release tag and signed build are explicitly
approved; provisioning encrypted subkey secrets alone must not start a build.

The trusted public key is `RPM-GPG-KEY-midorivpn`:

- Primary: `F848EF47481B45DA34469E6BAF9D3E9CF7E34163`
- Signing subkey: `C6833E4CA9141C07AD1564FCB5382507F46384A6`
- Identity: `Astian — MidoriVPN <walddys.dorrejo@astian.org>`

This replaces the unavailable historical primary
`BE000EFBCD8F4CDA53FC1A9F13FC1FEEE3315359`. It is a new trust anchor, not a
cryptographic revocation of that old key. Verify the new fingerprint through
the official release channel before trusting packages signed by it.

## Custody

Keep encrypted primary-key and revocation backups outside the checkout, with
owner-only directory/file permissions. Back up the passphrase separately in a
trusted password manager. A hidden directory is not a substitute for encryption.
Never commit private exports, passphrases or local key directories.

CI receives only an encrypted signing-subkey export (stub primary) and its
passphrase through the protected environment secrets `RPM_SIGNING_PRIVATE_KEY`
and `RPM_SIGNING_PASSPHRASE`. It must never receive the primary private key.
The environment must require human approval and allow only the release tag;
do not replace missing private-repository protections with an unprotected job.

Signing uses an isolated `GNUPGHOME`, overrides per-user RPM key macros and
selects the exact signing subkey. Noninteractive signing uses an owner-only
temporary passphrase file, deleted on exit. The workflow removes its private
keyring before retaining only `dist-packages/` evidence.

Run `bash scripts/test-signing-identity.sh` without production secrets to test
identity, expiration, revocation, availability and the tracked public key.
Actual RPM signature verification remains part of the signed build.
