## Bug Fixes

### Hardening
- Release builders no longer hold release credentials (#1498): version bump, Nix hash, generated-docs and SBOM jobs check out without `PAT_TOKEN` or persisted credentials and upload a data patch; the new Git-only `commit-generated.yml` takes its helpers from its own commit, requires the base commit to belong to the repository history, applies the patch to exact validated file paths, transplants that single commit onto the branch tip and pushes without force. `sync-branches` is Git-only with command-scoped authentication; the release branch is no longer deleted and recreated
- `cargo-publish.yml` is split into a credential-free `verify` (full `--dry-run` compile) and a `publish` job (tags only, `crates-io` environment holding the `CRATES_IO` secret, `--no-verify`) so no dependency code runs next to `CARGO_REGISTRY_TOKEN`
- Package uploads (8 jobs) run on hosted runners in the `package-publish` environment with a dedicated write-only rsync key (`PACKAGE_COSMIAN_SSH_PRIVATE_KEY`, server-side `rrsync -wo -no-del`) instead of the host SSH key mounted into a mutable container; new `.mise/scripts/release/push_package.sh`
- New `mise run sbom:check-advisories` (and `--policy-only` in `sbom:validate`) fails on vulnerable lock entries, the QUIC stack or HTTP/3 in the shipped graphs, and ignore/OpenVEX mismatches; `mise run dev:ci-security` runs the credential-isolation, restricted-upload and advisory regression tests in the `supply-chain.yml` job `release-security`

## Build

- `Cargo.lock`: `quinn-proto` 0.11.16 -> 0.11.19 (RUSTSEC-2026-0523/0524), `quinn-udp` 0.5.15 -> 0.5.16 (RUSTSEC-2026-0538), `rustix` 1.1.4 -> 1.1.6 (RUSTSEC-2026-0486); `rustix` is a real runtime dependency (via `tempfile`/`native-tls`), the QUIC stack is not compiled in
- Administrators must create the `crates-io` (required reviewers, `CRATES_IO` as environment secret only) and `package-publish` (`PACKAGE_COSMIAN_SSH_PRIVATE_KEY`) environments, a `kms-ci-upload` account on `package.cosmian.com` whose key is prefixed `restrict,command="/usr/bin/rrsync -wo -munge -no-del /mnt/package/kms"`, and make `PAT_TOKEN` available to the repository. See `.github/workflows/README_main.md`
