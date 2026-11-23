---
name: 'Lockfile & Nix Hashes'
description: 'Never renew Nix vendor hashes in a PR when Cargo.lock or pnpm-lock.yaml changes; the nightly workflow does it'
applyTo: 'Cargo.lock, ui/pnpm-lock.yaml'
---

# Lockfile → Nix vendor hashes: do NOT renew them

When `Cargo.lock` or `ui/pnpm-lock.yaml` changes, the Nix vendor hashes under `nix/expected-hashes/` become stale.
**Do not recompute or edit them** in a feature, fix, dependency or Dependabot PR: the nightly build does it.

- The nightly workflow (`.github/workflows/nightly.yml`, job `update-nix-hashes` calling `nix-update-hashes.yml`) runs `mise run release:nix-update-hashes` on Linux and macOS and commits the refreshed hashes back to the branch.
- Never run `mise run release:nix-update-hashes`, `mise run release:update-hashes`, `nix_build_update_hash.sh` or `nix-build -A <attr>` to refresh hashes by hand, and never copy a `got: sha256-...` value from a log into `nix/expected-hashes/`.
- Never hand-edit `nix/expected-hashes/*` in a PR. Leave them untouched, even when a Nix job fails with `hash mismatch` after a lock file change.
- Exception: a run of the nightly workflow itself (schedule, or a manual dispatch of it), or an explicit request from the user to renew them.

## Checklist

- [ ] The lock file change is intentional (revert it if not). Use `cargo update -p <crate>@<old> --precise <new>`; never hand-edit `Cargo.lock`.
- [ ] `nix/expected-hashes/` is not part of the diff.
- [ ] The PR description (or final summary) says that the Nix vendor hashes are left to the nightly build, so a `hash mismatch` on a Nix job is expected until it runs.
- [ ] New or bumped third-party packages in either lock file also go through `dependencies.instructions.md` (rule 4.19): `cargo vet check --locked` for `Cargo.lock`; release age, install scripts and `pnpm audit` for `ui/pnpm-lock.yaml`.

For a lockfile-only change, do not apply unrelated Rust source-audit skills.
This does not replace a requested dependency or supply-chain security review. If manifests or cryptographic behavior also changed,
apply their normal review gates.

> Rule 4.11 of `/kms-sync-rules`. For the full Nix workflow, see `nix.instructions.md`.
