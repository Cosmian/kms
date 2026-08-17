---
name: 'Lockfile & Nix Hashes'
description: 'Keep Nix vendor hashes in sync when Cargo.lock or pnpm-lock.yaml changes'
applyTo: 'Cargo.lock, ui/pnpm-lock.yaml'
---

# Lockfile → Nix vendor hash sync

When a lock file changes, the Nix vendor hashes must be updated to match.

## Checklist

- [ ] Update `nix/expected-hashes/` files with the correct `sha256-...` hash from CI output
- Hash files: `server.vendor.{static,dynamic}.sha256`, `cli.vendor.{static,dynamic}.{darwin,linux}.sha256`, `ui.vendor.{fips,non-fips}.sha256`, `ui.pnpm.{darwin,linux}.sha256`

When CI reports a hash mismatch, first verify the lock file changed **intentionally** in this PR;
if not, revert it.

> Rule 4.11 of `/kms-sync-rules`. For the full Nix workflow, see `nix.instructions.md`.
