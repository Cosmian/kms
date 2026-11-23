---
name: 'Nix Packaging'
description: 'Nix build expressions and vendor hash management'
applyTo: 'nix/**/*.nix'
---

# Nix packaging rules

## Structure

- `nix/` contains build expressions for the KMS server, CLI, UI, OpenSSL, and HSM backends.
- `nix/expected-hashes/` stores vendor hashes for reproducible builds (Cargo deps, npm deps).
- Deb and RPM packages are built via Nix derivations.

## Vendor hash mismatch workflow

When CI reports a hash mismatch:

1. **Verify intent**: Check if `Cargo.lock` or `ui/pnpm-lock.yaml` actually changed in this PR.
2. **If unintentional**: Revert the lock file change.
3. **If intentional**: Do **not** renew the hash in the PR, and do not edit `nix/expected-hashes/`. The nightly workflow (`nightly.yml` → `nix-update-hashes.yml`) recomputes and commits them. See `lockfile-hashes.instructions.md`. Only a nightly run, or an explicit user request, may renew them.

## CI entry point

All CI runs go through Nix:

```bash
mise run [--variant fips|non-fips] [--link static|dynamic] <task>
```

## OpenSSL bootstrap

- `nix/openssl.nix` handles the OpenSSL 3.6.5 build for Nix environments.
- `nix/openssl-fips-bootstrap.c` + `nix/openssl-fips-bootstrap.nix` handle FIPS module initialization.

## Best practices

- Pin all inputs — never use `fetchurl` without a hash.
- Keep derivations minimal — build logic belongs in `build.rs` or `Makefile`, not Nix.
- Test locally with `nix-build` before pushing hash changes.
