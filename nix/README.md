# Nix builds: determinism, offline guarantees & idempotent packaging

This directory contains the reproducible Nix derivations and helper scripts used to build and package the Cosmian KMS server.

Goals:

- Bit-for-bit deterministic KMS server binaries (FIPS & non-FIPS)
- Native hash enforcement inside the Nix derivation (installCheckPhase)
- Fully offline packaging after first prewarm
- Idempotent repeated packaging (no rebuild/download) via reuse & NO_PREWARM
- Unified DEB/RPM logic (single common script)
- Rust toolchain provisioned by Nix (no rustup/network)

## Determinism foundations

`nix/kms-server.nix` builds inside a hermetic, pinned environment:

- Pinned nixpkgs (24.05) to avoid upstream drift
- `cleanSourceWith` removes non-input artifacts (`result-*`, reports, caches)
- Locked Cargo dependency graph (`cargoHash`) — reproducible vendoring
- Deterministic Rust codegen & link flags: `-Cdebuginfo=0 -Ccodegen-units=1 -Cincremental=false -Clto=off -C link-arg=-Wl,--build-id=none`; Nix sets `SOURCE_DATE_EPOCH` for normalized embedded timestamps.
- Pinned OpenSSL 3.1.2 tarball (local or fetched by SRI hash)
- Sanitized ELF (RPATH removed, interpreter fixed) — avoids volatile store paths

Result: identical inputs ⇒ identical binary hash. Hash drift always means an intentional or accidental input change.

## Native hash verification (installCheckPhase)

During `installCheckPhase` we:

- Compute `sha256` of `$out/bin/cosmian_kms`
- Compare against a strict, platform-specific file: `nix/expected-hashes/<variant>.<system>.sha256`
      - `<variant>` is `fips` or `non-fips` depending on Cargo features
      - `<system>` is the Nix system triple (e.g., `x86_64-linux`, `aarch64-darwin`)
- Fail immediately on mismatch or if the required file is missing (no fallbacks)
- Assert static OpenSSL linkage, GLIBC symbol ceiling (≤ 2.28), OpenSSL version/mode

Update an expected hash after a legitimate change:

```bash
# Example for Apple Silicon macOS (aarch64-darwin)
nix-build -A kms-server-fips -o result-server-fips
sha256sum result-server-fips/bin/cosmian_kms | cut -d' ' -f1 > nix/expected-hashes/fips.aarch64-darwin.sha256

# Linux x86_64 example
nix-build -A kms-server-non-fips -o result-server-non-fips
sha256sum result-server-non-fips/bin/cosmian_kms | cut -d' ' -f1 > nix/expected-hashes/non-fips.x86_64-linux.sha256
```

## Proving determinism locally

```bash
# Two identical builds
nix-build -A kms-server-fips -o result-server-fips
nix-build -A kms-server-fips -o result-server-fips-2
sha256sum result-server-fips/bin/cosmian_kms result-server-fips-2/bin/cosmian_kms
```

Hashes must match.

To test failure path: edit one character in the expected hash file and rebuild; build must fail. Restore correct hash; build succeeds.

## Unified & idempotent packaging

`nix/scripts/package_common.sh` centralizes logic. Thin wrappers:

- `package_deb.sh --variant fips|non-fips`
- `package_rpm.sh --variant fips|non-fips`

Key behaviors:

- Reuse existing `result-server-<variant>` symlink (no rebuild)
- `NO_PREWARM=1` skips prewarm phase for fast repeat runs
- Tool provisioning via Nix: `ensure_modern_rust`, `ensure_cargo_deb`, `ensure_cargo_generate_rpm`
- FIPS artifacts renamed with `-fips` suffix consistently
- Packaging reuses already hash-verified binary (no duplicate check needed)

Idempotence demo:

```bash
bash .github/scripts/nix.sh package deb
bash .github/scripts/nix.sh package deb    # Reuses binary; no compilation
```

## Offline packaging flow

1. Prewarm (skipped if `NO_PREWARM=1`):
   - Realize `openssl312` & `kms-server-<variant>` in the Nix store
   - Ensure the local OpenSSL tarball exists at `resources/tarballs/openssl-3.1.2.tar.gz`
   - Prewarm Cargo registry into a persistent cache: `target/cargo-offline-home` using `cargo fetch --locked`
     (with `--features non-fips` for the non-FIPS variant)
2. Offline packaging: scripts set `CARGO_HOME=target/cargo-offline-home` and `CARGO_NET_OFFLINE=true`, then invoke
   `cargo deb --no-build` or `cargo generate-rpm` without hitting the network. Nix builds use
   `--option substituters ""` to avoid binary caches.
3. Package signing (optional): if a GPG signing key is configured, each package receives a detached GPG signature (`.asc` file).

Verification tip: after a successful prewarm, disable network and rerun packaging — it should still succeed and produce identical artifacts.

## Package signing

Packages (DEB, RPM, DMG) can be cryptographically signed with GPG for distribution integrity.

### Setup signing key

```bash
export GPG_SIGNING_KEY_PASSPHRASE='your-secure-passphrase'
bash nix/scripts/generate_signing_key.sh
```

This creates keys in `nix/signing-keys/`:

- `cosmian-kms-public.asc` - Public key for verification (distribute to users)
- `cosmian-kms-private.asc` - Private key for signing (encrypted with passphrase)
- `key-id.txt` - GPG key ID used by scripts

### Sign packages during build

Set the passphrase before packaging:

```bash
export GPG_SIGNING_KEY_PASSPHRASE='your-secure-passphrase'
bash .github/scripts/nix.sh package deb
```

Each package will have a corresponding `.asc` signature:

- `result-deb-fips/cosmian_kms_server_5.11.1_amd64.deb.asc`
- `result-rpm-fips/cosmian_kms_server_fips-5.11.1.x86_64.rpm.asc`
- `result-dmg-fips/Cosmian KMS Server_5.11.1_arm64.dmg.asc`

### Verify signatures

```bash
# Import public key once
gpg --import nix/signing-keys/cosmian-kms-public.asc

# Verify package
gpg --verify result-deb-fips/cosmian_kms_server_5.11.1_amd64.deb.asc
```

See `nix/signing-keys/README.md` for detailed signing documentation.

## Rust toolchain (no rustup)

`default.nix` exports `rustToolchain` (Rust 1.90.0). Scripts:

```bash
nix-build -A rustToolchain -o result-rust
export PATH="$(readlink -f result-rust)/bin:$PATH"
```

Benefits: consistent versions, no rustup downloads, contributes to determinism.

## Notes

- OpenSSL build fails if local tarball present but hash mismatched
- Install checks assert static linkage & version invariants
- Any intentional dependency / code change requires updating expected hash

## Troubleshooting

| Symptom | Likely cause | Resolution |
|---------|--------------|-----------|
| Hash mismatch failure | Genuine input change | Recalculate & commit expected hash |
| Rebuild on repeat packaging | Forgot `NO_PREWARM=1` | Export env var or adjust CI |
| Network access attempted (Nix) | Store not prewarmed | Run once without NO_PREWARM |
| `cargo-deb` or `cargo generate-rpm` hits crates.io | Cargo registry not prewarmed or offline env not active | Ensure prewarm ran; set `CARGO_HOME=target/cargo-offline-home` and `CARGO_NET_OFFLINE=true` |
| rustup downloads appear | Not using Nix toolchain | Ensure `ensure_modern_rust` ran |

## Files overview

- `kms-server.nix` — derivation + install checks
- `openssl-3_1_2.nix` — pinned OpenSSL
- `expected-hashes/` — authoritative binary hashes
- `scripts/package_common.sh` — shared packaging logic
- `scripts/package_deb.sh` / `scripts/package_rpm.sh` — thin wrappers
- `README.md` — this document

## Offline dependencies location

The prewarm steps populate the following paths so packaging can run fully offline:

- Pinned nixpkgs (24.05): realized to a store path and exported as `NIXPKGS_STORE`
      - Example: `/nix/store/<hash>-source`
- Nix derivations realized locally (symlinks point into the store):
      - `result-openssl-312` → `/nix/store/<hash>-openssl-3.1.2`
      - `result-server-<variant>` → `/nix/store/<hash>-cosmian-kms-server-<version>`
      - Rust toolchain 1.90.0: `result-rust-1_90` → `/nix/store/<hash>-rust-minimal-1.90.0`
      - Cargo tools:
            - `result-cargo-deb` → `/nix/store/<hash>-cargo-deb-<version>`
            - `result-cargo-generate-rpm` → `/nix/store/<hash>-cargo-generate-rpm-<version>`
      - Smoke-test tools realized in the store (no symlinks created): `dpkg`, `rpm`, `cpio`, `curl`
- OpenSSL source tarball (local copy for offline builds):
      - `resources/tarballs/openssl-3.1.2.tar.gz`
- Cargo registry and source cache used by `cargo-deb`/`cargo generate-rpm`:
      - `target/cargo-offline-home/`
            - Contains `registry/index/*`, `registry/cache/*`, and `git/db/*` populated during prewarm

## Summary

Determinism is enforced natively by Nix; offline & idempotent packaging is attained through prewarm reuse, a unified script, and Nix-provided Rust. Any hash change is investigated, justified, and then updated explicitly.
