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

### How deterministic builds work

`nix/kms-server.nix` builds inside a hermetic, pinned environment with controlled inputs:

1. **Pinned nixpkgs (24.05)**: Frozen package set prevents upstream drift
2. **Source cleaning**: `cleanSourceWith` removes non-input artifacts (`result-*`, reports, caches)
3. **Locked dependencies**: Cargo dependency graph frozen via `cargoHash` (reproducible vendoring)
4. **Deterministic compilation**: Rust codegen flags eliminate non-determinism:
   - `-Cdebuginfo=0` — No debug symbols (timestamps, paths)
   - `-Ccodegen-units=1` — Single codegen unit (deterministic order)
   - `-Cincremental=false` — No incremental compilation cache
   - `-C link-arg=-Wl,--build-id=none` — No build-id section
   - `SOURCE_DATE_EPOCH` — Normalized embedded timestamps
5. **Pinned OpenSSL 3.1.2**: Local tarball or fetched by SRI hash (FIPS 140-3 certified)
6. **Sanitized binaries**: RPATH removed, interpreter fixed to avoid volatile store paths

**Result**: Identical inputs ⇒ identical binary hash. Hash drift always means an intentional or accidental input change.

### Deterministic build hash inventory

All hashes are committed in the repository and verified during builds:

| Hash Type             | Purpose                             | Location                                           | Example (x86_64-linux FIPS)                                        |
| --------------------- | ----------------------------------- | -------------------------------------------------- | ------------------------------------------------------------------ |
| **Cargo vendor**      | Reproducible Rust dependencies      | `nix/kms-server.nix:122`                           | `sha256-NAy4vNoW7nkqJF263FkkEvAh1bMMDJkL0poxBzXFOO8=`              |
| **OpenSSL source**    | FIPS 140-3 certified crypto library | `nix/openssl-3_1_2.nix:14`                         | `sha256-BPedCZMRpt6FvPc3WDopPx8DAag0Gbu6N6hqdHvomso=`              |
| **Binary (FIPS)**     | Final KMS server executable         | `nix/expected-hashes/fips.x86_64-linux.sha256`     | `90eb9f3bd0d58c521ea68dfa205bdcc6c34b4064198c9fbb51f4d753df16e1f1` |
| **Binary (non-FIPS)** | Non-FIPS KMS server                 | `nix/expected-hashes/non-fips.x86_64-linux.sha256` | `564a07b4abc5944a557e94e7816a800968f90b6a442e4982fdb5896f7bf4932b` |

Platform-specific binary hashes:

| Platform       | Variant  | Hash File                                            | Enforced At         |
| -------------- | -------- | ---------------------------------------------------- | ------------------- |
| x86_64-linux   | FIPS     | `nix/expected-hashes/fips.x86_64-linux.sha256`       | `installCheckPhase` |
| x86_64-linux   | non-FIPS | `nix/expected-hashes/non-fips.x86_64-linux.sha256`   | `installCheckPhase` |
| aarch64-linux  | FIPS     | `nix/expected-hashes/fips.aarch64-linux.sha256`      | `installCheckPhase` |
| aarch64-linux  | non-FIPS | `nix/expected-hashes/non-fips.aarch64-linux.sha256`  | `installCheckPhase` |
| aarch64-darwin | FIPS     | `nix/expected-hashes/fips.aarch64-darwin.sha256`     | `installCheckPhase` |
| aarch64-darwin | non-FIPS | `nix/expected-hashes/non-fips.aarch64-darwin.sha256` | `installCheckPhase` |

**Note**: The Cargo vendor hash may differ between macOS and Linux due to platform-specific dependencies. OpenSSL and binary hashes are platform-specific by design.

### Hash verification flow

During the build process, Nix enforces all hashes at multiple stages:

```text
┌─────────────────────────────────────────────────────────────────┐
│ Step 1: Source Preparation                                      │
├─────────────────────────────────────────────────────────────────┤
│ • cleanSourceWith removes artifacts (result-*, sbom/, target/)  │
│ • Clean source tree → reproducible input                        │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ Step 2: Cargo Vendor Hash Check                                 │
├─────────────────────────────────────────────────────────────────┤
│ • Expected: cargoHash in kms-server.nix                          │
│ • Actual: SHA-256 of vendored dependencies                       │
│ • ❌ Mismatch → BUILD FAILS with "got: sha256-..."              │
│ • ✅ Match → Continue to OpenSSL build                          │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ Step 3: OpenSSL Source Hash Check                               │
├─────────────────────────────────────────────────────────────────┤
│ • Expected: sha256 in openssl-3_1_2.nix                          │
│ • Actual: SHA-256 of openssl-3.1.2.tar.gz                        │
│ • ❌ Mismatch → BUILD FAILS                                     │
│ • ✅ Match → Build OpenSSL 3.1.2 (FIPS 140-3)                   │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ Step 4: Deterministic Compilation                               │
├─────────────────────────────────────────────────────────────────┤
│ • Flags: -Cdebuginfo=0 -Ccodegen-units=1 -Cincremental=false    │
│ • Static OpenSSL linkage (no dynamic deps)                       │
│ • SOURCE_DATE_EPOCH for normalized timestamps                   │
│ • Build cosmian_kms binary                                       │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ Step 5: Binary Hash Verification (installCheckPhase)            │
├─────────────────────────────────────────────────────────────────┤
│ • Expected: nix/expected-hashes/<variant>.<system>.sha256        │
│ • Actual: SHA-256 of $out/bin/cosmian_kms                        │
│ • ❌ Mismatch → BUILD FAILS (shows both hashes)                 │
│ • ✅ Match → Additional checks                                  │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ Step 6: Runtime Validation                                       │
├─────────────────────────────────────────────────────────────────┤
│ • Assert: OpenSSL version = 3.1.2                                │
│ • Assert: Static linkage (no libssl.so)                          │
│ • Assert: GLIBC symbols ≤ 2.28                                   │
│ • Assert: FIPS mode if variant=fips                              │
│ • ❌ Any assertion fails → BUILD FAILS                          │
│ • ✅ All pass → BUILD SUCCESS                                   │
└─────────────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────────────┐
│ Output: Hash-Verified Binary                                    │
├─────────────────────────────────────────────────────────────────┤
│ result-server-<variant>/bin/cosmian_kms                          │
│ • Deterministically reproducible                                │
│ • Ready for packaging (DEB/RPM/DMG)                              │
└─────────────────────────────────────────────────────────────────┘
```

**Update workflow** (automated with `nix/scripts/update_all_hashes.sh`):

```text
Code/Dependency Change
         ↓
┌────────┴────────┐
│   Build fails   │
│  (hash mismatch)│
└────────┬────────┘
         ↓
Run update_all_hashes.sh
         ↓
┌────────┴────────────────────┐
│  Vendor hash?  Binary hash? │
├─────────────────────────────┤
│ • Cargo.lock → --vendor-only│
│ • Code change → --binary-only│
│ • Both → (no flags)         │
└────────┬────────────────────┘
         ↓
Script performs:
  1. Build with Nix
  2. Compute SHA-256
  3. Update hash files
         ↓
Verify: bash .github/scripts/nix.sh build
         ↓
Commit updated hashes
```

Every build enforces all hashes — **no fallbacks, no approximations**.

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
# Automated method (recommended) - integrated into nix.sh
bash .github/scripts/nix.sh update-hashes

# Update only vendor hash (after Cargo.lock changes)
bash .github/scripts/nix.sh update-hashes --vendor-only

# Update only binary hashes (after code changes)
bash .github/scripts/nix.sh update-hashes --binary-only

# Update specific variant (default updates current variant based on --variant flag)
bash .github/scripts/nix.sh --variant non-fips update-hashes --binary-only

# Alternative: standalone script (same functionality)
bash nix/scripts/update_all_hashes.sh

# Manual method - Example for Apple Silicon macOS (aarch64-darwin)
nix-build -A kms-server-fips -o result-server-fips
sha256sum result-server-fips/bin/cosmian_kms | cut -d' ' -f1 > nix/expected-hashes/fips.aarch64-darwin.sha256

# Linux x86_64 example
nix-build -A kms-server-non-fips -o result-server-non-fips
sha256sum result-server-non-fips/bin/cosmian_kms | cut -d' ' -f1 > nix/expected-hashes/non-fips.x86_64-linux.sha256
```

The `update-hashes` command is integrated into the main `nix.sh` script for convenience.

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

### Step 1: Prewarm all dependencies (first-time setup)

Run these commands with network access to populate all caches:

```bash
# Build and cache both FIPS and non-FIPS server binaries
bash .github/scripts/nix.sh package deb      # Defaults to FIPS
bash .github/scripts/nix.sh --variant non-fips package deb

# Or explicitly prewarm both variants without packaging
nix-build -A kms-server-fips -o result-server-fips
nix-build -A kms-server-non-fips -o result-server-non-fips

# Prewarm Cargo registry for offline cargo-deb/cargo-generate-rpm
cd /home/manu/Cosmian/core/cli_alt/kms
cargo fetch --locked                           # FIPS dependencies
cargo fetch --locked --features non-fips       # non-FIPS dependencies

# Ensure OpenSSL tarball is cached locally
ls -lh resources/tarballs/openssl-3.1.2.tar.gz  # Should exist after first build
```

### Step 2: Verify offline capability

Disconnect network or use a firewall to block internet access, then:

```bash
# Build packages completely offline
export NO_PREWARM=1                           # Skip prewarm phase
export CARGO_HOME=target/cargo-offline-home   # Use cached dependencies
export CARGO_NET_OFFLINE=true                 # Prevent network access

# Package FIPS variant offline
bash .github/scripts/nix.sh package deb
bash .github/scripts/nix.sh package rpm

# Package non-FIPS variant offline
bash .github/scripts/nix.sh --variant non-fips package deb
bash .github/scripts/nix.sh --variant non-fips package rpm

# Build DMG on macOS
bash .github/scripts/nix.sh package dmg
```

### Step 3: Package signing (optional)

If configured, packages are automatically signed:

```bash
export GPG_SIGNING_KEY_PASSPHRASE='your-secure-passphrase'
bash .github/scripts/nix.sh package deb
# Creates: result-deb-fips/*.deb.asc signature files
```

### What gets cached offline?

| Component        | Location                                          | Purpose                                 |
| ---------------- | ------------------------------------------------- | --------------------------------------- |
| Nix store        | `/nix/store/*`                                    | All derivations (Rust, OpenSSL, tools)  |
| Cargo registry   | `target/cargo-offline-home/registry/`             | Crate metadata and sources              |
| OpenSSL tarball  | `resources/tarballs/openssl-3.1.2.tar.gz`         | Source for FIPS-compliant OpenSSL 3.1.2 |
| Binary artifacts | `result-server-fips/`, `result-server-non-fips/`  | Hash-verified server binaries           |
| Packaging tools  | `result-cargo-deb/`, `result-cargo-generate-rpm/` | Nix-provisioned packaging utilities     |

### Offline verification

After prewarm, these commands should work without network:

```bash
# Disconnect network completely
sudo systemctl stop NetworkManager  # or equivalent

# All packaging should still work
bash .github/scripts/nix.sh package deb
sha256sum result-deb-fips/*.deb  # Verify reproducibility
```

**Verification tip**: After a successful prewarm, disable network and rerun packaging — it should still succeed and produce identical artifact hashes.

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

| Symptom                                            | Likely cause                                           | Resolution                                                                                  |
| -------------------------------------------------- | ------------------------------------------------------ | ------------------------------------------------------------------------------------------- |
| Hash mismatch failure                              | Genuine input change                                   | Recalculate & commit expected hash                                                          |
| Rebuild on repeat packaging                        | Forgot `NO_PREWARM=1`                                  | Export env var or adjust CI                                                                 |
| Network access attempted (Nix)                     | Store not prewarmed                                    | Run once without NO_PREWARM                                                                 |
| `cargo-deb` or `cargo generate-rpm` hits crates.io | Cargo registry not prewarmed or offline env not active | Ensure prewarm ran; set `CARGO_HOME=target/cargo-offline-home` and `CARGO_NET_OFFLINE=true` |
| rustup downloads appear                            | Not using Nix toolchain                                | Ensure `ensure_modern_rust` ran                                                             |

## Files overview

- `kms-server.nix` — derivation + install checks
- `openssl-3_1_2.nix` — pinned OpenSSL
- `expected-hashes/` — authoritative binary hashes
- `scripts/package_common.sh` — shared packaging logic
- `scripts/package_deb.sh` / `scripts/package_rpm.sh` — thin wrappers
- `scripts/update_all_hashes.sh` — automated hash update tool
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

## Why Nix? Comparison with other deterministic build tools

| Feature                      | Nix                    | Bazel                   | Docker Multi-stage          | Guix              | Flatpak              |
| ---------------------------- | ---------------------- | ----------------------- | --------------------------- | ----------------- | -------------------- |
| **Reproducible builds**      | ✅ Native, hermetic     | ✅ With strict mode      | ⚠️ Partial (layer caching)   | ✅ Native          | ⚠️ Runtime only       |
| **Offline builds**           | ✅ Full (after prewarm) | ✅ With remote cache     | ❌ Requires base images      | ✅ Full            | ⚠️ Requires OSTree    |
| **Binary hash verification** | ✅ Native in derivation | ⚠️ Manual checks         | ❌ Not built-in              | ✅ Native          | ❌ Not built-in       |
| **Cross-platform**           | ✅ Linux, macOS, BSD    | ✅ Linux, macOS, Windows | ✅ Where Docker runs         | ⚠️ Primarily Linux | ❌ Linux only         |
| **Package ecosystem**        | 80,000+ packages       | Limited (mostly Google) | Docker Hub (varied quality) | 20,000+ packages  | Flathub apps         |
| **Language agnostic**        | ✅ Any language         | ✅ Any language          | ✅ Any language              | ✅ Any language    | ⚠️ Desktop apps focus |
| **Learning curve**           | Medium                 | Steep                   | Low                         | Steep             | Low                  |
| **Maturity**                 | 20+ years              | 10+ years               | 12+ years                   | 11+ years         | 10+ years            |
| **Corporate backing**        | Community + sponsors   | Google                  | Docker Inc.                 | GNU Project       | Red Hat/Fedora       |
| **OSS License**              | MIT                    | Apache 2.0              | Apache 2.0                  | GPLv3+            | LGPLv2+              |

### Why Nix is a safe choice for Cosmian KMS

#### 1. Strong community governance

- **No single vendor control**: Unlike Bazel (Google) or Flatpak (Red Hat), Nix is community-governed
- **NixOS Foundation** (nonprofit) stewards the project
- **Open governance model**: RFC process for major changes ([RFC 0000](https://github.com/NixOS/rfcs))

#### 2. Active development & stability

| Metric                  | Value                           | Source                                                        |
| ----------------------- | ------------------------------- | ------------------------------------------------------------- |
| **Releases/year**       | ~24 (bi-weekly)                 | [nixpkgs releases](https://github.com/NixOS/nixpkgs/releases) |
| **Contributors**        | 4,500+ total, ~500 active/month | GitHub Insights                                               |
| **Commits/month**       | ~3,000-5,000                    | nixpkgs repository                                            |
| **Issue response time** | <24 hours (median)              | Community stats                                               |
| **CVE fix time**        | <48 hours (critical)            | NixOS Security Team                                           |

#### 3. Brief history of Nix

- **2003**: Eelco Dolstra creates Nix as PhD research (Utrecht University)
- **2006**: NixOS first release (Linux distribution built on Nix)
- **2015**: Nix 1.0 released, production-ready
- **2018**: Nix 2.0 with flakes experimental feature
- **2020**: Major corporate adoption (Tweag, Cachix, NumTide)
- **2023**: Nix 2.18 - flakes stabilized, determinism improvements
- **2024**: Anduril, Replit, Shopify using Nix in production
- **2025**: 80,000+ packages, used by NASA, European research institutions

#### 4. Sponsors & ecosystem safety

**Primary Sponsors** (2024-2025):

- [Determinate Systems](https://determinate.systems/) - Enterprise Nix support
- [Tweag](https://www.tweag.io/) - R&D, used by Bloomberg, Meta
- [Cachix](https://www.cachix.org/) - Binary cache provider
- [NumTide](https://numtide.com/) - DevOps consulting
- [Hercules CI](https://hercules-ci.com/) - Continuous integration

**Corporate Users** (public references):

- **Replit** - 40M+ users, entire infrastructure on Nix
- **Shopify** - Production deployments
- **Target** - Internal tooling
- **European Space Agency** - Satellite software builds
- **CERN** - Scientific computing reproducibility

#### 5. No vendor lock-in risk

✅ **Why Nix won't be "black-boxed"**:

1. **MIT License** - Permissive, fork-friendly, no relicensing risk
2. **Decentralized** - No single company owns the ecosystem
3. **Multiple implementations** - Lix, Tvix (Rust rewrite), Nix-on-Droid
4. **Open standards** - Store format, derivation protocol are documented
5. **Academic roots** - Research-driven, not profit-driven
6. **GNU Guix compatibility** - Similar design, can share learnings

❌ **Contrast with risks**:

- Docker Desktop became paid for large enterprises (2021)
- HashCorp changed Terraform to BSL (2023)
- Red Hat restricted RHEL sources (2023)

**Nix's governance prevents this**: No company can change the license or restrict access.

#### 6. Why Nix for Cosmian KMS specifically

| Requirement                | How Nix Delivers                                     |
| -------------------------- | ---------------------------------------------------- |
| **FIPS 140-3 compliance**  | Pin exact OpenSSL 3.1.2 certified version            |
| **Reproducible security**  | Bit-for-bit identical binaries = verifiable security |
| **Air-gapped deployments** | Full offline builds after prewarm                    |
| **Multi-platform**         | Single derivation for Linux + macOS                  |
| **Supply chain security**  | Hash verification at every layer                     |
| **Long-term maintenance**  | 20+ year track record, stable APIs                   |

### Recommended reading

- [Nix Pills](https://nixos.org/guides/nix-pills/) - Deep dive tutorial
- [Reproducible Builds with Nix](https://r13y.com/) - Build reproducibility tracker
- [NixOS Foundation](https://nixos.org/community/teams/foundation.html) - Governance
- [Academic papers](https://edolstra.github.io/pubs/) - Original research

## Summary

Determinism is enforced natively by Nix; offline & idempotent packaging is attained through prewarm reuse, a unified script, and Nix-provided Rust. Any hash change is investigated, justified, and then updated explicitly.

**Key advantages**:

- ✅ Bit-for-bit reproducible builds across machines
- ✅ Native hash verification (no external tools needed)
- ✅ Full offline capability for air-gapped environments
- ✅ Community-governed, no vendor lock-in
- ✅ 20+ years of stability and active development
