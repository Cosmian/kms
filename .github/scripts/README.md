# Cosmian KMS Script Suite

This directory contains the complete script infrastructure for building, testing, packaging, and releasing Cosmian KMS.
The primary entrypoint is `nix.sh`, which provides a unified interface to all workflows through Nix-managed environments.

## Quick Visual Overview

```text
                    ┌──────────────────────────────────┐
                    │   Developer / CI Entry Point     │
                    │                                  │
                    │  bash nix.sh <command> [opts]    │
                    └────────────┬─────────────────────┘
                                 │
                    ┌────────────┴─────────────┐
                    │    Commands Available    │
                    └──┬───┬───┬───┬────┬──────┘
                       │   │   │   │    │
           ┌───────────┘   │   │   │    └────────────┐
           │               │   │   │                 │
           ▼               ▼   ▼   ▼                 ▼
      ┌────────┐      ┌──────────────┐         ┌──────────┐
      │ build  │      │     test     │         │ package  │
      │        │      │              │         │          │
      │ Compile│      │ • sqlite     │         │ • deb    │
      │  KMS   │      │ • psql       │         │ • rpm    │
      │ binary │      │ • mysql      │         │ • dmg    │
      └────────┘      │ • redis      │         └──────────┘
                      │ • google_cse │
                      │ • pykmip     │         ┌──────────┐
                      │ • hsm        │         │   sbom   │
                      └──────────────┘         │          │
                                               │ Generate │
                      ┌──────────────┐         │  supply  │
                      │update-hashes │         │  chain   │
                      │              │         │   docs   │
                      │ Maintain Nix │         └──────────┘
                      │ build hashes │
                      └──────────────┘

                         Options (all commands):
                         • --profile <debug|release>
                         • --variant <fips|non-fips>
```

**🚀 Common workflows:**

```bash
# Development iteration
bash nix.sh test sqlite

# Full release build
bash nix.sh test all
bash nix.sh package

# SBOM for compliance
bash nix.sh sbom
```

**📊 For detailed visual execution flows, see [Script Ecosystem → Visual Execution Diagrams](#visual-execution-diagrams)**

---

## Table of Contents

1. [Overview](#overview)
2. [nix.sh — Unified Command Interface](#nixsh--unified-command-interface)
3. [The Role of Nix](#the-role-of-nix)
4. [Script Ecosystem](#script-ecosystem)
5. [Maintenance Guidelines](#maintenance-guidelines)
6. [Future Enhancements](#future-enhancements)

---

## Overview

Cosmian KMS uses **Nix** to achieve:

- **Reproducible builds**: Pinned dependencies (nixpkgs 24.05, Rust 1.90.0, OpenSSL 3.1.2)
- **Hermetic packaging**: Static linking, no runtime /nix/store paths
- **Offline capability**: Pre-warming enables network-free builds
- **Variant isolation**: FIPS and non-FIPS builds with controlled feature sets

**Key principle**: `nix.sh` is the single entrypoint for developers and CI; it orchestrates all other scripts within controlled Nix environments.

---

## nix.sh — Unified Command Interface

### Commands

#### 1. `test` — Run Test Suites

Executes comprehensive test suites across databases, cryptographic backends, and client protocols.

**Syntax:**

```bash
bash .github/scripts/nix.sh test [type] [backend] [--profile <debug|release>] [--variant <fips|non-fips>]
```

**Test Types:**

| Type            | Description                               | Script               | Notes                           |
| --------------- | ----------------------------------------- | -------------------- | ------------------------------- |
| `all`           | Run complete test suite (default)         | `test_all.sh`        | Includes DB + HSM (if release)  |
| `sqlite`        | SQLite embedded database tests            | `test_sqlite.sh`     | Always run; core functionality  |
| `mysql`         | MySQL backend tests                       | `test_mysql.sh`      | Requires MySQL server           |
| `psql`          | PostgreSQL backend tests                  | `test_psql.sh`       | Requires PostgreSQL server      |
| `redis`         | Redis-findex encrypted index tests        | `test_redis.sh`      | Non-FIPS only; requires Redis   |
| `google_cse`    | Google Client-Side Encryption integration | `test_google_cse.sh` | Requires OAuth credentials      |
| `pykmip`        | PyKMIP client compatibility tests         | `test_pykmip.sh`     | Non-FIPS only; uses Python venv |
| `hsm [backend]` | Hardware Security Module tests            | `test_hsm*.sh`       | Linux only; see backends below  |

**HSM Backends** (used with `test hsm [backend]`):

- `softhsm2` — Software HSM emulator (default in CI)
- `utimaco` — Utimaco simulator tests
- `proteccio` — Proteccio NetHSM tests
- `all` — Run all HSM backends sequentially (default)

**Environment Variables:**

Database connections:

- `REDIS_HOST`, `REDIS_PORT`
- `MYSQL_HOST`, `MYSQL_PORT`
- `POSTGRES_HOST`, `POSTGRES_PORT`

Google CSE (required for `google_cse` tests):

- `TEST_GOOGLE_OAUTH_CLIENT_ID`
- `TEST_GOOGLE_OAUTH_CLIENT_SECRET`
- `TEST_GOOGLE_OAUTH_REFRESH_TOKEN`
- `GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY`

**Examples:**

```bash
# Run all tests (default variant: FIPS, profile: debug)
bash .github/scripts/nix.sh test

# Specific database tests
bash .github/scripts/nix.sh test sqlite
bash .github/scripts/nix.sh test psql

# Redis tests (non-FIPS required)
bash .github/scripts/nix.sh --variant non-fips test redis

# PyKMIP client tests (non-FIPS, includes Python environment)
bash .github/scripts/nix.sh --variant non-fips test pykmip

# Google CSE tests (with credentials)
TEST_GOOGLE_OAUTH_CLIENT_ID=... \
TEST_GOOGLE_OAUTH_CLIENT_SECRET=... \
TEST_GOOGLE_OAUTH_REFRESH_TOKEN=... \
GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY=... \
  bash .github/scripts/nix.sh test google_cse

# HSM tests (specific backend)
bash .github/scripts/nix.sh test hsm softhsm2
bash .github/scripts/nix.sh test hsm all
```

**Special Modes:**

- **Pure shell**: Standard DB tests run in `--pure` mode (hermetic)
- **Non-pure shell**: HSM tests need system PKCS#11 libraries; automatically disables `--pure`
- **Auto-dependencies**: `nix.sh` injects `WITH_WGET`, `WITH_HSM`, `WITH_PYTHON` env vars to provision tools

---

#### 2. `package` — Build Distribution Packages

Creates platform-native packages (DEB, RPM, DMG) using Nix derivations, with mandatory smoke tests.

**Syntax:**

```bash
bash .github/scripts/nix.sh package [type] [--variant <fips|non-fips>]
```

**Package Types:**

| Type   | Platform | Output                   | Script                       |
| ------ | -------- | ------------------------ | ---------------------------- |
| `deb`  | Linux    | Debian/Ubuntu `.deb`     | `nix/scripts/package_deb.sh` |
| `rpm`  | Linux    | RedHat/SUSE `.rpm`       | `nix/scripts/package_rpm.sh` |
| `dmg`  | macOS    | macOS disk image `.dmg`  | `nix/scripts/package_dmg.sh` |
| (none) | Auto     | All types for current OS | —                            |

**Build Process:**

1. **Prewarm** (skippable via `NO_PREWARM=1`):
   - Fetch pinned nixpkgs (24.05) to local store
   - Pre-download packaging tools (`dpkg`, `rpm`, `cpio`) for offline use
2. **Build**:
   - Execute package-specific Nix script
   - On Linux: Use Nix derivations directly (`nix-build`)
   - On macOS: Use `nix-shell` (non-pure) + `cargo-packager` for DMG (requires `hdiutil`, `osascript`)
3. **Smoke Test** (mandatory):
   - Extract package to temp directory
   - Run `cosmian_kms --info`
   - Verify OpenSSL version is exactly `3.1.2`
   - Fail entire build if test fails
4. **Checksum**:
   - Generate SHA-256 checksum file (`.sha256`) alongside package

**Examples:**

```bash
# Build all packages for current platform (Linux: deb+rpm; macOS: dmg)
bash .github/scripts/nix.sh package

# Build specific package type (FIPS variant)
bash .github/scripts/nix.sh package deb
bash .github/scripts/nix.sh package rpm

# Build non-FIPS variant
bash .github/scripts/nix.sh --variant non-fips package deb
bash .github/scripts/nix.sh --variant non-fips package dmg
```

**Output Locations:**

- DEB: `result-deb-<variant>/` symlink
- RPM: `result-rpm-<variant>/` symlink
- DMG: `result-dmg-<variant>/` symlink

**Offline Builds:**
After one successful online run, subsequent package builds work offline (network disconnected) if:

- Nix store contains pinned nixpkgs
- Cargo vendor cache is populated
- OpenSSL 3.1.2 tarball is cached

---

#### 3. `sbom` — Generate Software Bill of Materials

Produces comprehensive SBOM files using `sbomnix` tools for supply chain transparency and compliance.

**Syntax:**

```bash
bash .github/scripts/nix.sh sbom [--variant <fips|non-fips>]
```

**What it does:**

- Automatically builds the server if not already built (works from scratch)
- Analyzes the Nix derivation for the specified variant
- Generates multiple SBOM formats + vulnerability reports
- Runs **outside** `nix-shell` (sbomnix needs direct `nix` commands)

**Generated Files** (in `./sbom/` directory):

| File            | Format    | Description                                  |
| --------------- | --------- | -------------------------------------------- |
| `bom.cdx.json`  | CycloneDX | Industry-standard SBOM (OWASP ecosystem)     |
| `bom.spdx.json` | SPDX      | ISO/IEC 5962:2021 standard SBOM              |
| `sbom.csv`      | CSV       | Spreadsheet-friendly dependency list         |
| `vulns.csv`     | CSV       | Vulnerability scan results (CVE mapping)     |
| `graph.png`     | PNG       | Visual dependency graph                      |
| `meta.json`     | JSON      | Build metadata (timestamps, variant, hashes) |
| `README.txt`    | Text      | Integration guide and usage instructions     |

**Examples:**

```bash
# Generate SBOM for FIPS variant
bash .github/scripts/nix.sh sbom

# Generate SBOM for non-FIPS variant
bash .github/scripts/nix.sh --variant non-fips sbom
```

**Use Cases:**

- Compliance audits (SBOM submission to customers)
- Vulnerability monitoring (scan `vulns.csv` for CVEs)
- License verification (check dependencies in `bom.spdx.json`)
- Supply chain attestation (provenance tracking)

---

#### 4. `update-hashes` — Update Expected Hashes

Automated hash maintenance for Nix build reproducibility verification.

**Syntax:**

```bash
bash .github/scripts/nix.sh update-hashes [options]
```

**Options:**

| Flag                         | Effect                                      | Use Case                            |
| ---------------------------- | ------------------------------------------- | ----------------------------------- |
| `--vendor-only`              | Update only Cargo vendor hash (`cargoHash`) | After `Cargo.lock` changes          |
| `--binary-only`              | Update only binary hashes                   | After code changes (deps unchanged) |
| `--variant <fips\|non-fips>` | Update specific variant only                | Single-variant changes              |
| (no flags)                   | Update all hashes (vendor + binaries)       | Full dependency + code update       |

**What it does:**

1. **Vendor Hash** (`--vendor-only` or default):
   - Triggers intentional Cargo vendor fetch failure
   - Extracts correct hash from Nix error message
   - Updates `nix/kms-server.nix` `cargoHash` field

2. **Binary Hashes** (`--binary-only` or default):
   - Builds FIPS and/or non-FIPS variants (static and dynamic)
   - Computes SHA-256 of resulting `cosmian_kms` binary
   - Updates `nix/expected-hashes/cosmian-kms-server.<variant>.<static-openssl|dynamic-openssl>.<arch>.<os>.sha256`

**Examples:**

```bash
# Update all hashes after dependency upgrade
bash .github/scripts/nix.sh update-hashes

# Update only vendor hash after Cargo.lock change
bash .github/scripts/nix.sh update-hashes --vendor-only

# Update only binary hashes after code change
bash .github/scripts/nix.sh update-hashes --binary-only

# Update only FIPS variant hashes
bash .github/scripts/nix.sh update-hashes --variant fips
```

**Platform Support:**

- `x86_64-linux` (Intel/AMD Linux)
- `aarch64-linux` (ARM64 Linux)
- `aarch64-darwin` (Apple Silicon macOS)

**Important**: Hash updates should be reviewed carefully. Binary hash changes indicate:

- Code modifications affecting the binary
- Dependency updates (even with locked `Cargo.lock`, Nix vendor hash may differ)
- Potential supply chain tampering (investigate unexpected changes)

---

### Global Options

All commands support these flags:

| Flag              | Values             | Default                               | Effect                    |
| ----------------- | ------------------ | ------------------------------------- | ------------------------- |
| `-p`, `--profile` | `debug`, `release` | `debug` (test)<br>`release` (package) | Cargo build profile       |
| `-v`, `--variant` | `fips`, `non-fips` | `fips`                                | Cryptographic feature set |
| `-h`, `--help`    | —                  | —                                     | Show usage and exit       |

**Feature Set Differences:**

| Aspect          | FIPS Variant                      | Non-FIPS Variant                |
| --------------- | --------------------------------- | ------------------------------- |
| Crypto backend  | OpenSSL 3.1.2 FIPS module         | OpenSSL 3.1.2 (standard)        |
| Redis-findex    | Disabled                          | Enabled                         |
| Reproducibility | Bit-for-bit deterministic (Linux) | Hash-verified (may vary by env) |
| Target users    | Government, regulated industries  | General enterprise              |

---

### Internal Mechanics

**Key Functions:**

| Function                         | Purpose                                                       |
| -------------------------------- | ------------------------------------------------------------- |
| `usage()`                        | Display help text and exit                                    |
| `compute_sha256(file)`           | Platform-agnostic SHA-256 hash (uses `sha256sum` or `shasum`) |
| `resolve_pinned_nixpkgs_store()` | Realize pinned nixpkgs tarball in local Nix store             |
| `prewarm_nixpkgs_and_tools()`    | Pre-fetch nixpkgs + packaging tools (skip via `NO_PREWARM=1`) |

**Execution Flow:**

```text
┌─────────────────────────────────────────────────────────────┐
│ 1. Parse CLI arguments (profile, variant, command)         │
└────────────────┬────────────────────────────────────────────┘
                 │
                 ├──[build/test]─→ Select script, enter nix-shell ──→ Run script
                 │                  (pure mode unless HSM/macOS DMG)
                 │
                 ├──[package]────→ Prewarm (unless NO_PREWARM) ──────→ For each type:
                 │                                                       ├─ Build via Nix
                 │                                                       ├─ Smoke test
                 │                                                       └─ Generate .sha256
                 │
                 └──[sbom]───────→ Delegate to generate_sbom.sh ────────→ Run sbomnix
                                   (outside nix-shell)
```

**Pure vs Non-Pure Shell:**

| Scenario                     | Mode     | Rationale                                        |
| ---------------------------- | -------- | ------------------------------------------------ |
| Database tests (sqlite/psql) | `--pure` | Self-contained test environment                  |
| HSM tests                    | Non-pure | Needs system PKCS#11 libraries (vendor-specific) |
| macOS DMG packaging          | Non-pure | Requires system tools (`hdiutil`, `osascript`)   |

---

## The Role of Nix

Nix provides the foundation for deterministic, auditable builds:

### Key Benefits

| Aspect                     | Implementation                                | Impact                                           |
| -------------------------- | --------------------------------------------- | ------------------------------------------------ |
| **Pinned Dependencies**    | nixpkgs 24.05 tarball locked by hash          | Identical build environment across machines/time |
| **Reproducible Toolchain** | Rust 1.90.0 from Nix (no rustup)              | Eliminates "works on my machine" compiler issues |
| **Static OpenSSL**         | Vendored 3.1.2 source tarball                 | No runtime SSL dependency; portable binaries     |
| **Hash Enforcement**       | Binary SHA-256 checked in `installCheckPhase` | Detects drift/tampering (FIPS builds on Linux)   |
| **Offline Capability**     | Pre-warmed store + Cargo offline cache        | Air-gapped builds after first online run         |
| **Variant Isolation**      | Separate derivations for FIPS/non-FIPS        | Controlled cryptographic footprint               |

### Reproducibility Guarantees

**FIPS builds on Linux** are **bit-for-bit reproducible**:

- Same source code + Nix environment → identical binary hash
- Verified by CI hash checks against `nix/expected-hashes/`

**Non-FIPS builds** use hash verification for consistency tracking but may produce different binaries across environments due to less restrictive build constraints.

### Hash Update Workflow

When binary hash mismatches occur:

1. **Investigate**: Determine if change is expected (code/dep update) or unexpected (supply chain issue)
2. **Rebuild**: `nix-build -A kms-server-<variant>`
3. **Verify**: `./result/bin/cosmian_kms --info` (check version, OpenSSL)
4. **Update**: Run `bash .github/scripts/nix.sh update-hashes` (or use `--binary-only`)
5. **Commit**: Include updated hash files in PR with justification

---

## Script Ecosystem

This section provides both tabular reference and visual execution diagrams to understand the complete script infrastructure.

**Navigation Guide:**

- **Visual Diagrams** → See [Visual Execution Diagrams](#visual-execution-diagrams) below for flowcharts showing command execution paths
- **Script Tables** → See [Core Scripts](#core-scripts) for reference tables of all scripts and their purposes
- **Call Graphs** → See [Script Dependencies Graph](#script-dependencies-graph) for understanding script relationships

### Visual Execution Diagrams

The following diagrams illustrate how commands flow through the script ecosystem. Each diagram focuses on a specific aspect:

1. **High-Level Command Flow** - Overview of nix.sh dispatch logic
2. **Build Command Flow** - Detailed build execution path
3. **Test Command Dispatch Tree** - How test types route to scripts
4. **Package Command Workflow** - Packaging process with smoke tests
5. **SBOM Generation Flow** - Supply chain documentation workflow
6. **Update Hashes Workflow** - Hash maintenance automation
7. **Nix Shell Environment Modes** - Pure vs non-pure execution contexts
8. **Complete Test Execution Matrix** - Test availability by profile/variant/platform
9. **Script Dependencies Graph** - Script source relationships and function sharing

### Core Scripts

#### `.github/scripts/`

| Script                     | Purpose                                 | Invocation Context          |
| -------------------------- | --------------------------------------- | --------------------------- |
| `nix.sh`                   | Unified entrypoint                      | Developer CLI, CI pipelines |
| `common.sh`                | Shared test helpers (sourced by others) | Never run directly          |
| `test_*.sh`                | Individual test suite runners           | Via `nix.sh test <type>`    |
| `release.sh`               | Version bump automation                 | Release workflow            |
| `test_docker_image.sh`     | Docker TLS/auth integration tests       | CI container tests          |
| `reinitialize_demo_kms.sh` | Demo server key rotation                | Demo VM cron job            |

#### `nix/scripts/`

| Script              | Purpose                           | Invocation Context        |
| ------------------- | --------------------------------- | ------------------------- |
| `package_deb.sh`    | Debian package build              | Via `nix.sh package deb`  |
| `package_rpm.sh`    | RPM package build                 | Via `nix.sh package rpm`  |
| `package_dmg.sh`    | macOS DMG build                   | Via `nix.sh package dmg`  |
| `generate_sbom.sh`  | SBOM generation orchestrator      | Via `nix.sh sbom`         |
| `get_version.sh`    | Extract version from `Cargo.toml` | Packaging scripts         |
| `package_common.sh` | Shared packaging helpers          | Sourced by `package_*.sh` |

### Test Scripts Detailed

#### Database Tests

| Test Type    | Script           | Requirements      | Key Features                         |
| ------------ | ---------------- | ----------------- | ------------------------------------ |
| SQLite       | `test_sqlite.sh` | None (embedded)   | Bins, benchmarks, DB tests           |
| PostgreSQL   | `test_psql.sh`   | PostgreSQL server | Connection check + targeted tests    |
| MySQL        | `test_mysql.sh`  | MySQL server      | Connection check + targeted tests    |
| Redis-findex | `test_redis.sh`  | Redis server      | Non-FIPS only; encrypted index tests |

#### Specialized Tests

| Test Type  | Script               | Requirements                   | Key Features                       |
| ---------- | -------------------- | ------------------------------ | ---------------------------------- |
| Google CSE | `test_google_cse.sh` | OAuth credentials (4 env vars) | Client-Side Encryption integration |
| PyKMIP     | `test_pykmip.sh`     | Python 3.11 + virtualenv       | KMIP protocol compatibility        |

#### HSM Tests

| Backend      | Script                  | Requirements           | Key Features                         |
| ------------ | ----------------------- | ---------------------- | ------------------------------------ |
| SoftHSM2     | `test_hsm_softhsm2.sh`  | SoftHSM2 library       | Token init, server + loader tests    |
| Utimaco      | `test_hsm_utimaco.sh`   | Utimaco simulator      | Simulator setup, PKCS#11 tests       |
| Proteccio    | `test_hsm_proteccio.sh` | Proteccio NetHSM       | NetHSM env config, integration tests |
| Orchestrator | `test_hsm.sh`           | All above (sequential) | Runs all three backends in order     |

**HSM Test Characteristics:**

- Run in **non-pure** `nix-shell` (needs system PKCS#11 libraries)
- Linux only (vendor libraries unavailable on macOS)
- Sequential execution (backends may conflict if parallel)

### Nix Visual Execution Diagrams

#### High-Level Command Flow

This diagram shows how `nix.sh` dispatches to different execution paths:

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                     nix.sh (Unified Entrypoint)                         │
│                                                                         │
│  Parses: --profile <debug|release>  --variant <fips|non-fips>           │
└────┬─────────────┬────────────┬────────────┬──────────────┬─────────────┘
     │             │            │            │              │
     ▼             ▼            ▼            ▼              ▼
  ┌──────┐    ┌───────┐   ┌──────────┐  ┌──────┐    ┌──────────────┐
  │BUILD │    │ TEST  │   │ PACKAGE  │  │ SBOM │    │UPDATE-HASHES │
  └──┬───┘    └───┬───┘   └─────┬────┘  └──┬───┘    └──────┬───────┘
     │            │             │          │               │
     │            │             │          │               │
     │            │             │          │               │
  Pure Nix    Pure/Non-Pure  Prewarm+   Outside        Update Nix
   Shell         Shell        Build     nix-shell       Files
```

#### Build Command Flow

```text
┌─────────────────────────────────────────────────────────────────────────┐
│  $ bash nix.sh build --profile release --variant fips                   │
└────────────────────────────────┬────────────────────────────────────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │   Enter nix-shell      │
                    │   (--pure mode)        │
                    │                        │
                    │  • Rust 1.90.0         │
                    │  • OpenSSL 3.1.2       │
                    │  • Build tools         │
                    └────────┬───────────────┘
                             │
                             ▼
                    ┌────────────────────────┐
                    │  nix/scripts/build.sh  │
                    └────────┬───────────────┘
                             │
                             ▼
              ┌──────────────────────────────┐
              │  cargo build                 │
              │    --profile release         │
              │    --features fips           │
              └──────────┬───────────────────┘
                         │
                         ▼
              ┌──────────────────────────────┐
              │  Binary Validation           │
              │                              │
              │  Linux:                      │
              │   • Strip /nix/store paths   │
              │   • Check GLIBC ≤ 2.28       │
              │   • Verify static OpenSSL    │
              │                              │
              │  macOS:                      │
              │   • Check dylib linkage      │
              └──────────┬───────────────────┘
                         │
                         ▼
              ┌──────────────────────────────┐
              │  Output:                     │
              │  Binary in target/           │
              └──────────────────────────────┘
              └──────────────────────────────┘
```

#### Test Command Dispatch Tree

```text
┌──────────────────────────────────────────────────────────────────────────┐
│  $ bash nix.sh test [type] [backend]                                     │
└────────────────────────────────┬─────────────────────────────────────────┘
                                 │
                    ┌────────────┴─────────────────────────────────────┐
                    │          Test Type Router                        │
                    └─┬──────┬──────┬───────┬──────┬──────┬──────┬─────┘
                      │      │      │       │      │      │      │
        ┌─────────────┘      │      │       │      │      │      └──────────────┐
        │                    │      │       │      │      │                     │
        ▼                    ▼      ▼       ▼      ▼      ▼                     ▼
   ┌────────┐         ┌─────────────────────────────┐  ┌─────────┐      ┌──────────┐
   │  all   │         │  Individual DB Tests        │  │google   │      │   hsm    │
   └───┬────┘         │  (sqlite|psql|mysql|redis)  │  │  _cse   │      └────┬─────┘
       │              └──────────┬──────────────────┘  └────┬────┘            │
       │                         │                          │                 │
       │                         │                          │                 │
       │                         │                          │                 │
       ▼                         ▼                          ▼                 ▼
┌──────────────┐      ┌──────────────────┐     ┌──────────────────┐  ┌──────────────┐
│test_all.sh   │      │test_<db>.sh      │     │test_google_cse.sh│  │ Backend      │
│              │      │                  │     │                  │  │ Selection    │
│ Sequential:  │      │ • source common  │     │ • Validate OAuth │  │              │
│ 1. sqlite    │      │ • init_build_env │     │ • cargo test     │  └──┬───┬───┬───┘
│ 2. psql*     │      │ • check DB conn  │     │                  │     │   │   │
│ 3. mysql*    │      │ • cargo test     │     └──────────────────┘     │   │   │
│ 4. redis**   │      └──────────────────┘                              │   │   │
│ 5. google*** │                                                        │   │   │
│ 6. hsm****   │    * Release profile only                              │   │   │
│              │   ** Non-FIPS variant only                             │   │   │
└──────────────┘  *** If credentials present                            │   │   │
                 **** Linux + Release only                              │   │   │
                                                                        │   │   │
                                                          ┌─────────────┘   │   └──────────────┐
                                                          │                 │                  │
                                                          ▼                 ▼                  ▼
                                                   ┌──────────┐      ┌──────────┐      ┌──────────┐
                                                   │softhsm2  │      │ utimaco  │      │proteccio │
                                                   └──────────┘      └──────────┘      └──────────┘
                                                          │                  │                  │
                                                          └──────────┬───────┴──────────────────┘
                                                                     │
                                                                     ▼
                                                          ┌──────────────────────┐
                                                          │ test_hsm.sh          │
                                                          │ (orchestrates all)   │
                                                          └──────────────────────┘
```

#### Package Command Workflow

```text
┌──────────────────────────────────────────────────────────────────────────┐
│  $ bash nix.sh package [deb|rpm|dmg] --variant <fips|non-fips>           │
└────────────────────────────────┬─────────────────────────────────────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │  Prewarm Phase         │
                    │  (skip: NO_PREWARM=1)  │
                    │                        │
                    │  1. Fetch nixpkgs      │
                    │  2. Pre-download tools │
                    └────────┬───────────────┘
                             │
                             ▼
              ┌──────────────┴─────────────────┐
              │     Platform Detection         │
              └──┬────────────────┬─────────┬──┘
                 │                │         │
         Linux   │                │         │  macOS
                 │                │         │
                 ▼                ▼         ▼
        ┌────────────┐   ┌────────────┐  ┌──────────────┐
        │    DEB     │   │    RPM     │  │     DMG      │
        └─────┬──────┘   └─────┬──────┘  └──────┬───────┘
              │                │                 │
              ▼                ▼                 ▼
   ┌──────────────────┐ ┌─────────────┐  ┌──────────────────┐
   │nix-build         │ │nix-build    │  │nix-shell         │
   │-A kms-deb-<var>  │ │-A kms-rpm.. │  │+ cargo-packager  │
   └──────┬───────────┘ └──────┬──────┘  └──────┬───────────┘
          │                    │                │
          │                    │                │
          └────────────────────┴────────────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │  Smoke Test          │
                    │  (Mandatory)         │
                    │                      │
                    │  1. Extract package  │
                    │  2. Run --info       │
                    │  3. Verify OpenSSL   │
                    │     version = 3.1.2  │
                    └──────────┬───────────┘
                               │
                         Pass  │  Fail
                    ┌──────────┴──────────┐
                    │                     │
                    ▼                     ▼
          ┌──────────────────┐   ┌────────────┐
          │ Generate .sha256 │   │ Exit 1     │
          │ checksum file    │   └────────────┘
          └──────────────────┘
                    │
                    ▼
          ┌──────────────────┐
          │ Output:          │
          │ result-<type>-   │
          │   <variant>/     │
          │ • package file   │
          │ • .sha256        │
          └──────────────────┘
```

#### SBOM Generation Flow

```text
┌──────────────────────────────────────────────────────────────────────────┐
│  $ bash nix.sh sbom --variant <fips|non-fips>                            │
└────────────────────────────────┬─────────────────────────────────────────┘
                                 │
                                 │  (Runs OUTSIDE nix-shell)
                                 │   sbomnix needs direct nix commands
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │ nix/scripts/           │
                    │ generate_sbom.sh       │
                    └────────┬───────────────┘
                             │
                             ▼
                    ┌────────────────────────┐
                    │ Check if binary exists │
                    │ (auto-build if needed) │
                    └────────┬───────────────┘
                             │
                             ▼
                    ┌────────────────────────┐
                    │  Run sbomnix tools     │
                    │                        │
                    │  • sbomnix             │
                    │  • vulnxscan           │
                    │  • nix-visualize       │
                    └────────┬───────────────┘
                             │
                             ▼
              ┌──────────────────────────────┐
              │  Generate Multiple Formats   │
              └──┬───────┬───────┬──────┬────┘
                 │       │       │      │
        ┌────────┘       │       │      └─────────┐
        │                │       │                │
        ▼                ▼       ▼                ▼
┌────────────┐  ┌─────────────┐ ┌────────┐  ┌──────────┐
│bom.cdx.json│  │bom.spdx.json│ │sbom.csv│  │vulns.csv │
│(CycloneDX) │  │   (SPDX)    │ │        │  │(CVE scan)│
└────────────┘  └─────────────┘ └────────┘  └──────────┘
        │                │            │           │
        └────────────────┴────────────┴───────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │ Additional Artifacts │
              │ • graph.png          │
              │ • meta.json          │
              │ • README.txt         │
              └──────────────────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │  Output: ./sbom/     │
              └──────────────────────┘
```

#### Update Hashes Workflow

```text
┌──────────────────────────────────────────────────────────────────────────┐
│  $ bash nix.sh update-hashes [--vendor-only|--binary-only] [--variant]   │
└────────────────────────────────┬─────────────────────────────────────────┘
                                 │
                                 ▼
                    ┌────────────────────────┐
                    │   Hash Update Process  │
                    │  (Integrated in build) │
                    └────────┬───────────────┘
                             │
                    ┌────────┴──────────────┐
                    │  Build & Compute Hash │
                    └───────────────────────┘
          vendor-only │                     │ binary-only
                      │                     │  (or default: both)
                      │                     │
                      ▼                     ▼
        ┌──────────────────────┐   ┌──────────────────────┐
        │ Update Cargo         │   │ Build Binaries       │
        │ Vendor Hash          │   │                      │
        │                      │   │ For each variant:    │
        │ 1. Trigger nix-build │   │  • nix-build         │
        │    (intentional fail)│   │  • Compute SHA-256   │
        │ 2. Extract hash from │   │                      │
        │    error message     │   │ For each platform:   │
        │ 3. Update            │   │  • x86_64-linux      │
        │    kms-server.nix    │   │  • aarch64-linux     │
        │    cargoHash field    │   │  • aarch64-darwin    │
        └──────────────────────┘   │                      │
                                   │ Update files in:     │
                                   │ nix/expected-hashes/ │
                                   │ cosmian-kms-server.<variant>.<static-openssl|dynamic-openssl>.<arch>.<os>.sha256 │
                                   └──────────────────────┘
                                              │
                                              ▼
                                   ┌──────────────────────┐
                                   │ Git diff summary     │
                                   │ (show what changed)  │
                                   └──────────────────────┘
```

#### Nix Shell Environment Modes

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                        Nix Shell Execution Modes                        │
└─────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│  PURE MODE (--pure flag)                                                 │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━    │
│                                                                          │
│  Use Cases:                                                              │
│   • Standard builds (build command)                                      │
│   • Database tests (sqlite, psql, mysql)                                 │
│   • Most test scenarios                                                  │
│                                                                          │
│  Characteristics:                                                        │
│   ✓ Hermetic environment (isolated from system)                         │
│   ✓ Reproducible builds                                                 │
│   ✓ No system PATH pollution                                            │
│   ✓ Only Nix-provided dependencies                                      │
│                                                                          │
│  Environment:                                                            │
│   ┌──────────────────────────────────────────────────────────────┐       │
│   │  • Rust 1.90.0 (from Nix)                                    │       │
│   │  • OpenSSL 3.1.2 (vendored)                                  │       │
│   │  • Build tools (cargo, gcc, etc.)                            │       │
│   │  • Test databases (if requested via WITH_* vars)             │       │
│   │  • /nix/store/... paths ONLY                                 │       │
│   └──────────────────────────────────────────────────────────────┘       │
└──────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│  NON-PURE MODE (no --pure flag)                                          │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━    │
│                                                                          │
│  Use Cases:                                                              │
│   • HSM tests (needs system PKCS#11 libraries)                           │
│   • macOS DMG packaging (needs hdiutil, osascript)                       │
│   • Tests requiring vendor-specific system libraries                     │
│                                                                          │
│  Characteristics:                                                        │
│   ✓ Access to system tools and libraries                                │
│   ✓ Can use /usr/bin, /usr/lib paths                                    │
│   ✓ Inherits system environment variables                                │
│   ~ Less reproducible (system-dependent)                                 │
│                                                                          │
│  Environment:                                                            │
│   ┌──────────────────────────────────────────────────────────────┐       │
│   │  • Nix-provided tools (Rust, OpenSSL, etc.)                  │       │
│   │  • PLUS: System tools (/usr/bin/*)                           │       │
│   │  • PLUS: System libraries (/usr/lib/*)                       │       │
│   │  • PLUS: Vendor HSM libraries (PKCS#11 .so files)            │       │
│   │  • Mixed /nix/store and system paths                         │       │
│   └──────────────────────────────────────────────────────────────┘       │
└──────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│  NO NIX SHELL (direct execution)                                         │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━    │
│                                                                          │
│  Use Cases:                                                              │
│   • SBOM generation (sbomnix needs direct nix commands)                  │
│   • Hash updates (nix-build outside shell)                               │
│                                                                          │
│  Characteristics:                                                        │
│   ✓ Direct system environment                                            │
│   ✓ Access to nix-build, nix-store commands                              │
│   ✓ Can manipulate Nix derivations                                       │
│                                                                          │
│  Rationale:                                                              │
│   Running inside nix-shell would create nested Nix contexts             │
│   which interferes with derivation analysis and store queries           │
└──────────────────────────────────────────────────────────────────────────┘
```

#### Complete Test Execution Matrix

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                    Test Execution Decision Matrix                       │
└─────────────────────────────────────────────────────────────────────────┘

┌──────────────┬──────────┬────────────┬──────────────┬─────────────────┐
│ Test Type    │ Profile  │  Variant   │  Platform    │  Dependencies   │
├──────────────┼──────────┼────────────┼──────────────┼─────────────────┤
│              │          │            │              │                 │
│ sqlite       │ Any      │  Any       │  Any         │  None (builtin) │
│              │          │            │              │                 │
├──────────────┼──────────┼────────────┼──────────────┼─────────────────┤
│              │          │            │              │  PostgreSQL     │
│ psql         │ Release  │  Any       │  Any         │  server running │
│              │ only     │            │              │                 │
├──────────────┼──────────┼────────────┼──────────────┼─────────────────┤
│              │          │            │              │  MySQL server   │
│ mysql        │ Release  │  Any       │  Any         │  running        │
│              │ only     │            │              │                 │
├──────────────┼──────────┼────────────┼──────────────┼─────────────────┤
│              │          │ non-FIPS   │              │  Redis server   │
│ redis        │ Release  │  ONLY      │  Any         │  running        │
│              │ only     │            │              │                 │
├──────────────┼──────────┼────────────┼──────────────┼─────────────────┤
│              │          │            │              │  4 OAuth env    │
│ google_cse   │ Release  │  Any       │  Any         │  variables set  │
│              │ only     │            │              │                 │
├──────────────┼──────────┼────────────┼──────────────┼─────────────────┤
│              │          │            │              │  Python 3.11    │
│ pykmip       │ Any      │ non-FIPS   │  Any         │  + venv         │
│              │          │  ONLY      │              │                 │
├──────────────┼──────────┼────────────┼──────────────┼─────────────────┤
│ hsm          │          │            │              │  PKCS#11 libs   │
│ (all types)  │ Release  │  Any       │ Linux ONLY   │  (vendor-       │
│              │ only     │            │              │   specific)     │
└──────────────┴──────────┴────────────┴──────────────┴─────────────────┘

Legend:
  Release only = Skipped in debug profile (per test_all.sh logic)
  non-FIPS ONLY = Feature not available in FIPS variant
  Linux ONLY = HSM vendor libraries not available on macOS
```

#### Script Dependencies Graph

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                        Script Source Dependencies                       │
└─────────────────────────────────────────────────────────────────────────┘

                              common.sh
                                  │
                                  │ sourced by
                                  │
                ┌─────────────────┼─────────────────┐
                │                 │                 │
                ▼                 ▼                 ▼
         ┌──────────────┐  ┌──────────────┐ ┌──────────────┐
         │ test_all.sh  │  │test_sqlite.sh│ │test_psql.sh  │
         └──────────────┘  └──────────────┘ └──────────────┘
                │                 │                 │
                │                 │                 │
         ┌──────┴──────┐          │                 │
         │             │          │                 │
         ▼             ▼          ▼                 ▼
  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
  │test_hsm  │  │test_goog │  │test_mysql│  │test_redis│
  │   .sh    │  │le_cse.sh │  │   .sh    │  │   .sh    │
  └────┬─────┘  └──────────┘  └──────────┘  └──────────┘
       │
       │ calls
       │
       ├────────────┬────────────┬─────────────┐
       │            │            │             │
       ▼            ▼            ▼             ▼
┌──────────┐ ┌──────────┐ ┌──────────┐  ┌──────────┐
│test_hsm_ │ │test_hsm_ │ │test_hsm_ │  │test_     │
│softhsm2  │ │utimaco   │ │proteccio │  │pykmip.sh │
│   .sh    │ │   .sh    │ │   .sh    │  └──────────┘
└──────────┘ └──────────┘ └──────────┘


                         package_common.sh
                                  │
                                  │ sourced by
                                  │
                ┌─────────────────┼─────────────────┐
                │                 │                 │
                ▼                 ▼                 ▼
         ┌──────────────┐  ┌──────────────┐ ┌──────────────┐
         │package_deb.sh│  │package_rpm.sh│ │package_dmg.sh│
         └──────────────┘  └──────────────┘ └──────────────┘


Functions provided by common.sh:
  • init_build_env()        - Parse variant/profile, set env vars
  • setup_test_logging()    - Configure RUST_LOG and test output
  • check_and_test_db()     - Validate DB connection + run cargo test
  • require_cmd()           - Check command availability

Functions provided by package_common.sh:
  • get_version()           - Extract version from Cargo.toml
  • validate_package()      - Run smoke test (--info check)
  • generate_checksum()     - Create .sha256 file
```

#### End-to-End Release Pipeline

This diagram shows the complete artifact generation pipeline for a production release:

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                    Full Release Build Pipeline                          │
│                    (Typical CI/CD workflow)                             │
└─────────────────────────────────────────────────────────────────────────┘

Step 1: BUILD BINARIES (both variants)
┌──────────────────────────────────────────────────────────────────────────┐
│                                                                          │
│  bash nix.sh build --profile release --variant fips                      │
│       └──→ target/release/cosmian_kms (FIPS)                             │
│                                                                          │
│  bash nix.sh build --profile release --variant non-fips                  │
│       └──→ target/release/cosmian_kms (non-FIPS)                         │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
Step 2: RUN COMPREHENSIVE TESTS
┌──────────────────────────────────────────────────────────────────────────┐
│                                                                          │
│  bash nix.sh test all --profile release --variant fips                   │
│    ├─ SQLite tests      ✓                                                │
│    ├─ PostgreSQL tests  ✓                                                │
│    ├─ MySQL tests       ✓                                                │
│    ├─ Google CSE tests  ✓  (if credentials available)                    │
│    └─ HSM tests         ✓  (Linux only)                                  │
│                                                                          │
│  bash nix.sh test all --profile release --variant non-fips               │
│    ├─ (all above)       ✓                                                │
│    ├─ Redis-findex      ✓  (non-FIPS only)                               │
│    └─ PyKMIP client     ✓  (non-FIPS only)                               │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
Step 3: BUILD PACKAGES (all platforms × variants)
┌──────────────────────────────────────────────────────────────────────────┐
│                                                                          │
│  For each variant (fips, non-fips):                                      │
│                                                                          │
│    Linux x86_64:                                                         │
│      bash nix.sh package deb --variant <variant>                         │
│        └──→ result-deb-<variant>/cosmian-kms_<ver>_amd64.deb             │
│        └──→ result-deb-<variant>/cosmian-kms_<ver>_amd64.deb.sha256      │
│                                                                          │
│      bash nix.sh package rpm --variant <variant>                         │
│        └──→ result-rpm-<variant>/cosmian-kms-<ver>.x86_64.rpm            │
│        └──→ result-rpm-<variant>/cosmian-kms-<ver>.x86_64.rpm.sha256     │
│                                                                          │
│    macOS ARM64:                                                          │
│      bash nix.sh package dmg --variant <variant>                         │
│        └──→ result-dmg-<variant>/cosmian-kms-<ver>-aarch64.dmg           │
│        └──→ result-dmg-<variant>/cosmian-kms-<ver>-aarch64.dmg.sha256    │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
Step 4: GENERATE SBOM DOCUMENTATION
┌──────────────────────────────────────────────────────────────────────────┐
│                                                                          │
│  bash nix.sh sbom --variant fips                                         │
│    └──→ sbom/                                                            │
│         ├─ bom.cdx.json       (CycloneDX format)                         │
│         ├─ bom.spdx.json      (SPDX format)                              │
│         ├─ sbom.csv           (Spreadsheet view)                         │
│         ├─ vulns.csv          (Vulnerability scan)                       │
│         ├─ graph.png          (Dependency visualization)                 │
│         ├─ meta.json          (Build metadata)                           │
│         └─ README.txt         (Usage instructions)                       │
│                                                                          │
│  bash nix.sh sbom --variant non-fips                                     │
│    └──→ sbom-non-fips/ (same structure)                                  │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
Step 5: VERIFY REPRODUCIBILITY
┌──────────────────────────────────────────────────────────────────────────┐
│                                                                          │
│  # Hash verification (Linux FIPS builds only - bit-for-bit identical)    │
│  sha256sum target/release/cosmian_kms                                    │
│  compare with: nix/expected-hashes/fips.openssl.x86_64.linux.sha256      │
│                                                                          │
│  # If hashes don't match (unexpected):                                   │
│    1. Investigate reason (code change? dep update? tampering?)           │
│    2. Update if legitimate: bash nix.sh update-hashes                    │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
                                 │
                                 ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                        RELEASE ARTIFACTS                                 │
│                                                                          │
│  Distribution Packages (6 files per variant = 12 total):                 │
│    • Debian package (.deb) + checksum                                    │
│    • RPM package (.rpm) + checksum                                       │
│    • macOS DMG (.dmg) + checksum                                         │
│                                                                          │
│  SBOM Files (2 directories):                                             │
│    • sbom/ (FIPS variant)                                                │
│    • sbom-non-fips/ (non-FIPS variant)                                   │
│                                                                          │
│  Source Code:                                                            │
│    • Git tag (e.g., v4.17.0)                                             │
│    • GitHub release with changelog                                       │
│                                                                          │
│  Signatures (if GPG/signing enabled):                                    │
│    • Package signatures (.asc files)                                     │
│    • SBOM signatures                                                     │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘

Total artifacts per release: ~30 files
  • 12 package files (6 per variant × 2 variants)
  • 14 SBOM files (7 per variant × 2 variants)
  • 2 hash tracking files (vendor hash + binary hashes)
  • Source archive + changelog
```

#### Artifact Flow Summary

```text
Source Code                  Build Outputs              Distribution
━━━━━━━━━━━                  ━━━━━━━━━━━━━              ━━━━━━━━━━━━

┌──────────┐                ┌──────────┐               ┌──────────┐
│ Cargo.   │───build───────→│cosmian_  │──package─────→│   .deb   │
│  toml    │                │   kms    │               │   .rpm   │
│          │                │  binary  │               │   .dmg   │
│ Cargo.   │                └──────────┘               └──────────┘
│  lock    │                      │                          │
│          │                      │                          │
│  src/    │                      │                     ┌────┴────┐
│  crate/  │                      │                     │ Smoke   │
└──────────┘                      │                     │  Test   │
     │                            │                     └────┬────┘
     │                            │                          │
     │                            │                          ▼
     │                            │                    ┌──────────┐
     │                            │                    │ .sha256  │
     │                            │                    │checksum  │
     │                            │                    └──────────┘
     │                            │
     │                            └──sbom──────────────→┌──────────┐
     │                                                  │CycloneDX │
     │                                                  │  SPDX    │
     │                                                  │  CSV     │
     └──hash tracking─────────────────────────────────→ │  Vulns   │
                                                        └──────────┘
```

---

## Maintenance Guidelines

### Adding a New Test Type

1. **Create test script**: `.github/scripts/test_<name>.sh`
   - Source `common.sh` for shared helpers
   - Call `init_build_env "$@"` to parse variant/profile
   - Use `require_cmd` to check dependencies
   - Run targeted `cargo test` commands

2. **Update dispatcher**: Add case to `nix.sh` test command handling

   ```bash
   <name>)
     SCRIPT="$REPO_ROOT/.github/scripts/test_<name>.sh"
     KEEP_VARS="..." # Add any required env vars
     ;;
   ```

3. **Update help text**: Add to `usage()` function in `nix.sh`

4. **Optional**: Add to `test_all.sh` if it should run in comprehensive test suite

### Updating Expected Hashes

**When to update:**

- After modifying source code (binary hash changes)
- After updating dependencies (`Cargo.lock` changes → vendor hash)
- After Nix derivation changes (build flags, OpenSSL version)

**Process:**

```bash
# Automatic (recommended):
bash .github/scripts/nix.sh update-hashes [--vendor-only | --binary-only]

# Manual (for verification):
nix-build -A kms-server-fips-static-openssl
sha256sum result/bin/cosmian_kms
# Update nix/expected-hashes/cosmian-kms-server.fips.<static-openssl|dynamic-openssl>.<arch>.<os>.sha256
```

**Review checklist:**

- [ ] Understand why hash changed (code change, dep update, etc.)
- [ ] Verify `cosmian_kms --info` shows correct version
- [ ] Smoke test passes (OpenSSL 3.1.2 present)
- [ ] No unexpected `/nix/store` paths in binary (Linux: `ldd`, `readelf -d`)
- [ ] Document reason in commit message

### Script Best Practices

- **Prefer `nix.sh` invocation**: Don't run test scripts directly; use `nix.sh test <type>` to ensure correct environment
- **Keep scripts side-effect minimal**: Rely on Nix for purity; avoid global state changes
- **Use `set -euo pipefail`**: Fail fast on errors; catch undefined variables
- **Source `common.sh`** for shared logic (don't duplicate)
- **Add usage functions**: Include `--help` text in all standalone scripts
- **Test in CI**: Ensure new scripts work in GitHub Actions (check `NO_PREWARM` behavior)

---

## Future Enhancements

### Proposed Improvements

| Enhancement                                     | Benefit                                  | Effort |
| ----------------------------------------------- | ---------------------------------------- | ------ |
| Structured JSON output (`nix.sh --json`)        | Easier CI parsing, dashboard integration | Medium |
| UI bundle checksums in Nix derivations          | Detect accidental web UI drift           | Low    |
| `shellcheck` + `shfmt` lint target              | Enforce consistent script style          | Low    |
| HSM slot/PIN via CLI flags (not env only)       | Clearer invocation, better security      | Medium |
| Parallel test execution (independent DB tests)  | Faster CI runs                           | High   |
| SBOM integration in packages (embed in DEB/RPM) | One-click supply chain transparency      | Medium |
| Cross-compilation support (ARM Linux from x86)  | Broader platform coverage                | High   |
| Nix flakes migration                            | Modern Nix UX, better reproducibility    | High   |

### Ongoing Maintenance

- **Keep nixpkgs pinned**: Avoid unexpected breakage; update deliberately with testing
- **Monitor OpenSSL**: Watch for 3.1.x security patches; update tarball + hashes
- **Rust toolchain updates**: Test clippy/fmt changes before updating `rust-toolchain.toml`
- **Documentation sync**: Update this README when adding commands/scripts

---

## Quick Reference

### Common Tasks

```bash
# Development
bash .github/scripts/nix.sh build                      # Debug FIPS build
bash .github/scripts/nix.sh test sqlite                # Quick test iteration

# Release preparation
bash .github/scripts/nix.sh build --profile release --variant fips
bash .github/scripts/nix.sh build --profile release --variant non-fips
bash .github/scripts/nix.sh test all                   # Full test suite
bash .github/scripts/nix.sh package                    # All packages
bash .github/scripts/nix.sh sbom                       # FIPS SBOM
bash .github/scripts/nix.sh --variant non-fips sbom    # Non-FIPS SBOM

# Hash maintenance
bash .github/scripts/nix.sh update-hashes --vendor-only    # After Cargo.lock change
bash .github/scripts/nix.sh update-hashes --binary-only    # After code change

# CI simulation
NO_PREWARM=1 bash .github/scripts/nix.sh package deb   # Skip prewarm (cached store)
```

### Environment Variables

**Build/Package:**

- `NO_PREWARM=1`: Skip nixpkgs pre-fetch (for cached/offline builds)
- `NIX_PATH`: Override nixpkgs location (set automatically by `nix.sh`)

**Tests:**

- `RUST_LOG=<level>`: Cargo test verbosity (debug, info, warn, error)
- `COSMIAN_KMS_CONF`: Path to KMS config file (default: `scripts/kms.toml`)
- Database connection vars (see test section above)
- Google CSE credential vars (see test section above)

---

**Generated**: 2025-01-23
**Last Updated**: Match with changes to `nix.sh` and related scripts
**Maintainer**: Cosmian KMS Team
