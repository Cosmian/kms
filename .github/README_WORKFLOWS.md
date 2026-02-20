# GitHub Workflows Documentation

This document provides a visual representation of all GitHub Actions workflows in the Cosmian KMS repository, their triggers, dependencies, and execution flows.

## Workflow Overview

```text
┌─────────────────────────────────────────────────────────────────────┐
│                         ENTRY POINT WORKFLOWS                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌────────────┐  ┌────────────┐  ┌─────────────────────┐            │
│  │  main.yml  │  │   pr.yml   │  │ github_cache_       │            │
│  │ (Push CI)  │  │  (PR CI)   │  │  cleanup.yml        │            │
│  └────────────┘  └────────────┘  └─────────────────────┘            │
│       │               │                     │                       │
│       │               │                     │                       │
│  Triggers:       Triggers:            Triggers:                     │
│  • Push          • Tags (push)        • Manual                      │
│  • Schedule      • Pull Requests      (workflow_dispatch)            │
│  • Manual        • Schedule                                         │
│                  • Manual                                           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```text

---

## 1. Push CI Workflow (`main.yml`)

Runs on direct pushes to branches, scheduled daily, and manual dispatch.

### Execution Flow

```text
main.yml
├── Determines build type (debug/release)
│   └── release: scheduled runs only
│   └── debug: push events & manual
│
└─► main_base.yml (reusable workflow)
    └── See detailed flow below
```text

### Triggers

- **Push**: Any push to repository
- **Schedule**: Daily at 1:00 AM UTC
- **Manual dispatch**: Via GitHub UI

---

## 2. PR CI Workflow (`pr.yml`)

Runs on pull requests, tags, scheduled daily, and manual dispatch. Includes full packaging.

### Execution Flow

```text
pr.yml
├── Determines build type (always debug for PRs)
│
└─► packaging.yml (always runs)
    └── Includes main_base.yml + packaging
    └── See detailed flow below
```text

### Triggers

- **Push to tags**: Any tag (`**`)
- **Pull requests**: All PRs
- **Schedule**: Daily at 1:00 AM UTC
- **Manual dispatch**: Via GitHub UI

---

## 3. Main Base Workflow (`main_base.yml`)

Core CI checks and testing orchestrator.

### Execution Flow

```text
main_base.yml
│
├─► cla-assistant (conditional)
│   ├── Runs on: External PRs
│   └── Verifies CLA signature
│
├─► cargo-clippy (external reusable)
│   └── Cosmian/reusable_workflows/.github/workflows/clippy.yml@develop
│
├─► cargo-deny (external reusable)
│   └── Cosmian/reusable_workflows/.github/workflows/cargo-audit.yml@develop
│
├─► cargo-machete (external reusable)
│   └── Cosmian/reusable_workflows/.github/workflows/cargo-machete.yml@develop
│
├─► cargo-publish
│   ├── Dry-run on non-tags
│   └── Actual publish on tags
│
├─► test_all.yml
│   └── See Test All flow below
│
└─► public_documentation
    ├── Staging deploy: develop branch
    │   └── Triggers: Cosmian/public_documentation staging.yml
    └── Production deploy: tags
        └── Triggers: Cosmian/public_documentation prod.yml
```text

---

## 4. Test All Workflow (`test_all.yml`)

Comprehensive testing across platforms and configurations.

### Execution Flow

```text
test_all.yml
│
├─► test-nix (Matrix)
│   ├── Platform: ubuntu-latest
│   ├── Test types:
│   │   ├── sqlite
│   │   ├── mysql
│   │   ├── psql
│   │   ├── google_cse
│   │   ├── redis (non-fips only)
│   │   └── pykmip
│   ├── Features: [fips, non-fips]
│   └── Steps:
│       ├── 1. Install Nix
│       ├── 2. Checkout code
│       ├── 3. Start Docker containers (compose)
│       └── 4. Run: nix.sh test <type>
│
├─► test (without Nix)
│   ├── Platforms: ubuntu-24.04, ubuntu-24.04-arm, macos-15
│   ├── Test types: sqlite only
│   ├── Features: [fips, non-fips]
│   └── Steps:
│       ├── 1. Setup Rust toolchain
│       ├── 2. Checkout code
│       └── 3. Run: test_sqlite.sh
│
├─► hsm (Matrix)
│   ├── HSM types:
│   │   ├── utimaco
│   │   ├── proteccio (fips only)
│   │   └── softhsm2
│   ├── Features: [fips, non-fips]
│   │   └── Note: proteccio excludes non-fips
│   └── Steps:
│       ├── 1. Install Nix
│       ├── 2. Checkout code
│       └── 3. Run: nix.sh test hsm <type>
│
├─► windows-2022
│   └── Calls: test_windows.yml
│
└─► cleanup
    └── Calls: Cosmian/reusable_workflows cleanup_cache.yml@develop
```text

### Test Matrix Visualization

```text
┌─────────────────────────────────────────────────────────────┐
│                     TEST-NIX MATRIX                         │
├──────────────┬──────────────┬──────────────┬────────────────┤
│ Test Type    │ FIPS         │ Non-FIPS     │ Notes          │
├──────────────┼──────────────┼──────────────┼────────────────┤
│ sqlite       │ ✓            │ ✓            │                │
│ mysql        │ ✓            │ ✓            │                │
│ psql         │ ✓            │ ✓            │                │
│ google_cse   │ ✓            │ ✓            │ Requires creds │
│ redis        │ ✗            │ ✓            │ Non-FIPS only  │
│ pykmip       │ ✓            │ ✓            │                │
└──────────────┴──────────────┴──────────────┴────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                     HSM MATRIX                              │
├──────────────┬──────────────┬──────────────┬────────────────┤
│ HSM Type     │ FIPS         │ Non-FIPS     │ Notes          │
├──────────────┼──────────────┼──────────────┼────────────────┤
│ utimaco      │ ✓            │ ✓            │                │
│ proteccio    │ ✓            │ ✗            │ FIPS only      │
│ softhsm2     │ ✓            │ ✓            │                │
└──────────────┴──────────────┴──────────────┴────────────────┘
```text

---

## 5. Windows Test Workflow (`test_windows.yml`)

Windows-specific testing.

### Execution Flow

```text
test_windows.yml
│
└─► cargo-test
    ├── Platform: windows-2022
    └── Steps:
        ├── 1. Checkout code
        ├── 2. Setup Rust toolchain
        ├── 3. Build static OpenSSL (vcpkg)
        │   └── vcpkg install --triplet x64-windows-static
        └── 4. Run tests
            └── PowerShell: cargo_test.ps1
```text

---

## 6. Packaging Workflow (`packaging.yml`)

Builds and packages KMS for multiple platforms using Nix.

### Execution Flow

```text
packaging.yml
│
├─► windows-package
│   └── Calls: build_windows.yml
│       └── See Windows Build flow below
│
├─► docker
│   └── Calls: packaging-docker.yml
│       └── See Docker Build flow below
│
├─► packages (Matrix)
│   ├── Features: [fips, non-fips]
│   ├── Link types: [static, dynamic]
│   ├── Runners: [ubuntu-24.04, ubuntu-24.04-arm, macos-15]
│   └── Steps:
│       ├── 1. Install Nix
│       ├── 2. Checkout code
│       ├── 3. Setup GPG signing
│       ├── 4. Run: nix.sh --profile release --variant <features> --link <link> package
│       └── 5. Upload artifacts:
│           ├── Hash artifacts (*.sha256)
│           └── Package artifacts:
│               ├── result-deb-<features>-<link>/ (.deb packages)
│               ├── result-rpm-<features>-<link>/ (.rpm packages)
│               └── result-dmg-<features>-<link>/ (.dmg packages - macOS only)
│
├─► tests
│   └── Calls: packaging-tests.yml
│       └── See Packaging Tests flow below
│
└─► push-artifacts
    └── Calls: push-artifacts.yml
        └── See Push Artifacts flow below
```text

### Packaging Matrix Visualization

```text
┌────────────────────────────────────────────────────────────────┐
│                   PACKAGE BUILD MATRIX                         │
├────────────────┬──────────────┬──────────────┬─────────────────┤
│ Runner         │ FIPS         │ Non-FIPS     │ Output          │
├────────────────┼──────────────┼──────────────┼─────────────────┤
│ ubuntu-24.04   │ ✓ (S+D)      │ ✓ (S+D)      │ .deb, .rpm      │
│ ubuntu-24.04   │              │              │                 │
│  -arm          │ ✓ (S+D)      │ ✓ (S+D)      │ .deb, .rpm      │
│ macos-15       │ ✗            │ ✓ (S+D)      │ .dmg            │
│ windows-2022   │ ✓ (DLLs)     │ ✓            │ .exe            │
└────────────────┴──────────────┴──────────────┴─────────────────┘

Note: (S+D) = Static and Dynamic linking variants
```text

---

## 7. Packaging Tests Workflow (`packaging-tests.yml`)

Tests packaged binaries across multiple Linux distributions.

### Execution Flow

```text
packaging-tests.yml
│
└─► packages-test (Matrix)
    ├── Containers:
    │   ├── Ubuntu: 25.04, 24.04, 22.04, 20.04
    │   ├── Debian: trixie, bookworm, bullseye, buster
    │   └── Rocky Linux: 10, 9, 8
    ├── Features: [fips, non-fips]
    ├── Link types: [static, dynamic]
    ├── Runners: [ubuntu-24.04, ubuntu-24.04-arm]
    └── Steps:
        ├── 1. Download package artifacts
        ├── 2. Install package (dpkg/rpm)
        ├── 3. Test binary:
        │   ├── cosmian_kms --version
        │   └── cosmian_kms --info
        └── 4. Smoke test server:
            └── curl http://127.0.0.1:9998/ui/
```text

---

## 8. Docker Packaging Workflow (`packaging-docker.yml`)

Multi-architecture Docker image creation using Nix.

### Execution Flow

```text
packaging-docker.yml
│
├─► nix-docker-image (Matrix)
│   ├── Features: [fips, non-fips]
│   ├── Runners: [ubuntu-24.04, ubuntu-24.04-arm]
│   └── Steps:
│       ├── 1. Derive architecture from runner
│       │   ├── ubuntu-24.04-arm → arm64, linux/arm64, suffix: -arm64
│       │   └── ubuntu-24.04 → amd64, linux/amd64, suffix: -amd64
│       ├── 2. Install Nix
│       ├── 3. Checkout code
│       ├── 4. Login to GHCR
│       ├── 5. Install Cosign
│       ├── 6. Extract Docker metadata
│       │   └── Tags: branch, PR, semver
│       ├── 7. Append arch suffix to tags
│       │   └── e.g., nix-amd64, nix-arm64, pr-596-amd64
│       ├── 8. Build and load Docker image
│       │   └── nix.sh --variant <features> docker --load --test
│       ├── 9. Tag and push single-arch images
│       │   └── Push each tag with arch suffix
│       ├── 10. Sign images with Cosign (keyless)
│       └── 11. Test Docker image
│
└─► nix-docker-manifest (Matrix)
    ├── Depends on: nix-docker-image
    ├── Features: [fips, non-fips]
    └── Steps:
        ├── 1. Login to GHCR
        ├── 2. Install Cosign
        ├── 3. Setup Buildx
        ├── 4. Compute tags (branch, PR, semver)
        ├── 5. Create and push multi-arch manifest
        │   ├── Combine: tag-amd64 + tag-arm64
        │   └── Tags: branch, PR, semver
        ├── 6. Sign manifests with Cosign (keyless)
        └── 7. Inspect manifests
```text

### Docker Build Matrix

```text
┌────────────────────────────────────────────────────────────────┐
│                 DOCKER IMAGE BUILD MATRIX                      │
├─────────────────┬───────────┬────────────────┬─────────────────┤
│ OS              │ Features  │ Architecture   │ Registry Image  │
├─────────────────┼───────────┼────────────────┼─────────────────┤
│ ubuntu-24.04    │ fips       │ amd64          │ kms-fips         │
│ ubuntu-24.04    │ non-fips   │ amd64          │ kms             │
│ ubuntu-24.04-   │           │                │                 │
│  arm            │ fips       │ arm64          │ kms-fips         │
│ ubuntu-24.04-   │           │                │                 │
│  arm            │ non-fips   │ arm64          │ kms             │
└─────────────────┴───────────┴────────────────┴─────────────────┘

Tags generated:
- type=ref,event=branch → <branch-name>-amd64, <branch-name>-arm64
- type=ref,event=pr → pr-<number>-amd64, pr-<number>-arm64
- type=semver → <version>-amd64, <version>-arm64

Final manifest combines: <image>:tag-amd64 + <image>:tag-arm64
                      → <image>:tag (multi-arch)
```text

---

## 9. Windows Build Workflow (`build_windows.yml`)

Windows binary and installer creation.

### Execution Flow

```text
build_windows.yml
│
├─► cargo-build
│   ├── Platform: windows-2022
│   └── Steps:
│       ├── 1. Checkout code
│       ├── 2. Setup Rust toolchain
│       ├── 3. Build static OpenSSL (vcpkg)
│       ├── 4. Build project
│       │   └── PowerShell: cargo_build.ps1
│       └── 5. Upload artifacts:
│           ├── *.exe
│           └── *cosmian_pkcs11.dll
│
├─► fips-build
│   ├── Platform: windows-2022
│   └── Steps:
│       ├── 1. Checkout code
│       ├── 2. Build FIPS OpenSSL
│       │   └── vcpkg install (using vcpkg_fips.json)
│       └── 3. Upload FIPS artifacts:
│           ├── fips.dll
│           └── legacy.dll
│
├─► combine-artifacts
│   ├── Depends: cargo-build, fips-build
│   └── Steps:
│       ├── 1. Download build artifacts
│       ├── 2. Download FIPS artifacts
│       └── 3. Upload combined package:
│           ├── *.exe
│           ├── *cosmian_pkcs11.dll
│           ├── fips.dll
│           └── legacy.dll
│
└─► test
    ├── Depends: combine-artifacts
    └── Steps:
        ├── 1. Download combined artifacts
        ├── 2. Copy legacy.dll to OpenSSL dir
        └── 3. Test all executables:
            └── cosmian*.exe -V
```text

---

## 10. Push Artifacts Workflow (`push-artifacts.yml`)

Upload packages to package.cosmian.com and GitHub Releases.

### Execution Flow

```text
push-artifacts.yml
│
└─► packages
    ├── Runs on: self-hosted runner
    ├── Container: cosmian/docker_doc_ci
    └── Steps:
        ├── 1. Download all artifacts:
        │   ├── fips_static_ubuntu-24.04-release
        │   ├── fips_dynamic_ubuntu-24.04-release
        │   ├── non-fips_static_ubuntu-24.04-release
        │   ├── non-fips_dynamic_ubuntu-24.04-release
        │   ├── fips_static_ubuntu-24.04-arm-release
        │   ├── fips_dynamic_ubuntu-24.04-arm-release
        │   ├── non-fips_static_ubuntu-24.04-arm-release
        │   ├── non-fips_dynamic_ubuntu-24.04-arm-release
        │   ├── non-fips_static_macos-15-release
        │   ├── non-fips_dynamic_macos-15-release
        │   ├── windows-release
        │   └── hash-*
        │
        ├── 2. Validate package count:
        │   ├── >= 8 .deb files (4 variants × 2 arches)
        │   ├── >= 8 .rpm files (4 variants × 2 arches)
        │   ├── >= 2 .dmg files (2 variants)
        │   └── >= 1 .exe file
        │
        ├── 3. Push to package.cosmian.com:
        │   ├── Path on tags: /mnt/package/kms/<tag>
        │   ├── Path on branches: /mnt/package/kms/last_build/<branch>
        │   └── Files:
        │       ├── *.deb, *.rpm (Linux x86_64 & ARM)
        │       ├── *.dmg (macOS)
        │       ├── *.exe (Windows)
        │       ├── *.sha256 (hash artifacts from nix/expected-hashes/)
        │       └── cosmian-kms-public.asc (GPG key)
        │
        └── 4. GitHub Release (tags only):
            └── Attach all packages to release
```text

### Artifact Flow

```text
┌────────────────────────────────────────────────────────────────┐
│                    ARTIFACT DESTINATIONS                       │
└────────────────────────────────────────────────────────────────┘

On Tags (e.g., v1.2.3):
├─► package.cosmian.com/kms/v1.2.3/
│   ├── *.deb (Ubuntu/Debian packages)
│   ├── *.rpm (Rocky Linux packages)
│   ├── *.dmg (macOS installer)
│   ├── *.exe (Windows installer)
│   └── cosmian-kms-public.asc
│
└─► GitHub Release (v1.2.3)
    └── Same files attached

On Branches (e.g., develop):
└─► package.cosmian.com/kms/last_build/develop/
    └── Same package structure
```text

---

## 11. Cargo Publish Workflow (`cargo-publish.yml`)

Publishes Rust crates to crates.io.

### Execution Flow

```text
cargo-publish.yml
│
└─► publish
    ├── Platform: ubuntu-latest
    └── Steps:
        ├── 1. Free disk space
        │   └── Remove: Android, .NET, Haskell, Docker images
        ├── 2. Checkout code
        ├── 3. Dry-run (non-tags):
        │   └── cargo publish --dry-run
        └── 4. Actual publish (tags only):
            ├── Install cargo-workspaces
            └── cargo workspaces publish --from-git
```text

---

## 12. CLA Assistant Workflow (`cla.yml`)

Contributor License Agreement verification.

### Execution Flow

```text
cla.yml
│
└─► cla-assistant
    ├── Trigger: workflow_call (from main_base.yml)
    ├── Conditions: External PRs
    └── Steps:
        └── 1. Run CLA Assistant GitHub Action
            ├── Document: CLA.md
            ├── Signatures: cla-signatures branch
            └── Storage: signatures/version1/cla.json
```text

---

## 13. Cache Cleanup Workflow (`github_cache_cleanup.yml`)

Manual cache cleanup.

### Execution Flow

```text
github_cache_cleanup.yml
│
└─► cleanup
    ├── Trigger: workflow_dispatch (manual)
    └── Calls: Cosmian/reusable_workflows cleanup_cache.yml@develop
```text

---

## Workflow Dependencies Graph

```text
┌──────────────────────────────────────────────────────────────────┐
│                      WORKFLOW CALL HIERARCHY                     │
└──────────────────────────────────────────────────────────────────┘

main.yml (Push CI - Entry Point)
└─► main_base.yml
    ├─► cla.yml
    ├─► cargo-publish.yml
    ├─► test_all.yml
    │   ├─► test_windows.yml
    │   └─► cleanup_cache.yml (external)
    └─► public_documentation (external triggers)

pr.yml (PR CI - Entry Point)
└─► packaging.yml
    ├─► main_base.yml (inherited from above)
    ├─► build_windows.yml
    ├─► packaging-docker.yml
    │   ├─► nix-docker-image (job)
    │   └─► nix-docker-manifest (job)
    ├─► packaging-tests.yml
    └─► push-artifacts.yml

github_cache_cleanup.yml (Manual)
└─► cleanup_cache.yml (external)
```text

---

## Trigger Summary

| Workflow                 | On Push | On PR | On Tags | On Schedule | Manual |
| ------------------------ | :-----: | :---: | :-----: | :---------: | :----: |
| main.yml (Push CI)       |   ✓     |   -   |    -    |  ✓ (daily)  |   ✓    |
| pr.yml (PR CI)           |   -     |   ✓   |    ✓    |  ✓ (daily)  |   ✓    |
| main_base.yml            |   -     |   -   |    -    |      -      | via WC |
| packaging.yml            |   -     |   -   |    -    |      -      | ✓, WC  |
| packaging-docker.yml     |   -     |   -   |    -    |      -      | ✓, WC  |
| packaging-tests.yml      |   -     |   -   |    -    |      -      | ✓, WC  |
| test_all.yml             |   -     |   -   |    -    |      -      | ✓, WC  |
| test_windows.yml         |   -     |   -   |    -    |      -      | via WC |
| build_windows.yml        |   -     |   -   |    -    |      -      | via WC |
| cargo-publish.yml        |   -     |   -   |    -    |      -      | via WC |
| push-artifacts.yml       |   -     |   -   |    -    |      -      | via WC |
| cla.yml                  |   -     |   -   |    -    |      -      | via WC |
| github_cache_cleanup.yml |   -     |   -   |    -    |      -      |   ✓    |

**Legend**: WC = Workflow Call (reusable workflow)

---

## Environment Variables & Secrets

### Required Secrets

- **GITHUB_TOKEN**: Automatic (GitHub provides)
- **PERSONAL_ACCESS_TOKEN**: CLA Assistant
- **GPG_SIGNING_KEY**: Package signing
- **GPG_SIGNING_KEY_PASSPHRASE**: Package signing
- **CRATES_IO**: Cargo publish token
- **PAT_TOKEN**: Public documentation deployment

### HSM Secrets

- **PROTECCIO_IP**: Proteccio HSM IP address
- **PROTECCIO_PASSWORD**: Proteccio HSM password
- **PROTECCIO_SLOT**: Proteccio HSM slot

### Google CSE Secrets

- **TEST_GOOGLE_OAUTH_CLIENT_ID**
- **TEST_GOOGLE_OAUTH_CLIENT_SECRET**
- **TEST_GOOGLE_OAUTH_REFRESH_TOKEN**
- **GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY**

### Database URLs

- **KMS_POSTGRES_URL**: `postgresql://kms:kms@127.0.0.1:5432/kms`
- **KMS_MYSQL_URL**: `mysql://root:kms@localhost:3306/kms`
- **KMS_REDIS_URL**: `redis://localhost:6379`
- **KMS_SQLITE_PATH**: `data/shared`

---

## Key Build Scripts

All scripts are located in `.github/scripts/`. See the [scripts README](.github/scripts/README.md) for comprehensive documentation.

### Nix Build System

- **`nix.sh`**: Main orchestrator for Nix-based builds, tests, and Docker
    - Commands: `build`, `test`, `package`, `docker`, `sbom`, `update-hashes`
    - Variants: `fips`, `non-fips`
    - Profiles: `debug`, `release`
    - Link types: `static`, `dynamic`
    - Example: `bash nix.sh --profile release --variant fips --link static package`

### Core Test Scripts

All test scripts are called via `nix.sh test <type>` for reproducible environments:

- **Database Backend Tests**:
    - `test_sqlite.sh`: SQLite embedded database tests
    - `test_mysql.sh`: MySQL backend tests (requires MySQL server)
    - `test_psql.sh`: PostgreSQL backend tests (requires PostgreSQL server)
    - `test_redis.sh`: Redis-findex encrypted index tests (non-FIPS only)

- **Integration Tests**:
    - `test_pykmip.sh`: PyKMIP client compatibility tests (non-FIPS only)
    - `test_google_cse.sh`: Google Client-Side Encryption integration tests
    - `google_cse_with_hsm.sh`: Google CSE with HSM integration

- **HSM Tests** (orchestrated by `test_hsm.sh`):
    - `test_hsm_softhsm2.sh`: SoftHSM2 emulator tests
    - `test_hsm_utimaco.sh`: Utimaco simulator tests
    - `test_hsm_proteccio.sh`: Proteccio NetHSM tests (FIPS only)
    - `test_hsm_crypt2pay.sh`: Crypt2pay HSM tests

- **Test Orchestration**:
    - `test_all.sh`: Run complete test suite
    - `test_docker_image.sh`: Docker image smoke tests

### Package Smoke Tests

- `smoke_test_deb.sh`: Test Debian packages installation and functionality
- `smoke_test_rpm.sh`: Test RPM packages installation and functionality
- `smoke_test_dmg.sh`: Test macOS DMG packages installation and functionality

### Windows Scripts (PowerShell)

- `cargo_build.ps1`: Windows build orchestrator with vcpkg OpenSSL
- `cargo_test.ps1`: Windows test orchestrator
- `windows_ui.ps1`: Windows UI build and packaging

### Utility Scripts

- `common.sh`: Shared functions and utilities
- `benchmarks.sh`: Performance benchmarking suite
- `reinitialize_demo_kms.sh`: Reset demo KMS instance
- `renew_server_doc.sh`: Regenerate server documentation
- `release.sh`: Release preparation and validation

### Docker Compose Configurations

- `.github/scripts/docker-compose.yml`: Single compose file for docker image smoke tests (auth/TLS, config-based, example, and load-balancer stacks)
- `test_data/configs/server/{no_auth,tls_auth_*,tls13_auth_*,lb_kms*_postgres}.toml`: Dedicated server configuration files mounted via `COSMIAN_KMS_CONF` (used by the compose services)

---

## Artifact Retention

All artifacts have a **1-day retention period** unless released:

- Build artifacts (intermediate)
- Package artifacts (before release)
- Test artifacts

Released artifacts are permanent:

- GitHub Releases (tags)
- package.cosmian.com
- ghcr.io (Docker registry)
- crates.io (Rust crates)

---

## Platform Coverage

### Operating Systems

- **Linux**: Ubuntu 20.04–25.04, Debian 10–13, Rocky Linux 8–10
- **macOS**: macOS 15 (ARM64 only for releases)
- **Windows**: Windows Server 2022

### Architectures

- **x86_64 (AMD64)**: All platforms
- **ARM64 (AARCH64)**: Linux, macOS

### FIPS Compliance

- **FIPS builds**: Linux (x86_64, ARM64), Windows (DLLs)
- **Non-FIPS builds**: All platforms
- **FIPS restrictions**: No Redis support, Proteccio HSM only

---

## Release Process

```text
┌──────────────────────────────────────────────────────────────────┐
│                      RELEASE WORKFLOW                            │
└──────────────────────────────────────────────────────────────────┘

1. Push tag (e.g., v1.2.3)
   │
   ├─► Triggers pr.yml (because on: push: tags: '**')
   │
   ├─► packaging.yml runs (which includes main_base.yml):
   │   ├── All CI checks (clippy, deny, machete)
   │   ├── Full test suite (all platforms)
   │   ├── Cargo publish to crates.io
   │   ├── Documentation deployment (prod)
   │   ├── Build packages (all platforms, static & dynamic)
   │   ├── Test packages (all distros)
   │   ├── Build Docker images (multi-arch, Nix-based)
   │   ├── Create manifests & sign
   │   └── Push to package.cosmian.com
   │
   └─► Artifacts published to:
       ├── GitHub Release (with all assets)
       ├── package.cosmian.com/kms/<tag>/
       │   ├── 8+ .deb packages (static/dynamic × fips/non-fips × amd64/arm64)
       │   ├── 8+ .rpm packages (static/dynamic × fips/non-fips × amd64/arm64)
       │   ├── 2 .dmg packages (static/dynamic × non-fips)
       │   ├── 1 .exe package (Windows installer)
       │   ├── *.sha256 hash files
       │   └── cosmian-kms-public.asc
       ├── ghcr.io/cosmian/kms:<tag> (multi-arch, non-FIPS)
       ├── ghcr.io/cosmian/kms-fips:<tag> (multi-arch, FIPS)
       └── crates.io (all workspace crates)
```text

---

## Continuous Integration Checks

### On every push (via main.yml)

1. **Code Quality** (via main_base.yml)
   - Clippy (lints)
   - Cargo deny (security audit)
   - Cargo machete (unused dependencies)

2. **Testing** (via test_all.yml)
   - SQLite (with and without Nix, all platforms)
   - MySQL (with Nix)
   - PostgreSQL (with Nix)
   - Redis (non-FIPS only, with Nix)
   - Google CSE (with Nix)
   - PyKMIP compatibility (with Nix)
   - HSMs: Utimaco, Proteccio, SoftHSM2 (with Nix)
   - Windows tests

### On pull requests and tags (via pr.yml)

All of the above, plus:

1. **Packaging** (via packaging.yml)
   - Debian packages (.deb) - static and dynamic
   - RPM packages - static and dynamic
   - macOS installer (.dmg) - static and dynamic (non-FIPS only)
   - Windows installer (.exe)
   - Docker images (multi-arch, FIPS and non-FIPS)

2. **Package Testing** (via packaging-tests.yml)
   - Installation on 13 different Linux distributions
   - Binary execution tests
   - UI endpoint smoke tests

3. **CLA Verification** (external contributors only)

---
