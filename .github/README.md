# GitHub Workflows Documentation

This document provides a visual representation of all GitHub Actions workflows in the Cosmian KMS repository, their triggers, dependencies, and execution flows.

## Workflow Overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                         ENTRY POINT WORKFLOWS                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌────────────┐         ┌─────────────────────┐                     │
│  │  main.yml  │         │ github_cache_       │                     │
│  │    (CI)    │         │  cleanup.yml        │                     │
│  └────────────┘         └─────────────────────┘                     │
│       │                           │                                 │
│       │                           │                                 │
│  Triggers:                   Triggers:                              │
│  • Tags (push)              • Manual (workflow_dispatch)             │
│  • Pull Requests                                                    │
│  • Schedule (daily 1AM)                                             │
│  • Manual                                                           │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 1. Main CI Workflow (`main.yml`)

The primary entry point for continuous integration.

### Execution Flow

```
main.yml
├── Determines build type (debug/release)
│   └── release: tags & scheduled runs
│   └── debug: PRs & other events
│
├─► main_base.yml (reusable workflow)
│   └── See detailed flow below
│
└─► packaging.yml (conditional)
    └── Runs on: tags, PRs, scheduled runs
    └── Not on: dependabot branches
    └── See detailed flow below
```

### Triggers

- **Push to tags**: Any tag (`**`)
- **Pull requests**: All PRs
- **Schedule**: Daily at 1:00 AM UTC
- **Manual dispatch**: Via GitHub UI

---

## 2. Main Base Workflow (`main_base.yml`)

Core CI checks and testing orchestrator.

### Execution Flow

```
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
│   ├── Dry-run on PRs
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
```

---

## 3. Test All Workflow (`test_all.yml`)

Comprehensive testing across platforms and configurations.

### Execution Flow

```
test_all.yml
│
├─► test-nix (Matrix)
│   ├── Platforms: ubuntu-latest
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
```

### Test Matrix Visualization

```
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
```

---

## 4. Windows Test Workflow (`test_windows.yml`)

Windows-specific testing.

### Execution Flow

```
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
```

---

## 5. Packaging Workflow (`packaging.yml`)

Builds and packages KMS for multiple platforms.

### Execution Flow

```
packaging.yml
│
├─► windows-2022
│   └── Calls: build_windows.yml
│       └── See Windows Build flow below
│
├─► packages (Matrix)
│   ├── Features: [fips, non-fips]
│   ├── Runners: [ubuntu-24.04, ubuntu-24.04-arm, macos-15]
│   └── Steps:
│       ├── 1. Install Nix
│       ├── 2. Checkout code
│       ├── 3. Setup GPG signing
│       ├── 4. Run: nix.sh package
│       └── 5. Upload artifacts:
│           ├── result-deb-* (.deb packages)
│           └── result-rpm-* (.rpm packages)
│
├─► packages-test (Matrix)
│   ├── Containers:
│   │   ├── Ubuntu: 25.04, 24.04, 22.04, 20.04
│   │   ├── Debian: trixie, bookworm, bullseye, buster
│   │   └── Rocky Linux: 10, 9, 8
│   ├── Features: [fips, non-fips]
│   ├── Runners: [ubuntu-24.04, ubuntu-24.04-arm]
│   └── Steps:
│       ├── 1. Download package artifacts
│       ├── 2. Install package (dpkg/rpm)
│       ├── 3. Test binary:
│       │   ├── cosmian_kms --version
│       │   └── cosmian_kms --info
│       └── 4. Smoke test server:
│           └── curl http://127.0.0.1:9998/ui/
│
├─► docker-image (Matrix)
│   └── Calls: build_docker_image.yml
│       └── See Docker Build flow below
│
├─► docker-manifest (Matrix)
│   ├── Features: [fips, non-fips]
│   └── Steps:
│       ├── 1. Login to GHCR
│       ├── 2. Create multi-arch manifest
│       │   ├── Combine: tag-amd64 + tag-arm64
│       │   └── Tags: branch, PR, semver
│       └── 3. Sign with Cosign (keyless)
│
└─► push-artifacts
    └── Calls: push-artifacts.yml
        └── See Push Artifacts flow below
```

### Packaging Matrix Visualization

```
┌────────────────────────────────────────────────────────────────┐
│                   PACKAGE BUILD MATRIX                         │
├────────────────┬──────────────┬──────────────┬─────────────────┤
│ Runner         │ FIPS         │ Non-FIPS     │ Output          │
├────────────────┼──────────────┼──────────────┼─────────────────┤
│ ubuntu-24.04   │ ✓            │ ✓            │ .deb, .rpm      │
│ ubuntu-24.04   │              │              │                 │
│  -arm          │ ✓            │ ✓            │ .deb, .rpm      │
│ macos-15       │ ✗            │ ✓            │ .dmg            │
│ windows-2022   │ ✓ (DLLs)     │ ✓            │ .exe            │
└────────────────┴──────────────┴──────────────┴─────────────────┘
```

---

## 6. Windows Build Workflow (`build_windows.yml`)

Windows binary and installer creation.

### Execution Flow

```
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
```

---

## 7. Docker Build Workflow (`build_docker_image.yml`)

Multi-architecture Docker image creation and testing.

### Execution Flow

```
build_docker_image.yml
│
├─► build-and-push-image
│   ├── Inputs:
│   │   ├── registry-image (ghcr.io/cosmian/kms[-fips])
│   │   ├── os (ubuntu-24.04 or ubuntu-24.04-arm)
│   │   └── features (fips or non-fips)
│   └── Steps:
│       ├── 1. Derive architecture
│       │   ├── ubuntu-24.04-arm → arm64, linux/arm64
│       │   └── ubuntu-24.04 → amd64, linux/amd64
│       ├── 2. Checkout code
│       ├── 3. Download .deb artifact
│       ├── 4. Login to GHCR
│       ├── 5. Install Cosign
│       ├── 6. Generate Docker metadata
│       │   └── Tags: branch, PR, semver
│       ├── 7. Append arch suffix to tags
│       │   └── e.g., :latest-amd64, :latest-arm64
│       ├── 8. Build & push single-arch image
│       │   └── docker build --platform=<platform>
│       └── 9. Sign image with Cosign (keyless)
│
└─► test-image
    ├── Depends: build-and-push-image
    └── Steps:
        ├── 1. Login to GHCR
        ├── 2. Pull image
        ├── 3. Inspect architecture
        ├── 4. Checkout code
        ├── 5. Setup Rust toolchain
        └── 6. Run test script:
            └── test_docker_image.sh
```

### Docker Build Matrix

```
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

Final manifest combines: <image>:tag-amd64 + <image>:tag-arm64
                      → <image>:tag (multi-arch)
```

---

## 8. Push Artifacts Workflow (`push-artifacts.yml`)

Upload packages to package.cosmian.com and GitHub Releases.

### Execution Flow

```
push-artifacts.yml
│
└─► packages
    ├── Runs on: self-hosted runner
    ├── Container: cosmian/docker_doc_ci
    └── Steps:
        ├── 1. Download all artifacts:
        │   ├── fips_ubuntu-24.04-release
        │   ├── non-fips_ubuntu-24.04-release
        │   ├── fips_ubuntu-24.04-arm-release
        │   ├── non-fips_ubuntu-24.04-arm-release
        │   ├── non-fips_macos-15-release
        │   └── windows-release
        │
        ├── 2. Validate package count:
        │   ├── >= 4 .deb files
        │   ├── >= 4 .rpm files
        │   ├── >= 1 .dmg file
        │   └── >= 1 .exe file
        │
        ├── 3. Push to package.cosmian.com:
        │   ├── Path on tags: /mnt/package/kms/<tag>
        │   ├── Path on branches: /mnt/package/kms/last_build/<branch>
        │   └── Files:
        │       ├── *.deb, *.rpm (Linux x86_64 & ARM)
        │       ├── *.dmg (macOS)
        │       ├── *.exe (Windows)
        │       └── cosmian-kms-public.asc (GPG key)
        │
        └── 4. GitHub Release (tags only):
            └── Attach all packages to release
```

### Artifact Flow

```
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
```

---

## 9. Cargo Publish Workflow (`cargo-publish.yml`)

Publishes Rust crates to crates.io.

### Execution Flow

```
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
```

---

## 10. CLA Assistant Workflow (`cla.yml`)

Contributor License Agreement verification.

### Execution Flow

```
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
```

---

## 11. Cache Cleanup Workflow (`github_cache_cleanup.yml`)

Manual cache cleanup.

### Execution Flow

```
github_cache_cleanup.yml
│
└─► cleanup
    ├── Trigger: workflow_dispatch (manual)
    └── Calls: Cosmian/reusable_workflows cleanup_cache.yml@develop
```

---

## Workflow Dependencies Graph

```
┌──────────────────────────────────────────────────────────────────┐
│                      WORKFLOW CALL HIERARCHY                     │
└──────────────────────────────────────────────────────────────────┘

main.yml (Entry Point)
├─► main_base.yml
│   ├─► cla.yml
│   ├─► cargo-publish.yml
│   ├─► test_all.yml
│   │   ├─► test_windows.yml
│   │   └─► cleanup_cache.yml (external)
│   └─► public_documentation (external triggers)
│
└─► packaging.yml
    ├─► build_windows.yml
    ├─► build_docker_image.yml
    └─► push-artifacts.yml

github_cache_cleanup.yml (Manual)
└─► cleanup_cache.yml (external)
```

---

## Trigger Summary

| Workflow                 | On Push Tags | On PR | On Schedule | Manual | On Workflow Call |
| ------------------------ | :----------: | :---: | :---------: | :----: | :--------------: |
| main.yml                 |      ✓       |   ✓   |  ✓ (daily)  |   ✓    |        -         |
| main_base.yml            |      -       |   -   |      -      |   -    |        ✓         |
| packaging.yml            |      -       |   -   |      -      |   ✓    |        ✓         |
| test_all.yml             |      -       |   -   |      -      |   ✓    |        ✓         |
| test_windows.yml         |      -       |   -   |      -      |   -    |        ✓         |
| build_windows.yml        |      -       |   -   |      -      |   -    |        ✓         |
| build_docker_image.yml   |      -       |   -   |      -      |   -    |        ✓         |
| cargo-publish.yml        |      -       |   -   |      -      |   -    |        ✓         |
| push-artifacts.yml       |      -       |   -   |      -      |   -    |        ✓         |
| cla.yml                  |      -       |   -   |      -      |   -    |        ✓         |
| github_cache_cleanup.yml |      -       |   -   |      -      |   ✓    |        -         |

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

### Nix Build System

- **`.github/scripts/nix.sh`**: Main orchestrator for Nix-based builds and tests
    - Commands: `test`, `package`
    - Variants: `fips`, `non-fips`
    - Profiles: `debug`, `release`

### Test Scripts

- **`test_sqlite.sh`**: SQLite backend tests
- **`test_mysql.sh`**: MySQL backend tests
- **`test_psql.sh`**: PostgreSQL backend tests
- **`test_redis.sh`**: Redis backend tests
- **`test_pykmip.sh`**: PyKMIP compatibility tests
- **`test_google_cse.sh`**: Google CSE integration tests
- **`test_hsm.sh`**: HSM integration orchestrator
    - **`test_hsm_utimaco.sh`**
    - **`test_hsm_proteccio.sh`**
    - **`test_hsm_softhsm2.sh`**
- **`test_docker_image.sh`**: Docker image smoke tests

### Windows Scripts (PowerShell)

- **`cargo_build.ps1`**: Windows build orchestrator
- **`cargo_test.ps1`**: Windows test orchestrator

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

```
┌──────────────────────────────────────────────────────────────────┐
│                      RELEASE WORKFLOW                            │
└──────────────────────────────────────────────────────────────────┘

1. Push tag (e.g., v1.2.3)
   │
   ├─► Triggers main.yml with release mode
   │
   ├─► main_base.yml runs:
   │   ├── All CI checks (clippy, deny, machete)
   │   ├── Full test suite (all platforms)
   │   ├── Cargo publish to crates.io
   │   └── Documentation deployment (prod)
   │
   ├─► packaging.yml runs:
   │   ├── Build packages (all platforms)
   │   ├── Test packages (all distros)
   │   ├── Build Docker images (multi-arch)
   │   ├── Create manifests & sign
   │   └── Push to package.cosmian.com
   │
   └─► Artifacts published to:
       ├── GitHub Release (with all assets)
       ├── package.cosmian.com/kms/<tag>/
       ├── ghcr.io/cosmian/kms:<tag> (multi-arch)
       ├── ghcr.io/cosmian/kms-fips:<tag> (multi-arch)
       └── crates.io (all workspace crates)
```

---

## Continuous Integration Checks

On every pull request:

1. **Code Quality**
   - Clippy (lints)
   - Cargo deny (security audit)
   - Cargo machete (unused dependencies)
   - CLA verification (external contributors)

2. **Testing**
   - SQLite (with and without Nix)
   - MySQL (with Nix)
   - PostgreSQL (with Nix)
   - Redis (non-FIPS only, with Nix)
   - Google CSE (with Nix)
   - PyKMIP compatibility (with Nix)
   - HSMs: Utimaco, Proteccio, SoftHSM2 (with Nix)
   - Windows tests

3. **Packaging**
   - Debian packages (.deb)
   - RPM packages
   - macOS installer (.dmg)
   - Windows installer (.exe)
   - Docker images (multi-arch)

4. **Package Testing**
   - Installation on 13 different Linux distributions
   - Binary execution tests
   - UI endpoint smoke tests

---
