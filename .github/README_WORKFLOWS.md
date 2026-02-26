# GitHub Workflows Documentation

This document provides a visual representation of all GitHub Actions workflows in the Cosmian KMS repository, their triggers, dependencies, and execution flows.

## Workflow Overview

```mermaid
flowchart LR
    subgraph entry["Entry Point Workflows"]
        main["main.yml<br/>(Push CI)<br/><br/>Triggers:<br/>· Push<br/>· Schedule<br/>· Manual"]
        pr["pr.yml<br/>(PR CI)<br/><br/>Triggers:<br/>· Tags<br/>· Pull Requests<br/>· Schedule<br/>· Manual"]
        cleanup["github_cache_cleanup.yml<br/><br/>Triggers:<br/>· Manual (workflow_dispatch)"]
    end
```

---

## 1. Push CI Workflow (`main.yml`)

Runs on direct pushes to branches, scheduled daily, and manual dispatch.

### Execution Flow

```mermaid
flowchart TB
    main["main.yml"]
    buildtype["Determine build type<br/>debug: push & manual<br/>release: scheduled only"]
    base["main_base.yml (reusable)"]
    main --> buildtype --> base
```

### Triggers

- **Push**: Any push to repository
- **Schedule**: Daily at 1:00 AM UTC
- **Manual dispatch**: Via GitHub UI

---

## 2. PR CI Workflow (`pr.yml`)

Runs on pull requests, tags, scheduled daily, and manual dispatch. Includes full packaging.

### Execution Flow

```mermaid
flowchart TB
    pr["pr.yml"]
    buildtype["Determine build type<br/>(always debug for PRs)"]
    packaging["packaging.yml<br/>(includes main_base.yml + packaging)"]
    pr --> buildtype --> packaging
```

### Triggers

- **Push to tags**: Any tag (`**`)
- **Pull requests**: All PRs
- **Schedule**: Daily at 1:00 AM UTC
- **Manual dispatch**: Via GitHub UI

---

## 3. Main Base Workflow (`main_base.yml`)

Core CI checks and testing orchestrator.

### Execution Flow

```mermaid
flowchart TB
    base["main_base.yml"]
    cla["cla-assistant<br/>(External PRs only)<br/>Verifies CLA signature"]
    clippy["cargo-clippy<br/>(external reusable)"]
    deny["cargo-deny<br/>(external reusable)"]
    machete["cargo-machete<br/>(external reusable)"]
    publish["cargo-publish<br/>dry-run: non-tags<br/>publish: tags"]
    tests["test_all.yml"]
    docs["public_documentation<br/>staging: develop branch<br/>production: tags"]
    base --> cla & clippy & deny & machete & publish & tests & docs
```

---

## 4. Test All Workflow (`test_all.yml`)

Comprehensive testing across platforms and configurations.

### Execution Flow

```mermaid
flowchart TB
    test_all["test_all.yml"]
    subgraph nix_matrix["test-nix (Matrix) — ubuntu-latest"]
        nix_types["Test types: sqlite · mysql · psql<br/>google_cse · redis (non-fips) · pykmip"]
        nix_feat["Features: fips · non-fips"]
        nix_steps["1. Install Nix<br/>2. Checkout code<br/>3. Start Docker<br/>4. nix.sh test <type>"]
    end
    subgraph nonix["test (without Nix)"]
        nonix_plat["Platforms: ubuntu-24.04 · ubuntu-24.04-arm · macos-15"]
        nonix_types["Test types: sqlite only · Features: fips · non-fips"]
        nonix_steps["1. Setup Rust · 2. Checkout · 3. test_sqlite.sh"]
    end
    subgraph hsm_matrix["hsm (Matrix)"]
        hsm_types["HSM types: utimaco · proteccio (fips) · softhsm2"]
        hsm_feat["Features: fips · non-fips (proteccio: fips only)"]
        hsm_steps["1. Install Nix · 2. Checkout · 3. nix.sh test hsm <type>"]
    end
    win["windows-2022<br/>Calls: test_windows.yml"]
    clean["cleanup<br/>Calls: cleanup_cache.yml (reusable)"]
    test_all --> nix_matrix & nonix & hsm_matrix & win & clean
```

### Test Matrix Visualization

| Test Type  | FIPS | Non-FIPS | Notes          |
|------------|:----:|:--------:|----------------|
| sqlite     | ✓    | ✓        |                |
| mysql      | ✓    | ✓        |                |
| psql       | ✓    | ✓        |                |
| google_cse | ✓    | ✓        | Requires creds |
| redis      | ✗    | ✓        | Non-FIPS only  |
| pykmip     | ✓    | ✓        |                |

| HSM Type  | FIPS | Non-FIPS | Notes     |
|-----------|:----:|:--------:|-----------|
| utimaco   | ✓    | ✓        |           |
| proteccio | ✓    | ✗        | FIPS only |
| softhsm2  | ✓    | ✓        |           |

---

## 5. Windows Test Workflow (`test_windows.yml`)

Windows-specific testing.

### Execution Flow

```mermaid
flowchart TB
    tw["test_windows.yml"]
    ct["cargo-test<br/>Platform: windows-2022"]
    steps["1. Checkout code<br/>2. Setup Rust toolchain<br/>3. Build static OpenSSL (vcpkg)<br/>4. Run tests (PowerShell: cargo_test.ps1)"]
    tw --> ct --> steps
```

---

## 6. Packaging Workflow (`packaging.yml`)

Builds and packages KMS for multiple platforms using Nix.

### Execution Flow

```mermaid
flowchart TB
    pkg["packaging.yml"]
    winpkg["windows-package<br/>Calls: build_windows.yml"]
    docker["docker<br/>Calls: packaging-docker.yml"]
    subgraph packages_matrix["packages (Matrix)"]
        pkg_feat["Features: fips · non-fips"]
        pkg_link["Link: static · dynamic"]
        pkg_run["Runners: ubuntu-24.04 · ubuntu-24.04-arm · macos-15"]
        pkg_steps["1. Install Nix · 2. Checkout · 3. GPG signing<br/>4. nix.sh package · 5. Upload artifacts"]
    end
    tests["tests<br/>Calls: packaging-tests.yml"]
    push["push-artifacts<br/>Calls: push-artifacts.yml"]
    pkg --> winpkg & docker & packages_matrix & tests & push
```

### Packaging Matrix Visualization

| Runner          | FIPS         | Non-FIPS     | Output        |
|-----------------|:------------:|:------------:|---------------|
| ubuntu-24.04    | ✓ (S+D)      | ✓ (S+D)      | .deb, .rpm    |
| ubuntu-24.04-arm | ✓ (S+D)     | ✓ (S+D)      | .deb, .rpm    |
| macos-15        | ✗            | ✓ (S+D)      | .dmg          |
| windows-2022    | ✓ (DLLs)     | ✓            | .exe          |

> Note: (S+D) = Static and Dynamic linking variants

---

## 7. Packaging Tests Workflow (`packaging-tests.yml`)

Tests packaged binaries across multiple Linux distributions.

### Execution Flow

```mermaid
flowchart TB
    pt["packaging-tests.yml"]
    subgraph matrix["packages-test (Matrix)"]
        containers["Containers:<br/>Ubuntu: 25.04, 24.04, 22.04, 20.04<br/>Debian: trixie, bookworm, bullseye, buster<br/>Rocky Linux: 10, 9, 8"]
        feat["Features: fips · non-fips"]
        link["Link: static · dynamic"]
        run["Runners: ubuntu-24.04 · ubuntu-24.04-arm"]
        steps["1. Download packages · 2. Install (dpkg/rpm)<br/>3. Test binary · 4. Smoke test server"]
    end
    pt --> matrix
```

---

## 8. Docker Packaging Workflow (`packaging-docker.yml`)

Multi-architecture Docker image creation using Nix.

### Execution Flow

```mermaid
flowchart TB
    pd["packaging-docker.yml"]
    subgraph image_matrix["nix-docker-image (Matrix)"]
        img_feat["Features: fips · non-fips"]
        img_run["Runners: ubuntu-24.04 · ubuntu-24.04-arm"]
        img_steps["1. Detect arch · 2. Install Nix · 3. Checkout<br/>4. Login GHCR · 5. Install Cosign · 6. Extract metadata<br/>7. Append arch suffix · 8. Build & load image<br/>9. Push single-arch · 10. Sign (Cosign) · 11. Test"]
    end
    subgraph manifest_matrix["nix-docker-manifest (Matrix)"]
        man_feat["Features: fips · non-fips"]
        man_dep["Depends on: nix-docker-image"]
        man_steps["1. Login GHCR · 2. Install Cosign · 3. Setup Buildx<br/>4. Compute tags · 5. Create multi-arch manifest<br/>6. Sign manifests · 7. Inspect manifests"]
    end
    pd --> image_matrix
    image_matrix --> manifest_matrix
```

### Docker Build Matrix

| OS               | Features | Architecture | Registry Image |
|------------------|:--------:|:------------:|----------------|
| ubuntu-24.04     | fips     | amd64        | kms-fips       |
| ubuntu-24.04     | non-fips | amd64        | kms            |
| ubuntu-24.04-arm | fips     | arm64        | kms-fips       |
| ubuntu-24.04-arm | non-fips | arm64        | kms            |

**Tag patterns:** `<branch>-<arch>`, `pr-<N>-<arch>`, `<version>-<arch>`
**Multi-arch manifest:** `<image>:tag-amd64` + `<image>:tag-arm64` → `<image>:tag`

---

## 9. Windows Build Workflow (`build_windows.yml`)

Windows binary and installer creation.

### Execution Flow

```mermaid
flowchart TB
    bw["build_windows.yml"]
    subgraph cargo_build["cargo-build — windows-2022"]
        cb_steps["1. Checkout · 2. Setup Rust<br/>3. Build OpenSSL (vcpkg) · 4. Build (cargo_build.ps1)<br/>5. Upload: *.exe, *cosmian_pkcs11.dll"]
    end
    subgraph fips_build["fips-build — windows-2022"]
        fb_steps["1. Checkout · 2. Build FIPS OpenSSL (vcpkg_fips.json)<br/>3. Upload: fips.dll, legacy.dll"]
    end
    subgraph combine["combine-artifacts"]
        co_steps["1. Download build artifacts<br/>2. Download FIPS artifacts<br/>3. Upload combined package"]
    end
    test["test<br/>1. Download combined artifacts<br/>2. Copy legacy.dll to OpenSSL dir<br/>3. Test: cosmian*.exe -V"]
    bw --> cargo_build & fips_build
    cargo_build & fips_build --> combine --> test
```

---

## 10. Push Artifacts Workflow (`push-artifacts.yml`)

Upload packages to package.cosmian.com and GitHub Releases.

### Execution Flow

```mermaid
flowchart TB
    pa["push-artifacts.yml"]
    subgraph packages["packages — self-hosted runner"]
        dl1["1. Download all artifacts<br/>(fips/non-fips × static/dynamic × linux/arm/macos/windows)"]
        validate["2. Validate package count<br/>≥8 .deb · ≥8 .rpm · ≥2 .dmg · ≥1 .exe"]
        push["3. Push to package.cosmian.com<br/>tags: /kms/<tag>/<br/>branches: /kms/last_build/<branch>/"]
        release["4. GitHub Release (tags only)<br/>Attach all packages"]
        dl1 --> validate --> push --> release
    end
    pa --> packages
```

### Artifact Flow

```mermaid
flowchart TB
    subgraph tags["On Tags (e.g., v1.2.3)"]
        pkg_server["package.cosmian.com/kms/v1.2.3/<br/>*.deb · *.rpm · *.dmg · *.exe<br/>cosmian-kms-public.asc"]
        gh_release["GitHub Release (v1.2.3)<br/>Same files attached"]
    end
    subgraph branches["On Branches (e.g., develop)"]
        pkg_branch["package.cosmian.com/kms/last_build/develop/<br/>Same package structure"]
    end
```

---

## 11. Cargo Publish Workflow (`cargo-publish.yml`)

Publishes Rust crates to crates.io.

### Execution Flow

```mermaid
flowchart TB
    cp["cargo-publish.yml"]
    pub["publish — ubuntu-latest"]
    steps["1. Free disk space (Android/.NET/Haskell/Docker)<br/>2. Checkout code<br/>3. Dry-run (non-tags): cargo publish --dry-run<br/>4. Actual publish (tags): cargo workspaces publish --from-git"]
    cp --> pub --> steps
```

---

## 12. CLA Assistant Workflow (`cla.yml`)

Contributor License Agreement verification.

### Execution Flow

```mermaid
flowchart TB
    cla["cla.yml"]
    assistant["cla-assistant<br/>Trigger: workflow_call (from main_base.yml)<br/>Conditions: External PRs only"]
    action["CLA Assistant GitHub Action<br/>Document: CLA.md<br/>Signatures: cla-signatures branch<br/>Storage: signatures/version1/cla.json"]
    cla --> assistant --> action
```

---

## 13. Cache Cleanup Workflow (`github_cache_cleanup.yml`)

Manual cache cleanup.

### Execution Flow

```mermaid
flowchart LR
    cleanup["github_cache_cleanup.yml"]
    job["cleanup — Trigger: workflow_dispatch (manual)"]
    ext["Cosmian/reusable_workflows<br/>cleanup_cache.yml@develop"]
    cleanup --> job --> ext
```

---

## Workflow Dependencies Graph

```mermaid
flowchart TB
    main_yml["main.yml<br/>(Push CI)"]
    pr_yml["pr.yml<br/>(PR CI)"]
    cache_yml["github_cache_cleanup.yml<br/>(Manual)"]
    main_base["main_base.yml"]
    packaging["packaging.yml"]
    cla["cla.yml"]
    pub["cargo-publish.yml"]
    test_all["test_all.yml"]
    test_win["test_windows.yml"]
    cache_ext["cleanup_cache.yml (external)"]
    pub_doc["public_documentation (external)"]
    build_win["build_windows.yml"]
    pkg_docker["packaging-docker.yml"]
    pkg_tests["packaging-tests.yml"]
    push_art["push-artifacts.yml"]

    main_yml --> main_base
    pr_yml --> packaging
    packaging --> main_base & build_win & pkg_docker & pkg_tests & push_art
    main_base --> cla & pub & test_all & pub_doc
    test_all --> test_win & cache_ext
    cache_yml --> cache_ext
```

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
    - Link types: `static`, `dynamic`
    - Example: `bash nix.sh --variant fips --link static package`

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

```mermaid
flowchart TB
    tag["Push tag (e.g., v1.2.3)"]
    pr_yml["Triggers pr.yml (on: push: tags: '**')"]
    packaging["packaging.yml (includes main_base.yml)"]
    checks["CI Checks: clippy · deny · machete"]
    tests["Full test suite (all platforms)"]
    publish["Cargo publish to crates.io"]
    docs["Documentation deployment (prod)"]
    build["Build packages (all platforms, static & dynamic)"]
    pkgtests["Test packages (13 Linux distros)"]
    docker["Build Docker images (multi-arch, FIPS & non-FIPS)<br/>Create manifests · Sign with Cosign"]
    pushpkg["Push to package.cosmian.com"]
    artifacts["Artifacts published to:<br/>GitHub Release<br/>package.cosmian.com/kms/<tag>/<br/>ghcr.io/cosmian/kms:<tag><br/>crates.io"]

    tag --> pr_yml --> packaging
    packaging --> checks & tests & publish & docs & build & pkgtests & docker & pushpkg
    checks & tests & publish & docs & build & pkgtests & docker & pushpkg --> artifacts
```

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
