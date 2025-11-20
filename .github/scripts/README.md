# Cosmian KMS Script Suite

This folder groups helper scripts for building, testing, packaging and releasing Cosmian KMS.
The primary entrypoint is `nix.sh` (unified Nix workflow). Other scripts provide UI builds,
test orchestration, HSM backends, release chores, Docker TLS checks and Windows support.

## 1. `nix.sh` – Unified Nix Orchestrator

Subcommands:

| Command | Purpose                                  | Types / Variants                                                                                                  | Notes                             |
| ------- | ---------------------------------------- | ----------------------------------------------------------------------------------------------------------------- | --------------------------------- |
| build   | Build the server inside pinned Nix shell | profile: debug / release; variant: fips / non-fips                                                                | Wraps `nix/scripts/build.sh`      |
| test    | Run test suites                          | all, sqlite, mysql, psql, redis, google_cse, pykmip, hsm [softhsm2 / utimaco / proteccio / all] | Adds env flags for extra tools    |
| package | Produce OS packages                      | deb, rpm, dmg (auto set per OS if omitted)                                                                        | Hash‑enforced build + smoke tests |

Options:

| Flag                           | Effect             | Default                               |
| ------------------------------ | ------------------ | ------------------------------------- |
| -p / --profile <debug/release> | Cargo profile      | debug (build/test); release (package) |
| -v / --variant <fips/non-fips> | Crypto feature set | fips                                  |
| -h / --help                    | Show usage         | —                                     |

Test environment variables consumed: `REDIS_HOST`, `REDIS_PORT`, `MYSQL_HOST`, `MYSQL_PORT`,
`POSTGRES_HOST`, `POSTGRES_PORT`, `TEST_GOOGLE_OAUTH_CLIENT_ID`, `TEST_GOOGLE_OAUTH_CLIENT_SECRET`,
`TEST_GOOGLE_OAUTH_REFRESH_TOKEN`, `GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY`.

Internal functions:

| Function                     | Responsibility                                              |
| ---------------------------- | ----------------------------------------------------------- |
| usage                        | Print help and exit                                         |
| resolve_pinned_nixpkgs_store | Realize pinned nixpkgs tarball locally                      |
| prewarm_nixpkgs_and_tools    | Pre-fetch nixpkgs + packaging tools (skip via `NO_PREWARM`) |

High level flow:

```text
main
  → parse options & command
  → select target script or package type
  → (package) prewarm_nixpkgs_and_tools
      → loop over deb|rpm|dmg
          → nix-build / nix-shell package_* script
          → smoke test (extract & cosmian_kms --info; assert OpenSSL 3.1.2)
  → (build/test) enter nix-shell (pure unless HSM or macOS dmg) and run script
```

Pure vs non‑pure shell:

| Scenario                       | Mode     | Reason                                  |
| ------------------------------ | -------- | --------------------------------------- |
| Standard build / non-HSM tests | pure     | Hermetic toolchain sufficient           |
| HSM tests                      | non-pure | Access vendor PKCS#11 libraries         |
| macOS dmg packaging            | non-pure | Needs system tools (hdiutil, osascript) |

Examples:

```bash
bash .github/scripts/nix.sh build --profile release --variant non-fips
bash .github/scripts/nix.sh test all
bash .github/scripts/nix.sh --variant non-fips test redis
TEST_GOOGLE_OAUTH_CLIENT_ID=... TEST_GOOGLE_OAUTH_CLIENT_SECRET=... \
TEST_GOOGLE_OAUTH_REFRESH_TOKEN=... GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY=... \
  bash .github/scripts/nix.sh test google_cse
bash .github/scripts/nix.sh package
```

# Cosmian KMS Script Suite

This folder groups helper scripts for building, testing, packaging and releasing Cosmian KMS.
The primary entrypoint is `nix.sh` (unified Nix workflow). Other scripts provide UI builds,
HSM backends, release chores, Docker TLS checks and Windows support.

## 1. `nix.sh` – Unified Nix Orchestrator

Subcommands:

| Command | Purpose                                  | Types / Variants                                                                     | Notes                             |
| ------- | ---------------------------------------- | ------------------------------------------------------------------------------------ | --------------------------------- |
| build   | Build the server inside pinned Nix shell | profile: debug / release; variant: fips / non-fips                                   | Wraps `nix/scripts/build.sh`      |
| test    | Run test suites                          | all, sqlite, mysql, psql, redis, google_cse, pykmip, hsm [softhsm2, utimaco, proteccio, all] | Adds env flags for extra tools    |
| package | Produce OS packages                      | deb, rpm, dmg (auto set per OS if omitted)                                           | Hash‑enforced build + smoke tests |

Options:

| Flag                             | Effect             | Default                               |
| -------------------------------- | ------------------ | ------------------------------------- |
| -p / --profile <debug / release> | Cargo profile      | debug (build/test); release (package) |
| -v / --variant <fips / non-fips> | Crypto feature set | fips                                  |
| -h / --help                      | Show usage         | —                                     |

Test environment variables consumed:
`REDIS_HOST`, `REDIS_PORT`, `MYSQL_HOST`, `MYSQL_PORT`, `POSTGRES_HOST`, `POSTGRES_PORT`,
`TEST_GOOGLE_OAUTH_CLIENT_ID`, `TEST_GOOGLE_OAUTH_CLIENT_SECRET`, `TEST_GOOGLE_OAUTH_REFRESH_TOKEN`,
`GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY`.

Internal functions:

| Function                     | Responsibility                                              |
| ---------------------------- | ----------------------------------------------------------- |
| usage                        | Print help and exit                                         |
| resolve_pinned_nixpkgs_store | Realize pinned nixpkgs tarball locally                      |
| prewarm_nixpkgs_and_tools    | Pre-fetch nixpkgs + packaging tools (skip via `NO_PREWARM`) |

High level flow:

```text
main
  → parse options & command
  → select target script or package type
  → (package) prewarm_nixpkgs_and_tools
      → loop over deb|rpm|dmg
          → nix-build / nix-shell package_* script
          → smoke test (extract & cosmian_kms --info; assert OpenSSL 3.1.2)
  → (build/test) enter nix-shell (pure unless HSM or macOS dmg) and run script
```

Pure vs non‑pure shell:

| Scenario                       | Mode     | Reason                                  |
| ------------------------------ | -------- | --------------------------------------- |
| Standard build / non-HSM tests | pure     | Hermetic toolchain sufficient           |
| HSM tests                      | non-pure | Access vendor PKCS#11 libraries         |
| macOS dmg packaging            | non-pure | Needs system tools (hdiutil, osascript) |

Examples:

```bash
bash .github/scripts/nix.sh build --profile release --variant non-fips
bash .github/scripts/nix.sh test all
bash .github/scripts/nix.sh --variant non-fips test redis
bash .github/scripts/nix.sh --variant non-fips test pykmip
TEST_GOOGLE_OAUTH_CLIENT_ID=... TEST_GOOGLE_OAUTH_CLIENT_SECRET=... \
TEST_GOOGLE_OAUTH_REFRESH_TOKEN=... GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY=... \
  bash .github/scripts/nix.sh test google_cse
bash .github/scripts/nix.sh package
bash .github/scripts/nix.sh --variant non-fips package rpm
```

## 2. Nix's Role

| Aspect                   | Contribution                  | Result                      |
| ------------------------ | ----------------------------- | --------------------------- |
| Pinned nixpkgs           | Fixed dependency graph        | Bit-for-bit reproducibility |
| Pinned Rust toolchain    | Stable compiler (1.90.0)      | Consistent builds / lints   |
| Static OpenSSL 3.1.2     | Vendored source tarball       | No runtime dynamic OpenSSL  |
| installCheckPhase hash   | Enforces expected binary hash | Early drift detection       |
| Prewarm + offline caches | Fetch once, reuse offline     | Offline packaging possible  |
| Single entrypoint        | Unified workflow              | Lower cognitive load        |
| Variant feature gating   | FIPS vs non-FIPS features     | Controlled crypto scope     |

Hash update (summary): build via `nix-build -A kms-server-<variant>` then replace the file in
`nix/expected-hashes/` with the new SHA-256 after review.

## 3. Script Call Graph Overview

| Script                                  | Purpose                                 | Key Functions / Steps                              | Call Graph Summary                                                                          |
| --------------------------------------- | --------------------------------------- | -------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| nix.sh                                  | Unified build/test/package orchestrator | parse, select, prewarm, smoke test                 | parse → dispatch → (package loop + smoke) or nix-shell exec                                 |
| common.sh                               | Shared test helpers                     | init_build_env, run_db_tests, check_and_test_db    | test_* source → init → db checks → cargo test                                               |
| build_ui.sh                             | Build WASM + web UI                     | parse variant, wasm-pack build, npm build          | variant → ensure Node → wasm-pack → copy → npm build → deploy                               |
| build_ui_all.sh                         | Build both UI variants                  | calls build_ui.sh twice                            | build_ui.sh fips → add → build_ui.sh non-fips → add                                         |
| release.sh                              | Version bump + artifacts                | sed replacements, UI build, cargo build, changelog | replace versions → build UIs → cargo build → README update → changelog                      |
| test_all.sh                             | Orchestrate all test categories         | run_step wrapper                                   | sqlite → (if release) psql → mysql → redis (non-fips) → google_cse (if creds) → hsm (Linux) |
| test_sqlite.sh                          | SQLite tests                            | cargo test bins, cargo bench, run_db_tests         | init → bins → bench → run_db_tests sqlite                                                   |
| test_psql.sh                            | PostgreSQL tests                        | check_and_test_db                                  | init → check_and_test_db postgres                                                           |
| test_mysql.sh                           | MySQL tests                             | check_and_test_db                                  | init → check_and_test_db mysql                                                              |
| test_redis.sh                           | Redis-findex tests                      | variant guard, check_and_test_db                   | guard → check_and_test_db redis-findex                                                      |
| test_google_cse.sh                      | Google CSE tests                        | credential validation, targeted test               | validate env → cargo test (filter)                                                          |
| test_hsm.sh                             | Aggregate HSM tests                     | sequential backend scripts                         | softhsm2 → utimaco → proteccio                                                              |
| test_hsm_softhsm2.sh                    | SoftHSM2 tests                          | token init, cargo tests                            | prepare token → cargo test server + loader                                                  |
| test_hsm_utimaco.sh                     | Utimaco tests                           | simulator prep, cargo tests                        | prepare simulator → cargo test server + loader                                              |
| test_hsm_proteccio.sh                   | Proteccio tests                         | env prep, cargo tests                              | prepare env → cargo test server + loader                                                    |
| reinitialize_demo_kms.sh                | Demo VM key rotation                    | redis flush, key imports                           | flush redis → import keys                                                                   |
| docker-compose-authentication-tests.yml | TLS/auth test stack                     | service defs                                       | compose up → expose ports for tests                                                         |
| test_docker_image.sh                    | TLS & UI endpoint tests                 | openssl_test, test_tls_failure                     | install cli → docker compose up → openssl probes → curl UI                                  |
| cargo_build.ps1                         | Windows build & packaging               | BuildProject                                       | add target → set OpenSSL → cargo build → cargo packager → dumpbin check                     |
| cargo_test.ps1                          | Windows testing                         | TestProject                                        | add target → set env → cargo test workspace                                                 |

Cross-script relationships:

```text
nix.sh → test_*.sh → common.sh
nix.sh → package_* (in nix/scripts) → smoke tests
test_all.sh → test_sqlite.sh (+ conditional others)
test_hsm.sh → test_hsm_softhsm2.sh, test_hsm_utimaco.sh, test_hsm_proteccio.sh
build_ui_all.sh → build_ui.sh (twice)
release.sh → build_ui_all.sh → cargo build → update_readme_kmip.py → git cliff
```

## 4. Maintenance Guidelines

- Prefer `nix.sh` for routine tasks: consistent pinned environment.
- Update expected hashes only after reviewing legitimate binary changes.
- To add a new test type: create `test_<name>.sh` sourcing `common.sh`, then extend dispatch in
  `nix.sh` and optionally `test_all.sh`.
- Keep scripts side‑effect minimal; rely on Nix for purity.

## 5. Future Ideas

| Idea                                          | Benefit                 |
| --------------------------------------------- | ----------------------- |
| JSON summary output from `nix.sh`             | Easier CI parsing       |
| Script lint (shellcheck & shfmt) via Nix      | Uniform style           |
| Checksums for built UI bundles                | Detect accidental drift |
| Flags for HSM slot/user (instead of env only) | Clearer invocation      |

---
Generated to improve discoverability; keep synchronized with script changes.

### Build release non-FIPS

bash .github/scripts/nix.sh build --profile release --variant non-fips

### Run all tests (auto adds wget; HSM tests if Linux & release profile)

bash .github/scripts/nix.sh test all

# Google CSE tests (requires credentials)

```bash
TEST_GOOGLE_OAUTH_CLIENT_ID=... \
TEST_GOOGLE_OAUTH_CLIENT_SECRET=... \
TEST_GOOGLE_OAUTH_REFRESH_TOKEN=... \
GOOGLE_SERVICE_ACCOUNT_PRIVATE_KEY=... \
bash .github/scripts/nix.sh test google_cse
```

# Package both DEB and RPM (Linux) with FIPS

```bash
bash .github/scripts/nix.sh package
```

# Package non-FIPS RPM only

```bash
bash .github/scripts/nix.sh --variant non-fips package rpm
```

# macOS DMG

```bash
bash .github/scripts/nix.sh package dmg
```

## 2. The Role of Nix in Cosmian KMS

Nix underpins reproducibility, build consistency, and offline operation:

| Aspect                               | Nix Contribution                                        | Result                                                           |
| ------------------------------------ | ------------------------------------------------------- | ---------------------------------------------------------------- |
| Pinned nixpkgs (24.05)               | Ensures identical dependency graph across machines & CI | Bit‑for‑bit reproducible FIPS builds (non-FIPS: hash tracking)   |
| Pinned Rust toolchain (1.90.0)       | Removes rustup variability                              | Stable compiler + consistent warnings/clippy output              |
| Static OpenSSL 3.1.2 derivation      | Local tarball vendoring; no runtime dynamic linkage     | Security + portability; smoke tests verify version               |
| `installCheckPhase` hash enforcement | Compares built binary hash to expected file (Linux only)| Guards against accidental drift or supply chain change (FIPS)    |
| Prewarm + offline flags              | `prewarm_nixpkgs_and_tools`, Cargo offline cache        | Repeatable offline packaging after first warm run                |
| Single entrypoint script             | `nix.sh` & derivations unify workflows                  | Lower cognitive load; simpler CI matrix                          |
| Variant matrix (FIPS / non-FIPS)     | Feature flags from build env                            | Controlled cryptographic footprint                               |

**Note**: Only FIPS builds on Linux achieve bit-for-bit deterministic reproducibility. Non-FIPS builds use hash verification
for consistency tracking but may produce different binaries across build environments.

Workflow summary: After a single online run (optional), subsequent `package` invocations succeed with network disconnected
(given local OpenSSL tarball and Cargo registry cache), validating hermetic packaging.

## 3. Script Call Graph Overview

Below is a condensed view of each script's internal functions and external calls. (YAML file treated as configuration.)

| Script                                    | Purpose                                      | Key Functions / Steps                                                                                                                                 | Call Graph Summary                                                                                                       |
| ----------------------------------------- | -------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| `nix.sh`                                  | Unified build/test/package orchestrator      | `usage`, `resolve_pinned_nixpkgs_store`, `prewarm_nixpkgs_and_tools`                                                                                  | parse → map command → (package loop + smoke test) OR nix-shell exec.                                                     |
| `common.sh`                               | Shared helpers for test scripts              | `init_build_env`, `require_cmd`, `get_repo_root`, `setup_test_logging`, `_run_workspace_tests`, `run_db_tests`, `_wait_for_port`, `check_and_test_db` | test script sources → init_build_env → setup_test_logging → db checks → cargo test.                                      |
| `build_ui.sh`                             | Build WASM + web UI for chosen variant       | (argument parse, `wasm-pack build`, `npm install/build/lint/audit`)                                                                                   | parse variant → ensure Node/npm → install wasm-pack → build WASM → copy artifacts → build UI → deploy to server UI dir.  |
| `build_ui_all.sh`                         | Build both FIPS & non-FIPS UIs               | (calls `build_ui.sh` twice)                                                                                                                           | invoke build_ui.sh (fips) → add → invoke (non-fips) → add.                                                               |
| `release.sh`                              | Bump version & regenerate artifacts          | (gnu-sed detection, mass sed replace, `build_ui_all.sh`, `cargo build`, `update_readme_kmip.py`, `git cliff`)                                         | gather args → replace versions → rebuild UIs → cargo build → update KMIP README → generate changelog.                    |
| `test_all.sh`                             | Orchestrate running all test categories      | `run_step` (local) + sources `common.sh`                                                                                                              | init_build_env → run sqlite → if release: psql → mysql → conditional redis / google_cse / hsm.                           |
| `test_sqlite.sh`                          | SQLite tests                                 | sources `common.sh`                                                                                                                                   | init_build_env → setup logging → cargo test bins → cargo bench (no run) → run_db_tests sqlite.                           |
| `test_psql.sh`                            | PostgreSQL tests                             | sources `common.sh`                                                                                                                                   | init_build_env → check_and_test_db postgres.                                                                             |
| `test_mysql.sh`                           | MySQL tests                                  | sources `common.sh`                                                                                                                                   | init_build_env → check_and_test_db mysql.                                                                                |
| `test_redis.sh`                           | Redis-findex tests                           | sources `common.sh`                                                                                                                                   | init_build_env → variant guard → check_and_test_db redis-findex.                                                         |
| `test_google_cse.sh`                      | Google CSE tests                             | sources `common.sh`                                                                                                                                   | check required env vars → targeted cargo test (`test_google_cse`).                                                       |
| `test_hsm.sh`                             | Aggregates HSM backends                      | (calls three backend scripts)                                                                                                                         | sequential: softhsm2 → utimaco → proteccio.                                                                              |
| `test_hsm_softhsm2.sh`                    | SoftHSM2 tests                               | sources `common.sh`                                                                                                                                   | init_build_env → token init → cargo test server + loader.                                                                |
| `test_hsm_utimaco.sh`                     | Utimaco tests                                | sources `common.sh` + vendor prep                                                                                                                     | init_build_env → simulator prep → cargo test server + loader.                                                            |
| `test_hsm_proteccio.sh`                   | Proteccio tests                              | sources `common.sh` + vendor prep                                                                                                                     | init_build_env → env export → cargo test server + loader.                                                                |
| `reinitialize_demo_kms.sh`                | Demo VM periodic key initialization          | (redis-cli flush, cosmian CLI imports)                                                                                                                | flush redis → import Google CSE key → import Microsoft DKE keys.                                                         |
| `docker-compose-authentication-tests.yml` | Compose services for TLS/auth test scenarios | (service definitions)                                                                                                                                 | run docker compose → containers expose TLS endpoints for `test_docker_image.sh`.                                         |
| `test_docker_image.sh`                    | TLS & UI endpoint tests using built image    | `openssl_test`, `test_tls_failure` (local)                                                                                                            | install CLI → configure profiles → docker compose up → openssl probes → cosmian CLI key creation → endpoint curl checks. |
| `cargo_build.ps1`                         | Windows build & packaging script             | `BuildProject`                                                                                                                                        | add target → set OpenSSL → install cargo-packager → build + package → dumpbin check for static linkage.                  |
| `cargo_test.ps1`                          | Windows test script                          | `TestProject`                                                                                                                                         | add target → set logging + OpenSSL → cargo test workspace.                                                               |

### 3.1 Simplified Cross-Script Relationships

```
[nix.sh]
  ├─ test_* scripts
  │    └─ source common.sh → (functions) → cargo test
  ├─ package_* (in nix/scripts/) → smoke tests
  └─ build (nix/scripts/build.sh)

[test_all.sh] → test_sqlite.sh (+ optionally other test_* scripts)
[test_hsm.sh] → test_hsm_softhsm2.sh, test_hsm_utimaco.sh, test_hsm_proteccio.sh
[build_ui_all.sh] → build_ui.sh (twice)
[release.sh] → build_ui_all.sh, cargo build, update_readme_kmip.py
```

## 4. Maintenance Notes

- Prefer invoking `nix.sh` over individual test scripts directly in developer workflows for consistency.
- Update expected hashes only after intentional binary changes; verify with `cosmian_kms --info` locally.
- When adding a new test category: implement `test_<name>.sh` sourcing `common.sh`, extend dispatcher inside `nix.sh` and (optionally) `test_all.sh`.
- Keep script side-effects minimal; rely on Nix derivations for build purity and reproducibility.

## 5. Future Enhancements (Suggestions)

| Idea                                                            | Benefit                                |
| --------------------------------------------------------------- | -------------------------------------- |
| Add structured JSON summary output in `nix.sh` (e.g., `--json`) | Easier CI parsing & dashboards         |
| Integrate checksum validation for UI build artifacts            | Early detection of accidental UI drift |
| Add `shellcheck` & `shfmt` lint target via Nix                  | Consistent script hygiene              |
| Parameterize HSM slot/user via flags (instead of env only)      | Clearer invocation ergonomics          |

---
*Generated documentation to improve discoverability and onboarding. Keep this README aligned with changes in `nix.sh` and related test scripts.*
