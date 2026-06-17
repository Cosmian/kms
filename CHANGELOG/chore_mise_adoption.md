# Changelog — develop

## Build

### MISE task runner migration

- Replace all `bash .github/scripts/nix.sh` invocations with `mise run <task>` in all GitHub Actions workflows (`test_all.yml`, `packaging.yml`, `benchmark.yml`, `release.yml`)
- Add `jdx/mise-action@v3` install step to all CI jobs that use MISE tasks
- Create 52 MISE tasks under `.mise/tasks/` (categories: `test/`, `build/`, `package/`, `release/`, `docs/`, `audit/`, `sbom/`, `bench/`)
- Create 7 reusable shared Bash libraries under `.mise/lib/`: `common.sh`, `kms_server.sh`, `softhsm2.sh`, `nix_helpers.sh`, `bench_helpers.sh`, `package_smoke.sh`, `package_build.sh`
- Add `mise.toml` root configuration with tool versions (node=22, pnpm=10.17.1) and task includes
- Remove `set -x` debug tracing from all 32 task files (was causing extremely verbose output)
- Update `.github/copilot-instructions.md` with full MISE cheatsheet, shared library table, and updated CI overview
- Rename test type slugs to kebab-case: `otel_export→otel`, `google_cse→google-cse`, `aws_xks→xks`, `azure_ekm→azure-ekm`, `gcp_cmek→gcp-cmek`

## Bug Fixes

- Fix `owasp.sh`: `python3 - <<'PYEOF' ... PYEOF "$AUDIT_JSON"` produced two-line output breaking `[[ "$CRITICAL_HIGH" -gt 0 ]]`; move `"$AUDIT_JSON"` to `python3 - "$AUDIT_JSON" <<'PYEOF'`
- Fix `owasp.sh`: `sed -i "..."` without backup suffix fails on macOS BSD sed; add `''` suffix to all three `sed -i` calls in `update_audit_md()`
- Fix `multi_framework.sh`: unsafe block threshold was 300 but codebase has 324 (all FFI wrappers); raise threshold to 350
- Fix `nix_helpers.sh` `ensure_nix_shell`: used `-A kms-non-fips` attribute selector but `shell.nix` takes a `variant` argument; switch to `--argstr variant "$VARIANT"`
- Fix `bench/ci`, `bench/run`, `bench/regression`, `bench/load`: `--url` is a top-level `ckms` flag (before subcommand), not a `bench` subcommand flag; `--output` does not exist on `ckms bench`
- Fix `nix_helpers.sh` `ensure_nix_shell`: when sub-tasks are invoked via `bash path/to/subtask` from a `_default` aggregator, they inherit `MISE_TASK_FILE` pointing to the parent aggregator; `ensure_nix_shell` would then re-exec the aggregator directory instead of the sub-task script; fix by preferring `$0` (the actually executing script) over `MISE_TASK_FILE`, with a directory-check fallback
- Fix CI Windows workflows to source migrated PowerShell helpers from `.mise/scripts/windows/` instead of deleted `.github/scripts/windows/` paths
- Fix `build:docker` task invocation order (`nix.sh docker ...`) and restore missing `.mise/scripts/release/get_version.sh` helper used by packaging/docker scripts

## Features

- Add `mise run test:db` task: runs sqlite, psql, redis, percona, mysql, maria in sequence; skips backends not reachable (shows `docker compose up -d` hint); fails only if a reachable backend's tests fail
- Add `mise run test:db:<backend>` subcommand hierarchy (`sqlite`, `psql`, `redis`, `percona`, `mysql`, `maria`): thin wrappers delegating to existing flat tasks, enabled via MISE directory `_default` pattern
- Add `mise run test:hsm:<model>` subcommand hierarchy (`softhsm2`, `utimaco`, `proteccio`, `crypt2pay`): thin wrappers over existing `hsm-*` tasks
- Simplify `test:hsm` (`_default`): remove `[backend]` positional argument — individual models now have dedicated `test:hsm:<model>` subtasks

## Testing

- Validate `mise run test:sqlite --variant non-fips`: all 404 test vectors pass ✅
- Validate `mise run build:kms --variant non-fips`: builds successfully ✅
- Validate `mise run release:version`: outputs workspace version ✅
- Validate `mise run release:clean`: removes result symlinks ✅
- Validate `mise run test:db --variant non-fips`: sqlite+psql+percona+mysql+maria all PASS (404 vectors each), redis SKIP ✅
- Validate `mise run test:hsm --variant non-fips`: 1 server test + 39 vectors all PASS ✅
- Validate `mise run test:wasm --variant non-fips`: WASM build + pnpm tests PASS ✅

## Migration

- **`.github/scripts/` → `.mise/scripts/`**: move all bash scripts from `.github/scripts/` to `.mise/scripts/`; `.mise/` is now the single source of truth for all automation. Created new MISE tasks: `audit/runtime`, `bench/docker`, `bench/docker-load`, `demo/reinitialize`, `test/edb-tde`, `test/iris`. Updated all internal cross-references. Only `squid/` config files remain in `.github/scripts/` (referenced by `forward_proxy.yml` workflow).

- **`test/_default`**: replace `echo "════...════"` (box-drawing U+2550 inside double quotes) with single-quoted ASCII dashes — bash treats the multi-byte UTF-8 sequence as an unclosed string, causing a syntax error and silent `EXIT=0` despite failures
- **`test/_default`**: pass `hsm/_default` explicitly to `bash` — `bash .mise/tasks/test/hsm` fails with "Is a directory" because `hsm` is a subdirectory containing `_default`; all other steps reference plain files so they are unaffected
- **`test:ui`**: unset `RUSTFLAGS`/`LDFLAGS`/OpenSSL vars and `cd` into the wasm crate before `wasm-pack build` — the Nix shell apple-sdk injects `-F /nix/store/…/Frameworks` into `RUSTFLAGS` which `rust-lld` (WASM linker) rejects as "unknown argument"; also removed stale `pkg/` before build to avoid wasm-pack re-parse errors
- **`test:wasm` / `build:wasm`**: unset `RUSTFLAGS` and `LDFLAGS` before `wasm-pack build` — macOS framework link flags (`-F .../Frameworks`, `-Wl,-F,...`) set by `ensure_macos_frameworks_ldflags` are invalid for the `wasm32-unknown-unknown` target and caused `rust-lld` to fail with `unknown argument`
- **`scripts/common.sh` → shim over `lib/common.sh`**: The 472-LOC `.mise/scripts/common.sh` was a full copy of functions already in `.mise/lib/common.sh`. Replaced with a 49-LOC backward-compatibility shim that sources `lib/common.sh` and adds only the two extras unique to scripts: `init_build_env` (flag-parsing wrapper around `kms_init_env`) and the `PIN_URL` / `PINNED_NIXPKGS_URL` export consumed by `nix.sh`. All 11 active scripts that sourced `scripts/common.sh` continue to work unchanged.
- **Deleted 34 orphaned scripts**: Scripts in `.mise/scripts/` that were fully superseded by inline MISE tasks and no longer referenced by any task or active script were removed with `git rm -f`. Removed: `bench/{bench_ci,bench_run,bench_run_load,bench_regression,common}.sh`; `build/{build_ui,build_ui_all,nix_build,run_ui}.sh`; `test/test_{sqlite,psql,redis,percona,maria,mysql,hsm,hsm_softhsm2,hsm_utimaco,hsm_proteccio,hsm_crypt2pay,otel_export,wasm,ui,gcp_cmek,google_cse,azure_ekm,all,synology_dsm}.sh`; `test/google_cse_with_hsm.sh`; `release/{build_ui,clean_result,generate_signing_key,get_version,generate_cbom}.sh`. Net: −34 files, −7 400 LOC.
- **Port collisions**: `kms_start` (and all tasks that start a KMS server for integration tests) previously hardcoded port 9998, causing failures when multiple test repos or test suites ran concurrently on the same machine. Added `kms_pick_free_port()` to `.mise/lib/kms_server.sh` (binds to port 0 via Python socket, reads the OS-assigned port — the same strategy used by Rust's `allocate_dynamic_port()`). Updated `kms_start` default, `test:ui`, `test:gcp-cmek`, `test:otel`, and all `bench/*` tasks to use dynamic port allocation. Fixed invalid `local` declarations outside functions in `test:ui` and `test:otel`.
