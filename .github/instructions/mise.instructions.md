---
name: 'MISE Task Conventions'
description: 'Best practices for writing MISE task scripts and shell libraries in the Cosmian KMS project'
applyTo: '.mise/**'
---

# MISE task and library conventions

## Task file structure

Every file under `.mise/tasks/` is an executable Bash script. The canonical header:

```bash
#!/usr/bin/env bash
#MISE description="One-line human description shown in mise tasks"
#USAGE flag "-v --variant <variant>" env="VARIANT" help="FIPS variant" default="fips" {
#USAGE   choices "fips" "non-fips"
#USAGE }
#USAGE flag "-l --link <link>" env="LINK" help="Linkage type" default="static" {
#USAGE   choices "static" "dynamic"
#USAGE }
set -euo pipefail
source "${MISE_CONFIG_ROOT}/.mise/lib/common.sh"
kms_init_env "${usage_variant:-fips}" "${usage_link:-static}"
```

Rules:

- `set -euo pipefail` is mandatory on every task file.
- Source `common.sh` via `"${MISE_CONFIG_ROOT}/.mise/lib/common.sh"` — never use a relative path or `$PWD`.
- Call `kms_init_env` immediately after sourcing `common.sh` for any task that touches build, variant, or linking.
- Variables injected by `#USAGE` are named `usage_<long_flag>` (e.g. `usage_variant`, `usage_release`).
  Always provide a safe default with `${usage_foo:-default}` in case the flag is absent.

## USAGE framework — flags and args

```bash
# Boolean flag (usage_release is "true" / "false")
#USAGE flag "-r --release" help="Build in release mode"

# Flag with a constrained choice list
#USAGE flag "-v --variant <variant>" env="VARIANT" help="FIPS variant" default="fips" {
#USAGE   choices "fips" "non-fips"
#USAGE }

# Positional argument
#USAGE arg "<old_version>" help="Current version (e.g. 5.22.0)"
#USAGE arg "<new_version>" help="New version (e.g. 5.23.0)"

# Optional flag (CI mode, extra toggle)
#USAGE flag "--ci" help="Run in CI mode (skip interactive prompts)"
```

- Declare `env="VAR"` on flags that should also be overridable as environment variables.
- Prefer `default=` over runtime `:-` fallbacks when the default is static.
- Use `choices` blocks to restrict accepted values; MISE validates them automatically.

## Variant / feature flag propagation

Use `kms_init_env` from `common.sh` — **never** re-derive `FEATURES_FLAG` inline:

```bash
kms_init_env "${usage_variant:-fips}" "${usage_link:-static}"

# FEATURES_FLAG is now ready to use:
cargo build -p cosmian_kms_server \
  ${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"} \
  "${CARGO_ARGS[@]}"
```

Pass `--variant` and `--link` when delegating to sub-tasks:

```bash
bash "${TASK_DIR}/sqlite" --variant "${VARIANT}" --link "${LINK}"
```

Never hard-code `--features non-fips`; always go through `FEATURES_FLAG`.

## Printing and user feedback

Use the helpers from `common.sh` — never use raw `echo` for status messages:

| Helper | Purpose |
|---|---|
| `print_header "…"` | Decorated section header (blue box) |
| `print_status "…"` | Info line `[INFO]` in green |
| `print_warning "…"` | Warning line `[WARN]` in yellow |
| `print_error "…"` | Error line `[ERROR]` in red + **exits** with code 1 |
| `print_success "…"` | Success line `[SUCCESS]` in green |
| `print_info "…"` | Info line `[i]` in blue |

Always end a successful task with `print_success "…"` so the CI log clearly marks completion.

## External commands

Check existence with `require_cmd` before use:

```bash
require_cmd cargo "Cargo is required to build test dependencies."
require_cmd curl  # uses the built-in default message when omitted
```

Never use `which` or `type -p`; they are not portable.

## Library sourcing and guard pattern

Every library under `.mise/lib/` must use a double-source guard:

```bash
[ -n "${_MISE_MY_LIB_SH_LOADED:-}" ] && return 0
_MISE_MY_LIB_SH_LOADED=1
```

Each library that depends on another must source it explicitly using its own `${BASH_SOURCE[0]}` directory:

```bash
_MY_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -z "${_MISE_COMMON_SH_LOADED:-}" ]; then
  source "${_MY_LIB_DIR}/common.sh"
fi
```

Never assume `common.sh` is already loaded; always guard the source.

## Available shared libraries — reuse before writing new code

| Library | What it provides |
|---|---|
| `.mise/lib/common.sh` | Colors, `print_*`, `kms_init_env`, `require_cmd`, `get_repo_root`, `setup_test_logging`, `run_isolated`, `wait_for_port`, `compute_sha256`, `build_test_deps`, `run_db_tests`, `setup_db_env`, `check_and_test_db`, `kms_wait_ready`, `pkcs11_check_warnings` |
| `.mise/lib/kms_build.sh` | `kms_build_server`, `kms_build_cli`, `kms_build_all`, `get_kms_bin`, `get_ckms_bin`, `get_cargo_target_dir` |
| `.mise/lib/kms_server.sh` | `kms_write_config`, `kms_start`, `kms_start_from_bin`, `kms_stop`, `kms_write_ckms_conf` + globals `KMS_PID`, `KMS_URL`, `KMS_PORT` |
| `.mise/lib/pkcs11_helpers.sh` | PKCS#11 slot and object helpers |
| `.mise/lib/nix_helpers.sh` | Nix shell invocation, hash lookup |
| `.mise/lib/package_build.sh` | Deb/RPM build helpers |
| `.mise/lib/package_smoke.sh` | Smoke-test helpers for packages |
| `.mise/lib/softhsm2.sh` | SoftHSM2 token init/teardown |
| `.mise/lib/k8s.sh` | Kubernetes helpers (helm, kubectl) |
| `.mise/lib/bench_helpers.sh` | Benchmark setup helpers |
| `.mise/lib/test_slots.sh` | Dynamic port-slot allocation |

**Always check these libraries first.** Do not re-implement `wait_for_port`, TCP probing,
free-port allocation, or SHA-256 computation — all three already exist.

## Aggregator tasks — collect failures, report at the end

For tasks that orchestrate multiple sub-steps, collect failures rather than aborting immediately:

```bash
FAILED=()

run_step() {
  local name="$1"
  shift
  print_status "Running: $name"
  if "$@"; then
    print_success "$name passed"
  else
    print_warning "$name FAILED (continuing...)"
    FAILED+=("$name")
  fi
}

run_step "sqlite"  bash "${TASK_DIR}/sqlite"  --variant "${VARIANT}" --link "${LINK}"
run_step "psql"    bash "${TASK_DIR}/psql"    --variant "${VARIANT}" --link "${LINK}"

if [ ${#FAILED[@]} -gt 0 ]; then
  echo '' >&2
  echo '============================================' >&2
  echo "  FAILED steps: ${FAILED[*]}" >&2
  echo '============================================' >&2
  exit 1
fi
print_success "All steps passed"
```

For conditional steps (FIPS-only, port-dependent):

```bash
if [ "${VARIANT}" = "non-fips" ]; then
  run_step "redis" bash "${TASK_DIR}/redis" --variant "${VARIANT}" --link "${LINK}"
fi
```

## Database test helpers

Use `setup_db_env` and `check_and_test_db` from `common.sh`; never inline connection-string assembly.

Port probe before running tests (instant, no retry loop):

```bash
port_open() {
  (exec 3<>"/dev/tcp/${1:-127.0.0.1}/$2") 2>/dev/null && {
    exec 3>&- 3<&-; return 0
  } || return 1
}

if ! port_open "127.0.0.1" "${KMS_SLOT_POSTGRES_PORT:-5432}"; then
  echo "[SKIP] PostgreSQL not reachable — start with: docker compose up -d postgres"
else
  run_db_tests "postgresql"
fi
```

Use the default ports from `common.sh` slot variables (`KMS_SLOT_POSTGRES_PORT`, `KMS_SLOT_REDIS_PORT`, etc.).

## KMS server lifecycle in tests

Always use `kms_server.sh` helpers; never inline server startup:

```bash
source "${MISE_CONFIG_ROOT}/.mise/lib/kms_server.sh"

KMS_PORT=$(kms_pick_free_port)
kms_write_config "$KMS_PORT" "/tmp/kms-test-data"
kms_start
# server PID is in $KMS_PID; URL in $KMS_URL
# kms_stop is registered via trap EXIT by kms_start
```

The `kms_start` function registers an `EXIT` trap that calls `kms_stop` automatically.
Do not register your own `EXIT` trap — append to it with `trap '…; kms_stop' EXIT` if needed.

## `run_isolated` — strip FIPS OpenSSL env from subprocesses

Commands that must not inherit the FIPS OpenSSL environment (pnpm, Python, curl):

```bash
run_isolated pnpm run build
run_isolated curl -sS http://127.0.0.1:9998/kmip/2_1
```

`run_isolated` strips `LD_PRELOAD`, `LD_LIBRARY_PATH`, `OPENSSL_CONF`, and `OPENSSL_MODULES`.

## Directory references

| Variable | Value / use |
|---|---|
| `MISE_CONFIG_ROOT` | Repository root (set by MISE) — use for all absolute paths inside scripts |
| `get_repo_root` | Function returning repo root via git or directory heuristic |
| `CARGO_TARGET_DIR` | Override via env; `get_cargo_target_dir` resolves it safely |

Never hard-code `/home/...` or relative `../../` paths. Always start from `${MISE_CONFIG_ROOT}`.

## Wrapper / alias tasks

A task that simply forwards to another task should use `exec` to replace the shell:

```bash
#!/usr/bin/env bash
#MISE description="Run MariaDB tests"
#USAGE flag "-v --variant <variant>" env="VARIANT" help="FIPS variant" default="fips" {
#USAGE   choices "fips" "non-fips"
#USAGE }
#USAGE flag "-l --link <link>" env="LINK" help="Linkage type" default="static" {
#USAGE   choices "static" "dynamic"
#USAGE }
set -euo pipefail
exec bash "${MISE_CONFIG_ROOT}/.mise/tasks/test/mariadb" "$@"
```

Using `exec` is cleaner than `bash … && exit $?` and preserves the exit code.

## Shell safety rules

- Always use `set -euo pipefail` — no exceptions.
- Quote all variable expansions: `"$var"`, `"${arr[@]}"`, `"${arr[@]+"${arr[@]}"}"`
  (the last form safely expands empty arrays with `nounset`).
- Prefer `local` for all function-internal variables.
- Use `:-` for safe defaults: `"${KMS_PORT:-9998}"`.
- Use `:=` to set-and-export defaults: `": ${REDIS_HOST:=127.0.0.1}"`.
- Never `eval`; never construct commands via string concatenation.

## Naming conventions

| Scope | Convention | Example |
|---|---|---|
| Task files | `kebab-case`, no extension | `.mise/tasks/test/psql` |
| Library files | `snake_case.sh` | `.mise/lib/kms_server.sh` |
| Library functions | `snake_case`, prefixed by lib name | `kms_write_config`, `kms_build_server` |
| Private (internal) functions | leading underscore | `_wait_for_port`, `_warn_system_kms_conf` |
| Guard variables | `_MISE_<LIB>_SH_LOADED` | `_MISE_COMMON_SH_LOADED` |
| Script variables | `SCREAMING_SNAKE_CASE` for globals | `FAILED=()`, `VARIANT` |
| Local variables | `snake_case` | `local port="$1"` |

## Adding a new library

1. Create `.mise/lib/<name>.sh` with the guard pattern.
2. Source `common.sh` if you need print helpers or environment functions.
3. Add a `# Provides:` comment block at the top listing exported functions.
4. Register the new library in the table above in this file.

## Adding a new task

1. Create `.mise/tasks/<group>/<name>` (no extension, executable: `chmod +x`).
2. Add the standard header (`#!/usr/bin/env bash`, `#MISE description`, `#USAGE …`, `set -euo pipefail`).
3. Source only the libraries you need; prefer the smallest set.
4. End with `print_success "…"` on the happy path.
5. If the task orchestrates sub-tasks, use the `run_step` aggregator pattern.
