---
name: mise
description: 'Create, modify, and refactor MISE task and library Bash scripts. Covers the full MISE conventions: task headers, USAGE framework, library sourcing, aggregator patterns, KMS server lifecycle, naming, and safety rules. Use when working on .mise/tasks/, .mise/lib/, or .mise/scripts/ files.'
---

# MISE Task & Library Conventions

Authoritative conventions for every Bash file under `.mise/`. Full reference:
`.github/instructions/mise.instructions.md`.

---

## Core principle — explore before writing

**Every new task or helper must start with an exploration step.** Never write a
function or a pattern before checking whether it already exists.

### Mandatory exploration checklist

Before creating a new task or library:

```bash
# 1. Scan existing libraries for the capability you need
grep -n "^[a-z_]+\(\)" .mise/lib/*.sh | grep -i "<keyword>"

# 2. Find similar tasks to use as templates
ls .mise/tasks/*/<pattern> 2>/dev/null

# 3. Check if common.sh already provides the function
grep "^[a-z_]*()" .mise/lib/common.sh
```

If the function exists → **use it**. If a similar task exists → **copy its
structure as a starting point**. Never start from an empty file.

---

## Task file structure (canonical)

```bash
#!/usr/bin/env bash
#MISE description="One-line human description"
#USAGE flag "-v --variant <variant>" env="VARIANT" help="FIPS variant" default="fips" {
#USAGE   choices "fips" "non-fips"
#USAGE }
#USAGE flag "-l --link <link>" env="LINK" help="Linkage type" default="static" {
#USAGE   choices "static" "dynamic"
#USAGE }
set -euo pipefail
source "${MISE_CONFIG_ROOT}/.mise/lib/common.sh"
kms_init_env "${usage_variant:-fips}" "${usage_link:-static}"

# ... task body ...

print_success "Task completed"
```

### Mandatory rules

| Rule | Why |
|------|-----|
| `set -euo pipefail` | No silent failures. Never omit. |
| Source via `"${MISE_CONFIG_ROOT}/.mise/lib/..."` | Never relative path or `$PWD` |
| Call `kms_init_env` after sourcing | Sets `VARIANT`, `LINK`, `FEATURES_FLAG`, etc. |
| Variables from `#USAGE` are `usage_<long_flag>` | `usage_variant`, `usage_release` — always default: `${usage_foo:-default}` |
| Never hard-code `--features non-fips` | Always use `"${FEATURES_FLAG[@]}"` |
| End with `print_success "..."` | CI log clarity |

---

## Minimize Bash LOC — patterns that shrink code

### 1. Wrapper tasks → `exec`

Instead of `bash ... && exit $?`, use `exec` (replaces shell, preserves exit code):

```bash
set -euo pipefail
exec bash "${MISE_CONFIG_ROOT}/.mise/tasks/test/mariadb" "$@"
```

### 2. Aggregator tasks → `run_step` + `FAILED=()`

Instead of `set -e` abort on first failure, collect failures and report at the end:

```bash
FAILED=()

run_step() {
  local name="$1"; shift
  print_status "Running: $name"
  if "$@"; then print_success "$name passed"
  else print_warning "$name FAILED (continuing...)"; FAILED+=("$name"); fi
}

run_step "sqlite" bash "${TASK_DIR}/sqlite" --variant "${VARIANT}" --link "${LINK}"

if [ ${#FAILED[@]} -gt 0 ]; then
  echo "FAILED steps: ${FAILED[*]}" >&2; exit 1
fi
print_success "All steps passed"
```

### 3. Database tests → `check_and_test_db` / `run_db_tests`

Never inline connection-string assembly. Use the library helpers:

```bash
# With port probe (skips silently if DB not reachable):
check_and_test_db "PostgreSQL" "postgresql" "PG_HOST" "PG_PORT"

# Without port probe (fails if DB unreachable):
run_db_tests "sqlite"
```

### 4. KMS lifecycle → `kms_server.sh` helpers

Never inline server startup/teardown:

```bash
source "${MISE_CONFIG_ROOT}/.mise/lib/kms_server.sh"

KMS_PORT=$(kms_pick_free_port)
kms_write_config "$KMS_PORT" "/tmp/kms-test-data"
kms_start    # sets $KMS_PID, $KMS_URL; registers EXIT trap to kms_stop
```

### 5. Feature flag propagation → `FEATURES_FLAG`

Never derive flags manually. Use the array `kms_init_env` sets:

```bash
kms_init_env "${usage_variant:-fips}" "${usage_link:-static}"
# Now use:
cargo build -p cosmian_kms_server ${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"}
```

When delegating to sub-tasks, always pass `--variant` and `--link`:

```bash
bash "${TASK_DIR}/sqlite" --variant "${VARIANT}" --link "${LINK}"
```

---

## Library files — guard pattern (mandatory)

Every `.mise/lib/*.sh` must prevent double-sourcing:

```bash
#!/usr/bin/env bash
# .mise/lib/my_lib.sh — <one-line purpose>
#
# Provides:
#   my_func_one  — <what it does>
#   my_func_two  — <what it does>

[ -n "${_MISE_MY_LIB_SH_LOADED:-}" ] && return 0
_MISE_MY_LIB_SH_LOADED=1

# Source dependencies (always guarded):
_MY_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -z "${_MISE_COMMON_SH_LOADED:-}" ]; then
  source "${_MY_LIB_DIR}/common.sh"
fi
```

---

## Shell safety rules

| Rule | Example |
|------|---------|
| Quote all expansions | `"$var"`, `"${arr[@]}"` |
| Safe empty arrays with `nounset` | `"${arr[@]+\"${arr[@]}\"}"` |
| Defaults with `:-` | `"${KMS_PORT:-9998}"` |
| Set-and-export with `:=` | `: "${REDIS_HOST:=127.0.0.1}"` |
| Local in functions | `local port="$1"` |
| Never `eval` | — |
| Never construct commands via string concat | Use arrays: `cmd "${args[@]}"` |
| Use `require_cmd` not `which`/`type -p` | `require_cmd cargo "Cargo is required"` |
| `run_isolated` for non-OpenSSL subprocesses | `run_isolated pnpm run build` |

---

## Naming conventions

| Scope | Convention | Example |
|-------|-----------|---------|
| Task files | `kebab-case`, no extension, `chmod +x` | `.mise/tasks/test/psql` |
| Library files | `snake_case.sh` | `.mise/lib/kms_server.sh` |
| Library functions | `snake_case`, prefixed by lib name | `kms_write_config` |
| Private functions | leading `_` | `_wait_for_port` |
| Guard variables | `_MISE_<LIB>_SH_LOADED` | `_MISE_COMMON_SH_LOADED` |
| Global script vars | `SCREAMING_SNAKE_CASE` | `FAILED=()`, `VARIANT` |
| Local vars | `snake_case` | `local port="$1"` |

---

## Library reference — what already exists

| Library | Key functions |
|---------|--------------|
| `.mise/lib/common.sh` | `print_header/status/warning/error/success/info`, `kms_init_env`, `require_cmd`, `get_repo_root`, `setup_test_logging`, `run_isolated`, `wait_for_port`, `compute_sha256`, `build_test_deps`, `run_db_tests`, `setup_db_env`, `check_and_test_db`, `kms_wait_ready` |
| `.mise/lib/kms_build.sh` | `kms_build_server`, `kms_build_cli`, `kms_build_all`, `get_kms_bin`, `get_ckms_bin`, `get_cargo_target_dir` |
| `.mise/lib/kms_server.sh` | `kms_write_config`, `kms_start`, `kms_start_from_bin`, `kms_stop`, `kms_write_ckms_conf`, `kms_pick_free_port`. Globals: `KMS_PID`, `KMS_URL`, `KMS_PORT` |
| `.mise/lib/pkcs11_helpers.sh` | PKCS#11 slot and object helpers |
| `.mise/lib/nix_helpers.sh` | Nix shell invocation, hash lookup |
| `.mise/lib/package_build.sh` | Deb/RPM build helpers |
| `.mise/lib/package_smoke.sh` | Smoke-test helpers for packages |
| `.mise/lib/softhsm2.sh` | SoftHSM2 token init/teardown, `run_db_softhsm2_tests` |
| `.mise/lib/k8s.sh` | Kubernetes helpers (helm, kubectl) |
| `.mise/lib/bench_helpers.sh` | Benchmark setup helpers |
| `.mise/lib/test_slots.sh` | Dynamic port-slot allocation |

**Always check these before writing a helper.** Never re-implement `wait_for_port`,
TCP probing, free-port allocation, or SHA-256 computation — all exist.

---

## USAGE framework reference

```bash
# Boolean flag (usage_release is "true"/"false")
#USAGE flag "-r --release" help="Build in release mode"

# Flag with constrained choices
#USAGE flag "-v --variant <variant>" env="VARIANT" help="FIPS variant" default="fips" {
#USAGE   choices "fips" "non-fips"
#USAGE }

# Positional argument
#USAGE arg "<old_version>" help="Current version (e.g. 5.22.0)"

# Optional CI toggle
#USAGE flag "--ci" help="Run in CI mode (skip interactive prompts)"
```

- `env="VAR"` makes the flag overridable as an environment variable.
- `default=` is preferred over runtime `${var:-fallback}` for static defaults.
- `choices { ... }` blocks are validated by MISE automatically.

---

## Workflow: adding a new task

1. **Explore**: `ls .mise/tasks/<group>/` — find a similar task as template.
2. **Check libraries**: `grep "<keyword>" .mise/lib/*.sh` — reuse existing helpers.
3. Create `.mise/tasks/<group>/<name>` (no extension, `chmod +x`).
4. Add header: `#!/usr/bin/env bash`, `#MISE description`, `#USAGE`, `set -euo pipefail`.
5. Source **only** the libraries you need; prefer the smallest set.
6. End with `print_success "..."` on the happy path.
7. If orchestrating sub-tasks, use the `run_step` + `FAILED=()` aggregator pattern.

## Workflow: adding a new library

1. **Explore**: `grep "<function_name>" .mise/lib/*.sh` — avoid duplicates.
2. Create `.mise/lib/<name>.sh` with the guard pattern (double-source prevention).
3. Add `# Provides:` comment listing exported functions.
4. Source `common.sh` if you need print helpers or environment functions.
5. Source other libs with the `${BASH_SOURCE[0]}` directory guard pattern.

## Workflow: refactoring to minimize LOC

1. **Inline single-use wrappers** — if a task just calls another with `exec`, that's already minimal. Do not add layers.
2. **Replace inline patterns with library calls** — e.g., inline `wait_for_port` loop → `wait_for_port` from `common.sh`.
3. **Consolidate repeated blocks** into a `run_step` loop if ≥ 3 sub-steps share the same call pattern.
4. **Remove dead code** — functions and variables not referenced anywhere under `.mise/`.
5. After refactoring: `shellcheck .mise/tasks/<name>` on the changed file.

---

## Full reference

`.github/instructions/mise.instructions.md` — complete specification with:
- KMS server lifecycle details
- Database test helpers and port probing
- `run_isolated` usage for non-OpenSSL subprocesses
- Directory variable reference (`MISE_CONFIG_ROOT`, `CARGO_TARGET_DIR`)
- Nix shell invocation patterns
- Library dependency management
