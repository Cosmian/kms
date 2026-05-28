#!/usr/bin/env bash
set -euo pipefail
set -x

# bench_ci.sh — Benchmark smoke-test and (optional) regression run.
#
# In CI this script:
#   1. Builds the KMS server + ckms CLI binaries.
#   2. Starts a KMS server (SQLite, plain HTTP) on a temporary port.
#   3. Runs `ckms bench --speed sanity --format json` to verify every benchmark
#      operation succeeds end-to-end.
#   4. Optionally saves/loads a named criterion baseline for comparison when
#      BENCH_SAVE_BASELINE or BENCH_LOAD_BASELINE env vars are set.
#   5. Stops the server and exits.
#
# For meaningful regression gates a stable, dedicated machine is required (see
# https://github.com/Cosmian/kms/issues/776).  The sanity run is always
# performed regardless of baseline settings.
#
# Environment variables (all optional):
#   BENCH_SAVE_BASELINE   Save criterion results under this baseline name.
#   BENCH_LOAD_BASELINE   Compare results against this previously saved baseline.
#   BENCH_SPEED           Speed mode passed to `ckms bench` (default: sanity).
#   BENCH_FORMAT          Output format passed to `ckms bench` (default: json).
#   BENCH_PORT            Port for the temporary KMS server (default: 19997).

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=.github/scripts/benchmarks/common.sh
source "${SCRIPT_DIR}/common.sh"

init_build_env "$@"
setup_test_logging
REPO_ROOT=$(get_repo_root "$SCRIPT_DIR")
cd "$REPO_ROOT"
require_cmd cargo "Cargo is required to build and run tests. Install Rust (rustup) and retry."

echo "========================================="
echo "Benchmarks"
echo "========================================="

# ── Build server + CLI ──────────────────────────────────────────────────────
bench_build_binaries

# ── Temporary workspace ─────────────────────────────────────────────────────
TMP_DIR=$(mktemp -d)
bench_register_cleanup

# ── Start KMS server (SQLite, plain HTTP) ───────────────────────────────────
BENCH_PORT="${BENCH_PORT:-19997}"
bench_start_server "${BENCH_PORT}" "${TMP_DIR}"

# ── Run benchmarks ───────────────────────────────────────────────────────────
BENCH_SPEED="${BENCH_SPEED:-sanity}"
BENCH_FORMAT="${BENCH_FORMAT:-json}"

BENCH_ARGS=(
  --url "http://127.0.0.1:${BENCH_PORT}"
  bench
  --speed "$BENCH_SPEED"
  --format "$BENCH_FORMAT"
)

if [ -n "${BENCH_SAVE_BASELINE:-}" ]; then
  BENCH_ARGS+=(--save-baseline "$BENCH_SAVE_BASELINE")
fi

if [ -n "${BENCH_LOAD_BASELINE:-}" ]; then
  BENCH_ARGS+=(--load-baseline "$BENCH_LOAD_BASELINE")
fi

echo "Running: ckms ${BENCH_ARGS[*]}"
"$CKMS_BIN" "${BENCH_ARGS[@]}"

echo "Benchmarks completed successfully."
