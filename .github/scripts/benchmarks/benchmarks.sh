#!/usr/bin/env bash
set -euo pipefail
set -x

# Benchmark smoke-test and (optional) regression run.
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
source "${SCRIPT_DIR}/../common.sh"

init_build_env "$@"
setup_test_logging

require_cmd cargo "Cargo is required to build and run tests. Install Rust (rustup) and retry."

echo "========================================="
echo "Benchmarks"
echo "========================================="

# ── Build server + CLI ──────────────────────────────────────────────────────
echo "Building cosmian_kms server and ckms CLI..."
cargo build -p cosmian_kms_server -p ckms "${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"}"

CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
KMS_BIN="$CARGO_TARGET_DIR/debug/cosmian_kms"
CKMS_BIN="$CARGO_TARGET_DIR/debug/ckms"

# ── Temporary workspace ─────────────────────────────────────────────────────
TMP_DIR=$(mktemp -d)
KMS_PID=""

_cleanup_bench() {
  [ -n "${KMS_PID:-}" ] && {
    kill "$KMS_PID" 2>/dev/null || true
    wait "$KMS_PID" 2>/dev/null || true
  }
  rm -rf "${TMP_DIR:-}"
}
trap _cleanup_bench EXIT

# ── Start KMS server (SQLite, plain HTTP) ───────────────────────────────────
BENCH_PORT="${BENCH_PORT:-19997}"
SQLITE_PATH="$TMP_DIR/kms-data"
KMS_CONF="$TMP_DIR/kms.toml"

cat >"$KMS_CONF" <<KMS_CONF_EOF
[db]
database_type = "sqlite"
sqlite_path = "${SQLITE_PATH}"

[http]
hostname = "0.0.0.0"
port = ${BENCH_PORT}
KMS_CONF_EOF

echo "Starting KMS server on port ${BENCH_PORT}..."
"$KMS_BIN" --config "$KMS_CONF" >"$TMP_DIR/kms.log" 2>&1 &
KMS_PID=$!

kms_wait_ready "http://127.0.0.1:${BENCH_PORT}/kmip/2_1" "$KMS_PID" "$TMP_DIR/kms.log" 60

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
