#!/usr/bin/env bash
# bench_run.sh — Build KMS + CLI, start a temporary server, run ckms bench
#               and write documentation to documentation/docs/benchmarks.md.
#
# Produces:
#   documentation/docs/benchmarks.md    (markdown benchmark report)
#
# Usage (from workspace root):
#   bash .github/scripts/benchmarks/bench_run.sh [--variant fips|non-fips]
#
# ENV (all optional):
#   VARIANT          fips or non-fips  (default: non-fips via init_build_env)
#   BENCH_MODE       all|encrypt|key-creation|sign-verify|batch  (default: all)
#   BENCH_SPEED      normal|quick|sanity  (default: quick)
#   BENCH_PORT       TCP port for the temporary KMS server  (default: 19996)
#   OUT_MD           Output markdown path  (default: documentation/docs/benchmarks.md)
#   CARGO_TARGET_DIR Override cargo target directory

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=.github/scripts/benchmarks/common.sh
source "${SCRIPT_DIR}/common.sh"

init_build_env "$@"
setup_test_logging

REPO_ROOT="$(get_repo_root "${SCRIPT_DIR}")"
cd "${REPO_ROOT}"

require_cmd cargo "Cargo is required to build and run benchmarks. Install Rust (rustup) and retry."

echo "========================================="
echo "  Benchmark Documentation Generator"
echo "========================================="

# ── Build server + CLI ───────────────────────────────────────────────────────
bench_build_binaries "$@"

# ── Temporary workspace ──────────────────────────────────────────────────────
TMP_DIR="$(mktemp -d)"
bench_register_cleanup

# ── Start KMS server (SQLite, plain HTTP) ────────────────────────────────────
BENCH_PORT="${BENCH_PORT:-19996}"
bench_start_server "${BENCH_PORT}" "${TMP_DIR}"

# ── Run benchmarks ───────────────────────────────────────────────────────────
BENCH_MODE="${BENCH_MODE:-all}"
BENCH_SPEED="${BENCH_SPEED:-quick}"

echo ""
echo "Running: ckms bench --mode ${BENCH_MODE} --speed ${BENCH_SPEED} --format markdown"
rm -rf target/criterion
"$CKMS_BIN" \
  --url "http://127.0.0.1:${BENCH_PORT}" \
  bench \
  --mode "${BENCH_MODE}" \
  --speed "${BENCH_SPEED}" \
  --format markdown

# ── Write documentation ──────────────────────────────────────────────────────
OUT_MD="${OUT_MD:-documentation/docs/benchmarks.md}"
CRITERION_MD="target/criterion/benchmarks.md"

bench_write_md "${OUT_MD}" "${BENCH_PORT}" "${CRITERION_MD}" "Benchmarks"

echo ""
echo "Benchmark documentation generated successfully."
