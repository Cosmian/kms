#!/usr/bin/env bash
# bench_run_load.sh — Build KMS + CLI, start a temporary server, run ckms bench --load
#                     and write documentation to documentation/docs/benchmarks_load_tests.md.
#
# Produces:
#   documentation/docs/benchmarks_load_tests.md    (load test benchmark report)
#   documentation/docs/benchmarks_load_tests.html  (gnuplot HTML report, if gnuplot installed)
#
# Usage (from workspace root):
#   bash .github/scripts/benchmarks/bench_run_load.sh [--variant fips|non-fips]
#
# ENV (all optional):
#   VARIANT          fips or non-fips  (default: fips via init_build_env)
#   BENCH_MODE       all|encrypt|key-creation|sign-verify|batch  (default: all)
#   BENCH_TIME       Time in seconds per concurrency level  (default: 5)
#   BENCH_CONCURRENCY Comma-separated concurrency levels  (default: 1,2,4,8,16,32)
#   BENCH_PORT       TCP port for the temporary KMS server  (default: 19995)
#   OUT_MD           Output markdown path  (default: documentation/docs/benchmarks_load_tests.md)
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

echo "============================================================"
echo "  Cosmian KMS — Load Test Benchmark Documentation Generator"
echo "  Variant : ${VARIANT}"
echo "============================================================"

# ── Build server + CLI ───────────────────────────────────────────────────────
bench_build_binaries

# ── Temporary workspace ──────────────────────────────────────────────────────
TMP_DIR="$(mktemp -d)"
bench_register_cleanup

# ── Start KMS server (SQLite, plain HTTP) ────────────────────────────────────
BENCH_PORT="${BENCH_PORT:-19995}"
bench_start_server "${BENCH_PORT}" "${TMP_DIR}"

# ── Run load benchmarks (markdown) ───────────────────────────────────────────
BENCH_MODE="${BENCH_MODE:-all}"
BENCH_TIME="${BENCH_TIME:-5}"
BENCH_CONCURRENCY="${BENCH_CONCURRENCY:-1,2,4,8,16,32}"

echo ""
echo "Running: ckms bench --load --mode ${BENCH_MODE} --time ${BENCH_TIME} --format markdown"
rm -f target/criterion/benchmarks_load_tests.md
"${CKMS_BIN}" \
  --url "http://127.0.0.1:${BENCH_PORT}" \
  bench \
  --load \
  --mode "${BENCH_MODE}" \
  --time "${BENCH_TIME}" \
  --load-concurrency "${BENCH_CONCURRENCY}" \
  --format markdown

CRITERION_MD="target/criterion/benchmarks_load_tests.md"
echo "    Load test benchmarks complete."

# ── Run HTML report (optional — requires gnuplot) ────────────────────────────
OUT_MD="${OUT_MD:-documentation/docs/benchmarks_load_tests.md}"
CRITERION_HTML="target/criterion/load-report/index.html"
OUT_HTML="${OUT_MD%.md}.html"

if command -v gnuplot >/dev/null 2>&1; then
  echo ""
  echo "Running: ckms bench --load --mode ${BENCH_MODE} --format html"
  rm -rf target/criterion/load-report
  set +e
  "${CKMS_BIN}" \
    --url "http://127.0.0.1:${BENCH_PORT}" \
    bench \
    --load \
    --mode "${BENCH_MODE}" \
    --time "${BENCH_TIME}" \
    --load-concurrency "${BENCH_CONCURRENCY}" \
    --format html
  html_exit=$?
  set -e
  if [ "${html_exit}" -eq 0 ] && [ -f "${CRITERION_HTML}" ]; then
    mkdir -p "$(dirname "${OUT_HTML}")"
    cp "${CRITERION_HTML}" "${OUT_HTML}"
    echo "    Written: ${OUT_HTML}"
  else
    echo "    WARNING: HTML report generation failed (exit ${html_exit})"
  fi
else
  echo ""
  echo "    INFO: gnuplot not found — skipping HTML report generation."
fi

# ── Write documentation ───────────────────────────────────────────────────────
bench_write_md "${OUT_MD}" "${BENCH_PORT}" "${CRITERION_MD}" "Load Test Benchmarks"

echo ""
echo "Load benchmark documentation generated successfully."
