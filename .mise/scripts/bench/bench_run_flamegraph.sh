#!/usr/bin/env bash
# bench_run_flamegraph.sh — Run the HTTP throughput CPU-scaling benchmark and produce
#                           per-worker-count flamegraph SVGs alongside a markdown report.
#
# The benchmark (`crate/test_kms_server/benches/http_throughput.rs`) starts its own
# in-process KMS server for each worker count, so no separate server process is needed.
#
# Produces:
#   target/flamegraphs/ecdsa_w<N>.svg               (one SVG per worker count)
#   target/criterion/KMS CPU Scaling/*/report/      (Criterion HTML report)
#   documentation/docs/certifications_and_compliance/cryptographic_algorithms/
#     benchmarks/cpu_scaling.md                     (updated with fresh results)
#
# Usage (from workspace root):
#   bash .github/scripts/benchmarks/bench_run_flamegraph.sh [--variant fips|non-fips]
#
# ENV (all optional):
#   VARIANT          fips or non-fips  (default: fips via init_build_env)
#   WORKER_COUNTS    Space-separated worker counts to sweep  (default: "1 2 4 8")
#   PROFILE_TIME     Seconds to record per flamegraph  (default: 15)
#   BENCH_OPERATION  Criterion bench filter for flamegraph  (default: "ECDSA P-256 sign")
#   OUT_MD           Output markdown path  (default: documentation/docs/…/cpu_scaling.md)
#   CARGO_TARGET_DIR Override cargo target directory
#   SKIP_FLAMEGRAPH  Set to 1 to skip flamegraph generation (throughput bench only)
#   SKIP_THROUGHPUT  Set to 1 to skip the throughput bench (flamegraphs only)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=.github/scripts/benchmarks/common.sh
source "${SCRIPT_DIR}/common.sh"

init_build_env "$@"
setup_test_logging

REPO_ROOT="$(get_repo_root "${SCRIPT_DIR}")"
cd "${REPO_ROOT}"

require_cmd cargo "Cargo is required. Install Rust (rustup) and retry."

CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${REPO_ROOT}/target}"
export CARGO_TARGET_DIR

WORKER_COUNTS="${WORKER_COUNTS:-1 2 4 8}"
PROFILE_TIME="${PROFILE_TIME:-15}"
BENCH_OPERATION="${BENCH_OPERATION:-ECDSA P-256 sign}"
SKIP_FLAMEGRAPH="${SKIP_FLAMEGRAPH:-0}"
SKIP_THROUGHPUT="${SKIP_THROUGHPUT:-0}"
OUT_MD="${OUT_MD:-documentation/docs/certifications_and_compliance/cryptographic_algorithms/benchmarks/cpu_scaling.md}"

echo "============================================================"
echo "  Cosmian KMS — CPU Scaling Flamegraph Benchmark"
echo "  Variant       : ${VARIANT}"
echo "  Worker counts : ${WORKER_COUNTS}"
echo "  Profile time  : ${PROFILE_TIME}s per worker count"
echo "  Operation     : ${BENCH_OPERATION}"
echo "============================================================"

# ── Detect OS — flamegraph requires Linux perf ───────────────────────────────
OS="$(uname -s)"
if [ "${OS}" != "Linux" ] && [ "${SKIP_FLAMEGRAPH}" != "1" ]; then
  echo "WARNING: flamegraph generation requires Linux perf. Disabling flamegraphs."
  SKIP_FLAMEGRAPH=1
fi

# ── Check / install prerequisites ────────────────────────────────────────────
if [ "${SKIP_FLAMEGRAPH}" != "1" ]; then
  if ! command -v perf >/dev/null 2>&1; then
    echo "ERROR: 'perf' not found. Install linux-perf (apt-get install linux-perf) and retry."
    echo "       Or set SKIP_FLAMEGRAPH=1 to run the throughput bench only."
    exit 1
  fi

  if ! cargo flamegraph --version >/dev/null 2>&1; then
    echo "cargo-flamegraph not found — installing..."
    cargo install flamegraph --locked
  fi

  # Relax perf permissions if needed (requires sudo; best-effort).
  PARANOID="$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo "2")"
  if [ "${PARANOID}" -gt "0" ]; then
    echo "Setting perf_event_paranoid to -1 (requires sudo)..."
    echo -1 | sudo tee /proc/sys/kernel/perf_event_paranoid >/dev/null
    echo 0   | sudo tee /proc/sys/kernel/kptr_restrict >/dev/null
  fi
fi

# ── Determine cargo feature flags ────────────────────────────────────────────
BENCH_FEATURES_ARGS=()
if [ -n "${FEATURES_FLAG[*]+x}" ] && [ "${#FEATURES_FLAG[@]}" -gt 0 ]; then
  BENCH_FEATURES_ARGS=("${FEATURES_FLAG[@]}")
fi

# ── Run throughput benchmark ──────────────────────────────────────────────────
THROUGHPUT_OUTPUT="${CARGO_TARGET_DIR}/http_throughput_bench.txt"

if [ "${SKIP_THROUGHPUT}" != "1" ]; then
  echo ""
  echo "── Running HTTP throughput benchmark ────────────────────────────────"
  echo "   (worker sweep: ${WORKER_COUNTS}; all three operations)"
  CARGO_PROFILE_BENCH_DEBUG=true \
  cargo bench \
    --bench http_throughput \
    -p test_kms_server \
    "${BENCH_FEATURES_ARGS[@]+"${BENCH_FEATURES_ARGS[@]}"}" \
    -- \
    --output-format bencher \
    2>&1 | tee "${THROUGHPUT_OUTPUT}"
  echo ""
  echo "    Throughput bench complete. Criterion HTML: ${CARGO_TARGET_DIR}/criterion/"
fi

# ── Run flamegraph per worker count ──────────────────────────────────────────
FLAMEGRAPH_DIR="${CARGO_TARGET_DIR}/flamegraphs"
mkdir -p "${FLAMEGRAPH_DIR}"

if [ "${SKIP_FLAMEGRAPH}" != "1" ]; then
  echo ""
  echo "── Generating flamegraphs ────────────────────────────────────────────"

  for workers in ${WORKER_COUNTS}; do
    SVG_OUT="${FLAMEGRAPH_DIR}/ecdsa_w${workers}.svg"
    BENCH_FILTER="${BENCH_OPERATION}/${workers} workers"
    echo ""
    echo "   Worker count: ${workers}  →  ${SVG_OUT}"
    CARGO_PROFILE_BENCH_DEBUG=true \
    cargo flamegraph \
      --bench http_throughput \
      -p test_kms_server \
      "${BENCH_FEATURES_ARGS[@]+"${BENCH_FEATURES_ARGS[@]}"}" \
      --output "${SVG_OUT}" \
      -- \
      --bench \
      "${BENCH_FILTER}" \
      --profile-time "${PROFILE_TIME}" \
      || echo "    WARNING: flamegraph for ${workers} workers failed (non-fatal)"
    if [ -f "${SVG_OUT}" ]; then
      echo "    Written: ${SVG_OUT}"
    fi
  done
fi

# ── Collect results for markdown ─────────────────────────────────────────────
BENCH_DATE="$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
LSCPU_OUTPUT="$(lscpu 2>/dev/null || echo "lscpu not available")"
KMS_VERSION="$(cargo metadata --no-deps --format-version 1 2>/dev/null \
  | python3 -c "import sys,json; pkgs=json.load(sys.stdin)['packages']; \
    print(next((p['version'] for p in pkgs if p['name']=='cosmian_kms_server'), 'unknown'))" \
  2>/dev/null || echo "unknown")"

# Build throughput table from bencher-format output (lines: "bench_name: iter ns/iter")
THROUGHPUT_TABLE=""
if [ -f "${THROUGHPUT_OUTPUT}" ]; then
  THROUGHPUT_TABLE="$(awk '
    /^test .* bench:/ {
      name = $2
      ns   = $4
      if (ns > 0) {
        # Throughput in req/s  ≈ 1e9 / ns  (bencher reports ns/iter; iter = 1 concurrent batch)
        rps = int(1e9 / ns)
        printf "| %s | %s |\n", name, rps
      }
    }
  ' "${THROUGHPUT_OUTPUT}" 2>/dev/null || true)"
fi

# Build flamegraph links section
FLAMEGRAPH_SECTION=""
if [ "${SKIP_FLAMEGRAPH}" != "1" ]; then
  FLAMEGRAPH_SECTION=$'\n## Flamegraphs\n\nGenerated by `cargo-flamegraph` / Linux `perf` during a `'"${PROFILE_TIME}"'`-second profiling window.\n\n'
  for workers in ${WORKER_COUNTS}; do
    SVG_OUT="${FLAMEGRAPH_DIR}/ecdsa_w${workers}.svg"
    if [ -f "${SVG_OUT}" ]; then
      FLAMEGRAPH_SECTION+="### ${workers} worker(s) — \`${BENCH_OPERATION}\`

![ flamegraph ${workers} workers](${SVG_OUT})

"
    fi
  done
fi

# ── Write documentation ───────────────────────────────────────────────────────
mkdir -p "$(dirname "${OUT_MD}")"
cat >"${OUT_MD}" <<MDEOF
# CPU Scaling & Flamegraph Analysis

> Generated on ${BENCH_DATE}
>
> KMS version: ${KMS_VERSION}
> Variant: ${VARIANT}

## Machine Info

\`\`\`
${LSCPU_OUTPUT}
\`\`\`

## Throughput Results

Benchmark: \`http_throughput\` Criterion bench, 16 concurrent tasks per iteration,
worker sweep: \`${WORKER_COUNTS}\`.

| Benchmark | ~req/s |
|-----------|--------|
${THROUGHPUT_TABLE:-| (run with SKIP_THROUGHPUT=0 to populate) | — |}

## How to Reproduce

\`\`\`bash
# Throughput only
bash .github/scripts/benchmarks/bench_run_flamegraph.sh --variant ${VARIANT}

# Flamegraph for 8 workers (requires Linux perf)
WORKER_COUNTS=8 bash .github/scripts/benchmarks/bench_run_flamegraph.sh --variant ${VARIANT}

# Skip flamegraph (throughput only)
SKIP_FLAMEGRAPH=1 bash .github/scripts/benchmarks/bench_run_flamegraph.sh
\`\`\`
${FLAMEGRAPH_SECTION}
MDEOF

echo ""
echo "Written: ${OUT_MD}"
echo ""
echo "CPU scaling flamegraph benchmark complete."
