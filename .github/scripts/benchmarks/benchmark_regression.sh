#!/usr/bin/env bash
# benchmark_regression.sh — Retrieve baseline benchmarks from package.cosmian.com,
# run the current branch's benchmarks, and fail if the average regression exceeds
# REGRESSION_THRESHOLD percent.
#
# Workflow:
#   a. Retrieve reference benchmarks from
#      https://package.cosmian.com/kms/<version>/benchmarks.json
#      (falls back gracefully if unavailable)
#   b. Build the KMS server + ckms CLI for the current git branch (release mode).
#   c. Start a temporary KMS server and run `ckms bench --format json`.
#   d. Compute per-benchmark regression:
#        delta% = (current_mean_ns - ref_mean_ns) / ref_mean_ns * 100
#   e. Compute the global average delta across all matched benchmarks.
#   f. If the average is > REGRESSION_THRESHOLD, print a detailed report and exit 1.
#
# Environment variables (all optional):
#   VARIANT              fips | non-fips (default: fips; affects FEATURES_FLAG)
#   BENCH_SPEED          Speed mode: sanity | quick | normal (default: quick)
#   BENCH_PORT           Port for the temporary KMS server (default: 19998)
#   REGRESSION_THRESHOLD Maximum allowed average regression in % (default: 10)
#   REFERENCE_URL        Override the reference benchmarks URL.
#   CARGO_TARGET_DIR     Override the cargo target directory.
#
# Requirements:
#   - cargo, curl, jq, bc

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../common.sh"

# ── Initialise build environment (VARIANT, FEATURES_FLAG) ──────────────────
init_build_env "$@"
setup_test_logging

REPO_ROOT=$(get_repo_root "$SCRIPT_DIR")
cd "$REPO_ROOT"

# ── Runtime dependencies ────────────────────────────────────────────────────
require_cmd cargo "Cargo is required to build the KMS server and ckms CLI."
require_cmd curl  "curl is required to download the reference benchmarks."
require_cmd jq    "jq is required to parse benchmark JSON results."
require_cmd bc    "bc is required to compute regression percentages."

# ── Configuration ───────────────────────────────────────────────────────────
BENCH_SPEED="${BENCH_SPEED:-quick}"
BENCH_PORT="${BENCH_PORT:-19998}"
REGRESSION_THRESHOLD="${REGRESSION_THRESHOLD:-10}"

# Derive the KMS version from the workspace Cargo.toml.
KMS_VERSION=$(cargo metadata --no-deps --format-version 1 \
  | jq -r '.packages[] | select(.name == "cosmian_kms_server") | .version' \
  | head -1)
if [ -z "$KMS_VERSION" ]; then
  # Fallback: parse Cargo.toml directly.
  KMS_VERSION=$(grep -m1 '^version' "$REPO_ROOT/Cargo.toml" | sed 's/.*= *"\(.*\)"/\1/')
fi

REFERENCE_URL="${REFERENCE_URL:-https://package.cosmian.com/kms/${KMS_VERSION}/benchmarks.json}"

CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$REPO_ROOT/target}"
KMS_BIN="$CARGO_TARGET_DIR/release/cosmian_kms"
CKMS_BIN="$CARGO_TARGET_DIR/release/ckms"

# ── Temporary workspace ─────────────────────────────────────────────────────
TMP_DIR=$(mktemp -d)
KMS_PID=""

_cleanup() {
  if [ -n "${KMS_PID:-}" ]; then
    kill "$KMS_PID" 2>/dev/null || true
    wait "$KMS_PID" 2>/dev/null || true
  fi
  rm -rf "${TMP_DIR:-}"
}
trap _cleanup EXIT

REFERENCE_JSON="$TMP_DIR/reference.json"
CURRENT_JSON="$TMP_DIR/current.json"

echo "======================================================="
echo " Cosmian KMS Benchmark Regression Analysis"
echo "======================================================="
echo " Version       : ${KMS_VERSION}"
echo " Variant       : ${VARIANT}"
echo " Bench speed   : ${BENCH_SPEED}"
echo " KMS port      : ${BENCH_PORT}"
echo " Threshold     : ${REGRESSION_THRESHOLD}%"
echo " Reference URL : ${REFERENCE_URL}"
echo "======================================================="

# ── (a) Retrieve reference benchmarks ───────────────────────────────────────
echo ""
echo "[a] Downloading reference benchmarks..."
REFERENCE_AVAILABLE=false
if curl -fsSL --max-time 30 -o "$REFERENCE_JSON" "$REFERENCE_URL" 2>/dev/null; then
  BENCHMARK_COUNT=$(jq '.benchmarks | length' "$REFERENCE_JSON" 2>/dev/null || echo 0)
  if [ "$BENCHMARK_COUNT" -gt 0 ]; then
    echo "    Downloaded ${BENCHMARK_COUNT} benchmarks from ${REFERENCE_URL}"
    REFERENCE_AVAILABLE=true
  else
    echo "    WARNING: Downloaded file is empty or has no benchmarks; skipping regression."
  fi
else
  echo "    WARNING: Could not download reference benchmarks from ${REFERENCE_URL}."
  echo "             Proceeding without regression analysis (benchmarks will still run)."
fi

# ── (b) Build server + CLI (release) ────────────────────────────────────────
echo ""
echo "[b] Building cosmian_kms server and ckms CLI (release)..."
cargo build --release \
  -p cosmian_kms_server \
  -p ckms \
  "${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"}"
echo "    Build complete."

# ── Start KMS server (SQLite, plain HTTP) ───────────────────────────────────
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

echo ""
echo "[b] Starting KMS server on port ${BENCH_PORT}..."
"$KMS_BIN" --config "$KMS_CONF" >"$TMP_DIR/kms.log" 2>&1 &
KMS_PID=$!

kms_wait_ready "http://127.0.0.1:${BENCH_PORT}/kmip/2_1" "$KMS_PID" "$TMP_DIR/kms.log" 60
echo "    KMS server ready (PID ${KMS_PID})."

# ── (c) Run current-branch benchmarks ───────────────────────────────────────
echo ""
echo "[c] Running benchmarks (speed=${BENCH_SPEED})..."
"$CKMS_BIN" \
  --url "http://127.0.0.1:${BENCH_PORT}" \
  bench \
  --speed "$BENCH_SPEED" \
  --format json \
  >/dev/null  # JSON is written to target/criterion/benchmarks.json

# Copy the generated file to our temp workspace.
CRITERION_JSON="${CARGO_TARGET_DIR}/criterion/benchmarks.json"
if [ ! -f "$CRITERION_JSON" ]; then
  echo "ERROR: Expected benchmark results file not found: ${CRITERION_JSON}"
  exit 1
fi
cp "$CRITERION_JSON" "$CURRENT_JSON"
CURRENT_COUNT=$(jq '.benchmarks | length' "$CURRENT_JSON")
echo "    Collected ${CURRENT_COUNT} benchmarks."

# Stop the KMS server now (we no longer need it).
kill "$KMS_PID" 2>/dev/null || true
wait "$KMS_PID" 2>/dev/null || true
KMS_PID=""

# ── (d–f) Regression analysis ───────────────────────────────────────────────
if [ "$REFERENCE_AVAILABLE" = false ]; then
  echo ""
  echo "[d] Reference benchmarks unavailable — skipping regression analysis."
  echo "    Benchmarks ran successfully."
  exit 0
fi

echo ""
echo "[d] Comparing benchmarks against reference..."

# Build a lookup: id -> mean estimate (ns) from the reference JSON.
# Output: one line per match: "id|ref_mean|cur_mean|delta%"
COMPARISON=$(jq -r --slurpfile ref "$REFERENCE_JSON" '
  # Build reference lookup as object: id -> mean estimate
  ($ref[0].benchmarks | map({ (.id): .mean.estimate }) | add) as $ref_map |
  .benchmarks[]
  | . as $b
  | if ($ref_map | has($b.id)) then
      ($ref_map[$b.id]) as $ref_mean |
      ($b.mean.estimate)      as $cur_mean |
      if $ref_mean > 0 then
        (($cur_mean - $ref_mean) / $ref_mean * 100) as $delta |
        "\($b.id)|\($ref_mean)|\($cur_mean)|\($delta)"
      else empty end
    else empty end
' "$CURRENT_JSON")

if [ -z "$COMPARISON" ]; then
  echo "    WARNING: No benchmark IDs matched between reference and current run."
  echo "             Cannot perform regression analysis."
  exit 0
fi

MATCHED=0
TOTAL_DELTA=0
REGRESSIONS=0

# Print a header.
echo ""
printf "%-60s %12s %12s %8s\n" "Benchmark" "Ref (µs)" "Current (µs)" "Delta%"
printf '%.0s-' {1..96}
echo

while IFS='|' read -r id ref_mean cur_mean delta; do
  MATCHED=$((MATCHED + 1))
  TOTAL_DELTA=$(echo "$TOTAL_DELTA + $delta" | bc)

  # Convert ns → µs for display.
  ref_us=$(echo "scale=2; $ref_mean / 1000" | bc)
  cur_us=$(echo "scale=2; $cur_mean / 1000" | bc)

  # Flag regressions (delta > threshold).
  flag=""
  regression_check=$(echo "$delta > $REGRESSION_THRESHOLD" | bc)
  if [ "$regression_check" -eq 1 ]; then
    REGRESSIONS=$((REGRESSIONS + 1))
    flag=" <<"
  fi

  printf "%-60s %12s %12s %7.1f%%%s\n" "$id" "$ref_us" "$cur_us" "$delta" "$flag"
done <<< "$COMPARISON"

printf '%.0s-' {1..96}
echo

# ── (e) Average global performance ──────────────────────────────────────────
AVG_DELTA=$(echo "scale=2; $TOTAL_DELTA / $MATCHED" | bc)
echo ""
echo "  Matched benchmarks      : ${MATCHED}"
echo "  Regressions (>${REGRESSION_THRESHOLD}%)    : ${REGRESSIONS}"
echo "  Average delta           : ${AVG_DELTA}%"

# ── (f) Fail if average regression > threshold ──────────────────────────────
FAIL=$(echo "$AVG_DELTA > $REGRESSION_THRESHOLD" | bc)
echo ""
if [ "$FAIL" -eq 1 ]; then
  echo "FAIL: Average regression ${AVG_DELTA}% exceeds threshold ${REGRESSION_THRESHOLD}%."
  echo "      This indicates a significant performance regression on the current branch."
  exit 1
else
  echo "PASS: Average regression ${AVG_DELTA}% is within the ${REGRESSION_THRESHOLD}% threshold."
fi
