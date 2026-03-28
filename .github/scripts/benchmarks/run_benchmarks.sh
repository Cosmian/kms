#!/usr/bin/env bash
# run_benchmarks.sh — Start a KMS server, run ckms bench and generate documentation.
#
# Produces:
#   documentation/docs/benchmarks.md                (REST/HTTP benchmark results)
#
# Usage (from workspace root):
#   bash scripts/run_benchmarks.sh
#
# OPTIONS (environment variables):
#   KMS_BIN     Path to the KMS server binary  (default: target/release/cosmian_kms)
#   KMS_CONF    Path to KMS server config      (default: test_data/configs/server/test/auth_https.toml)
#   CKMS_CONF   Path to ckms CLI config        (default: test_data/configs/client/test/auth_https_owner.toml)
#   EXTRA_ARGS  Extra arguments passed to ckms bench (default: "")
#   CKMS_CARGO_ARGS Extra args passed to cargo run for ckms
#                   (default: "--release --features non-fips")
#
# Requirements:
#   - Both binaries built: cargo build --release --features non-fips

set -euo pipefail

KMS_BIN="${KMS_BIN:-target/release/cosmian_kms}"
KMS_CONF="${KMS_CONF:-test_data/configs/server/test/auth_https.toml}"
CKMS_CONF="${CKMS_CONF:-test_data/configs/client/test/auth_https_owner.toml}"
BENCH_MODE="${BENCH_MODE:-all}"
EXTRA_ARGS_STR="${EXTRA_ARGS:---speed quick}"
read -r -a EXTRA_ARGS <<<"${EXTRA_ARGS_STR}"
CKMS_CARGO_ARGS_STR="${CKMS_CARGO_ARGS:---release --features non-fips}"
read -r -a CKMS_CARGO_ARGS <<<"${CKMS_CARGO_ARGS_STR}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
cd "${ROOT_DIR}"

OUT_REST_MD="documentation/docs/benchmarks.md"
KMS_PID=""

cleanup() {
    if [ -n "${KMS_PID}" ] && kill -0 "${KMS_PID}" 2>/dev/null; then
        echo "Stopping KMS server (PID ${KMS_PID})…"
        kill "${KMS_PID}" 2>/dev/null || true
        wait "${KMS_PID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "============================================================"
echo "  Cosmian KMS benchmark runner (ckms bench)"
echo "  CLI run    : cargo run -p ckms ${CKMS_CARGO_ARGS_STR}"
echo "  KMS binary : ${KMS_BIN}"
echo "  KMS config : ${KMS_CONF}"
echo "  CLI config : ${CKMS_CONF}"
echo "  Bench mode : ${BENCH_MODE}"
echo "  Extra args : ${EXTRA_ARGS_STR:-<none>}"
echo "============================================================"

# ─── Check binaries ──────────────────────────────────────────────────────────
for bin in ${KMS_BIN}; do
    if [ ! -x "${bin}" ]; then
        echo "ERROR: ${bin} not found or not executable."
        echo "Build with: cargo build --release --features non-fips"
        exit 1
    fi
done
if ! command -v cargo >/dev/null 2>&1; then
    echo "ERROR: cargo is required but was not found in PATH."
    exit 1
fi
if [ ! -f "${KMS_CONF}" ]; then
    echo "ERROR: KMS config not found: ${KMS_CONF}"
    exit 1
fi

# ─── Start KMS server ────────────────────────────────────────────────────────
echo ""
echo "[1/3] Starting KMS server…"
"${KMS_BIN}" --config "${KMS_CONF}" &
KMS_PID=$!

# Detect HTTP port from config (macOS-compatible: avoid grep -P)
KMS_PORT="$(grep -A2 '^\[http\]' "${KMS_CONF}" | awk -F'=' '/port/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' || true)"
KMS_PORT="${KMS_PORT:-9998}"

# Detect if TLS is enabled (tls_p12_file for PKCS#12 configs, tls_cert_file for PEM configs)
if grep -qE 'tls_p12_file|tls_cert_file' "${KMS_CONF}"; then
    KMS_SCHEME="https"
    CURL_EXTRA="-k"
else
    KMS_SCHEME="http"
    CURL_EXTRA=""
fi

MAX_WAIT=30
for _ in $(seq 1 "${MAX_WAIT}"); do
    if curl -sf ${CURL_EXTRA} "${KMS_SCHEME}://localhost:${KMS_PORT}/version" >/dev/null 2>&1; then
        echo "    KMS server ready (${KMS_SCHEME}://${KMS_PORT}, PID ${KMS_PID})"
        break
    fi
    if ! kill -0 "${KMS_PID}" 2>/dev/null; then
        echo "ERROR: KMS server exited prematurely"
        exit 1
    fi
    sleep 1
done
if ! curl -sf ${CURL_EXTRA} "${KMS_SCHEME}://localhost:${KMS_PORT}/version" >/dev/null 2>&1; then
    echo "ERROR: KMS server did not become ready within ${MAX_WAIT}s"
    exit 1
fi

# ─── REST benchmarks ─────────────────────────────────────────────────────────
echo ""
echo "[2/3] Running REST benchmarks (ckms bench --mode ${BENCH_MODE} --format markdown)…"
rm -rf target/criterion
BENCH_ARGS=(--mode "${BENCH_MODE}" --format markdown "${EXTRA_ARGS[@]}")

set +e
RUST_LOG=off cargo run -q -p ckms "${CKMS_CARGO_ARGS[@]}" -- --conf-path "${CKMS_CONF}" bench "${BENCH_ARGS[@]}" 2>&1
BENCH_STATUS=$?
set -e
if [[ ${BENCH_STATUS} -ne 0 ]]; then
    echo "ERROR: ckms bench command failed"
    exit ${BENCH_STATUS}
fi

CRITERION_MD="target/criterion/benchmarks.md"

echo "    REST benchmarks complete."

echo ""
echo "[3/3] Writing ${OUT_REST_MD}…"

if [ -f "${CRITERION_MD}" ]; then
    BENCH_MD="$(cat "${CRITERION_MD}")"
else
    BENCH_MD="No markdown report generated."
fi

# Collect machine info and server version
KMS_VERSION="$(curl -sf ${CURL_EXTRA} "${KMS_SCHEME}://localhost:${KMS_PORT}/version" 2>/dev/null || echo "unknown")"
LSCPU_OUTPUT="$(lscpu 2>/dev/null || echo "lscpu not available")"
BENCH_DATE="$(date -u '+%Y-%m-%d %H:%M:%S UTC')"

cat >"${OUT_REST_MD}" <<MDEOF
# Benchmarks

> Generated on ${BENCH_DATE}
>
> KMS server version: ${KMS_VERSION}

## Machine Info

\`\`\`
${LSCPU_OUTPUT}
\`\`\`

## Results

${BENCH_MD}
MDEOF

echo "    Written: ${OUT_REST_MD}"

echo ""
echo "Done."
