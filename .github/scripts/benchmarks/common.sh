#!/usr/bin/env bash
# benchmarks/common.sh — Shared helpers for KMS benchmark scripts.
#
# Source this file; do NOT execute it directly.
#
# Provides:
#   bench_build_binaries [release]       — cargo build + export KMS_BIN / CKMS_BIN
#   bench_start_server <port> <tmp_dir>  — write kms.toml, start server, export KMS_PID
#   bench_register_cleanup               — register EXIT trap (uses globals KMS_PID / TMP_DIR)
#   bench_write_md <out> <port> <md> <title> — write documented markdown report
#
# Requires the parent common.sh (kms_wait_ready, init_build_env, …) to be loaded first.
# This file sources the parent automatically so callers only need to source this one.

# ── Guard against double-sourcing ─────────────────────────────────────────────
if [ -n "${_KMS_BENCH_COMMON_SH_LOADED:-}" ]; then
  return 0
fi
_KMS_BENCH_COMMON_SH_LOADED=1

# ── Source parent helpers ─────────────────────────────────────────────────────
_BENCH_COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=.github/scripts/common.sh
source "${_BENCH_COMMON_DIR}/../common.sh"

# ── Binary build ──────────────────────────────────────────────────────────────

# Build KMS server and ckms CLI with the current FEATURES_FLAG.
# Usage: bench_build_binaries [release]
#   Passing "release" produces a --release build; default is debug.
# Sets (and exports) globals: CARGO_TARGET_DIR, KMS_BIN, CKMS_BIN
# Requires globals: REPO_ROOT, FEATURES_FLAG (set by init_build_env)
bench_build_binaries() {
  local build_mode="${1:-debug}"
  local cargo_args=()
  if [ "${build_mode}" = "release" ]; then
    cargo_args=(--release)
  fi
  echo "Building cosmian_kms server and ckms CLI (${build_mode})..."
  cargo build -p cosmian_kms_server -p ckms \
    "${cargo_args[@]}" \
    "${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"}"
  CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${REPO_ROOT}/target}"
  KMS_BIN="${CARGO_TARGET_DIR}/${build_mode}/cosmian_kms"
  CKMS_BIN="${CARGO_TARGET_DIR}/${build_mode}/ckms"
  export CARGO_TARGET_DIR KMS_BIN CKMS_BIN
}

# ── Server lifecycle ───────────────────────────────────────────────────────────

# Start a temporary SQLite KMS server on a plain HTTP port.
# Usage: bench_start_server <port> <tmp_dir>
# Sets (and exports) global: KMS_PID
# Requires globals: KMS_BIN (set by bench_build_binaries or caller)
bench_start_server() {
  local port="$1" tmp_dir="$2"
  local sqlite_path="${tmp_dir}/kms-data"
  local kms_conf="${tmp_dir}/kms.toml"
  local kms_log="${tmp_dir}/kms.log"

  cat >"${kms_conf}" <<KMS_CONF_EOF
[db]
database_type = "sqlite"
sqlite_path = "${sqlite_path}"

[http]
hostname = "0.0.0.0"
port = ${port}
KMS_CONF_EOF

  echo "Starting KMS server on port ${port}..."
  "${KMS_BIN}" --config "${kms_conf}" >"${kms_log}" 2>&1 &
  KMS_PID=$!
  export KMS_PID

  kms_wait_ready "http://127.0.0.1:${port}/kmip/2_1" "${KMS_PID}" "${kms_log}" 60
}

# ── Cleanup trap ───────────────────────────────────────────────────────────────

# Internal cleanup handler — uses globals KMS_PID and TMP_DIR.
_bench_cleanup() {
  [ -n "${KMS_PID:-}" ] && {
    kill "${KMS_PID}" 2>/dev/null || true
    wait "${KMS_PID}" 2>/dev/null || true
  }
  rm -rf "${TMP_DIR:-}"
}

# Register an EXIT trap that stops the KMS server and removes TMP_DIR.
# Call this once after setting TMP_DIR and KMS_PID="" globals.
bench_register_cleanup() {
  trap '_bench_cleanup' EXIT
}

# ── Report writing ─────────────────────────────────────────────────────────────

# Write a markdown documentation file combining machine info + benchmark results.
# Usage: bench_write_md <out_path> <kms_port> <criterion_md_path> <page_title>
# Requires: curl in PATH (guaranteed by prior kms_wait_ready call)
bench_write_md() {
  local out_path="$1" kms_port="$2" criterion_md="$3" page_title="${4:-Benchmarks}"
  local bench_date kms_version lscpu_output bench_md

  bench_date="$(date -u '+%Y-%m-%d %H:%M:%S UTC')"
  kms_version="$(curl -sf "http://127.0.0.1:${kms_port}/version" 2>/dev/null || echo "unknown")"
  lscpu_output="$(lscpu 2>/dev/null || echo "lscpu not available")"

  if [ -f "${criterion_md}" ]; then
    bench_md="$(cat "${criterion_md}")"
  else
    bench_md="No markdown report generated."
  fi

  mkdir -p "$(dirname "${out_path}")"
  cat >"${out_path}" <<MDEOF
# ${page_title}

> Generated on ${bench_date}
>
> KMS server version: ${kms_version}

## Machine Info

\`\`\`
${lscpu_output}
\`\`\`

${bench_md}
MDEOF
  echo "Written: ${out_path}"
}
