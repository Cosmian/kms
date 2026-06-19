#!/usr/bin/env bash
# .mise/lib/bench_helpers.sh — Benchmark helpers for KMS benchmark tasks.
#
# Source this from a task file:
#   source "${MISE_CONFIG_ROOT:-.}/.mise/lib/bench_helpers.sh"
#
# Provides:
#   bench_build_binaries [release|debug]
#   bench_start_server <port> <tmp_dir>
#   bench_register_cleanup
#   bench_write_md <out_path> <kms_port> <criterion_md_path> [page_title]
#
# Globals set:
#   CARGO_TARGET_DIR, KMS_BIN, CKMS_BIN, KMS_PID, TMP_DIR

# ── Guard ─────────────────────────────────────────────────────────────────────
[ -n "${_MISE_BENCH_HELPERS_SH_LOADED:-}" ] && return 0
_MISE_BENCH_HELPERS_SH_LOADED=1

# ── Require common.sh ─────────────────────────────────────────────────────────
if [ -z "${_MISE_COMMON_SH_LOADED:-}" ]; then
  source "${MISE_CONFIG_ROOT:-.}/.mise/lib/common.sh"
fi

# ── State ─────────────────────────────────────────────────────────────────────
KMS_BIN=""
CKMS_BIN=""
KMS_PID=""
TMP_DIR=""

# Build KMS server and ckms CLI.
# Usage: bench_build_binaries [release|debug]
# Sets: CARGO_TARGET_DIR, KMS_BIN, CKMS_BIN
bench_build_binaries() {
  local build_mode="${1:-debug}"
  local cargo_args=()
  if [ "${build_mode}" = "release" ]; then
    cargo_args=(--release)
  fi

  local repo_root
  repo_root="$(get_repo_root)"

  echo "Building cosmian_kms server and ckms CLI (${build_mode})..."
  cargo build -p cosmian_kms_server -p ckms \
    "${cargo_args[@]}" \
    ${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"}

  CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${repo_root}/target}"
  KMS_BIN="${CARGO_TARGET_DIR}/${build_mode}/cosmian_kms"
  CKMS_BIN="${CARGO_TARGET_DIR}/${build_mode}/ckms"
  export CARGO_TARGET_DIR KMS_BIN CKMS_BIN
}

# Start a temporary SQLite KMS server for benchmarks.
# Usage: bench_start_server <port> <tmp_dir>
# Sets: KMS_PID
bench_start_server() {
  local port="$1" tmp_dir="$2"
  local sqlite_path="${tmp_dir}/kms-data"
  local kms_conf="${tmp_dir}/kms.toml"
  local kms_log="${tmp_dir}/kms.log"

  mkdir -p "$sqlite_path"

  cat >"${kms_conf}" <<EOF
[db]
database_type = "sqlite"
sqlite_path = "${sqlite_path}"

[http]
hostname = "0.0.0.0"
port = ${port}
EOF

  echo "Starting KMS server on port ${port}..."
  "${KMS_BIN}" --config "${kms_conf}" >"${kms_log}" 2>&1 &
  KMS_PID=$!
  export KMS_PID

  kms_wait_ready "http://127.0.0.1:${port}/kmip/2_1" "${KMS_PID}" "${kms_log}" 60
}

# Internal cleanup handler.
_bench_cleanup() {
  [ -n "${KMS_PID:-}" ] && {
    kill "${KMS_PID}" 2>/dev/null || true
    wait "${KMS_PID}" 2>/dev/null || true
  }
  rm -rf "${TMP_DIR:-}"
}

# Register EXIT trap for benchmark cleanup.
bench_register_cleanup() {
  trap '_bench_cleanup' EXIT
}

# Write a markdown benchmark report.
# Usage: bench_write_md <out_path> <kms_port> <criterion_md_path> [page_title]
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
