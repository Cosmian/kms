#!/usr/bin/env bash
# .mise/lib/bench_helpers.sh — Benchmark helpers for KMS benchmark tasks.
#
# Source this from a task file:
#   source "${MISE_CONFIG_ROOT:-.}/.mise/lib/bench_helpers.sh"
#
# Provides:
#   bench_build_ckms [release|debug]
#   bench_build_binaries [release|debug]
#   bench_download_server <version> <out_dir>
#   bench_start_server <port> <tmp_dir> [http_workers]
#   bench_register_cleanup
#   bench_write_md <out_path> <kms_port> <criterion_md_path> [page_title]
#
# Globals set:
#   CARGO_TARGET_DIR, KMS_BIN, CKMS_BIN, KMS_PID, TMP_DIR
#   BENCH_DEB_BINARY, BENCH_DEB_OSSL_MODS  (after bench_download_server)
#   OPENSSL_MODULES_DIR                    (set by caller for deb-based server)

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
BENCH_DEB_BINARY=""
BENCH_DEB_OSSL_MODS=""
OPENSSL_MODULES_DIR=""

# Build only the ckms CLI (no server).
# Usage: bench_build_ckms [release|debug]
# Sets: CARGO_TARGET_DIR, CKMS_BIN
bench_build_ckms() {
  local build_mode="${1:-debug}"
  local cargo_args=()
  [ "${build_mode}" = "release" ] && cargo_args=(--release)

  local repo_root
  # shellcheck disable=SC2119
  repo_root="$(get_repo_root)"

  echo "Building ckms CLI (${build_mode})..."
  cargo build -p ckms \
    "${cargo_args[@]}" \
    ${FEATURES_FLAG[@]+"${FEATURES_FLAG[@]}"}

  CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${repo_root}/target}"
  CKMS_BIN="${CARGO_TARGET_DIR}/${build_mode}/ckms"
  export CARGO_TARGET_DIR CKMS_BIN
}

# Build KMS server and ckms CLI.
# Usage: bench_build_binaries [release|debug]
# Sets: CARGO_TARGET_DIR, KMS_BIN, CKMS_BIN
bench_build_binaries() {
  local build_mode="${1:-debug}"
  local cargo_args=()
  [ "${build_mode}" = "release" ] && cargo_args=(--release)

  local repo_root
  # shellcheck disable=SC2119
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

# Download a KMS server .deb from package.cosmian.com and extract the binary.
# Usage: bench_download_server <version> <out_dir>
# Sets: BENCH_DEB_BINARY, BENCH_DEB_OSSL_MODS
bench_download_server() {
  local version="$1" out_dir="$2"

  local arch
  case "$(uname -m)" in
    x86_64) arch="amd64" ;;
    aarch64 | arm64) arch="arm64" ;;
    *)
      echo "ERROR: unsupported architecture $(uname -m)"
      return 1
      ;;
  esac

  for cmd in curl dpkg-deb; do
    command -v "${cmd}" >/dev/null 2>&1 ||
      {
        echo "ERROR: ${cmd} not found in PATH"
        return 1
      }
  done

  local deb="cosmian-kms-server-non-fips-static-openssl_${version}_${arch}.deb"
  local url="https://package.cosmian.com/kms/${version}/deb/${arch}/non-fips/static/${deb}"

  mkdir -p "${out_dir}"
  echo "Downloading KMS ${version} from package.cosmian.com..."
  curl -fsSL -o "${out_dir}/${deb}" "${url}" ||
    {
      echo "ERROR: download failed — ${url}"
      return 1
    }

  echo "Extracting ${deb}..."
  dpkg-deb -x "${out_dir}/${deb}" "${out_dir}/extract"

  BENCH_DEB_BINARY="${out_dir}/extract/usr/sbin/cosmian_kms"
  BENCH_DEB_OSSL_MODS="${out_dir}/extract/usr/local/cosmian/lib/ossl-modules"

  [ -f "${BENCH_DEB_BINARY}" ] ||
    {
      echo "ERROR: binary not found at ${BENCH_DEB_BINARY}"
      return 1
    }
  chmod +x "${BENCH_DEB_BINARY}"
  export BENCH_DEB_BINARY BENCH_DEB_OSSL_MODS
  echo "Server binary: ${BENCH_DEB_BINARY}"
}

# Warn when CPU frequency scaling / turbo may distort load-sweep scaling curves.
# On power-limited CPUs (laptops, Intel "T" SKUs, thermally constrained hosts) a
# heavy concurrency level draws more power and throttles to a LOWER clock than a
# light level, which exaggerates sublinear scaling independently of the server.
# No warmup/cooldown value can compensate for load-dependent DVFS; pin the clock.
bench_warn_cpu_scaling() {
  local gov="" turbo="" f0="" fmax=""
  gov=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || true)
  [ -r /sys/devices/system/cpu/intel_pstate/no_turbo ] &&
    turbo=$(cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null || true)
  f0=$(cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_min_freq 2>/dev/null || true)
  fmax=$(cat /sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq 2>/dev/null || true)
  local wide_range=0
  if [ -n "$f0" ] && [ -n "$fmax" ] && [ "$f0" -gt 0 ] 2>/dev/null; then
    [ $((fmax * 100 / f0)) -ge 200 ] && wide_range=1
  fi
  if { [ -n "$gov" ] && [ "$gov" != "performance" ]; } || [ "${turbo:-1}" = "0" ] || [ "$wide_range" = 1 ]; then
    echo "-------------------------------------------------------------------------------"
    echo "WARNING: dynamic CPU frequency scaling is active"
    echo "         (governor='${gov:-unknown}', turbo=$([ "${turbo:-0}" = 1 ] && echo disabled || echo enabled))."
    echo "         Scaling curves may be DISTORTED: heavier concurrency levels draw more"
    echo "         power and can throttle to a lower clock than light levels, exaggerating"
    echo "         apparent sublinear scaling. For reproducible scaling curves, pin the clock:"
    echo "           sudo cpupower frequency-set -g performance"
    echo "           echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo"
    echo "         and, ideally, run the client on a SEPARATE host so it does not compete"
    echo "         with the server for CPU (co-location caps throughput on shared cores)."
    echo "-------------------------------------------------------------------------------"
  fi
}

# Start a temporary SQLite KMS server for benchmarks.
# Usage: bench_start_server <port> <tmp_dir> [http_workers]
# Sets: KMS_PID
bench_start_server() {
  local port="$1" tmp_dir="$2" http_workers="${3:-}"
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

  if [ -n "${http_workers}" ]; then
    printf 'http_workers = %s\n' "${http_workers}" >>"${kms_conf}"
  fi

  # Optional CPU pinning (BENCH_SERVER_CPUS, e.g. "0-7") isolates the server from
  # the client so a capacity sweep is not distorted by co-location on shared cores.
  local pin=()
  [ -n "${BENCH_SERVER_CPUS:-}" ] && pin=(taskset -c "${BENCH_SERVER_CPUS}")
  echo "Starting KMS server on port ${port}...${BENCH_SERVER_CPUS:+ (cpus ${BENCH_SERVER_CPUS})}"
  if [ -n "${OPENSSL_MODULES_DIR:-}" ]; then
    OPENSSL_MODULES="${OPENSSL_MODULES_DIR}" ${pin[@]+"${pin[@]}"} "${KMS_BIN}" --config "${kms_conf}" >"${kms_log}" 2>&1 &
  else
    ${pin[@]+"${pin[@]}"} "${KMS_BIN}" --config "${kms_conf}" >"${kms_log}" 2>&1 &
  fi
  KMS_PID=$!
  export KMS_PID

  kms_wait_ready "http://127.0.0.1:${port}/kmip/2_1" "${KMS_PID}" "${kms_log}" 60
}

# Stop the benchmark server started by bench_start_server. Used between capacity
# sweep iterations so each worker count runs against a fresh, uncontended server.
bench_stop_server() {
  [ -n "${KMS_PID:-}" ] || return 0
  kill "${KMS_PID}" 2>/dev/null || true
  wait "${KMS_PID}" 2>/dev/null || true
  KMS_PID=""
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

# Start a KMS server backed by a SoftHSM2 token with a key_encryption_key.
#
# Sets up a fresh SoftHSM2 token, writes a kms.toml with the HSM instance and
# key_encryption_key pointing at the new token, starts the server, then creates
# the KEK via ckms so the server is immediately usable.
#
# Prerequisites:
#   - softhsm2.sh must already be sourced by the caller.
#   - bench_build_binaries (or bench_build_ckms) must have run, so KMS_BIN and
#     CKMS_BIN are set.
#
# Usage: bench_start_server_hsm <port> <tmp_dir> [http_workers]
# Sets:  KMS_PID, HSM_KEK_UID
bench_start_server_hsm() {
  local port="$1" tmp_dir="$2" http_workers="${3:-}"
  local sqlite_path="${tmp_dir}/kms-data"
  local kms_conf="${tmp_dir}/kms.toml"
  local kms_log="${tmp_dir}/kms.log"

  require_cmd softhsm2-util \
    "SoftHSM2 (softhsm2-util) is required for HSM benchmarks. Install: brew install softhsm (macOS) or apt install softhsm2 (Linux)"

  # Initialize a fresh single-token SoftHSM2 environment.
  softhsm2_setup "${tmp_dir}/softhsm2/tokens" "${tmp_dir}/softhsm2/softhsm2.conf"
  local init_out
  init_out=$(softhsm2_init_token "bench_kek" "${HSM_USER_PASSWORD}" "${HSM_USER_PASSWORD}" 2>&1 | tee /dev/stderr)
  SOFTHSM2_HSM_SLOT_ID=$(softhsm2_get_slot_id "$init_out" "bench_kek")
  export SOFTHSM2_HSM_SLOT_ID

  HSM_KEK_UID="hsm::${SOFTHSM2_HSM_SLOT_ID}::bench_kek"
  export HSM_KEK_UID

  mkdir -p "$sqlite_path"

  # Write kms.toml with HSM + key_encryption_key.
  # The server will not start wrapping until the KEK is created (see below).
  cat >"${kms_conf}" <<EOF
key_encryption_key = "${HSM_KEK_UID}"

hsm_model    = "softhsm2"
hsm_admin    = ["admin"]
hsm_slot     = [${SOFTHSM2_HSM_SLOT_ID}]
hsm_password = ["${HSM_USER_PASSWORD}"]

[db]
database_type = "sqlite"
sqlite_path   = "${sqlite_path}"

[http]
hostname = "0.0.0.0"
port     = ${port}
EOF

  if [ -n "${http_workers}" ]; then
    printf 'http_workers = %s\n' "${http_workers}" >>"${kms_conf}"
  fi

  echo "Starting KMS server (HSM-backed) on port ${port}..."
  local lib_path_var
  lib_path_var=$(softhsm2_lib_path_var)
  local lib_path
  lib_path=$(softhsm2_lib_search_path)

  env \
    "${lib_path_var}=${lib_path}" \
    SOFTHSM2_PKCS11_LIB="${SOFTHSM2_PKCS11_LIB_PATH}" \
    SOFTHSM2_CONF="${SOFTHSM2_CONF}" \
    "${KMS_BIN}" --config "${kms_conf}" \
    >"${kms_log}" 2>&1 &
  KMS_PID=$!
  export KMS_PID

  kms_wait_ready "http://127.0.0.1:${port}/kmip/2_1" "${KMS_PID}" "${kms_log}" 60

  # Create the KEK on the HSM now that the server is running.
  # The server's kek_bootstrap logic allows creating an object whose UID equals
  # key_encryption_key even when it does not yet exist.
  echo "Creating KEK on HSM (UID: ${HSM_KEK_UID})..."
  env \
    "${lib_path_var}=${lib_path}" \
    SOFTHSM2_PKCS11_LIB="${SOFTHSM2_PKCS11_LIB_PATH}" \
    SOFTHSM2_CONF="${SOFTHSM2_CONF}" \
    "${CKMS_BIN}" \
    --url "http://127.0.0.1:${port}" \
    sym keys create \
    --algorithm aes \
    --number-of-bits 256 \
    "${HSM_KEK_UID}"
  echo "KEK created: ${HSM_KEK_UID}"
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

# Snapshot machine and benchmark configuration into an env.json file.
# Usage: bench_collect_env <out_file>
# Reads globals: BUILD_MODE, BENCH_VARIANT, BENCH_HTTP_WORKERS, BENCH_MODE,
#                BENCH_PROTOCOL, BENCH_TIME, BENCH_CONCURRENCY,
#                BENCH_WARMUP, BENCH_COOLDOWN
bench_collect_env() {
  local out_file="$1"

  # Pass all bench globals as prefixed env vars so the Python snippet can read
  # them safely through os.environ (avoids bash quoting/expansion issues inside
  # the single-quoted heredoc).
  _BENCH_BUILD_MODE="${BUILD_MODE:-release}" \
    _BENCH_VARIANT="${BENCH_VARIANT:-non-fips}" \
    _BENCH_HTTP_WORKERS="${BENCH_HTTP_WORKERS:-}" \
    _BENCH_MODE="${BENCH_MODE:-all}" \
    _BENCH_PROTOCOL="${BENCH_PROTOCOL:-all}" \
    _BENCH_TIME="${BENCH_TIME:-20}" \
    _BENCH_CONCURRENCY="${BENCH_CONCURRENCY:-1,2,4,8,16}" \
    _BENCH_WARMUP="${BENCH_WARMUP:-5}" \
    _BENCH_COOLDOWN="${BENCH_COOLDOWN:-2}" \
    python3 - >"${out_file}" <<'PYEOF'
import json, os, re, subprocess
from datetime import datetime, timezone

def _read(path):
    try:
        with open(path) as fh:
            return fh.read()
    except OSError:
        return ""

# ── CPU ──────────────────────────────────────────────────────────────────────
cpuinfo = _read("/proc/cpuinfo")
m = re.search(r"model name\s*:\s*(.+)", cpuinfo)
cpu_model = m.group(1).strip() if m else "unknown"
cpu_logical = len(re.findall(r"^processor\s*:", cpuinfo, re.MULTILINE))
# Count unique (physical_id, core_id) pairs to get physical core count.
phys = re.findall(r"^physical id\s*:\s*(\S+)", cpuinfo, re.MULTILINE)
core = re.findall(r"^core id\s*:\s*(\S+)", cpuinfo, re.MULTILINE)
cpu_physical = len(set(zip(phys, core))) if phys and core else cpu_logical
m = re.search(r"cpu MHz\s*:\s*([\d.]+)", cpuinfo)
cpu_mhz = round(float(m.group(1))) if m else None

# ── Memory ───────────────────────────────────────────────────────────────────
m = re.search(r"MemTotal:\s*(\d+)", _read("/proc/meminfo"))
mem_gb = round(int(m.group(1)) / 1024 / 1024, 1) if m else None

# ── OS / kernel ───────────────────────────────────────────────────────────────
os_name = "unknown"
for ln in _read("/etc/os-release").splitlines():
    if ln.startswith("PRETTY_NAME="):
        os_name = ln.split("=", 1)[1].strip('"\'')
        break
try:
    kernel = subprocess.check_output(["uname", "-r"], text=True).strip()
except Exception:
    kernel = "unknown"

# ── lscpu (best-effort) ───────────────────────────────────────────────────────
try:
    lscpu = subprocess.check_output(["lscpu"], text=True).strip()
except Exception:
    lscpu = ""

# ── Benchmark globals ────────────────────────────────────────────────────────
g = os.environ.get

def _int(key, default):
    try:
        return int(g(key, ""))
    except (ValueError, TypeError):
        return default

http_workers_raw = g("_BENCH_HTTP_WORKERS", "")
http_workers = _int("_BENCH_HTTP_WORKERS", None) if http_workers_raw else None

env = {
    "date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    "build_mode":        g("_BENCH_BUILD_MODE", "release"),
    "variant":           g("_BENCH_VARIANT", "non-fips"),
    "http_workers":      http_workers,
    "bench_mode":        g("_BENCH_MODE", "all"),
    "bench_protocol":    g("_BENCH_PROTOCOL", "all"),
    "bench_time_s":      _int("_BENCH_TIME", 20),
    "bench_concurrency": g("_BENCH_CONCURRENCY", "1,2,4,8,16"),
    "bench_warmup_s":    _int("_BENCH_WARMUP", 5),
    "bench_cooldown_s":  _int("_BENCH_COOLDOWN", 2),
    "cpu_model":         cpu_model,
    "cpu_physical_cores": cpu_physical,
    "cpu_logical_cores": cpu_logical,
    "cpu_mhz":           cpu_mhz,
    "mem_gb":            mem_gb,
    "os":                os_name,
    "kernel":            kernel,
    "lscpu":             lscpu,
}
print(json.dumps(env, indent=2))
PYEOF
}

# Generate SVG charts and a markdown report from benchmark data.
# Call after running load tests and/or criterion benchmarks.
# Usage: bench_generate_report <kms_port>
# Reads:  $CRITERION_HOME/load_*.json  (load tests)
#         $CRITERION_HOME/criterion.json  (criterion benchmarks)
# Writes: $CRITERION_HOME/reports/<version>/  data files + report.md + SVGs
#         $CRITERION_HOME/reports/<version>/load/       load SVGs
#         $CRITERION_HOME/reports/<version>/criterion/  criterion SVGs
#         $CRITERION_HOME/reports/<version>/report.md   combined report
bench_generate_report() {
  local port="$1"

  # Compute criterion home step-by-step to avoid deeply nested expansions.
  local crit_home
  if [ -n "${CRITERION_HOME:-}" ]; then
    crit_home="${CRITERION_HOME}"
  elif [ -n "${CARGO_TARGET_DIR:-}" ]; then
    crit_home="${CARGO_TARGET_DIR}/criterion"
  else
    # shellcheck disable=SC2119
    crit_home="$(get_repo_root)/target/criterion"
  fi

  local report_dir="${crit_home}/reports"
  # shellcheck disable=SC2119
  local plot_script="${MISE_CONFIG_ROOT:-$(get_repo_root)}/.mise/scripts/bench/plot_version_compare.py"

  # Derive version label from running server (only the numeric part, e.g. "5.24.0").
  local raw_version
  raw_version="$(curl -sf "http://127.0.0.1:${port}/version" 2>/dev/null || true)"
  local version
  # Strip JSON quotes then take only the first whitespace-delimited token.
  version="$(printf '%s' "${raw_version}" | tr -d '"' | awk '{print $1}')"
  [ -z "${version}" ] && version="current"

  echo "Collecting results for version '${version}'..."
  mkdir -p "${report_dir}/${version}"

  echo "Collecting environment data..."
  bench_collect_env "${report_dir}/${version}/env.json"

  local found=0
  for f in "${crit_home}"/load_*.json; do
    [ -f "$f" ] && cp "$f" "${report_dir}/${version}/" && found=1
  done
  if [ -f "${crit_home}/criterion.json" ]; then
    cp "${crit_home}/criterion.json" "${report_dir}/${version}/"
    found=1
  fi

  if [ "${found}" -eq 0 ]; then
    echo "WARNING: no benchmark data files found in ${crit_home}"
    return 0
  fi

  echo "Generating report..."
  python3 "${plot_script}" "${report_dir}" "${version}" || {
    echo "WARNING: report generation failed — raw data is in ${report_dir}/${version}/"
    return 0
  }

  echo ""
  echo "Report      : ${report_dir}/${version}/report.md"
  echo "Load charts : ${report_dir}/${version}/load/"
  echo "Crit charts : ${report_dir}/${version}/criterion/"

  # Mirror the freshly generated report into the documentation tree so the
  # checked-in docs always reflect the latest run (committed by the CI job or
  # the developer's local run).
  local docs_bench_dir
  # shellcheck disable=SC2119
  docs_bench_dir="$(get_repo_root)/documentation/docs/benchmarks/ckms_bench"
  echo "Updating docs: ${docs_bench_dir}..."
  rm -rf "${docs_bench_dir:?}"
  mkdir -p "${docs_bench_dir}"
  cp -r "${report_dir}/${version}/." "${docs_bench_dir}/"
  echo "Docs updated."
}
