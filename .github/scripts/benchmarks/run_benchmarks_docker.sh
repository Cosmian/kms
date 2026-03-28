#!/usr/bin/env bash
# run_benchmarks_docker.sh — Run ckms benchmarks against Dockerized KMS versions.
#
# Usage:
#   bash scripts/run_benchmarks_docker.sh 5.17              # single version, save baseline
#   bash scripts/run_benchmarks_docker.sh 5.12..5.17        # range, one report per version
#   bash scripts/run_benchmarks_docker.sh 5.14.0 5.17.0    # diff: baseline vs compare
#   bash scripts/run_benchmarks_docker.sh                   # defaults to 5.17
#
# Two-version mode:
#   ARG1 = baseline version (benchmarked first, saved as criterion baseline)
#   ARG2 = compare version  (benchmarked second, compared against baseline)
#   Output: documentation/docs/benchmarks/docker/benchmarks-<v1>-vs-<v2>.md
#
# Optional env vars:
#   MAX_MINOR_PER_MAJOR  Upper bound used when expanding cross-major ranges
#                        (default: 29, e.g. 4.24..5.17 => 4.24..4.29 + 5.0..5.17)

set -euo pipefail

if [[ $# -gt 2 ]]; then
  echo "Usage: $0 [<version|range> [<compare-version>]]"
  echo "Examples:"
  echo "  $0 5.17"
  echo "  $0 5.12..5.17"
  echo "  $0 5.14.0 5.17.0"
  echo "  $0"
  exit 1
fi

VERSION_SPEC="${1:-5.17}"
COMPARE_SPEC="${2:-}"

if [[ "${VERSION_SPEC}" == "-h" || "${VERSION_SPEC}" == "--help" ]]; then
  echo "Usage: $0 [<version|range> [<compare-version>]]"
  echo "Examples:"
  echo "  $0 5.17"
  echo "  $0 5.12..5.17"
  echo "  $0 5.14.0 5.17.0"
  exit 0
fi

IMAGE_REPO="${IMAGE_REPO:-ghcr.io/cosmian/kms}"
HOST_PORT="${HOST_PORT:-9998}"
BENCH_MODE="${BENCH_MODE:-all}"
EXTRA_ARGS_STR="${EXTRA_ARGS:---speed quick}"
read -r -a EXTRA_ARGS <<<"${EXTRA_ARGS_STR}"
OUT_DIR="${OUT_DIR:-documentation/docs/benchmarks/docker}"
MAX_MINOR_PER_MAJOR="${MAX_MINOR_PER_MAJOR:-29}"
CKMS_CARGO_ARGS_STR="${CKMS_CARGO_ARGS:---release --features non-fips}"
read -r -a CKMS_CARGO_ARGS <<<"${CKMS_CARGO_ARGS_STR}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
cd "${ROOT_DIR}"

if ! command -v cargo >/dev/null 2>&1; then
  echo "ERROR: cargo is required but was not found in PATH."
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker is required but was not found in PATH."
  exit 1
fi

mkdir -p "${OUT_DIR}"

CONTAINER_NAME="kms-bench-docker"
TMP_CKMS_CONF="$(mktemp)"

cleanup() {
  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
  rm -f "${TMP_CKMS_CONF}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

write_ckms_conf() {
  cat >"${TMP_CKMS_CONF}" <<EOF
[http_config]
server_url = "http://127.0.0.1:${HOST_PORT}"
accept_invalid_certs = true
EOF
}

normalize_version() {
  local v="$1"
  echo "${v}"
}

expand_versions() {
  local spec="$1"
  if [[ "${spec}" == *".."* ]]; then
    local start="${spec%%..*}"
    local end="${spec##*..}"
    if [[ ! "${start}" =~ ^([0-9]+)\.([0-9]+)$ ]]; then
      echo "ERROR: range start must be MAJOR.MINOR (got: ${start})" >&2
      return 1
    fi
    local start_major="${BASH_REMATCH[1]}"
    local start_minor="${BASH_REMATCH[2]}"

    if [[ ! "${end}" =~ ^([0-9]+)\.([0-9]+)$ ]]; then
      echo "ERROR: range end must be MAJOR.MINOR (got: ${end})" >&2
      return 1
    fi
    local end_major="${BASH_REMATCH[1]}"
    local end_minor="${BASH_REMATCH[2]}"

    if ((start_major > end_major)); then
      echo "ERROR: range start major must be <= end major" >&2
      return 1
    fi
    if ((start_major == end_major && start_minor > end_minor)); then
      echo "ERROR: range start minor must be <= end minor when major is equal" >&2
      return 1
    fi

    local major
    local minor
    local from_minor
    local to_minor
    for ((major = start_major; major <= end_major; major++)); do
      if ((major == start_major)); then
        from_minor=${start_minor}
      else
        from_minor=0
      fi

      if ((major == end_major)); then
        to_minor=${end_minor}
      else
        to_minor=${MAX_MINOR_PER_MAJOR}
      fi

      for ((minor = from_minor; minor <= to_minor; minor++)); do
        echo "${major}.${minor}"
      done
    done
  else
    if [[ ! "${spec}" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]; then
      echo "ERROR: version must be MAJOR.MINOR or MAJOR.MINOR.PATCH (got: ${spec})" >&2
      return 1
    fi
    normalize_version "${spec}"
  fi
}

resolve_image_tag() {
  local version="$1"
  local image_try

  image_try="${IMAGE_REPO}:${version}"
  if docker pull "${image_try}" >/dev/null 2>&1; then
    echo "${version}"
    return 0
  fi

  if [[ "${version}" =~ ^[0-9]+\.[0-9]+$ ]]; then
    image_try="${IMAGE_REPO}:${version}.0"
    if docker pull "${image_try}" >/dev/null 2>&1; then
      echo "${version}.0"
      return 0
    fi
  fi

  return 1
}

wait_kms_ready() {
  local image="$1"
  local max_wait=45
  local i
  for ((i = 1; i <= max_wait; i++)); do
    if curl -sf "http://127.0.0.1:${HOST_PORT}/version" >/dev/null 2>&1; then
      return 0
    fi
    if ! docker ps --format '{{.Names}}' | grep -Fxq "${CONTAINER_NAME}"; then
      echo "ERROR: container exited early for image ${image}" >&2
      docker logs "${CONTAINER_NAME}" 2>/dev/null || true
      return 1
    fi
    sleep 1
  done
  echo "ERROR: KMS did not become ready on port ${HOST_PORT} for image ${image}" >&2
  docker logs "${CONTAINER_NAME}" 2>/dev/null || true
  return 1
}

# Run ckms bench for one version, write a per-version markdown report.
# Args: version resolved_tag baseline_flag...
run_bench_version() {
  local version="$1"
  local resolved_tag="$2"
  shift 2
  local bench_extra_flags=("$@") # e.g. --save-baseline v5.14.0

  local out_file="${OUT_DIR}/benchmarks-${version}.md"
  local image="${IMAGE_REPO}:${resolved_tag}"

  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true

  echo "[${version}] Starting container..."
  docker run -d --rm \
    --name "${CONTAINER_NAME}" \
    -p "${HOST_PORT}:9998" \
    "${image}" \
    --database-type sqlite --sqlite-path /var/lib/cosmian-kms >/dev/null || {
    cat >"${out_file}" <<EOF
# Benchmarks — KMS ${version} (Docker)

Image: \`${image}\`

Status: FAILED

Reason: failed to start container.
EOF
    echo "[${version}] Container start failed, wrote failure report ${out_file}"
    return 1
  }

  if ! wait_kms_ready "${image}"; then
    cat >"${out_file}" <<EOF
# Benchmarks — KMS ${version} (Docker)

Image: \`${image}\`

Status: FAILED

Reason: container did not become ready.
EOF
    echo "[${version}] Readiness failed, wrote failure report ${out_file}"
    docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
    return 1
  fi
  echo "[${version}] Server ready on http://127.0.0.1:${HOST_PORT}"

  echo "[${version}] Running ckms bench..."
  local bench_args=(--mode "${BENCH_MODE}" --format markdown "${bench_extra_flags[@]}" "${EXTRA_ARGS[@]}")

  set +e
  local bench_stderr
  bench_stderr="$(mktemp)"
  RUST_LOG=off cargo run -q -p ckms "${CKMS_CARGO_ARGS[@]}" -- --conf-path "${TMP_CKMS_CONF}" bench "${bench_args[@]}" 2>"${bench_stderr}"
  local bench_status=$?
  set -e

  if [[ ${bench_status} -ne 0 ]]; then
    cat >"${out_file}" <<EOF
# Benchmarks — KMS ${version} (Docker)

Image: \`${image}\`

Status: FAILED

Reason: ckms bench command failed.

\`\`\`text
$(cat "${bench_stderr}")
\`\`\`
EOF
    echo "[${version}] Benchmark failed, wrote failure report ${out_file}"
    rm -f "${bench_stderr}"
    docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
    return 1
  fi
  cat "${bench_stderr}" >&2
  rm -f "${bench_stderr}"

  local json_file="${OUT_DIR}/benchmarks-${version}.json"
  if [[ -f target/criterion/benchmarks.json ]]; then
    cp target/criterion/benchmarks.json "${json_file}"
  fi

  local criterion_md="target/criterion/benchmarks.md"
  local bench_md
  if [[ -f "${criterion_md}" ]]; then
    bench_md="$(cat "${criterion_md}")"
  else
    bench_md="No markdown report generated."
  fi

  cat >"${out_file}" <<EOF
# Benchmarks — KMS ${version} (Docker)

Image: \`${image}\`

Source command:

\`\`\`bash
cargo run -p ckms ${CKMS_CARGO_ARGS_STR} -- --conf-path ${TMP_CKMS_CONF} bench ${bench_args[*]}
\`\`\`

${bench_md}
EOF

  echo "[${version}] Written ${out_file}"
  # Generate HTML version via pandoc if available
  local out_html="${out_file%.md}.html"
  if command -v pandoc >/dev/null 2>&1; then
    pandoc -s --metadata title="Benchmarks \u2014 KMS ${version}" -f gfm \
      "${out_file}" -o "${out_html}" 2>/dev/null && echo "[${version}] Written ${out_html}" ||
      echo "[${version}] WARNING: pandoc HTML conversion failed"
  else
    echo "[${version}] INFO: pandoc not found \u2014 skipping HTML conversion of ${out_file}"
  fi
  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
}

write_ckms_conf

# =============================================================================
# TWO-VERSION DIFF MODE
# =============================================================================
if [[ -n "${COMPARE_SPEC}" ]]; then
  BASELINE_VERSION="${VERSION_SPEC}"
  COMPARE_VERSION="${COMPARE_SPEC}"

  for v in "${BASELINE_VERSION}" "${COMPARE_VERSION}"; do
    if [[ ! "${v}" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]; then
      echo "ERROR: diff mode requires MAJOR.MINOR or MAJOR.MINOR.PATCH versions (got: ${v})"
      exit 1
    fi
  done

  echo "============================================================"
  echo "  Cosmian KMS Docker benchmark diff"
  echo "  CLI run      : cargo run -p ckms ${CKMS_CARGO_ARGS_STR}"
  echo "  Image repo   : ${IMAGE_REPO}"
  echo "  Baseline     : ${BASELINE_VERSION}"
  echo "  Compare      : ${COMPARE_VERSION}"
  echo "  Bench mode   : ${BENCH_MODE}"
  echo "  Extra args   : ${EXTRA_ARGS_STR}"
  echo "  Output dir   : ${OUT_DIR}"
  echo "============================================================"

  echo ""
  echo "[${BASELINE_VERSION}] Resolving image tag..."
  if ! baseline_tag="$(resolve_image_tag "${BASELINE_VERSION}")"; then
    echo "ERROR: could not pull image for baseline version ${BASELINE_VERSION}"
    exit 1
  fi

  echo ""
  echo "[${COMPARE_VERSION}] Resolving image tag..."
  if ! compare_tag="$(resolve_image_tag "${COMPARE_VERSION}")"; then
    echo "ERROR: could not pull image for compare version ${COMPARE_VERSION}"
    exit 1
  fi

  if ! command -v criterion-table >/dev/null 2>&1; then
    echo "INFO: criterion-table not found — installing via: cargo install criterion-table"
    cargo install criterion-table
  fi

  bench_args_common=(--mode "${BENCH_MODE}" --format json "${EXTRA_ARGS[@]}")
  diff_out="${OUT_DIR}/benchmarks-${BASELINE_VERSION}-vs-${COMPARE_VERSION}.md"

  # Step 1: baseline version → JSON with version label (clean criterion state)
  echo ""
  echo "[${BASELINE_VERSION}] Running baseline bench..."
  rm -rf target/criterion
  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
  docker run -d --rm \
    --name "${CONTAINER_NAME}" \
    -p "${HOST_PORT}:9998" \
    "${IMAGE_REPO}:${baseline_tag}" \
    --database-type sqlite --sqlite-path /var/lib/cosmian-kms >/dev/null
  if ! wait_kms_ready "${IMAGE_REPO}:${baseline_tag}"; then
    echo "ERROR: baseline container did not become ready"
    exit 1
  fi
  echo "[${BASELINE_VERSION}] Server ready on http://127.0.0.1:${HOST_PORT}"
  set +e
  json_baseline="$(mktemp)"
  RUST_LOG=off cargo run -q -p ckms "${CKMS_CARGO_ARGS[@]}" -- --conf-path "${TMP_CKMS_CONF}" \
    bench "${bench_args_common[@]}" --version-label "v${BASELINE_VERSION}" >"${json_baseline}"
  baseline_status=$?
  set -e
  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
  if [[ ${baseline_status} -ne 0 ]]; then
    echo "ERROR: baseline bench failed"
    rm -f "${json_baseline}"
    exit 1
  fi

  # Step 2: compare version → JSON with version label (clean criterion state)
  echo ""
  echo "[${COMPARE_VERSION}] Running compare bench..."
  rm -rf target/criterion
  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
  docker run -d --rm \
    --name "${CONTAINER_NAME}" \
    -p "${HOST_PORT}:9998" \
    "${IMAGE_REPO}:${compare_tag}" \
    --database-type sqlite --sqlite-path /var/lib/cosmian-kms >/dev/null
  if ! wait_kms_ready "${IMAGE_REPO}:${compare_tag}"; then
    echo "ERROR: compare container did not become ready"
    rm -f "${json_baseline}"
    exit 1
  fi
  echo "[${COMPARE_VERSION}] Server ready on http://127.0.0.1:${HOST_PORT}"
  set +e
  json_compare="$(mktemp)"
  RUST_LOG=off cargo run -q -p ckms "${CKMS_CARGO_ARGS[@]}" -- --conf-path "${TMP_CKMS_CONF}" \
    bench "${bench_args_common[@]}" --version-label "v${COMPARE_VERSION}" >"${json_compare}"
  compare_status=$?
  set -e
  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
  if [[ ${compare_status} -ne 0 ]]; then
    echo "ERROR: compare bench failed"
    rm -f "${json_baseline}" "${json_compare}"
    exit 1
  fi

  # Step 3: baseline JSON first (→ reference column, 1.00x), then compare JSON → criterion-table
  {
    cat <<EOF
# Benchmark diff — KMS ${BASELINE_VERSION} vs ${COMPARE_VERSION}

Baseline image: \`${IMAGE_REPO}:${baseline_tag}\`
Compare image:  \`${IMAGE_REPO}:${compare_tag}\`

Source command:

\`\`\`bash
cargo run -p ckms ${CKMS_CARGO_ARGS_STR} -- bench ${bench_args_common[*]} --version-label v<VERSION>
cat v${BASELINE_VERSION}.json v${COMPARE_VERSION}.json | criterion-table
\`\`\`

EOF
    cat "${json_baseline}" "${json_compare}" | criterion-table
  } >"${diff_out}"

  rm -f "${json_baseline}" "${json_compare}"

  # Post-process: fix markdown lint issues from criterion-table output
  # MD025: criterion-table emits "# Benchmarks" which creates a second H1 → demote to ##
  # MD051: "pkcsv1.5" anchor fragment strips the dot → fix TOC links to match
  sed -i \
    -e 's/^# Benchmarks$/## Benchmarks/' \
    -e 's/(#rsa-pkcsv1\.5---/(#rsa-pkcsv15---/g' \
    "${diff_out}"

  echo ""
  echo "Diff report written to ${diff_out}"

  # Generate HTML version of diff report via pandoc if available
  diff_out_html="${diff_out%.md}.html"
  if command -v pandoc >/dev/null 2>&1; then
    pandoc -s \
      --metadata title="Benchmark diff \u2014 KMS ${BASELINE_VERSION} vs ${COMPARE_VERSION}" \
      -f gfm "${diff_out}" -o "${diff_out_html}" 2>/dev/null &&
      echo "HTML diff report written to ${diff_out_html}" ||
      echo "WARNING: pandoc HTML conversion failed"
  else
    echo "INFO: pandoc not found \u2014 skipping HTML conversion of ${diff_out}"
  fi
  exit 0
fi

# =============================================================================
# SINGLE-VERSION / RANGE MODE
# =============================================================================
echo "============================================================"
echo "  Cosmian KMS Docker benchmark runner"
echo "  CLI run      : cargo run -p ckms ${CKMS_CARGO_ARGS_STR}"
echo "  Image repo   : ${IMAGE_REPO}"
echo "  Version spec : ${VERSION_SPEC}"
echo "  Bench mode   : ${BENCH_MODE}"
echo "  Extra args   : ${EXTRA_ARGS_STR}"
echo "  Output dir   : ${OUT_DIR}"
echo "============================================================"

mapfile -t VERSIONS < <(expand_versions "${VERSION_SPEC}")

for version in "${VERSIONS[@]}"; do
  echo ""
  echo "[${version}] Resolving image tag..."
  if ! resolved_tag="$(resolve_image_tag "${version}")"; then
    out_file="${OUT_DIR}/benchmarks-${version}.md"
    cat >"${out_file}" <<EOF
# Benchmarks — KMS ${version} (Docker)

Status: FAILED

Reason: could not pull image tag \`${IMAGE_REPO}:${version}\` nor fallback \`${IMAGE_REPO}:${version}.0\`.
EOF
    echo "[${version}] Image not found, wrote failure report ${out_file}"
    continue
  fi

  echo "[${version}] Using image ${IMAGE_REPO}:${resolved_tag}"
  rm -rf target/criterion
  run_bench_version "${version}" "${resolved_tag}" --save-baseline "v${version}" || true
done

echo ""
echo "Done. Generated ${#VERSIONS[@]} benchmark file(s) in ${OUT_DIR}."
