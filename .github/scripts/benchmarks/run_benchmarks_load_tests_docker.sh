#!/usr/bin/env bash
# run_benchmarks_load_tests_docker.sh — Run ckms load-test benchmarks against Dockerized KMS versions.
#
# Usage:
#   bash scripts/run_benchmarks_load_tests_docker.sh 5.18              # single version report
#   bash scripts/run_benchmarks_load_tests_docker.sh 5.17 5.18        # diff: baseline vs compare
#
# Two-version mode:
#   ARG1 = baseline version  (benchmarked first)
#   ARG2 = compare version   (benchmarked second, compared against baseline)
#   Output: documentation/docs/benchmarks/docker/load-tests-<v1>-vs-<v2>.md
#
# Optional env vars:
#   IMAGE_REPO       Docker image registry   (default: ghcr.io/cosmian/kms)
#   HOST_PORT        Port to expose on host  (default: 9998)
#   BENCH_MODE       Benchmark mode          (default: all)
#   EXTRA_ARGS       Extra args for ckms bench (default: "--time 5")
#   OUT_DIR          Output directory        (default: documentation/docs/benchmarks/docker)
#   CKMS_CARGO_ARGS  Cargo build args        (default: "--release --features non-fips")

set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "Usage: $0 <version> [<compare-version>]"
  echo "Examples:"
  echo "  $0 5.18"
  echo "  $0 5.17 5.18"
  exit 1
fi

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  echo "Usage: $0 <version> [<compare-version>]"
  echo "Examples:"
  echo "  $0 5.18"
  echo "  $0 5.17 5.18"
  exit 0
fi

VERSION_SPEC="$1"
COMPARE_SPEC="${2:-}"

IMAGE_REPO="${IMAGE_REPO:-ghcr.io/cosmian/kms}"
HOST_PORT="${HOST_PORT:-9998}"
BENCH_MODE="${BENCH_MODE:-all}"
EXTRA_ARGS_STR="${EXTRA_ARGS:---time 5}"
read -r -a EXTRA_ARGS <<<"${EXTRA_ARGS_STR}"
OUT_DIR="${OUT_DIR:-documentation/docs/benchmarks/docker}"
CKMS_CARGO_ARGS_STR="${CKMS_CARGO_ARGS:---release --features non-fips}"
read -r -a CKMS_CARGO_ARGS <<<"${CKMS_CARGO_ARGS_STR}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
cd "${ROOT_DIR}"

for cmd in cargo docker python3 curl; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "ERROR: ${cmd} is required but was not found in PATH."
    exit 1
  fi
done

mkdir -p "${OUT_DIR}"

CONTAINER_NAME="kms-bench-load-docker"
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

# Run ckms bench --load for one version and save the per-version markdown report.
# Usage: run_load_bench_version <version> <resolved_tag>
run_load_bench_version() {
  local version="$1"
  local resolved_tag="$2"

  local out_file="${OUT_DIR}/load-tests-${version}.md"
  local image="${IMAGE_REPO}:${resolved_tag}"

  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true

  echo "[${version}] Starting container ${image}..."
  docker run -d --rm \
    --name "${CONTAINER_NAME}" \
    -p "${HOST_PORT}:9998" \
    "${image}" \
    --database-type sqlite --sqlite-path /var/lib/cosmian-kms >/dev/null || {
    cat >"${out_file}" <<EOF
# Load Test Benchmarks — KMS ${version} (Docker)

Image: \`${image}\`

Status: FAILED

Reason: failed to start container.
EOF
    echo "[${version}] Container start failed, wrote failure report ${out_file}"
    return 1
  }

  if ! wait_kms_ready "${image}"; then
    cat >"${out_file}" <<EOF
# Load Test Benchmarks — KMS ${version} (Docker)

Image: \`${image}\`

Status: FAILED

Reason: container did not become ready.
EOF
    echo "[${version}] Readiness failed, wrote failure report ${out_file}"
    docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
    return 1
  fi
  echo "[${version}] Server ready on http://127.0.0.1:${HOST_PORT}"

  local server_version
  server_version="$(curl -sf "http://127.0.0.1:${HOST_PORT}/version" 2>/dev/null || echo "unknown")"

  echo "[${version}] Running ckms bench --load --mode ${BENCH_MODE} --format markdown..."
  rm -f target/criterion/benchmarks_load_tests.md
  local bench_args=(--load --mode "${BENCH_MODE}" --format markdown "${EXTRA_ARGS[@]}")

  set +e
  local bench_stderr
  bench_stderr="$(mktemp)"
  RUST_LOG=off cargo run -q -p ckms "${CKMS_CARGO_ARGS[@]}" -- \
    --conf-path "${TMP_CKMS_CONF}" bench "${bench_args[@]}" 2>"${bench_stderr}"
  local bench_status=$?
  set -e

  if [[ ${bench_status} -ne 0 ]]; then
    docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
    cat >"${out_file}" <<EOF
# Load Test Benchmarks — KMS ${version} (Docker)

Image: \`${image}\`

Status: FAILED

Reason: ckms bench --load command failed.

\`\`\`text
$(cat "${bench_stderr}")
\`\`\`
EOF
    echo "[${version}] Benchmark failed, wrote failure report ${out_file}"
    rm -f "${bench_stderr}"
    return 1
  fi
  cat "${bench_stderr}" >&2
  rm -f "${bench_stderr}"

  # HTML report — run while the container is still alive
  echo "[${version}] Running ckms bench --load --mode ${BENCH_MODE} --format html..."
  rm -rf target/criterion/load-report
  local html_bench_args=(--load --mode "${BENCH_MODE}" --format html "${EXTRA_ARGS[@]}")
  set +e
  RUST_LOG=off cargo run -q -p ckms "${CKMS_CARGO_ARGS[@]}" -- \
    --conf-path "${TMP_CKMS_CONF}" bench "${html_bench_args[@]}" >/dev/null 2>&1
  local html_bench_status=$?
  set -e

  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true

  local criterion_md="target/criterion/benchmarks_load_tests.md"
  if [[ -f "${criterion_md}" ]]; then
    local bench_md
    bench_md="$(cat "${criterion_md}")"
    cat >"${out_file}" <<EOF
# Load Test Benchmarks — KMS ${version} (Docker)

Image: \`${image}\`

Server version: ${server_version}

Source command:

\`\`\`bash
cargo run -p ckms ${CKMS_CARGO_ARGS_STR} -- bench ${bench_args[*]}
\`\`\`

${bench_md}
EOF
    echo "[${version}] Written ${out_file}"
    # Copy HTML report if the HTML bench run succeeded
    local out_html="${out_file%.md}.html"
    if [[ ${html_bench_status} -eq 0 && -f target/criterion/load-report/index.html ]]; then
      cp target/criterion/load-report/index.html "${out_html}"
      echo "[${version}] Written ${out_html}"
    else
      echo "[${version}] WARNING: HTML load test report not generated (gnuplot may be missing)"
    fi
  else
    cat >"${out_file}" <<EOF
# Load Test Benchmarks — KMS ${version} (Docker)

Image: \`${image}\`

Status: FAILED

Reason: no markdown output found (target/criterion/benchmarks_load_tests.md missing).
EOF
    echo "[${version}] No benchmark output, wrote failure report ${out_file}"
    return 1
  fi
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
  echo "  Cosmian KMS Docker load test diff"
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
  echo "[${BASELINE_VERSION}] Using image ${IMAGE_REPO}:${baseline_tag}"

  echo ""
  echo "[${COMPARE_VERSION}] Resolving image tag..."
  if ! compare_tag="$(resolve_image_tag "${COMPARE_VERSION}")"; then
    echo "ERROR: could not pull image for compare version ${COMPARE_VERSION}"
    exit 1
  fi
  echo "[${COMPARE_VERSION}] Using image ${IMAGE_REPO}:${compare_tag}"

  echo ""
  echo "[${BASELINE_VERSION}] Running load test benchmarks..."
  rm -f target/criterion/benchmarks_load_tests.md
  run_load_bench_version "${BASELINE_VERSION}" "${baseline_tag}"

  echo ""
  echo "[${COMPARE_VERSION}] Running load test benchmarks..."
  rm -f target/criterion/benchmarks_load_tests.md
  run_load_bench_version "${COMPARE_VERSION}" "${compare_tag}"

  diff_out="${OUT_DIR}/load-tests-${BASELINE_VERSION}-vs-${COMPARE_VERSION}.md"
  baseline_md="${OUT_DIR}/load-tests-${BASELINE_VERSION}.md"
  compare_md="${OUT_DIR}/load-tests-${COMPARE_VERSION}.md"

  echo ""
  echo "Generating comparison report ${diff_out}..."

  python3 - \
    "${baseline_md}" \
    "${compare_md}" \
    "v${BASELINE_VERSION}" \
    "v${COMPARE_VERSION}" \
    "${diff_out}" \
    "${IMAGE_REPO}:${baseline_tag}" \
    "${IMAGE_REPO}:${compare_tag}" \
    "${BASELINE_VERSION}" \
    "${COMPARE_VERSION}" \
    <<'PYTHON_EOF'
import sys
import re
from pathlib import Path


def parse_load_md(path: str) -> dict:
    """Parse a load test markdown file.

    Returns dict of {operation: [(concurrency, rps, p50, p95, p99, samples)]}
    """
    text = Path(path).read_text(encoding="utf-8")
    sections: dict = {}
    current_section = None
    for line in text.splitlines():
        m = re.match(r"^### (.+)$", line)
        if m:
            current_section = m.group(1).strip()
            if current_section not in sections:
                sections[current_section] = []
            continue
        if current_section and re.match(r"^\| *\d+", line):
            parts = [p.strip() for p in line.strip("|").split("|")]
            if len(parts) >= 6:
                try:
                    concurrency = int(parts[0])
                    rps = float(parts[1])
                    p50 = float(parts[2])
                    p95 = float(parts[3])
                    p99 = float(parts[4])
                    samples = int(parts[5])
                    sections[current_section].append(
                        (concurrency, rps, p50, p95, p99, samples)
                    )
                except (ValueError, IndexError):
                    pass
    return sections


def fmt_rps_delta(v1: float, v2: float) -> str:
    """Format throughput delta: higher is better."""
    if v1 == 0:
        return "N/A"
    pct = (v2 - v1) / v1 * 100
    sign = "+" if pct >= 0 else ""
    badge = "✅" if pct >= 0 else "❌"
    return f"{sign}{pct:.1f}% {badge}"


def generate_compare_md(
    base_data: dict,
    cmp_data: dict,
    v1_label: str,
    v2_label: str,
    out_path: str,
    baseline_image: str,
    compare_image: str,
    v1: str,
    v2: str,
) -> None:
    lines = [
        f"# Load Test diff — KMS {v1} vs {v2}",
        "",
        f"Baseline image: `{baseline_image}`",
        f"Compare image:  `{compare_image}`",
        "",
        "Source command:",
        "",
        "```bash",
        f"bash scripts/run_benchmarks_load_tests_docker.sh {v1} {v2}",
        "```",
        "",
        "> **Throughput (Req/s)**: higher is better — ✅ = faster, ❌ = slower",
        "> **Latency p50/p95/p99 (ms)**: lower is better",
        "",
        "## Results",
        "",
    ]

    all_ops = list(base_data.keys())
    for op in cmp_data:
        if op not in all_ops:
            all_ops.append(op)

    for op in all_ops:
        lines.append(f"### {op}")
        lines.append("")
        lines.append(
            f"| Concurrency"
            f" | {v1_label} Req/s | {v2_label} Req/s | Δ Throughput"
            f" | {v1_label} p50 (ms) | {v2_label} p50 (ms)"
            f" | {v1_label} p95 (ms) | {v2_label} p95 (ms)"
            f" | {v1_label} p99 (ms) | {v2_label} p99 (ms) |"
        )
        lines.append(
            "|-------------|"
            "------------|"
            "------------|"
            "--------------|"
            "----------------|"
            "----------------|"
            "----------------|"
            "----------------|"
            "----------------|"
            "----------------|"
        )

        v1_rows = {r[0]: r for r in base_data.get(op, [])}
        v2_rows = {r[0]: r for r in cmp_data.get(op, [])}

        all_conc = sorted(set(list(v1_rows.keys()) + list(v2_rows.keys())))
        for conc in all_conc:
            r1 = v1_rows.get(conc)
            r2 = v2_rows.get(conc)
            if r1 and r2:
                rps1, p50_1, p95_1, p99_1 = r1[1], r1[2], r1[3], r1[4]
                rps2, p50_2, p95_2, p99_2 = r2[1], r2[2], r2[3], r2[4]
                delta = fmt_rps_delta(rps1, rps2)
                lines.append(
                    f"| {conc}"
                    f" | {rps1:.1f} | {rps2:.1f} | {delta}"
                    f" | {p50_1:.1f} | {p50_2:.1f}"
                    f" | {p95_1:.1f} | {p95_2:.1f}"
                    f" | {p99_1:.1f} | {p99_2:.1f} |"
                )
            elif r1:
                rps1, p50_1, p95_1, p99_1 = r1[1], r1[2], r1[3], r1[4]
                lines.append(
                    f"| {conc}"
                    f" | {rps1:.1f} | N/A | N/A"
                    f" | {p50_1:.1f} | N/A"
                    f" | {p95_1:.1f} | N/A"
                    f" | {p99_1:.1f} | N/A |"
                )
            else:
                r2 = v2_rows[conc]
                rps2, p50_2, p95_2, p99_2 = r2[1], r2[2], r2[3], r2[4]
                lines.append(
                    f"| {conc}"
                    f" | N/A | {rps2:.1f} | N/A"
                    f" | N/A | {p50_2:.1f}"
                    f" | N/A | {p95_2:.1f}"
                    f" | N/A | {p99_2:.1f} |"
                )

        lines.append("")

    Path(out_path).write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    (
        base_md,
        cmp_md,
        v1_label,
        v2_label,
        out_file,
        baseline_image,
        compare_image,
        v1,
        v2,
    ) = sys.argv[1:10]

    base_data = parse_load_md(base_md)
    cmp_data = parse_load_md(cmp_md)
    generate_compare_md(
        base_data,
        cmp_data,
        v1_label,
        v2_label,
        out_file,
        baseline_image,
        compare_image,
        v1,
        v2,
    )
    print(f"Written: {out_file}")
PYTHON_EOF

  echo ""
  echo "Reports written to:"
  echo "  ${baseline_md}"
  echo "  ${compare_md}"
  echo "  ${diff_out}"
  exit 0
fi

# =============================================================================
# SINGLE-VERSION MODE
# =============================================================================
VERSION="${VERSION_SPEC}"

if [[ ! "${VERSION}" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]]; then
  echo "ERROR: version must be MAJOR.MINOR or MAJOR.MINOR.PATCH (got: ${VERSION})"
  exit 1
fi

echo "============================================================"
echo "  Cosmian KMS Docker load test runner"
echo "  CLI run      : cargo run -p ckms ${CKMS_CARGO_ARGS_STR}"
echo "  Image repo   : ${IMAGE_REPO}"
echo "  Version      : ${VERSION}"
echo "  Bench mode   : ${BENCH_MODE}"
echo "  Extra args   : ${EXTRA_ARGS_STR}"
echo "  Output dir   : ${OUT_DIR}"
echo "============================================================"

echo ""
echo "[${VERSION}] Resolving image tag..."
if ! resolved_tag="$(resolve_image_tag "${VERSION}")"; then
  echo "ERROR: could not pull image for version ${VERSION}"
  exit 1
fi
echo "[${VERSION}] Using image ${IMAGE_REPO}:${resolved_tag}"

echo ""
rm -f target/criterion/benchmarks_load_tests.md
run_load_bench_version "${VERSION}" "${resolved_tag}"

echo ""
echo "Done. Load test report written to ${OUT_DIR}/load-tests-${VERSION}.md"
