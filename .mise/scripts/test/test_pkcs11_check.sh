#!/usr/bin/env bash
# Run the vendor-neutral pkcs11-check suite against a fresh plain KMS server.
# The HSM-KEK suite runs before this script; this script deliberately starts a
# separate server so the external suite observes the normal provider path.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
MISE_CONFIG_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
source "${MISE_CONFIG_ROOT}/.mise/lib/common.sh"
source "${MISE_CONFIG_ROOT}/.mise/lib/kms_build.sh"
source "${MISE_CONFIG_ROOT}/.mise/lib/kms_server.sh"
source "${MISE_CONFIG_ROOT}/.mise/lib/pkcs11_helpers.sh"
source "${MISE_CONFIG_ROOT}/.mise/lib/nix_helpers.sh"

VARIANT_ARG="non-fips"
LINK_ARG="static"
MARKER_ARG="smoke"
while [ $# -gt 0 ]; do
  case "$1" in
    --variant)
      VARIANT_ARG="$2"
      shift 2
      ;;
    --link)
      LINK_ARG="$2"
      shift 2
      ;;
    --marker)
      MARKER_ARG="$2"
      shift 2
      ;;
    *) print_error "Unknown argument: $1" ;;
  esac
done

if [ "${VARIANT_ARG}" != "non-fips" ]; then
  print_error "pkcs11-check requires the non-fips provider (got: ${VARIANT_ARG})"
fi

kms_init_env "${VARIANT_ARG}" "${LINK_ARG}"
setup_test_logging

# shellcheck disable=SC2119  # get_repo_root intentionally receives no task arguments
REPO_ROOT="$(get_repo_root)"
REPORT_DIR="${PKCS11_CHECK_REPORT_DIR:-${REPO_ROOT}/test_reports}"
mkdir -p "${REPORT_DIR}"

print_header "Running pkcs11-check (${MARKER_ARG:-full}) against a fresh plain KMS"

# The comprehensive HSM test already built these artifacts. Keep this call
# incremental so the runner is also useful on its own and after a partial run.
# shellcheck disable=SC2119  # build helper intentionally receives no task arguments
kms_build_all
export KMS_SKIP_BUILD=1
# shellcheck disable=SC2119  # library resolver intentionally receives no task arguments
PKCS11_LIB="$(get_cosmian_pkcs11_lib)"

trap kms_stop EXIT
kms_start "$(kms_pick_free_port)"
kms_write_ckms_conf "${KMS_URL}" >/dev/null
export CKMS_CONF="${KMS_CKMS_CONF}"

PKCS11_CHECK_VENV="${PKCS11_CHECK_VENV:-${REPO_ROOT}/target/pkcs11-check-venv}"
if [ ! -x "${PKCS11_CHECK_VENV}/bin/pkcs11-check" ]; then
  require_cmd python3 "Python 3.12 or newer is required for pkcs11-check"
  rm -rf "${PKCS11_CHECK_VENV}"
  python3 -m venv "${PKCS11_CHECK_VENV}"
  "${PKCS11_CHECK_VENV}/bin/python" -m pip install --quiet \
    -r "${SCRIPT_DIR}/requirements-pkcs11-check.txt"
fi
PKCS11_CHECK_BIN="${PKCS11_CHECK_VENV}/bin/pkcs11-check"

JSON_REPORT="${REPORT_DIR}/pkcs11_check_${MARKER_ARG:-full}.json"
JUNIT_REPORT="${REPORT_DIR}/pkcs11_check_${MARKER_ARG:-full}.xml"

run_check() {
  local format="$1" output_file="$2"
  local args=(test --module "${PKCS11_LIB}" --pin 1234 --slot 0
    --output "${format}" --output-file "${output_file}" --isolation file)
  if [ -n "${MARKER_ARG}" ]; then
    args+=(--marker "${MARKER_ARG}")
  fi

  set +e
  "${PKCS11_CHECK_BIN}" "${args[@]}"
  local status=$?
  set -e
  # pkcs11-check returns 1 for provider findings; the report validator below
  # decides whether the run contained a crash, timeout, incomplete unit, or
  # CRITICAL finding that must fail this task.
  if [ "${status}" -gt 1 ]; then
    print_error "pkcs11-check ${format} run failed before producing a usable report (exit ${status})"
  fi
}

run_check junit "${JUNIT_REPORT}"
run_check json "${JSON_REPORT}"

BASELINE_JSON="${PKCS11_CHECK_XFAIL_BASELINE:-}"
python3 - "${JSON_REPORT}" "${REPORT_DIR}/report.jsonl" "${BASELINE_JSON}" <<'PY'
import json
import pathlib
import sys
baseline_path = pathlib.Path(sys.argv[3]) if len(sys.argv) > 3 and sys.argv[3] else None

results_path = pathlib.Path(sys.argv[1])
report_log_path = pathlib.Path(sys.argv[2])
results = json.loads(results_path.read_text(encoding="utf-8"))
summary = results.get("summary", {})
problems = {
    key: int(summary.get(key, 0) or 0)
    for key in ("error", "crashed", "timeout")
    if int(summary.get(key, 0) or 0) > 0
}
if summary.get("incomplete"):
    problems["incomplete"] = 1
critical = 0
if report_log_path.is_file():
    for line in report_log_path.read_text(encoding="utf-8").splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("outcome") == "fail" and record.get("severity") == "CRITICAL":
            critical += 1
if critical:
    problems["critical_findings"] = critical
if baseline_path is not None:
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    expected_xfail = int(baseline.get("summary", {}).get("xfailed", 0) or 0)
    current_xfail = int(summary.get("xfailed", 0) or 0)
    allowed_delta = max(5, int(expected_xfail * 0.10))
    if abs(current_xfail - expected_xfail) > allowed_delta:
        problems["xfail_variance"] = {
            "baseline": expected_xfail,
            "current": current_xfail,
            "allowed_delta": allowed_delta,
        }
if problems:
    raise SystemExit(f"pkcs11-check safety gate failed: {problems}")
print(
    "pkcs11-check completed: "
    f"passed={summary.get('passed', 0)} "
    f"xfail={summary.get('xfailed', 0)} "
    f"failed={summary.get('failed', 0)} "
    f"skipped={summary.get('skipped', 0)}"
)
PY

print_success "pkcs11-check completed; reports: ${JSON_REPORT}, ${JUNIT_REPORT}"
