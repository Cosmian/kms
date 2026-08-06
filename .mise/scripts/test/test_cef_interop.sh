#!/usr/bin/env bash
# CEF export interoperability test.
#
# Validates that `ckms audit export --format cef` produces output that a
# real, independent, widely used CEF parser (jc: kellyjonbrazil/jc) can
# correctly ingest — i.e. that the KMS's hand-rolled CEF serialisation
# (crate/access/src/audit/cef.rs) is genuinely compatible with third-party
# SIEM/CEF tooling, not just self-consistent with our own Rust unit tests.
#
# No live KMS server is involved: the fixture is a real JSONL audit-log
# artifact previously produced by an actual KMS run, so no server startup or
# ephemeral port handling is required for this test.
#
# Usage:
#   bash .mise/scripts/nix.sh test cef_interop
#   bash .mise/scripts/test/test_cef_interop.sh [--variant fips|non-fips]
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../common.sh"
source "${SCRIPT_DIR}/../../lib/kms_build.sh"

init_build_env "$@"
setup_test_logging

HELPER="${SCRIPT_DIR}/cef_interop_helper.py"
FIXTURE="$(get_repo_root)/test_data/audit/kms-audit-e2e.jsonl"
KMS_VERSION="test-interop-1.0.0"

VENV_DIR=""
CEF_OUTPUT=""

cleanup() {
  [ -n "${VENV_DIR:-}" ] && { rm -rf "${VENV_DIR}" || true; }
  [ -n "${CEF_OUTPUT:-}" ] && { rm -f "${CEF_OUTPUT}" || true; }
}
trap cleanup EXIT

echo "==========================================="
echo "CEF export interoperability test (jc)"
echo "==========================================="

if [ ! -f "${FIXTURE}" ]; then
  echo "ERROR: fixture not found at ${FIXTURE}" >&2
  exit 1
fi

# ── Build ckms and export the fixture as CEF ─────────────────────────────────

echo "==> Building ckms CLI..."
kms_build_cli
ckms_bin=$(get_ckms_bin)

echo "==> Exporting fixture as CEF (kms-version=${KMS_VERSION})..."
CEF_OUTPUT="$(mktemp -t cef-export-XXXXXX.txt)"
"${ckms_bin}" audit export \
  --path "${FIXTURE}" \
  --format cef \
  --kms-version "${KMS_VERSION}" \
  >"${CEF_OUTPUT}"

fixture_lines=$(grep -c . "${FIXTURE}")
cef_lines=$(grep -c . "${CEF_OUTPUT}")
if [ "${fixture_lines}" != "${cef_lines}" ]; then
  echo "ERROR: fixture has ${fixture_lines} events but CEF output has ${cef_lines} lines" >&2
  exit 1
fi
echo "    Exported ${cef_lines} CEF line(s)."

# ── Python venv setup (jc) ───────────────────────────────────────────────────

echo "==> Setting up Python virtualenv with jc..."
VENV_DIR="$(mktemp -d -t cef-interop-venv-XXXXXX)"
python3 -m venv "${VENV_DIR}"
# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"
pip install --quiet -r "${SCRIPT_DIR}/requirements-cef.txt"
echo "    Python venv OK ($(python3 --version), jc $(pip show jc | grep ^Version | awk '{print $2}'))"

# ── Round-trip validation ────────────────────────────────────────────────────

echo ""
echo "==> Parsing CEF output with jc and validating field-by-field round-trip..."
python3 "${HELPER}" --jsonl "${FIXTURE}" --cef "${CEF_OUTPUT}"

echo ""
echo "CEF export interoperability test passed."
