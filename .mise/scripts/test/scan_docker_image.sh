#!/usr/bin/env bash
# Scan a KMS Docker image with Syft (SBOM) and Grype (vulnerabilities).
# Also scans Cargo.lock and ui/pnpm-lock.yaml: the Rust crates and the Web UI bundle are
# compiled into the image, where Syft cannot identify them.
# Fails on any finding of severity >= GRYPE_FAIL_ON (default: high) that has a fix available.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../../.." && pwd)"
: "${DOCKER_IMAGE_NAME:?DOCKER_IMAGE_NAME must be set (mise task: test:docker-scan --image)}"
: "${VARIANT:?VARIANT must be set by the caller (mise task: test:docker-scan)}"
FAIL_ON="${GRYPE_FAIL_ON:-high}"
OUT_DIR="${REPO_ROOT}/target/image-scan/${VARIANT}"
TOOLS_LINK="${REPO_ROOT}/result-image-scan-tools"

nix-build "${REPO_ROOT}/default.nix" -A image-scan-tools -o "${TOOLS_LINK}"
export PATH="${TOOLS_LINK}/bin:${PATH}"
mkdir -p "${OUT_DIR}"
syft version
grype version

syft scan "docker:${DOCKER_IMAGE_NAME}" \
  -o "spdx-json=${OUT_DIR}/sbom.spdx.json" \
  -o "cyclonedx-json=${OUT_DIR}/sbom.cdx.json"

status=0
scan() {
  local name="$1" source="$2"
  echo "=== Grype: ${name} (${source}) ==="
  grype "${source}" --only-fixed --fail-on "${FAIL_ON}" \
    -o table -o "json=${OUT_DIR}/grype-${name}.json" | tee "${OUT_DIR}/grype-${name}.txt" || status=1
}
scan image "sbom:${OUT_DIR}/sbom.spdx.json"
scan cargo "file:${REPO_ROOT}/Cargo.lock"
scan pnpm "file:${REPO_ROOT}/ui/pnpm-lock.yaml"

if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "### Grype — ${DOCKER_IMAGE_NAME} (fail on fixable >= ${FAIL_ON})"
    for name in image cargo pnpm; do
      printf '#### %s\n```\n' "${name}"
      cat "${OUT_DIR}/grype-${name}.txt"
      printf '```\n'
    done
  } >>"${GITHUB_STEP_SUMMARY}"
fi
exit "${status}"
