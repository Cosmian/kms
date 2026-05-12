#!/usr/bin/env bash
# k8s-hsm-kmsv2 integration tests
#
# Clones the Cosmian/k8s-hsm-kmsv2 repository and runs the Go integration
# tests against SoftHSM2 (no minikube / Docker / cluster required).
#
# The Go test suite exercises the full PKCS#11 encrypt/decrypt round-trip
# through the KMS v2 plugin interface:
#   - TestProviderEncryptDecrypt     — AES-256-GCM via SoftHSM2 KEK
#   - TestProviderDecryptWrongData   — error path on malformed ciphertext
#   - TestServiceStatus              — gRPC Status() response
#   - TestServiceEncryptDecryptRoundTrip — gRPC Encrypt → Decrypt round-trip
#
# Usage (from kms repo root):
#   bash .github/scripts/nix.sh --variant non-fips test k8s-hsm
#   bash .github/scripts/test/test_k8s_hsm.sh
set -euo pipefail
set -x

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=.github/scripts/common.sh
source "${SCRIPT_DIR}/../common.sh"

REPO_ROOT=$(get_repo_root "$SCRIPT_DIR")
init_build_env "$@"
setup_test_logging

echo "============================================="
echo "Running k8s-hsm-kmsv2 integration tests"
echo "============================================="

# ── Locate libsofthsm2.so via the nix store (WITH_HSM=1 adds softhsm2-util) ──
SOFTHSM2_BIN_PATH="$(command -v softhsm2-util || true)"
if [ -z "$SOFTHSM2_BIN_PATH" ]; then
    echo "ERROR: softhsm2-util not found in PATH — ensure WITH_HSM=1 is set" >&2
    exit 1
fi
SOFTHSM2_PREFIX="$(dirname "$(dirname "$SOFTHSM2_BIN_PATH")")"
if [ -d "$SOFTHSM2_PREFIX/lib/softhsm" ]; then
    SOFTHSM2_LIB_DIR="$SOFTHSM2_PREFIX/lib/softhsm"
else
    SOFTHSM2_LIB_DIR="$SOFTHSM2_PREFIX/lib"
fi
# Use .dylib on macOS, .so on Linux
if [[ "$(uname)" == "Darwin" ]]; then
    export SOFTHSM2_LIB="${SOFTHSM2_LIB_DIR}/libsofthsm2.dylib"
else
    export SOFTHSM2_LIB="${SOFTHSM2_LIB_DIR}/libsofthsm2.so"
fi

if [ ! -f "$SOFTHSM2_LIB" ]; then
    echo "ERROR: SoftHSM2 library not found at $SOFTHSM2_LIB" >&2
    exit 1
fi
echo "==> Using SoftHSM2 library: $SOFTHSM2_LIB"

# ── Clone k8s-hsm-kmsv2 ───────────────────────────────────────────────────────
K8S_HSM_DIR=$(mktemp -d)
trap 'rm -rf "$K8S_HSM_DIR"' EXIT

echo "==> Cloning Cosmian/k8s-hsm-kmsv2..."
git clone --depth 1 "https://github.com/Cosmian/k8s-hsm-kmsv2.git" "$K8S_HSM_DIR"

# ── Run Go integration tests ──────────────────────────────────────────────────
cd "$K8S_HSM_DIR"

echo "==> Running: go test ./test/integration/..."
CGO_ENABLED=1 \
    LD_LIBRARY_PATH="${SOFTHSM2_LIB_DIR}${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}" \
    DYLD_LIBRARY_PATH="${SOFTHSM2_LIB_DIR}${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" \
    go test -v ./test/integration/... -timeout 120s

echo "============================================="
echo "k8s-hsm-kmsv2 integration tests PASSED"
echo "============================================="
