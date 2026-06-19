#!/usr/bin/env bash
set -euo pipefail
set -x

# Secret backend integration test — Cosmian KMS
#
# Starts a local Cosmian KMS server (no auth, SQLite), imports a SecretData
# object with a known value via the KMIP HTTP API, runs the Rust #[ignore]
# integration test, then cleans up.
#
# No external credentials required; the server runs on localhost.
# Required tools: cargo, python3

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
source "${SCRIPT_DIR}/../common.sh"
# shellcheck source=.mise/lib/kms_server.sh
source "${SCRIPT_DIR}/../../lib/kms_server.sh"
# shellcheck source=.mise/lib/test_slots.sh
source "${SCRIPT_DIR}/../../lib/test_slots.sh"

init_build_env "$@"
setup_test_logging

require_cmd cargo "Cargo is required."
require_cmd python3 "python3 is required for JSON parsing."

echo "========================================="
echo "Running secret backend test: Cosmian KMS"
echo "Variant: ${VARIANT_NAME}"
echo "========================================="

KMS_HOST="127.0.0.1"
KMS_PORT=$(kms_pick_free_port)
KMS_URL="http://${KMS_HOST}:${KMS_PORT}"
SQLITE_PATH="$(mktemp -d -t kms-secret-test-XXXXXX)"
KMS_CONF_PATH="$(mktemp -t kms-secret-test-conf-XXXXXX.toml)"
KMS_PID=""

# The secret value we will store and expect back
SECRET_VALUE="ci-secret-value"
# UTF-8 hex encoding of SECRET_VALUE
SECRET_HEX="63692d7365637265742d76616c7565"
# Length in bits (15 bytes * 8)
SECRET_BITS=120

cleanup() {
  if [ -n "${KMS_PID:-}" ]; then
    echo "Stopping KMS server (PID ${KMS_PID})..."
    kill "${KMS_PID}" 2>/dev/null || true
    wait "${KMS_PID}" 2>/dev/null || true
  fi
  rm -rf "${SQLITE_PATH}" "${KMS_CONF_PATH}"
}
trap cleanup EXIT

# ── Write KMS config ─────────────────────────────────────────────────────────
cat >"${KMS_CONF_PATH}" <<EOF
[http]
hostname = "${KMS_HOST}"
port = ${KMS_PORT}

[db]
database_type = "sqlite"
sqlite_path = "${SQLITE_PATH}"
clear_database = true
EOF

# ── Build & start KMS server ─────────────────────────────────────────────────
echo "Building KMS server..."
# shellcheck disable=SC2068
cargo build ${FEATURES_FLAG[@]+${FEATURES_FLAG[@]}} --bin cosmian_kms

echo "Starting KMS server on port ${KMS_PORT}..."
"$(get_cargo_target_dir)/debug/cosmian_kms" \
  --config "${KMS_CONF_PATH}" \
  &
KMS_PID=$!

echo "Waiting for KMS to be ready..."
if ! _wait_for_port "${KMS_HOST}" "${KMS_PORT}" 60; then
  echo "ERROR: KMS server failed to start on port ${KMS_PORT}" >&2
  exit 1
fi
echo "KMS server ready."

# ── Import a SecretData object ────────────────────────────────────────────────
# Build a KMIP Register request carrying a SecretData (Password type) whose
# key material is the UTF-8 bytes of SECRET_VALUE.
echo "Registering SecretData object with value '${SECRET_VALUE}'..."
REGISTER_PAYLOAD=$(
  cat <<EOF
{
  "tag": "Register",
  "value": [
    {
      "tag": "ObjectType",
      "type": "Enumeration",
      "value": "SecretData"
    },
    {
      "tag": "Attributes",
      "value": []
    },
    {
      "tag": "SecretData",
      "value": [
        {
          "tag": "SecretDataType",
          "type": "Enumeration",
          "value": "Password"
        },
        {
          "tag": "KeyBlock",
          "value": [
            {
              "tag": "KeyFormatType",
              "type": "Enumeration",
              "value": "Opaque"
            },
            {
              "tag": "KeyValue",
              "value": [
                {
                  "tag": "KeyMaterial",
                  "type": "ByteString",
                  "value": "${SECRET_HEX}"
                }
              ]
            },
            {
              "tag": "CryptographicLength",
              "type": "Integer",
              "value": ${SECRET_BITS}
            }
          ]
        }
      ]
    }
  ]
}
EOF
)

export REGISTER_PAYLOAD KMS_URL
REGISTER_RESPONSE=$(
  python3 - <<'PYEOF'
import json, os, urllib.request
url = os.environ["KMS_URL"] + "/kmip/2_1"
payload = os.environ["REGISTER_PAYLOAD"].encode()
req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
with urllib.request.urlopen(req) as resp:
    print(resp.read().decode())
PYEOF
)

echo "Register response: ${REGISTER_RESPONSE}"

# Extract the UniqueIdentifier from the TTLV JSON response
OBJECT_ID=$(
  REGISTER_RESPONSE="${REGISTER_RESPONSE}" python3 - <<'PYEOF'
import sys, json, os

def find_unique_id(node):
    """Recursively search for UniqueIdentifier in TTLV JSON."""
    if isinstance(node, dict):
        if node.get("tag") == "UniqueIdentifier":
            return node.get("value")
        for v in node.values():
            result = find_unique_id(v)
            if result:
                return result
    elif isinstance(node, list):
        for item in node:
            result = find_unique_id(item)
            if result:
                return result
    return None

data = json.loads(os.environ["REGISTER_RESPONSE"])
uid = find_unique_id(data)
if uid:
    print(uid)
    sys.exit(0)
sys.exit(1)
PYEOF
)

if [ -z "${OBJECT_ID:-}" ]; then
  echo "ERROR: failed to extract UniqueIdentifier from Register response" >&2
  exit 1
fi
echo "Registered SecretData with ID: ${OBJECT_ID}"

# ── Run the integration test ──────────────────────────────────────────────────
echo "Running Cosmian KMS secret backend integration test..."
# shellcheck disable=SC2068
KMS_TEST_COSMIAN_KMS_URI="cosmian-kms://${KMS_HOST}:${KMS_PORT}/${OBJECT_ID}" \
  KMS_TEST_COSMIAN_KMS_EXPECTED="${SECRET_VALUE}" \
  cargo test ${FEATURES_FLAG[@]+${FEATURES_FLAG[@]}} -p cosmian_kms_server --lib -- \
  --ignored --nocapture test_secret_cosmian_kms

echo "Cosmian KMS secret backend test completed successfully."
