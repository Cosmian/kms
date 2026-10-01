#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# Alpine-container smoke test for the musl release tarballs.
#
# Unlike test_docker_image.sh (which exercises the glibc Nix Docker image),
# this script proves the musl server + CLI binaries actually run on *real*
# Alpine Linux — not just that they link correctly in the Nix sandbox. It:
#   1. Copies the server/CLI binaries into a throwaway image built FROM the
#      requested Alpine version (apk add libgcc only for the FIPS/dynamic
#      variant — see crate/server/src/openssl_providers.rs).
#   2. Starts the server and waits for /version.
#   3. Round-trips AES/RSA/EC (+ PQC/Covercrypt for non-FIPS) via ckms,
#      exercising deep call stacks (notably SLH-DSA) to catch musl's smaller
#      default thread-stack-size class of bug.
#   4. Confirms the FIPS provider loaded (FIPS) or the legacy-provider-skip
#      warning fired (non-FIPS) by grepping the container logs.
#
# Usage:
#   bash test_alpine_musl.sh --variant fips|non-fips \
#     --server-bin <path> --cli-bin <path> [--alpine-tag 3.20]
# ---------------------------------------------------------------------------

VARIANT="fips"
SERVER_BIN=""
CLI_BIN=""
ALPINE_TAG="3.20"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --variant)
      VARIANT="$2"
      shift 2
      ;;
    --server-bin)
      SERVER_BIN="$2"
      shift 2
      ;;
    --cli-bin)
      CLI_BIN="$2"
      shift 2
      ;;
    --alpine-tag)
      ALPINE_TAG="$2"
      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

[ -x "${SERVER_BIN}" ] || {
  echo "ERROR: --server-bin not found or not executable: ${SERVER_BIN}" >&2
  exit 1
}
[ -x "${CLI_BIN}" ] || {
  echo "ERROR: --cli-bin not found or not executable: ${CLI_BIN}" >&2
  exit 1
}

IMAGE_TAG="kms-alpine-smoke-${VARIANT}-${ALPINE_TAG}"
CONTAINER_NAME="kms-alpine-smoke-${VARIANT}-${ALPINE_TAG}-$$"
WORK_DIR="$(mktemp -d)"
# The usr/local/cosmian/lib/ tree copied below may still carry read-only
# directory permissions inherited (via the musl tarball's own `cp -r` from a
# read-only Nix store path, then preserved through tar) — `chmod -R u+w`
# before `rm -rf` ensures cleanup can never fail on that; `|| true` on both
# so a best-effort cleanup step never overrides this script's real exit code.
trap 'docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true; chmod -R u+w "${WORK_DIR}" 2>/dev/null || true; rm -rf "${WORK_DIR}" || true' EXIT

cp "${SERVER_BIN}" "${WORK_DIR}/cosmian_kms"
cp "${CLI_BIN}" "${WORK_DIR}/ckms"
chmod 755 "${WORK_DIR}/cosmian_kms" "${WORK_DIR}/ckms"

# FIPS dynamic-musl tarballs bundle a usr/local/cosmian/lib/ tree alongside
# the binary (FIPS provider module + openssl.cnf, dlopen'd at runtime —
# see nix/kms-server-musl.nix and package_musl_tarball.sh). Without it the
# server cannot start at all. Carry it into the image if the extracted
# tarball provided one (sibling of --server-bin).
SERVER_ROOT="$(cd "$(dirname "${SERVER_BIN}")" && pwd)"
HAS_COSMIAN_LIB=0
if [ -d "${SERVER_ROOT}/usr/local/cosmian/lib" ]; then
  HAS_COSMIAN_LIB=1
  mkdir -p "${WORK_DIR}/usr/local/cosmian/lib"
  cp -r "${SERVER_ROOT}/usr/local/cosmian/lib/." "${WORK_DIR}/usr/local/cosmian/lib/"
  chmod -R u+w "${WORK_DIR}/usr/local/cosmian/lib"
fi

if [ "${VARIANT}" = "fips" ]; then
  EXTRA_APK="RUN apk add --no-cache libgcc ca-certificates"
else
  EXTRA_APK="RUN apk add --no-cache ca-certificates"
fi

if [ "${HAS_COSMIAN_LIB}" = "1" ]; then
  OPENSSL_ENV="ENV OPENSSL_CONF=/usr/local/cosmian/lib/ssl/openssl.cnf
ENV OPENSSL_MODULES=/usr/local/cosmian/lib/ossl-modules
COPY usr /usr"
else
  OPENSSL_ENV=""
fi

cat >"${WORK_DIR}/Dockerfile" <<EOF
FROM alpine:${ALPINE_TAG}
${EXTRA_APK}
COPY cosmian_kms /usr/local/bin/cosmian_kms
COPY ckms /usr/local/bin/ckms
${OPENSSL_ENV}
EXPOSE 9998
ENTRYPOINT ["/usr/local/bin/cosmian_kms"]
EOF

echo "=== Building ${IMAGE_TAG} (alpine:${ALPINE_TAG}) ==="
docker build -t "${IMAGE_TAG}" "${WORK_DIR}"

HOST_PORT="$((19000 + RANDOM % 1000))"
echo "=== Starting server (variant=${VARIANT}, port=${HOST_PORT}) ==="
docker run -d --name "${CONTAINER_NAME}" -p "${HOST_PORT}:9998" "${IMAGE_TAG}" \
  --database-type sqlite --sqlite-path /tmp/data

echo "=== Waiting for /version ==="
for _ in $(seq 1 30); do
  if curl -sf "http://localhost:${HOST_PORT}/version" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
VERSION_OUTPUT="$(curl -sf "http://localhost:${HOST_PORT}/version")"
echo "Version: ${VERSION_OUTPUT}"
echo "${VERSION_OUTPUT}" | grep -qi "${VARIANT/non-fips/non-FIPS}" || {
  echo "ERROR: /version output does not mention ${VARIANT}: ${VERSION_OUTPUT}" >&2
  docker logs "${CONTAINER_NAME}" >&2
  exit 1
}

echo "=== Checking provider-loading log line ==="
LOGS="$(docker logs "${CONTAINER_NAME}" 2>&1)"
if [ "${VARIANT}" = "fips" ]; then
  echo "${LOGS}" | grep -q "Load FIPS provider" || {
    echo "ERROR: expected 'Load FIPS provider' in logs" >&2
    echo "${LOGS}" >&2
    exit 1
  }
else
  echo "${LOGS}" | grep -q "Legacy OpenSSL provider unavailable" || {
    echo "ERROR: expected the legacy-provider-skip warning in logs (fully static musl cannot dlopen)" >&2
    echo "${LOGS}" >&2
    exit 1
  }
fi

echo "=== Writing ckms config ==="
mkdir -p "${WORK_DIR}/conf"
cat >"${WORK_DIR}/conf/ckms.toml" <<EOF
print_json = false
[http_config]
server_url = "http://localhost:${HOST_PORT}"
EOF

CLI_IMAGE_TAG="${IMAGE_TAG}-cli"
cat >"${WORK_DIR}/Dockerfile.cli" <<EOF
FROM alpine:${ALPINE_TAG}
${EXTRA_APK}
COPY ckms /usr/local/bin/ckms
ENTRYPOINT ["/usr/local/bin/ckms"]
EOF
docker build -t "${CLI_IMAGE_TAG}" -f "${WORK_DIR}/Dockerfile.cli" "${WORK_DIR}"

run_ckms() {
  docker run --rm --network host \
    -v "${WORK_DIR}/conf/ckms.toml:/root/.cosmian/ckms.toml:ro" \
    -v "${WORK_DIR}:/data" \
    "${CLI_IMAGE_TAG}" "$@"
}

echo "=== AES round-trip ==="
AES_OUT="$(run_ckms sym keys create --number-of-bits 256 --algorithm aes)"
AES_KEY="$(echo "${AES_OUT}" | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')"
echo "Alpine musl smoke test" >"${WORK_DIR}/plain.txt"
run_ckms sym encrypt -k "${AES_KEY}" -o /data/cipher.bin /data/plain.txt
run_ckms sym decrypt -k "${AES_KEY}" -o /data/decrypted.txt /data/cipher.bin
diff "${WORK_DIR}/plain.txt" "${WORK_DIR}/decrypted.txt"
echo "AES round-trip OK"

echo "=== RSA round-trip ==="
RSA_OUT="$(run_ckms rsa keys create --size_in_bits 2048)"
RSA_PRIV="$(echo "${RSA_OUT}" | grep "Private key" | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')"
run_ckms rsa encrypt -k "${RSA_PRIV}_pk" -o /data/rsa.bin /data/plain.txt
run_ckms rsa decrypt -k "${RSA_PRIV}" -o /data/rsa_dec.txt /data/rsa.bin
diff "${WORK_DIR}/plain.txt" "${WORK_DIR}/rsa_dec.txt"
echo "RSA round-trip OK"

echo "=== EC key generation ==="
run_ckms ec keys create --curve nist-p256 >/dev/null
echo "EC key generation OK"

if [ "${VARIANT}" = "non-fips" ]; then
  echo "=== PQC: SLH-DSA-SHAKE-256f (deepest call stack — musl thread-stack regression canary) ==="
  SLH_OUT="$(run_ckms pqc keys create --algorithm slh-dsa-shake-256f)"
  SLH_PRIV="$(echo "${SLH_OUT}" | grep "Private key" | grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')"
  run_ckms pqc sign -k "${SLH_PRIV}" -o /data/sig.bin /data/plain.txt
  echo "SLH-DSA-SHAKE-256f sign OK"

  echo "=== PQC: ML-KEM-1024 and ML-DSA-87 ==="
  run_ckms pqc keys create --algorithm ml-kem-1024 >/dev/null
  run_ckms pqc keys create --algorithm ml-dsa-87 >/dev/null
  echo "ML-KEM/ML-DSA key generation OK"
fi

echo "=== Server stability check (no panics/restarts) ==="
docker inspect "${CONTAINER_NAME}" --format '{{.State.Status}} (restarts={{.RestartCount}})'
docker inspect "${CONTAINER_NAME}" --format '{{.State.Status}}' | grep -q "^running$" || {
  echo "ERROR: server container is not running anymore" >&2
  docker logs "${CONTAINER_NAME}" >&2
  exit 1
}

echo "====================================================="
echo "Alpine ${ALPINE_TAG} smoke test (${VARIANT}) PASSED"
echo "====================================================="
