#!/usr/bin/env bash
set -euo pipefail

# ---------------------------------------------------------------------------
# Alpine-container smoke test for the Alpine .apk packages.
#
# Unlike test_docker_image.sh (which exercises the glibc Nix Docker image),
# this script proves the musl server + CLI packages actually install and run
# on *real* Alpine Linux — not just that they link correctly in the Nix
# sandbox. It:
#   1. `apk add`s the server/CLI packages into a throwaway image built FROM
#      the requested Alpine version (dependencies such as libgcc for the
#      FIPS/dynamic variant are pulled automatically from the apk metadata).
#   2. Starts the server and waits for /version.
#   3. Round-trips AES/RSA/EC (+ PQC/Covercrypt for non-FIPS) via ckms,
#      exercising deep call stacks (notably SLH-DSA) to catch musl's smaller
#      default thread-stack-size class of bug.
#   4. Confirms the FIPS provider loaded (FIPS) or the legacy-provider-skip
#      warning fired (non-FIPS) by grepping the container logs.
#
# Usage:
#   bash test_alpine_musl.sh --variant fips|non-fips \
#     --server-apk <path> --cli-apk <path> [--alpine-tag 3.20]
# ---------------------------------------------------------------------------

VARIANT="fips"
SERVER_APK=""
CLI_APK=""
ALPINE_TAG="3.20"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --variant)
      VARIANT="$2"
      shift 2
      ;;
    --server-apk)
      SERVER_APK="$2"
      shift 2
      ;;
    --cli-apk)
      CLI_APK="$2"
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

[ -f "${SERVER_APK}" ] || {
  echo "ERROR: --server-apk not found: ${SERVER_APK}" >&2
  exit 1
}
[ -f "${CLI_APK}" ] || {
  echo "ERROR: --cli-apk not found: ${CLI_APK}" >&2
  exit 1
}

IMAGE_TAG="kms-alpine-smoke-${VARIANT}-${ALPINE_TAG}"
CONTAINER_NAME="kms-alpine-smoke-${VARIANT}-${ALPINE_TAG}-$$"
WORK_DIR="$(mktemp -d)"
trap 'docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true; rm -rf "${WORK_DIR}" || true' EXIT

cp "${SERVER_APK}" "${WORK_DIR}/server.apk"
cp "${CLI_APK}" "${WORK_DIR}/cli.apk"

# The packages are GPG-signed out-of-band (.asc), not abuild-signed, hence
# --allow-untrusted. The server's OpenRC service normally exports
# OPENSSL_CONF/OPENSSL_MODULES; there is no init system in the container, so
# set them here (pointing at the package-installed FIPS provider tree).
# The packaged /etc/cosmian/kms.toml is removed so the server accepts the
# command-line arguments below (a default config file makes it reject them).
cat >"${WORK_DIR}/Dockerfile" <<EOF
FROM alpine:${ALPINE_TAG}
RUN apk add --no-cache ca-certificates
COPY server.apk cli.apk /tmp/
RUN apk add --no-cache --allow-untrusted /tmp/server.apk /tmp/cli.apk && rm /tmp/*.apk /etc/cosmian/kms.toml
ENV OPENSSL_CONF=/usr/local/cosmian/lib/ssl/openssl.cnf
ENV OPENSSL_MODULES=/usr/local/cosmian/lib/ossl-modules
EXPOSE 9998
ENTRYPOINT ["/usr/sbin/cosmian_kms"]
EOF

echo "=== Building ${IMAGE_TAG} (alpine:${ALPINE_TAG}) ==="
docker build -t "${IMAGE_TAG}" "${WORK_DIR}"

echo "=== Pre-check installed binaries (--version / --info) ==="
docker run --rm --entrypoint /usr/sbin/cosmian_kms "${IMAGE_TAG}" --version
docker run --rm --entrypoint /usr/sbin/cosmian_kms "${IMAGE_TAG}" --info
docker run --rm --user nobody --entrypoint /usr/bin/ckms "${IMAGE_TAG}" --version

echo "=== Starting server (variant=${VARIANT}) ==="
# Let Docker pick a free ephemeral host port (loopback only): no pick-then-bind race.
docker run -d --name "${CONTAINER_NAME}" -p 127.0.0.1::9998 "${IMAGE_TAG}" \
  --database-type sqlite --sqlite-path /tmp/data
HOST_PORT="$(docker port "${CONTAINER_NAME}" 9998/tcp | head -n1 | sed 's/.*://')"
echo "Server mapped to 127.0.0.1:${HOST_PORT}"

echo "=== Waiting for /version ==="
for _ in $(seq 1 30); do
  if curl -sf "http://127.0.0.1:${HOST_PORT}/version" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
VERSION_OUTPUT="$(curl -sf "http://127.0.0.1:${HOST_PORT}/version")"
echo "Version: ${VERSION_OUTPUT}"
echo "${VERSION_OUTPUT}" | grep -qi "${VARIANT/non-fips/non-FIPS}" || {
  echo "ERROR: /version output does not mention ${VARIANT}: ${VERSION_OUTPUT}" >&2
  docker logs "${CONTAINER_NAME}" >&2
  exit 1
}

echo "=== Checking UI endpoint ==="
curl -sfI "http://127.0.0.1:${HOST_PORT}/ui/index.html"

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

run_ckms() {
  docker run --rm --network host \
    -v "${WORK_DIR}/conf/ckms.toml:/root/.cosmian/ckms.toml:ro" \
    -v "${WORK_DIR}:/data" \
    --entrypoint /usr/bin/ckms \
    "${IMAGE_TAG}" "$@"
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
