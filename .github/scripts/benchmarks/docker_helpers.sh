#!/usr/bin/env bash
# Shared Docker + KMS helpers for benchmark scripts.
#
# Usage (from benchmarks/run_benchmarks_docker.sh or run_benchmarks_load_tests_docker.sh):
#   source "$(cd "$(dirname "$0")" && pwd)/docker_helpers.sh"
#
# Requires these variables to be set by the caller before sourcing:
#   IMAGE_REPO   — Docker image repository (e.g. ghcr.io/cosmian/kms)
#   HOST_PORT    — local port to expose from the container

# Prevent double-sourcing
[ -n "${_DOCKER_HELPERS_SH_LOADED:-}" ] && return 0
_DOCKER_HELPERS_SH_LOADED=1

# Write a minimal ckms config pointing at the local Docker-hosted KMS.
# Usage: docker_write_ckms_conf <tmpfile> <port>
docker_write_ckms_conf() {
  local conf_file="$1"
  local port="${2:-${HOST_PORT:-9998}}"
  cat >"${conf_file}" <<EOF
[http_config]
server_url = "http://127.0.0.1:${port}"
accept_invalid_certs = true
EOF
}

# Resolve a KMS Docker image tag: try MAJOR.MINOR first, then MAJOR.MINOR.0.
# Returns the resolved tag string on stdout; exits non-zero if neither tag is pullable.
# Usage: docker_resolve_image_tag <version>
docker_resolve_image_tag() {
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

# Wait for the KMS server inside the Docker container to become ready on HOST_PORT.
# Usage: docker_wait_kms_ready <image_label_for_errors> [max_wait_seconds]
docker_wait_kms_ready() {
  local image="$1"
  local max_wait="${2:-45}"
  local i
  for ((i = 1; i <= max_wait; i++)); do
    if curl -sf "http://127.0.0.1:${HOST_PORT}/version" >/dev/null 2>&1; then
      return 0
    fi
    if ! docker ps --format '{{.Names}}' | grep -Fxq "${DOCKER_CONTAINER_NAME}"; then
      echo "ERROR: container exited early for image ${image}" >&2
      docker logs "${DOCKER_CONTAINER_NAME}" 2>/dev/null || true
      return 1
    fi
    sleep 1
  done
  echo "ERROR: KMS did not become ready on port ${HOST_PORT} for image ${image}" >&2
  docker logs "${DOCKER_CONTAINER_NAME}" 2>/dev/null || true
  return 1
}
