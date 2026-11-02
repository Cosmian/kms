#!/usr/bin/env bash
# Generate SQLite migration fixtures with each release's server and ckms.
set -euo pipefail

# shellcheck source=.mise/lib/common.sh
source "${MISE_CONFIG_ROOT}/.mise/lib/common.sh"
REPO_ROOT="$(get_repo_root)"
require_cmd docker
require_cmd python3
require_cmd curl
docker_ready || print_error "Docker must be running to generate migration fixtures."
[ "$#" -le 1 ] || print_error "Usage: $0 [VERSION]"
SELECTED_VERSION="${1:-}"

# Resolve pins with: docker pull ghcr.io/cosmian/kms:<version>
# The Digest line identifies the immutable release manifest.
readonly IMAGES=(
  "ghcr.io/cosmian/kms:5.20.0@sha256:a74dc266e85a75e038ab75243afe64c2d5f65a0219a5561eb99d2b7febc47e80"
  "ghcr.io/cosmian/kms:5.24.0@sha256:a8c2b6577ce366c534fb29e388b8b7b473fc8a4445fa2ab6f32c8da13004e50a"
  "ghcr.io/cosmian/kms:5.28.0@sha256:7b60fd4484930969906caa5722b727054ff96d49339ce81e3c64ca9e4278540e"
  "ghcr.io/cosmian/kms:5.29.0@sha256:a5592576c17854868c8abe6536b0ab89c49f31eb978c2778d2ee471330e083c8"
)
WORK_DIR="$(mktemp -d -t kms-db-migration-fixtures-XXXXXX)"
CONTAINER_ID=""

cleanup() {
  local status="$?"
  if [ -n "${CONTAINER_ID}" ]; then
    if ! docker rm --force "${CONTAINER_ID}" >/dev/null; then
      print_warning "Could not remove fixture container ${CONTAINER_ID}."
      status=1
    fi
  fi
  if ! rm -rf -- "${WORK_DIR:?}"; then
    print_warning "Could not remove fixture scratch directory ${WORK_DIR}."
    status=1
  fi
  exit "${status}"
}
trap cleanup EXIT

fixture_ckms() {
  docker exec "${CONTAINER_ID}" /usr/local/bin/ckms --url http://127.0.0.1:9998 "$@"
}

populate_fixture() {
  fixture_ckms sym keys create --number-of-bits 256 --algorithm aes --tag mig mig_kek
  fixture_ckms sym keys create --number-of-bits 256 --algorithm aes --tag mig --wrapping-key-id mig_kek mig_wrapped
  fixture_ckms rsa keys create --size_in_bits 2048 --tag mig mig_rsa
  fixture_ckms sym keys create --number-of-bits 256 --algorithm aes --tag mig mig_revoked
  fixture_ckms sym keys revoke --key-id mig_revoked "Migration fixture revocation"
  fixture_ckms certificates certify --generate-key-pair --algorithm rsa2048 \
    --certificate-id mig_cert --subject-name "CN=Migration fixture" --tag mig
  fixture_ckms access-rights grant --object-uid mig_kek mig_user get encrypt decrypt
}

# Docker can accept TCP connections before the KMS endpoint is ready.
wait_for_fixture_ready() {
  local port="$1" deadline=$((SECONDS + 60)) status=""
  while ((SECONDS < deadline)); do
    if status="$(run_isolated curl -sS --max-time 2 -o /dev/null -w '%{http_code}' \
      -X POST -H 'Content-Type: application/json' -d '{}' \
      "http://127.0.0.1:${port}/kmip/2_1" 2>/dev/null)" && [ "${status}" = 422 ]; then
      return 0
    fi
    if [ "$(docker inspect --format '{{.State.Running}}' "${CONTAINER_ID}")" != true ]; then
      print_warning "Fixture container exited before its KMIP endpoint was ready."
      return 1
    fi
    sleep 1
  done
  print_warning "Fixture KMIP endpoint did not return HTTP 422 (last status: ${status:-000})."
  return 1
}

write_fixture() {
  python3 - "$1" "$2" "$3" <<'PY'
import json
import sqlite3
import sys
from pathlib import Path

source, destination = map(Path, sys.argv[1:3])
version = sys.argv[3]
with sqlite3.connect(source) as connection:
    connection.execute("VACUUM INTO ?", (str(destination),))
with sqlite3.connect(destination) as connection:
    columns = {row[1] for row in connection.execute("PRAGMA table_info(objects)")}
    parameters = dict(connection.execute("SELECT name, value FROM parameters"))
    objects = dict(connection.execute("SELECT id, state FROM objects"))
    expected = {"mig_kek", "mig_wrapped", "mig_rsa", "mig_rsa_pk", "mig_revoked", "mig_cert"}
    if not expected <= objects.keys() or len(objects) != 8:
        raise RuntimeError(f"Missing fixture objects: {expected - objects.keys()}")
    if objects["mig_revoked"] != "Deactivated":
        raise RuntimeError("The revoked fixture key must be deactivated")
    if ("wrapping_key_id" in columns) != (version in {"5.28.0", "5.29.0"}):
        raise RuntimeError(f"Unexpected wrapping_key_id column for {version}")
    if parameters.get("wrapping_key_id_backfilled") != (
        "true" if version in {"5.28.0", "5.29.0"} else None
    ):
        raise RuntimeError(f"Unexpected wrapping backfill marker for {version}")
    if "db_version" in parameters:
        raise RuntimeError(f"Unexpected database version for {version}")
    if parameters.get("certificate_serial_tag_backfilled") != (
        "true" if version == "5.29.0" else None
    ):
        raise RuntimeError(f"Unexpected serial-tag marker for {version}")
    tagged = {row[0] for row in connection.execute("SELECT id FROM tags WHERE tag='mig'")}
    if tagged != objects.keys():
        raise RuntimeError("Every fixture object must carry the mig tag")
    grant = connection.execute(
        "SELECT permissions FROM read_access WHERE id='mig_kek' AND userid='mig_user'"
    ).fetchone()
    if grant is None or set(json.loads(grant[0])) != {"get", "encrypt", "decrypt"}:
        raise RuntimeError("Missing or incorrect mig_user grant")
    serial_tags = connection.execute(
        "SELECT count(*) FROM tags WHERE id='mig_cert' AND tag GLOB '_serial=*'"
    ).fetchone()[0]
    if serial_tags != (1 if version == "5.29.0" else 0):
        raise RuntimeError(f"Unexpected certificate serial tag count for {version}")
    if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
        raise RuntimeError(f"Invalid SQLite fixture for {version}")
    print(f"{version}: verified {len(objects)} objects, unversioned SQLite fixture")
PY
}

generate_fixture() {
  local image="$1" version="$2"
  local data_dir="${WORK_DIR}/${version}"
  local output_dir="${REPO_ROOT}/test_data/db_migration/${version}/sqlite"
  local address port
  mkdir -p "${data_dir}" "${output_dir}"
  [ ! -e "${output_dir}/kms.db" ] || print_error "Fixture already exists: ${output_dir}/kms.db"
  print_status "Generating SQLite fixture with ${image}"
  CONTAINER_ID="$(docker run --detach --publish 127.0.0.1::9998 \
    --volume "${data_dir}:/data" "${image}" \
    --database-type sqlite --sqlite-path /data)"
  address="$(docker port "${CONTAINER_ID}" 9998/tcp)"
  port="${address##*:}"
  if ! wait_for_fixture_ready "${port}"; then
    docker logs "${CONTAINER_ID}" >&2
    print_error "Release ${version} did not start."
  fi
  fixture_ckms --version
  populate_fixture
  docker exec "${CONTAINER_ID}" chown -R "$(id -u):$(id -g)" /data
  docker stop "${CONTAINER_ID}" >/dev/null
  docker rm "${CONTAINER_ID}" >/dev/null
  CONTAINER_ID=""
  write_fixture "${data_dir}/kms.db" "${output_dir}/kms.db" "${version}"
}

selected=false
for image in "${IMAGES[@]}"; do
  version="${image#*:}"
  version="${version%%@*}"
  if [ -n "${SELECTED_VERSION}" ] && [ "${version}" != "${SELECTED_VERSION}" ]; then
    continue
  fi
  selected=true
  generate_fixture "${image}" "${version}"
done
[ "${selected}" = true ] || print_error "Unknown fixture version: ${SELECTED_VERSION}"
print_success "Released SQLite migration fixtures generated and verified."
