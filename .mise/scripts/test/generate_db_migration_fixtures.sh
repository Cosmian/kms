#!/usr/bin/env bash
# Generate migration fixtures with each release's server and ckms.
# Usage: generate_db_migration_fixtures.sh [sqlite|postgresql|mysql|all] [VERSION]
set -euo pipefail

# shellcheck source=.mise/lib/common.sh
source "${MISE_CONFIG_ROOT}/.mise/lib/common.sh"
REPO_ROOT="$(get_repo_root)"
require_cmd docker
require_cmd python3
require_cmd curl
docker_ready || print_error "Docker must be running to generate migration fixtures."
[ "$#" -le 2 ] || print_error "Usage: $0 [sqlite|postgresql|mysql|all] [VERSION]"
SELECTED_VERSION="${2:-}"

case "${1:-all}" in
  sqlite | postgresql | mysql) readonly BACKENDS=("$1") ;;
  all) readonly BACKENDS=(sqlite postgresql mysql) ;;
  *) print_error "Usage: $0 [sqlite|postgresql|mysql|all]" ;;
esac

# Resolve pins with: docker pull <image>:<tag>
# The Digest line identifies the immutable release manifest.
readonly IMAGES=(
  "ghcr.io/cosmian/kms:5.14.0@sha256:137d2fcfaa149bb5060cc932f515bb53ee63c5a3fc2224586711352d9455e7c7"
  "ghcr.io/cosmian/kms:5.20.0@sha256:a74dc266e85a75e038ab75243afe64c2d5f65a0219a5561eb99d2b7febc47e80"
  "ghcr.io/cosmian/kms:5.24.0@sha256:a8c2b6577ce366c534fb29e388b8b7b473fc8a4445fa2ab6f32c8da13004e50a"
  "ghcr.io/cosmian/kms:5.28.0@sha256:7b60fd4484930969906caa5722b727054ff96d49339ce81e3c64ca9e4278540e"
  "ghcr.io/cosmian/kms:5.29.0@sha256:a5592576c17854868c8abe6536b0ab89c49f31eb978c2778d2ee471330e083c8"
)
# 5.14.0 ships no ckms, so the 5.20.0 client drives it.
readonly CKMS_FALLBACK_IMAGE="${IMAGES[1]}"
readonly POSTGRES_IMAGE="postgres:18@sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336"
readonly MYSQL_IMAGE="mysql:8.0@sha256:99d774bf02a48a1bb1c599920d2571946d31e5940b854b02737d5e95c184358f"
# Throwaway credentials of the fixture database containers.
readonly DB_PASSWORD="kms-fixture"

# One line of facts per restored dump; expected_facts spells out the required values.
PG_FACTS="$(
  cat <<'SQL'
SELECT concat_ws(' ',
  'objects=' || (SELECT count(*) FROM objects),
  'named=' || (SELECT count(*) FROM objects WHERE id IN
    ('mig_kek', 'mig_wrapped', 'mig_rsa', 'mig_rsa_pk', 'mig_revoked', 'mig_cert')),
  'revoked=' || (SELECT state FROM objects WHERE id = 'mig_revoked'),
  'untagged=' || (SELECT count(*) FROM objects o
    WHERE NOT EXISTS (SELECT 1 FROM tags t WHERE t.id = o.id AND t.tag = 'mig')),
  'grant=' || (SELECT string_agg(p, ',' ORDER BY p)
    FROM read_access, json_array_elements_text(permissions) p
    WHERE id = 'mig_kek' AND userid = 'mig_user'),
  'serial_tags=' || (SELECT count(*) FROM tags WHERE id = 'mig_cert' AND tag LIKE '_serial=%'),
  'wrapping_column=' || (SELECT count(*) FROM information_schema.columns
    WHERE table_name = 'objects' AND column_name = 'wrapping_key_id'),
  'parameters=' || (SELECT coalesce(string_agg(name || ':' || value, ',' ORDER BY name), '')
    FROM parameters),
  'attributes=' || (SELECT data_type FROM information_schema.columns
    WHERE table_name = 'objects' AND column_name = 'attributes'));
SQL
)"
readonly PG_FACTS
MYSQL_FACTS="$(
  cat <<'SQL'
SELECT CONCAT_WS(' ',
  CONCAT('objects=', (SELECT COUNT(*) FROM objects)),
  CONCAT('named=', (SELECT COUNT(*) FROM objects WHERE id IN
    ('mig_kek', 'mig_wrapped', 'mig_rsa', 'mig_rsa_pk', 'mig_revoked', 'mig_cert'))),
  CONCAT('revoked=', (SELECT state FROM objects WHERE id = 'mig_revoked')),
  CONCAT('untagged=', (SELECT COUNT(*) FROM objects o
    WHERE NOT EXISTS (SELECT 1 FROM tags t WHERE t.id = o.id AND t.tag = 'mig'))),
  CONCAT('grant=', (SELECT GROUP_CONCAT(j.p ORDER BY j.p)
    FROM read_access, JSON_TABLE(permissions, '$[*]' COLUMNS (p VARCHAR(32) PATH '$')) j
    WHERE id = 'mig_kek' AND userid = 'mig_user')),
  CONCAT('serial_tags=', (SELECT COUNT(*) FROM tags WHERE id = 'mig_cert' AND tag LIKE '_serial=%')),
  CONCAT('wrapping_column=', (SELECT COUNT(*) FROM information_schema.columns
    WHERE table_schema = DATABASE() AND table_name = 'objects' AND column_name = 'wrapping_key_id')),
  CONCAT('parameters=', COALESCE((SELECT GROUP_CONCAT(name, ':', value ORDER BY name)
    FROM parameters), '')));
SQL
)"
readonly MYSQL_FACTS

WORK_DIR="$(mktemp -d -t kms-db-migration-fixtures-XXXXXX)"
readonly NETWORK="kms-fixtures-${WORK_DIR##*-}"
readonly KMS_NAME="${NETWORK}-kms" DB_NAME="${NETWORK}-db"
CKMS_IMAGE=""

cleanup() {
  local status="$?"
  # docker rm --force succeeds on a missing container, so a failure here is real.
  if ! docker rm --force "${KMS_NAME}" "${DB_NAME}" >/dev/null 2>&1; then
    print_warning "Could not remove fixture containers ${KMS_NAME} and ${DB_NAME}."
    status=1
  fi
  if docker network inspect "${NETWORK}" >/dev/null 2>&1 &&
    ! docker network rm "${NETWORK}" >/dev/null; then
    print_warning "Could not remove fixture network ${NETWORK}."
    status=1
  fi
  if ! rm -rf -- "${WORK_DIR:?}"; then
    print_warning "Could not remove fixture scratch directory ${WORK_DIR}."
    status=1
  fi
  exit "${status}"
}
trap cleanup EXIT

fixture_ckms() {
  docker run --rm --network "${NETWORK}" --entrypoint /usr/local/bin/ckms "${CKMS_IMAGE}" \
    --url "http://${KMS_NAME}:9998" "$@"
}

# Start a release server on the fixture network; the arguments follow `docker run`.
# docker-proxy accepts TCP before the server listens, so readiness is an actual KMS call.
start_kms() {
  docker run --detach --name "${KMS_NAME}" --network "${NETWORK}" "$@" >/dev/null
  for _ in $(seq 1 60); do
    if fixture_ckms server version >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  docker logs "${KMS_NAME}" >&2
  print_error "The KMS server did not start."
}

stop_kms() {
  docker stop "${KMS_NAME}" >/dev/null
  docker rm "${KMS_NAME}" >/dev/null
}

# Run one client action against the fixture database container.
db_client() {
  local mysql_env=(--env "MYSQL_PWD=${DB_PASSWORD}")
  case "$1/$2" in
    postgresql/ready) docker exec "${DB_NAME}" pg_isready --quiet --host 127.0.0.1 --username kms --dbname kms ;;
    postgresql/dump) docker exec "${DB_NAME}" pg_dump --no-owner --no-privileges --inserts --username kms kms ;;
    postgresql/restore) docker exec --interactive "${DB_NAME}" psql --quiet --set ON_ERROR_STOP=1 --username kms --dbname kms ;;
    postgresql/facts) docker exec "${DB_NAME}" psql --no-align --tuples-only --username kms --dbname kms --command "${PG_FACTS}" ;;
    mysql/ready) docker exec "${mysql_env[@]}" "${DB_NAME}" mysqladmin ping --silent --host 127.0.0.1 --user kms ;;
    mysql/dump)
      docker exec "${mysql_env[@]}" "${DB_NAME}" mysqldump --no-tablespaces --skip-add-locks \
        --skip-lock-tables --skip-comments --set-gtid-purged=OFF --user kms kms
      ;;
    mysql/restore) docker exec --interactive "${mysql_env[@]}" "${DB_NAME}" mysql --user kms kms ;;
    mysql/facts) docker exec "${mysql_env[@]}" "${DB_NAME}" mysql --batch --skip-column-names --user kms kms --execute "${MYSQL_FACTS}" ;;
    *) print_error "Unknown database client action: $1/$2" ;;
  esac
}

# Start an empty database server. The images run their init server without TCP,
# so a TCP probe only succeeds against the final server.
start_db() {
  local backend="$1"
  if [ "${backend}" = postgresql ]; then
    docker run --detach --name "${DB_NAME}" --network "${NETWORK}" --env POSTGRES_USER=kms \
      --env POSTGRES_PASSWORD="${DB_PASSWORD}" --env POSTGRES_DB=kms "${POSTGRES_IMAGE}" >/dev/null
  else
    docker run --detach --name "${DB_NAME}" --network "${NETWORK}" --env MYSQL_USER=kms \
      --env MYSQL_PASSWORD="${DB_PASSWORD}" --env MYSQL_ROOT_PASSWORD="${DB_PASSWORD}" \
      --env MYSQL_DATABASE=kms "${MYSQL_IMAGE}" >/dev/null
  fi
  for _ in $(seq 1 120); do
    if db_client "${backend}" ready >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  docker logs "${DB_NAME}" >&2
  print_error "The ${backend} fixture database did not start."
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

# 5.14.0 is versioned and stores attributes as json; 5.28.0 ran the wrapping backfill.
expected_facts() {
  local backend="$1" version="$2"
  local facts="objects=8 named=6 revoked=Deactivated untagged=0 grant=decrypt,encrypt,get serial_tags=0"
  case "${version}" in
    5.14.0) facts+=' wrapping_column=0 parameters=db_state:"ready",db_version:5.14.0' ;;
    5.28.0) facts+=" wrapping_column=1 parameters=wrapping_key_id_backfilled:true" ;;
    *) facts+=" wrapping_column=0 parameters=" ;;
  esac
  if [ "${backend}" = postgresql ] && [ "${version}" = 5.14.0 ]; then
    facts+=" attributes=json"
  elif [ "${backend}" = postgresql ]; then
    facts+=" attributes=jsonb"
  fi
  echo "${facts}"
}

# Dump the populated database, then prove the dump restores into an empty server.
write_sql_fixture() {
  local backend="$1" version="$2" output="$3"
  local dump="${WORK_DIR}/dump.sql" facts expected
  # pg_dump 18 brackets the dump in psql-only \restrict meta-commands.
  db_client "${backend}" dump | grep -v -E '^\\(un)?restrict ' >"${dump}"
  if grep -q '^[\]' "${dump}"; then
    print_error "Unexpected psql meta-command in the ${backend} ${version} dump"
  fi
  docker rm --force "${DB_NAME}" >/dev/null
  start_db "${backend}"
  db_client "${backend}" restore <"${dump}" >/dev/null
  facts="$(db_client "${backend}" facts)"
  expected="$(expected_facts "${backend}" "${version}")"
  if [ "${facts}" != "${expected}" ]; then
    print_error "Unexpected ${backend} ${version} fixture: got '${facts}', expected '${expected}'"
  fi
  docker rm --force "${DB_NAME}" >/dev/null
  mv "${dump}" "${output}"
  echo "${version}: verified ${backend} dump: ${facts}"
}

generate_sqlite_fixture() {
  local image="$1" version="$2" output="$3"
  local data_dir="${WORK_DIR}/${version}"
  mkdir -p "${data_dir}"
  start_kms --volume "${data_dir}:/data" "${image}" --database-type sqlite --sqlite-path /data
  fixture_ckms --version
  populate_fixture
  docker exec "${KMS_NAME}" chown -R "$(id -u):$(id -g)" /data
  stop_kms
  write_fixture "${data_dir}/kms.db" "${output}" "${version}"
}

generate_sql_fixture() {
  local backend="$1" image="$2" version="$3" output="$4"
  local port=5432
  [ "${backend}" = postgresql ] || port=3306
  start_db "${backend}"
  start_kms "${image}" --database-type "${backend}" \
    --database-url "${backend}://kms:${DB_PASSWORD}@${DB_NAME}:${port}/kms"
  fixture_ckms --version
  populate_fixture
  stop_kms
  write_sql_fixture "${backend}" "${version}" "${output}"
}

generate_fixture() {
  local backend="$1" image="$2" version="$3"
  local output_dir="${REPO_ROOT}/test_data/db_migration/${version}/${backend}"
  local output="${output_dir}/dump.sql"
  [ "${backend}" != sqlite ] || output="${output_dir}/kms.db"
  [ ! -e "${output}" ] || print_error "Fixture already exists: ${output}"
  mkdir -p "${output_dir}"
  CKMS_IMAGE="${image}"
  [ "${version}" != 5.14.0 ] || CKMS_IMAGE="${CKMS_FALLBACK_IMAGE}"
  print_status "Generating ${backend} fixture with ${image}"
  if [ "${backend}" = sqlite ]; then
    generate_sqlite_fixture "${image}" "${version}" "${output}"
  else
    generate_sql_fixture "${backend}" "${image}" "${version}" "${output}"
  fi
}

docker network create "${NETWORK}" >/dev/null
selected=false
for backend in "${BACKENDS[@]}"; do
  for image in "${IMAGES[@]}"; do
    version="${image#*:}"
    version="${version%%@*}"
    if [ -n "${SELECTED_VERSION}" ] && [ "${version}" != "${SELECTED_VERSION}" ]; then
      continue
    fi
    selected=true
    # Only PostgreSQL has a step (json to jsonb) older than the 5.20.0 baseline.
    if [ "${version}" = 5.14.0 ] && [ "${backend}" != postgresql ]; then
      continue
    fi
    # The 5.29.0 fixture exercises the SQLite runner's completed state.
    if [ "${version}" = 5.29.0 ] && [ "${backend}" != sqlite ]; then
      continue
    fi
    generate_fixture "${backend}" "${image}" "${version}"
  done
done
[ "${selected}" = true ] || print_error "Unknown fixture version: ${SELECTED_VERSION}"
print_success "Released ${BACKENDS[*]} migration fixtures generated and verified."
