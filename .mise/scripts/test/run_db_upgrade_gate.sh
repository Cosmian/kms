#!/usr/bin/env bash
# Run the live Docker old-image -> new-image database upgrade gate across backends.
set -euo pipefail

# shellcheck source=.mise/lib/common.sh
source "${MISE_CONFIG_ROOT}/.mise/lib/common.sh"
REPO_ROOT="$(get_repo_root "${MISE_CONFIG_ROOT}")"
require_cmd docker
require_cmd python3
require_cmd curl
docker_ready || print_error "Docker must be running to execute the database upgrade gate."

readonly POSTGRES_IMAGE="postgres:18@sha256:74935e72241653ca55e0414067e6d8763aceb8a810eb51b452253ec3dcfc4336"
readonly MYSQL_IMAGE="mysql:8.0@sha256:99d774bf02a48a1bb1c599920d2571946d31e5940b854b02737d5e95c184358f"
readonly REDIS_IMAGE="redis:7.2@sha256:5b816bb37d9707a70f10ef5002ecf8ee431750d397010fc4314c93dca887962f"
# Test-only database password for ephemeral containers on the isolated network.
readonly DB_PASSWORD="kms-upgrade-gate"

VARIANT="fips"
BACKEND_ARG="all"
OLD_VERSION_ARG="nightly"
NEW_IMAGE="${DOCKER_IMAGE_NAME:-}"
SEED_ARG=""
RANDOM_COUNT="10"
ROTATION_INDEX=""
ARTIFACTS_DIR="${REPO_ROOT}/target/db-upgrade-gate/fips"

# Parse command-line arguments.
parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --variant) VARIANT="$2" ;;
      --backend) BACKEND_ARG="$2" ;;
      --old-version) OLD_VERSION_ARG="$2" ;;
      --new-image) NEW_IMAGE="$2" ;;
      --seed) SEED_ARG="$2" ;;
      --random-count) RANDOM_COUNT="$2" ;;
      --rotation-index) ROTATION_INDEX="$2" ;;
      --artifacts-dir) ARTIFACTS_DIR="$2" ;;
      *) print_error "Unknown argument: $1" ;;
    esac
    shift 2
  done
  [ -n "${NEW_IMAGE}" ] || print_error "--new-image (or DOCKER_IMAGE_NAME) is required."
}

# Read SUPPORTED_BASELINE (e.g. 5.20.0) directly from migrate.rs so the pool tracks code changes.
read_supported_baseline() {
  python3 - "${REPO_ROOT}/crate/server_database/src/stores/migrate.rs" <<'PY'
import re, sys
from pathlib import Path
text = Path(sys.argv[1]).read_text(encoding="utf-8")
m = re.search(r"SUPPORTED_BASELINE:\s*Version\s*=\s*Version\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)", text)
if not m:
    raise SystemExit("Could not parse SUPPORTED_BASELINE from migrate.rs")
print(f"{m.group(1)}.{m.group(2)}.{m.group(3)}")
PY
}

# Resolve the ordered list of old KMS versions to test (N-1, baseline, + 2 round-robin middle tags).
resolve_old_versions() {
  local baseline
  baseline="$(read_supported_baseline)"
  python3 - "${REPO_ROOT}" "${baseline}" "${OLD_VERSION_ARG}" "${ROTATION_INDEX}" "${GITHUB_REF_NAME:-}" <<'PY'
import re, subprocess, sys, time
repo_root, baseline, arg, rot, ref_name = sys.argv[1:6]
if arg != "nightly":
    print("\n".join(v.strip() for v in arg.split(",") if v.strip()))
    raise SystemExit(0)
ver = lambda s: tuple(int(x) for x in s.split("."))
sem = re.compile(r"^\d+\.\d+\.\d+$")
tags = subprocess.check_output(["git", "-C", repo_root, "tag", "-l"], text=True).splitlines()
sem_tags = [t.strip() for t in tags if sem.match(t.strip())]
if len(sem_tags) < 2:
    remote = subprocess.check_output(["git", "-C", repo_root, "ls-remote", "--tags", "--refs", "origin"], text=True).splitlines()
    sem_tags = [line.split("refs/tags/")[-1].strip() for line in remote if "refs/tags/" in line and sem.match(line.split("refs/tags/")[-1].strip())]
pool = sorted({t for t in sem_tags if ver(t) >= ver(baseline) and (not sem.match(ref_name) or ver(t) < ver(ref_name))}, key=ver)
if not pool:
    raise SystemExit(f"No released semver tags >= {baseline}")
selected = [baseline] + ([pool[-1]] if pool[-1] != baseline else [])
middle = [v for v in pool if v not in selected]
day_idx = int(rot) if rot else int(time.time() // 86400)
for offset in range(min(2, len(middle))):
    pick = middle[(day_idx * 2 + offset) % len(middle)]
    if pick not in selected:
        selected.append(pick)
print("\n".join(selected))
PY
}

# Resolve the list of database backends for the current variant.
resolve_backends() {
  case "${BACKEND_ARG}" in
    all)
      if [ "${VARIANT}" = "non-fips" ]; then
        echo "sqlite postgresql mysql redis"
      else
        echo "sqlite postgresql mysql"
      fi
      ;;
    redis)
      [ "${VARIANT}" = "non-fips" ] || print_error "Redis-findex is only supported in non-fips mode."
      echo "redis"
      ;;
    sqlite | postgresql | mysql) echo "${BACKEND_ARG}" ;;
    *) print_error "Unsupported backend: ${BACKEND_ARG}" ;;
  esac
}

WORK_DIR="$(mktemp -d -t kms-db-upgrade-gate-XXXXXX)"
NETWORK="kms-upgrade-gate-$$"
KMS_CONTAINER="kms-upgrade-srv-$$"
DB_CONTAINER="kms-upgrade-db-$$"

# Remove containers, network, and temporary working directory on exit.
cleanup() {
  local status="$?"
  docker rm --force "${KMS_CONTAINER}" "${DB_CONTAINER}" >/dev/null 2>&1 || true
  docker network rm "${NETWORK}" >/dev/null 2>&1 || true
  rm -rf -- "${WORK_DIR:?}" 2>/dev/null || true
  exit "${status}"
}
trap cleanup EXIT

# Pull a Docker image (if not already present locally) using retry from common.sh.
pull_image_with_retry() {
  local image="$1"
  if ! docker image inspect "${image}" >/dev/null 2>&1; then
    retry 3 5 docker pull --quiet "${image}" >/dev/null || print_error "Could not pull image ${image}"
  fi
  local digest
  digest="$(docker inspect --format '{{join .RepoDigests ","}}' "${image}" 2>/dev/null || true)"
  print_status "Using image ${image} (digest=${digest:-local})"
}

# Execute a readiness or backup command against the active database container.
db_client() {
  local mysql_env=(--env "MYSQL_PWD=${DB_PASSWORD}")
  case "$1/$2" in
    postgresql/ready) docker exec "${DB_CONTAINER}" pg_isready --quiet --host 127.0.0.1 --username kms --dbname kms ;;
    postgresql/dump) docker exec "${DB_CONTAINER}" pg_dump --no-owner --no-privileges --inserts --username kms kms ;;
    postgresql/create-restore)
      docker exec "${DB_CONTAINER}" psql --quiet -U kms -d postgres \
        -c "DROP DATABASE IF EXISTS kms_restore" \
        -c "CREATE DATABASE kms_restore"
      ;;
    postgresql/restore) docker exec --interactive "${DB_CONTAINER}" psql --quiet --set ON_ERROR_STOP=1 --username kms --dbname kms_restore ;;
    mysql/ready) docker exec "${mysql_env[@]}" "${DB_CONTAINER}" mysqladmin ping --silent --host 127.0.0.1 --user kms ;;
    mysql/dump)
      docker exec "${mysql_env[@]}" "${DB_CONTAINER}" mysqldump --no-tablespaces --skip-add-locks \
        --skip-lock-tables --skip-comments --set-gtid-purged=OFF --user kms kms
      ;;
    mysql/create-restore)
      docker exec "${mysql_env[@]}" "${DB_CONTAINER}" mysql --user root -e \
        "DROP DATABASE IF EXISTS kms_restore; CREATE DATABASE kms_restore; GRANT ALL PRIVILEGES ON kms_restore.* TO 'kms'@'%'; FLUSH PRIVILEGES;"
      ;;
    mysql/restore) docker exec --interactive "${mysql_env[@]}" "${DB_CONTAINER}" mysql --user kms kms_restore ;;
    redis/ready) docker exec "${DB_CONTAINER}" redis-cli ping | grep -q PONG ;;
    redis/save) docker exec "${DB_CONTAINER}" redis-cli SAVE >/dev/null ;;
    *) print_error "Unknown db_client command: $1/$2" ;;
  esac
}

# Start a fresh database container for postgresql, mysql, or redis.
start_db_container() {
  local backend="$1"
  docker rm --force "${DB_CONTAINER}" >/dev/null 2>&1 || true
  case "${backend}" in
    sqlite) return 0 ;;
    postgresql)
      docker run --detach --name "${DB_CONTAINER}" --network "${NETWORK}" \
        --env POSTGRES_USER=kms --env POSTGRES_PASSWORD="${DB_PASSWORD}" \
        --env POSTGRES_DB=kms "${POSTGRES_IMAGE}" >/dev/null
      ;;
    mysql)
      docker run --detach --name "${DB_CONTAINER}" --network "${NETWORK}" \
        --env MYSQL_USER=kms --env MYSQL_PASSWORD="${DB_PASSWORD}" \
        --env MYSQL_ROOT_PASSWORD="${DB_PASSWORD}" --env MYSQL_DATABASE=kms \
        "${MYSQL_IMAGE}" >/dev/null
      ;;
    redis)
      docker run --detach --name "${DB_CONTAINER}" --network "${NETWORK}" \
        "${REDIS_IMAGE}" --save "" --appendonly no >/dev/null
      ;;
  esac
  wait_for_command 120 db_client "${backend}" ready >/dev/null 2>&1 || {
    docker logs "${DB_CONTAINER}" >&2 || true
    return 1
  }
}

# Probe the mTLS KMIP endpoint on the published container port.
probe_container_kmip() {
  [ "$(docker inspect --format '{{.State.Running}}' "${KMS_CONTAINER}" 2>/dev/null || true)" = "true" ] || return 1
  local code
  code="$(curl -sS --max-time 2 -o /dev/null -w '%{http_code}' \
    --cacert "${REPO_ROOT}/test_data/certificates/client_server/ca/ca.crt" \
    --cert "${REPO_ROOT}/test_data/certificates/client_server/owner/owner.client.acme.com.crt" \
    --key "${REPO_ROOT}/test_data/certificates/client_server/owner/owner.client.acme.com.key" \
    --resolve "kmserver.acme.com:${KMS_HOST_PORT}:127.0.0.1" \
    -X POST -H 'Content-Type: application/json' -d '{}' \
    "https://kmserver.acme.com:${KMS_HOST_PORT}/kmip/2_1" 2>/dev/null || true)"
  [ "${code}" = "422" ]
}

# Start a KMS container with mTLS and the target backend configuration.
start_kms_container() {
  local image="$1" backend="$2" target_db="$3" log_file="$4"
  local db_args=() vol_args=(-v "${REPO_ROOT}/test_data:/test_data:ro")
  case "${backend}" in
    sqlite)
      vol_args+=(-v "${target_db}:/data")
      db_args=(--database-type sqlite --sqlite-path /data)
      ;;
    postgresql)
      db_args=(--database-type postgresql --database-url "postgresql://kms:${DB_PASSWORD}@${DB_CONTAINER}:5432/${target_db}")
      ;;
    mysql)
      db_args=(--database-type mysql --database-url "mysql://kms:${DB_PASSWORD}@${DB_CONTAINER}:3306/${target_db}")
      ;;
    redis)
      db_args=(--database-type redis-findex --database-url "redis://${DB_CONTAINER}:6379" --redis-master-password "${DB_PASSWORD}")
      ;;
  esac
  docker rm --force "${KMS_CONTAINER}" >/dev/null 2>&1 || true
  docker run --detach --name "${KMS_CONTAINER}" --network "${NETWORK}" \
    --publish 127.0.0.1::9998 "${vol_args[@]}" "${image}" "${db_args[@]}" \
    --tls-cert-file /test_data/certificates/client_server/server/kmserver.acme.com.crt \
    --tls-key-file /test_data/certificates/client_server/server/kmserver.acme.com.key \
    --clients-ca-cert-file /test_data/certificates/client_server/ca/ca.crt >/dev/null
  local addr
  addr="$(docker port "${KMS_CONTAINER}" 9998/tcp | head -n 1)"
  KMS_HOST_PORT="${addr##*:}"
  if ! wait_for_command 60 probe_container_kmip; then
    docker logs "${KMS_CONTAINER}" >"${log_file}" 2>&1 || true
    tail -n 30 "${log_file}" >&2 || true
    return 1
  fi
}

# Stop the KMS container and save its logs to the given path.
stop_kms_container() {
  local backend="$1" log_file="$2"
  docker logs "${KMS_CONTAINER}" >"${log_file}" 2>&1 || true
  if [ "${backend}" = "sqlite" ]; then
    docker exec "${KMS_CONTAINER}" chown -R "$(id -u):$(id -g)" /data 2>/dev/null || true
  fi
  docker stop "${KMS_CONTAINER}" >/dev/null 2>&1 || true
  docker rm --force "${KMS_CONTAINER}" >/dev/null 2>&1 || true
}

# Take a cold backup of the seeded database before starting the candidate server.
backup_seeded_db() {
  local backend="$1" cell_dir="$2"
  case "${backend}" in
    sqlite)
      cp -a "${cell_dir}/db-seed" "${cell_dir}/backup" &&
        cp -a "${cell_dir}/backup" "${cell_dir}/db-candidate"
      ;;
    postgresql)
      db_client postgresql dump | grep -v -E '^\\(un)?restrict ' >"${cell_dir}/backup.sql" &&
        db_client postgresql create-restore &&
        db_client postgresql restore <"${cell_dir}/backup.sql" >/dev/null
      ;;
    mysql)
      db_client mysql dump >"${cell_dir}/backup.sql" &&
        db_client mysql create-restore &&
        db_client mysql restore <"${cell_dir}/backup.sql" >/dev/null
      ;;
    redis)
      db_client redis save &&
        docker cp "${DB_CONTAINER}:/data/dump.rdb" "${cell_dir}/backup.rdb"
      ;;
  esac
}

# Prepare the restored pre-upgrade database for Phase 4.
prepare_restore_db() {
  local backend="$1" cell_dir="$2"
  if [ "${backend}" = "sqlite" ]; then
    cp -a "${cell_dir}/backup" "${cell_dir}/db-restore"
  elif [ "${backend}" = "redis" ]; then
    docker rm --force "${DB_CONTAINER}" >/dev/null 2>&1 || true
    mkdir -p "${cell_dir}/redis-restore"
    cp "${cell_dir}/backup.rdb" "${cell_dir}/redis-restore/dump.rdb"
    chmod 644 "${cell_dir}/redis-restore/dump.rdb"
    docker run --detach --name "${DB_CONTAINER}" --network "${NETWORK}" \
      -v "${cell_dir}/redis-restore:/data" "${REDIS_IMAGE}" \
      --dbfilename dump.rdb --dir /data >/dev/null
    wait_for_command 60 db_client redis ready >/dev/null 2>&1
  fi
}

# Copy logs, snapshot, and database backup to ARTIFACTS_DIR when a cell fails.
save_failure_artifacts() {
  local backend="$1" version="$2" cell_dir="$3"
  local dest="${ARTIFACTS_DIR}/${backend}-${version}"
  mkdir -p "${dest}"
  docker logs "${KMS_CONTAINER}" >"${cell_dir}/active-container.log" 2>&1 || true
  cp -a "${cell_dir}/." "${dest}/" 2>/dev/null || true
  print_warning "Saved failure artifacts to ${dest}"
}

# Format the one-line replay command for a (backend, old_version, seed) cell.
format_replay_cmd() {
  local backend="$1" old_version="$2" seed="$3"
  local cmd="mise run test:upgrade-db --variant ${VARIANT} --backend ${backend} --old-version ${old_version} --new-image ${NEW_IMAGE} --seed ${seed}"
  if [ "${RANDOM_COUNT}" != "10" ]; then
    cmd+=" --random-count ${RANDOM_COUNT}"
  fi
  echo "${cmd}"
}

# Run verify_db_upgrade.py with mTLS owner and grantee credentials against the active KMS container.
run_py_verifier() {
  local subcmd="$1" backend="$2" old_version="$3" seed="$4"
  shift 4
  local cert_dir="${REPO_ROOT}/test_data/certificates/client_server"
  local replay
  replay="$(format_replay_cmd "${backend}" "${old_version}" "${seed}")"
  python3 "${REPO_ROOT}/.mise/scripts/test/verify_db_upgrade.py" "${subcmd}" \
    --url "https://127.0.0.1:${KMS_HOST_PORT}" \
    --ca-cert "${cert_dir}/ca/ca.crt" \
    --client-cert "${cert_dir}/owner/owner.client.acme.com.crt" \
    --client-key "${cert_dir}/owner/owner.client.acme.com.key" \
    --grantee-cert "${cert_dir}/user/user.client.acme.com.crt" \
    --grantee-key "${cert_dir}/user/user.client.acme.com.key" \
    --old-version "${old_version}" --new-version "${NEW_IMAGE}" \
    --backend "${backend}" --variant "${VARIANT}" --replay-cmd "${replay}" "$@"
}

# Seed the database with the old KMS container and capture the pre-upgrade snapshot.
seed_cell_db() {
  local backend="$1" old_version="$2" old_image="$3" seed="$4" cell_dir="$5" seed_target="$6"
  start_kms_container "${old_image}" "${backend}" "${seed_target}" "${cell_dir}/old-seed.log" &&
    run_py_verifier seed "${backend}" "${old_version}" "${seed}" \
      --snapshot "${cell_dir}/snapshot.json" --seed "${seed}" --count "${RANDOM_COUNT}" \
      --sample-cert "${REPO_ROOT}/test_data/certificates/client_server/server/kmserver.acme.com.crt" &&
    stop_kms_container "${backend}" "${cell_dir}/old-seed.log"
}

# Run the 4-phase upgrade gate for one (backend, old_version) pair.
run_upgrade_cell() {
  local backend="$1" old_version="$2" old_image="$3" seed="$4"
  local cell_dir="${WORK_DIR}/${backend}-${old_version}"
  mkdir -p "${cell_dir}/db-seed"
  local seed_target="kms" cand_target="kms" rest_target="kms_restore"
  if [ "${backend}" = "sqlite" ]; then
    seed_target="${cell_dir}/db-seed"
    cand_target="${cell_dir}/db-candidate"
    rest_target="${cell_dir}/db-restore"
  fi

  start_db_container "${backend}" &&
    seed_cell_db "${backend}" "${old_version}" "${old_image}" "${seed}" "${cell_dir}" "${seed_target}" &&
    backup_seeded_db "${backend}" "${cell_dir}" &&
    start_kms_container "${NEW_IMAGE}" "${backend}" "${cand_target}" "${cell_dir}/new-candidate.log" &&
    run_py_verifier verify "${backend}" "${old_version}" "${seed}" \
      --snapshot "${cell_dir}/snapshot.json" --phase candidate --mutate &&
    stop_kms_container "${backend}" "${cell_dir}/new-candidate.log" &&
    start_kms_container "${NEW_IMAGE}" "${backend}" "${cand_target}" "${cell_dir}/new-restart.log" &&
    run_py_verifier verify "${backend}" "${old_version}" "${seed}" \
      --snapshot "${cell_dir}/snapshot.json" --phase candidate-restart &&
    stop_kms_container "${backend}" "${cell_dir}/new-restart.log" &&
    prepare_restore_db "${backend}" "${cell_dir}" &&
    start_kms_container "${old_image}" "${backend}" "${rest_target}" "${cell_dir}/old-restore.log" &&
    run_py_verifier verify "${backend}" "${old_version}" "${seed}" \
      --snapshot "${cell_dir}/snapshot.json" --phase restore &&
    stop_kms_container "${backend}" "${cell_dir}/old-restore.log"
  local rc="$?"
  docker rm --force "${DB_CONTAINER}" >/dev/null 2>&1 || true
  return "${rc}"
}

parse_args "$@"
RAW_VERSIONS="$(resolve_old_versions)"
RAW_BACKENDS="$(resolve_backends)"
mapfile -t VERSIONS <<<"${RAW_VERSIONS}"
read -r -a BACKENDS <<<"${RAW_BACKENDS}"
[ -n "${VERSIONS[0]:-}" ] || print_error "Resolved empty old-version list."
[ -n "${BACKENDS[0]:-}" ] || print_error "Resolved empty backend list."

docker network create "${NETWORK}" >/dev/null
BASE_SEED="${SEED_ARG:-$(date +%s)}"
REPO_PREFIX="ghcr.io/cosmian/kms"
[ "${VARIANT}" != "fips" ] || REPO_PREFIX="ghcr.io/cosmian/kms-fips"

print_header "DB Upgrade Gate (variant=${VARIANT}, backends=${BACKENDS[*]}, versions=${VERSIONS[*]}, seed=${BASE_SEED})"

for backend in "${BACKENDS[@]}"; do
  case "${backend}" in
    postgresql) pull_image_with_retry "${POSTGRES_IMAGE}" ;;
    mysql) pull_image_with_retry "${MYSQL_IMAGE}" ;;
    redis) pull_image_with_retry "${REDIS_IMAGE}" ;;
  esac
done

FAILED=()
REPLAYS=()
for old_ver in "${VERSIONS[@]}"; do
  old_img="${REPO_PREFIX}:${old_ver}"
  pull_image_with_retry "${old_img}"
  for backend in "${BACKENDS[@]}"; do
    print_status "Testing upgrade ${old_ver} -> ${NEW_IMAGE} on ${backend} (${VARIANT}, seed=${BASE_SEED})"
    if (run_upgrade_cell "${backend}" "${old_ver}" "${old_img}" "${BASE_SEED}"); then
      print_success "${backend} (${VARIANT}) upgrade from ${old_ver} passed"
    else
      print_warning "${backend} (${VARIANT}) upgrade from ${old_ver} FAILED"
      save_failure_artifacts "${backend}" "${old_ver}" "${WORK_DIR}/${backend}-${old_ver}"
      FAILED+=("${backend}:${old_ver}")
      REPLAYS+=("$(format_replay_cmd "${backend}" "${old_ver}" "${BASE_SEED}")")
    fi
  done
done

if [ "${#FAILED[@]}" -gt 0 ]; then
  echo "ERROR: Database upgrade gate failed for: ${FAILED[*]}" >&2
  for cmd in "${REPLAYS[@]}"; do
    echo "  Replay: ${cmd}" >&2
  done
  exit 1
fi
print_success "All database upgrade gate checks passed (${VARIANT})"
