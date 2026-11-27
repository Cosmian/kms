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
readonly BASELINE_VERSION="5.9.0"

VARIANT="fips"
BACKEND_ARG="all"
OLD_VERSION_ARG="nightly"
NEW_IMAGE="${DOCKER_IMAGE_NAME:-}"
SEED_ARG=""
RANDOM_COUNT="10"
ROTATION_INDEX=""
ARTIFACTS_DIR="${REPO_ROOT}/target/db-upgrade-gate/fips"
NEW_KMS=""
CKMS_BIN=""
KEK_ID="upgrade-gate-kek" # key encryption key created on the old server; configured on every later start
KEK_ACTIVE=""
PHASE=""
OLD_KMS=""
EXPLICIT_NEW_KMS=""
HOST_KMS_PID=""
DB_HOST_PORT=""
KMS_HOST_PORT=""
NEW_LABEL=""

# True when version A is strictly lower than version B.
version_lt() {
  [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n1)" = "$1" ]
}

# Parse command-line arguments.
parse_args() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --variant) VARIANT="$2" ;;
      --backend) BACKEND_ARG="$2" ;;
      --old-version) OLD_VERSION_ARG="$2" ;;
      --new-image) NEW_IMAGE="$2" ;;
      --new-kms) NEW_KMS="$2" ;;
      --ckms) CKMS_BIN="$2" ;;
      --seed) SEED_ARG="$2" ;;
      --old-kms) OLD_KMS="$2" ;;
      --explicit-new-kms) EXPLICIT_NEW_KMS="$2" ;;
      --random-count) RANDOM_COUNT="$2" ;;
      --rotation-index) ROTATION_INDEX="$2" ;;
      --artifacts-dir) ARTIFACTS_DIR="$2" ;;
      *) print_error "Unknown argument: $1" ;;
    esac
    shift 2
  done
  if [ -n "${NEW_IMAGE}" ] && [ -n "${NEW_KMS}" ]; then print_error "Pass exactly one of --new-image or --new-kms."; fi
  if [ -z "${NEW_IMAGE}" ] && [ -z "${NEW_KMS}" ]; then print_error "Pass exactly one of --new-image or --new-kms."; fi
  if [ -n "${NEW_KMS}" ]; then
    [ -x "${NEW_KMS}" ] || print_error "--new-kms is not an executable file: ${NEW_KMS}"
    [ ! -e /etc/cosmian/kms.toml ] || print_error "/etc/cosmian/kms.toml would override the host server CLI flags; move it away."
  fi
  if [ -n "${CKMS_BIN}" ]; then [ -x "${CKMS_BIN}" ] || print_error "--ckms is not an executable file: ${CKMS_BIN}"; fi
  if [ -n "${OLD_KMS}" ]; then [ -x "${OLD_KMS}" ] || print_error "--old-kms is not an executable file: ${OLD_KMS}"; fi
}

# Resolve the ordered list of old KMS versions to test (baseline 5.9.0, N-1, + 2 round-robin middle tags; or all).
resolve_old_versions() {
  python3 - "${REPO_ROOT}" "${BASELINE_VERSION}" "${OLD_VERSION_ARG}" "${ROTATION_INDEX}" "${GITHUB_REF_NAME:-}" <<'PY'
import re, subprocess, sys, time
repo_root, baseline, arg, rot, ref_name = sys.argv[1:6]
if arg not in ("nightly", "all"):
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
if arg == "all":
    print("\n".join(pool))
    raise SystemExit(0)
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
  [ -z "${HOST_KMS_PID}" ] || kill "${HOST_KMS_PID}" 2>/dev/null || true
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
    retry docker pull --quiet "${image}" >/dev/null || print_error "Could not pull image ${image}"
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
  local backend="$1" port=""
  docker rm --force "${DB_CONTAINER}" >/dev/null 2>&1 || true
  case "${backend}" in
    sqlite) return 0 ;;
    postgresql)
      port=5432
      docker run --detach --name "${DB_CONTAINER}" --network "${NETWORK}" --publish "127.0.0.1::${port}" \
        --env POSTGRES_USER=kms --env POSTGRES_PASSWORD="${DB_PASSWORD}" \
        --env POSTGRES_DB=kms "${POSTGRES_IMAGE}" >/dev/null
      ;;
    mysql)
      port=3306
      docker run --detach --name "${DB_CONTAINER}" --network "${NETWORK}" --publish "127.0.0.1::${port}" \
        --env MYSQL_USER=kms --env MYSQL_PASSWORD="${DB_PASSWORD}" \
        --env MYSQL_ROOT_PASSWORD="${DB_PASSWORD}" --env MYSQL_DATABASE=kms \
        "${MYSQL_IMAGE}" >/dev/null
      ;;
    redis)
      port=6379
      docker run --detach --name "${DB_CONTAINER}" --network "${NETWORK}" --publish "127.0.0.1::${port}" \
        "${REDIS_IMAGE}" --save "" --appendonly no >/dev/null
      ;;
  esac
  wait_for_command 120 db_client "${backend}" ready >/dev/null 2>&1 || {
    docker logs "${DB_CONTAINER}" >&2 || true
    return 1
  }
  DB_HOST_PORT="$(docker port "${DB_CONTAINER}" "${port}/tcp" | head -n1)"
  DB_HOST_PORT="${DB_HOST_PORT##*:}"
}

# Probe the mTLS KMIP endpoint on a local port.
probe_kmip_port() {
  local code
  code="$(curl -sS --max-time 2 -o /dev/null -w '%{http_code}' \
    --cacert "${REPO_ROOT}/test_data/certificates/client_server/ca/ca.crt" \
    --cert "${REPO_ROOT}/test_data/certificates/client_server/owner/owner.client.acme.com.crt" \
    --key "${REPO_ROOT}/test_data/certificates/client_server/owner/owner.client.acme.com.key" \
    --resolve "kmserver.acme.com:$1:127.0.0.1" \
    -X POST -H 'Content-Type: application/json' -d '{}' \
    "https://kmserver.acme.com:$1/kmip/2_1" 2>/dev/null || true)"
  [ "${code}" = "422" ]
}

# Probe the KMS container on its published port.
probe_container_kmip() {
  [ "$(docker inspect --format '{{.State.Running}}' "${KMS_CONTAINER}" 2>/dev/null || true)" = "true" ] || return 1
  # The published port can be missing right after `docker run --detach` under load: resolve it on every probe.
  local addr
  addr="$(docker port "${KMS_CONTAINER}" 9998/tcp 2>/dev/null | head -n 1)" || true
  [ -n "${addr}" ] || return 1
  KMS_HOST_PORT="${addr##*:}"
  probe_kmip_port "${KMS_HOST_PORT}"
}

# Probe the host KMS process.
probe_host_kmip() {
  kill -0 "${HOST_KMS_PID}" 2>/dev/null || return 1
  probe_kmip_port "${KMS_HOST_PORT}"
}

# Start a KMS container with mTLS and the target backend configuration.
# The optional 5th argument is the old release version (empty for candidate images).
start_kms_container() {
  local image="$1" backend="$2" target_db="$3" log_file="$4" old_version="${5:-}"
  local db_args=() vol_args=(-v "${REPO_ROOT}/test_data:/test_data:ro")
  local cert_dir=/test_data/certificates/client_server
  local tls_args=(--tls-cert-file "${cert_dir}/server/kmserver.acme.com.crt" --tls-key-file "${cert_dir}/server/kmserver.acme.com.key")
  # PKCS#12 identity: fips images before 5.13.0 (5.13.0+ list only --tls-cert-file), non-fips images before 5.17.0.
  local p12_before=5.17.0
  [ "${VARIANT}" != "fips" ] || p12_before=5.13.0
  if [ -n "${old_version}" ] && version_lt "${old_version}" "${p12_before}"; then
    tls_args=(--tls-p12-file "${cert_dir}/server/kmserver.acme.com.p12" --tls-p12-password password)
  fi
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
    "${tls_args[@]}" \
    --clients-ca-cert-file "${cert_dir}/ca/ca.crt" ${KEK_ACTIVE:+"${KEK_ID}"} >/dev/null
  if ! wait_for_command 60 probe_container_kmip; then
    docker logs "${KMS_CONTAINER}" >"${log_file}" 2>&1 || true
    tail -n 30 "${log_file}" >&2 || true
    echo "container ${KMS_CONTAINER} port='${KMS_HOST_PORT:-}' state: $(docker inspect --format '{{json .State}}' "${KMS_CONTAINER}" 2>&1)" >&2
    return 1
  fi
}

# Start the host (cargo-built) candidate server with mTLS on a free port.
start_host_kms() {
  local bin="$1" backend="$2" target="$3" log="$4"
  local cert_dir="${REPO_ROOT}/test_data/certificates/client_server"
  KMS_HOST_PORT="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')"
  local args=()
  case "${backend}" in
    sqlite) args=(--database-type sqlite --sqlite-path "${target}") ;;
    postgresql) args=(--database-type postgresql --database-url "postgresql://kms:${DB_PASSWORD}@127.0.0.1:${DB_HOST_PORT}/${target}") ;;
    mysql) args=(--database-type mysql --database-url "mysql://kms:${DB_PASSWORD}@127.0.0.1:${DB_HOST_PORT}/${target}") ;;
    redis) args=(--database-type redis-findex --database-url "redis://127.0.0.1:${DB_HOST_PORT}" --redis-master-password "${DB_PASSWORD}") ;;
  esac
  mkdir -p "${log%.log}-workspace" "${log%.log}-tmp"
  args+=(--hostname 127.0.0.1 --port "${KMS_HOST_PORT}" --root-data-path "${log%.log}-workspace" --tmp-path "${log%.log}-tmp"
    --tls-cert-file "${cert_dir}/server/kmserver.acme.com.crt" --tls-key-file "${cert_dir}/server/kmserver.acme.com.key"
    --clients-ca-cert-file "${cert_dir}/ca/ca.crt" ${KEK_ACTIVE:+"${KEK_ID}"})
  env -u COSMIAN_KMS_CONF "${bin}" "${args[@]}" >"${log}" 2>&1 &
  HOST_KMS_PID=$!
  if ! wait_for_command 120 probe_host_kmip; then
    tail -n 30 "${log}" >&2 || true
    kill "${HOST_KMS_PID}" 2>/dev/null || true
    HOST_KMS_PID=""
    return 1
  fi
}

# Stop the host candidate server.
stop_host_kms() {
  kill "${HOST_KMS_PID}" 2>/dev/null || true
  wait "${HOST_KMS_PID}" 2>/dev/null || true
  HOST_KMS_PID=""
}

# Start the old server (host binary with --old-kms, else release container).
start_old() {
  if [ -n "${OLD_KMS}" ]; then
    start_host_kms "${OLD_KMS}" "$1" "$2" "$3"
  else
    start_kms_container "$@"
  fi
}

# Stop the old server and keep its logs.
stop_old() {
  if [ -n "${OLD_KMS}" ]; then
    stop_host_kms
  else
    stop_kms_container "$@"
  fi
}

# Start the candidate server (host binary with --new-kms, else container).
start_candidate() {
  if [ -n "${NEW_KMS}" ]; then
    start_host_kms "${NEW_KMS}" "$@"
  else
    start_kms_container "${NEW_IMAGE}" "$@"
  fi
}

# Stop the candidate server and keep its logs.
stop_candidate() {
  if [ -n "${NEW_KMS}" ]; then
    stop_host_kms
  else
    stop_kms_container "$@"
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
      --publish "127.0.0.1::6379" -v "${cell_dir}/redis-restore:/data" "${REDIS_IMAGE}" \
      --dbfilename dump.rdb --dir /data >/dev/null
    DB_HOST_PORT="$(docker port "${DB_CONTAINER}" 6379/tcp | head -n1)"
    DB_HOST_PORT="${DB_HOST_PORT##*:}"
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
  local old_flag="--old-version ${old_version}"
  if [ -n "${OLD_KMS}" ]; then old_flag="--old-kms ${OLD_KMS}"; fi
  local cmd="mise run test:db:upgrade --variant ${VARIANT} --backend ${backend} ${old_flag} --seed ${seed}"
  if [ -n "${NEW_IMAGE}" ]; then cmd+=" --new-image ${NEW_IMAGE}"; fi
  if [ -n "${EXPLICIT_NEW_KMS}" ]; then cmd+=" --new-kms ${NEW_KMS}"; fi
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
  python3 "${REPO_ROOT}/.mise/scripts/test/db/verify_db_upgrade.py" "${subcmd}" \
    --url "https://127.0.0.1:${KMS_HOST_PORT}" \
    --ca-cert "${cert_dir}/ca/ca.crt" \
    --client-cert "${cert_dir}/owner/owner.client.acme.com.crt" \
    --client-key "${cert_dir}/owner/owner.client.acme.com.key" \
    --grantee-cert "${cert_dir}/user/user.client.acme.com.crt" \
    --grantee-key "${cert_dir}/user/user.client.acme.com.key" \
    --old-version "${old_version}" --new-version "${NEW_LABEL}" \
    --backend "${backend}" --variant "${VARIANT}" --replay-cmd "${replay}" "$@"
}

# Run populate_db.sh (populate|verify) against the active server; no-op without --ckms.
run_populate() {
  local mode="$1" state_dir="$2"
  shift 2
  if [ -z "${CKMS_BIN}" ]; then
    [ "${mode}:${state_dir##*/}" != "populate:populate-old" ] || print_status "populate_db.sh skipped (no --ckms)"
    return 0
  fi
  bash "${REPO_ROOT}/.mise/scripts/test/db/populate_db.sh" "${mode}" --ckms "${CKMS_BIN}" \
    --url "https://127.0.0.1:${KMS_HOST_PORT}" --state-dir "${state_dir}" --variant "${VARIANT}" "$@"
}

# Append a cell's populate coverage (ops.tsv) to the per-backend report.
report_coverage() {
  local backend="$1" old_version="$2" cell_dir="$3" suffix pass skip
  for suffix in old new; do
    [ -f "${cell_dir}/populate-${suffix}/ops.tsv" ] || continue
    mkdir -p "${ARTIFACTS_DIR}"
    local report="${ARTIFACTS_DIR}/coverage-${backend}.tsv"
    [ "${suffix}" = "old" ] || report="${ARTIFACTS_DIR}/coverage-${backend}-new.tsv"
    awk -v v="${old_version}" '{print v "\t" $0}' "${cell_dir}/populate-${suffix}/ops.tsv" >>"${report}"
    pass="$(awk -F'\t' '$2=="PASS"' "${cell_dir}/populate-${suffix}/ops.tsv" | wc -l | tr -d ' ')"
    skip="$(awk -F'\t' '$2=="SKIP"' "${cell_dir}/populate-${suffix}/ops.tsv" | wc -l | tr -d ' ')"
    print_status "${backend} ${old_version}: ${pass} PASS, ${skip} SKIP on the ${suffix} server"
  done
}

# Create the key encryption key (KEK) on the active, KEK-less server; every later start configures it.
create_kek() {
  [ -n "${CKMS_BIN}" ] || return 0
  COSMIAN_KMS_CLI_FORMAT=json "${CKMS_BIN}" -c "${REPO_ROOT}/test_data/configs/client/cert_owner.toml" \
    --url "https://127.0.0.1:${KMS_HOST_PORT}" sym keys create --number-of-bits 256 "${KEK_ID}" >/dev/null
}

# Seed the database with the old KMS container and capture the pre-upgrade snapshot. With --ckms, then
# restart the old server with a KEK configured (KEK_ACTIVE for every later start) and fill it again,
# so the objects created by that run are wrapped at rest by the KEK.
seed_cell_db() {
  local backend="$1" old_version="$2" old_image="$3" seed="$4" cell_dir="$5" seed_target="$6"
  start_old "${old_image}" "${backend}" "${seed_target}" "${cell_dir}/old-seed.log" "${old_version}" &&
    run_py_verifier seed "${backend}" "${old_version}" "${seed}" \
      --snapshot "${cell_dir}/snapshot.json" --seed "${seed}" --count "${RANDOM_COUNT}" \
      --sample-cert "${REPO_ROOT}/test_data/certificates/client_server/server/kmserver.acme.com.crt" &&
    run_populate populate "${cell_dir}/populate-old" --prefix pop --lenient &&
    create_kek &&
    stop_old "${backend}" "${cell_dir}/old-seed.log" || return 1
  [ -n "${CKMS_BIN}" ] || return 0
  KEK_ACTIVE=1
  start_old "${old_image}" "${backend}" "${seed_target}" "${cell_dir}/old-kek.log" "${old_version}" &&
    run_populate populate "${cell_dir}/populate-kek" --prefix kek --lenient &&
    stop_old "${backend}" "${cell_dir}/old-kek.log"
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

  local legacy_state=() # releases before 5.13.0 stored a State in the JSON that lags the enforced column
  ! version_lt "${old_version}" 5.13.0 || legacy_state=(--legacy-state)
  # Redis releases before 5.29.0 can leave a Findex tag the stored record lost; see populate_db.sh
  if [ "${backend}" = "redis" ] && version_lt "${old_version}" 5.29.0; then legacy_state+=(--legacy-locate); fi
  local nested_wrap=() # releases before 5.29.0 cannot unwrap a key wrapped by a user key after a restart when a KEK is configured
  ! version_lt "${old_version}" 5.29.0 || nested_wrap=(--legacy-nested-wrap)
  PHASE=seed
  start_db_container "${backend}" &&
    seed_cell_db "${backend}" "${old_version}" "${old_image}" "${seed}" "${cell_dir}" "${seed_target}" &&
    backup_seeded_db "${backend}" "${cell_dir}" &&
    { PHASE=candidate; } &&
    start_candidate "${backend}" "${cand_target}" "${cell_dir}/new-candidate.log" &&
    run_py_verifier verify "${backend}" "${old_version}" "${seed}" \
      --snapshot "${cell_dir}/snapshot.json" --phase candidate --mutate &&
    run_populate verify "${cell_dir}/populate-old" "${legacy_state[@]}" &&
    { [ -z "${KEK_ACTIVE}" ] || run_populate verify "${cell_dir}/populate-kek" "${legacy_state[@]}"; } &&
    run_populate populate "${cell_dir}/populate-new" --prefix new --migrated-state "${cell_dir}/populate-old" ${KEK_ACTIVE:+--kek-wrapped} &&
    { PHASE=candidate-restart; } &&
    stop_candidate "${backend}" "${cell_dir}/new-candidate.log" &&
    start_candidate "${backend}" "${cand_target}" "${cell_dir}/new-restart.log" &&
    run_py_verifier verify "${backend}" "${old_version}" "${seed}" \
      --snapshot "${cell_dir}/snapshot.json" --phase candidate-restart &&
    run_populate verify "${cell_dir}/populate-old" "${legacy_state[@]}" &&
    { [ -z "${KEK_ACTIVE}" ] || run_populate verify "${cell_dir}/populate-kek" "${legacy_state[@]}"; } &&
    run_populate verify "${cell_dir}/populate-new" &&
    stop_candidate "${backend}" "${cell_dir}/new-restart.log" &&
    { PHASE=restore; } &&
    prepare_restore_db "${backend}" "${cell_dir}" &&
    start_old "${old_image}" "${backend}" "${rest_target}" "${cell_dir}/old-restore.log" "${old_version}" &&
    run_py_verifier verify "${backend}" "${old_version}" "${seed}" \
      --snapshot "${cell_dir}/snapshot.json" --phase restore &&
    run_populate verify "${cell_dir}/populate-old" "${legacy_state[@]}" &&
    { [ -z "${KEK_ACTIVE}" ] || run_populate verify "${cell_dir}/populate-kek" "${legacy_state[@]}" "${nested_wrap[@]}"; } &&
    stop_old "${backend}" "${cell_dir}/old-restore.log"
  local rc="$?"
  [ "${rc}" = 0 ] || echo "cell ${backend}:${old_version} failed in phase: ${PHASE}" >&2
  [ -z "${HOST_KMS_PID}" ] || stop_host_kms
  docker rm --force "${DB_CONTAINER}" >/dev/null 2>&1 || true
  return "${rc}"
}

parse_args "$@"
NEW_LABEL="${NEW_IMAGE}"
if [ -n "${NEW_KMS}" ]; then NEW_LABEL="$("${NEW_KMS}" --version | head -n1)"; fi
if [ -n "${OLD_KMS}" ]; then
  RAW_VERSIONS="$("${OLD_KMS}" --version | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)"
  [ -n "${RAW_VERSIONS}" ] || print_error "Cannot read a version from: ${OLD_KMS} --version"
  ! version_lt "${RAW_VERSIONS}" 5.17.0 || print_error "--old-kms needs a >= 5.17.0 binary (host start uses PEM TLS)"
else
  RAW_VERSIONS="$(resolve_old_versions)"
fi
RAW_BACKENDS="$(resolve_backends)"
mapfile -t VERSIONS <<<"${RAW_VERSIONS}"
read -r -a BACKENDS <<<"${RAW_BACKENDS}"
[ -n "${VERSIONS[0]:-}" ] || print_error "Resolved empty old-version list."
[ -n "${BACKENDS[0]:-}" ] || print_error "Resolved empty backend list."

docker network create "${NETWORK}" >/dev/null
BASE_SEED="${SEED_ARG:-$(date +%s)}"
REPO_PREFIX="ghcr.io/cosmian/kms"
[ "${VARIANT}" != "fips" ] || REPO_PREFIX="ghcr.io/cosmian/kms-fips"

print_header "DB Upgrade Gate (variant=${VARIANT}, new=${NEW_KMS:-${NEW_IMAGE}}, backends=${BACKENDS[*]}, versions=${VERSIONS[*]}, seed=${BASE_SEED})"

for backend in "${BACKENDS[@]}"; do
  case "${backend}" in
    postgresql) pull_image_with_retry "${POSTGRES_IMAGE}" ;;
    mysql) pull_image_with_retry "${MYSQL_IMAGE}" ;;
    redis) pull_image_with_retry "${REDIS_IMAGE}" ;;
  esac
done

# report_coverage appends per cell: start each run with empty reports.
for backend in "${BACKENDS[@]}"; do
  rm -f "${ARTIFACTS_DIR}/coverage-${backend}.tsv" "${ARTIFACTS_DIR}/coverage-${backend}-new.tsv"
done

FAILED=()
REPLAYS=()
for old_ver in "${VERSIONS[@]}"; do
  old_img="${REPO_PREFIX}:${old_ver}"
  [ -n "${OLD_KMS}" ] || pull_image_with_retry "${old_img}"
  for backend in "${BACKENDS[@]}"; do
    if [ "${backend}" = "redis" ] && version_lt "${old_ver}" 5.12.0; then
      print_warning "redis: skipping ${old_ver} (pre-5.12.0 Redis/Findex data is refused by design, crate/server_database/src/stores/redis/migrations/mod.rs:122)"
      continue
    fi
    print_status "Testing upgrade ${old_ver} -> ${NEW_KMS:-${NEW_IMAGE}} on ${backend} (${VARIANT}, seed=${BASE_SEED})"
    if (run_upgrade_cell "${backend}" "${old_ver}" "${old_img}" "${BASE_SEED}"); then
      print_success "${backend} (${VARIANT}) upgrade from ${old_ver} passed"
    else
      print_warning "${backend} (${VARIANT}) upgrade from ${old_ver} FAILED"
      save_failure_artifacts "${backend}" "${old_ver}" "${WORK_DIR}/${backend}-${old_ver}"
      FAILED+=("${backend}:${old_ver}")
      REPLAYS+=("$(format_replay_cmd "${backend}" "${old_ver}" "${BASE_SEED}")")
    fi
    report_coverage "${backend}" "${old_ver}" "${WORK_DIR}/${backend}-${old_ver}"
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
