#!/bin/bash
# EDB TDE KMIP Integration Test Runner
# Tests Cosmian KMS compatibility with EDB Postgres Advanced Server TDE.
#
# Expects the EDB container to already be running (lifecycle owned by the nix
# wrapper .github/scripts/test/test_edb_tde.sh and test_all.yml in CI).
# Requires CONTAINER_NAME and EDB_MASTER_KEY_UID to be exported by the caller.
#
# Flow:
#   1. Connects to the running edb-tde container (started by nix wrapper).
#   2. EDB Postgres initialises with TDE — initdb calls the REAL
#      /usr/edb/kmip/client/edb_tde_kmip_client.py (wrap command) to seal
#      the cluster DEK against the Cosmian KMS.
#   3. All wrap/unwrap roundtrip tests run via
#      `docker exec <container> python3 /usr/edb/kmip/client/edb_tde_kmip_client.py`
#      exercising the real EDB client end-to-end.
#   4. TDE verification: checks data_encryption_version=1, writes and reads
#      back an encrypted row.
#
# Master key creation uses create_master_key.py (a minimal helper) because the
# official edb_tde_kmip_client.py only implements 'encrypt' and 'decrypt'.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

print_status() { echo -e "${GREEN}[INFO]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
print_success() { echo -e "${GREEN}[PASS]${NC} $1"; }
print_fail() { echo -e "${RED}[FAIL]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

# ── Clients ──────────────────────────────────────────────────────────────────
# Key-creation helper — the official edb_tde_kmip_client.py (shipped inside the
# EDB container at /usr/edb/kmip/client/) only implements 'encrypt' and 'decrypt'.
# create_master_key.py fills the gap: it issues KMIP Create + Activate via PyKMIP.
CREATE_KEY_SCRIPT="$SCRIPT_DIR/create_master_key.py"
PYKMIP_CONF_HOST="$SCRIPT_DIR/pykmip.conf"
PYTHON_CMD="${PYTHON_CMD:-python}"

# Real client — path inside the EDB container.
EDB_REAL_CLIENT="/usr/edb/kmip/client/edb_tde_kmip_client.py"
# PyKMIP config inside the container (volume-mounted from pykmip_docker.conf).
EDB_PYKMIP_CONF="/kmip-certs/pykmip.conf"

# Real client — path inside the EDB container.
EDB_REAL_CLIENT="/usr/edb/kmip/client/edb_tde_kmip_client.py"
# PyKMIP config inside the container (volume-mounted from pykmip_docker.conf).
EDB_PYKMIP_CONF="/kmip-certs/pykmip.conf"

# Fail immediately if the required token is absent.
if ! command -v docker >/dev/null 2>&1; then
  echo "Error: docker is not available." >&2
  exit 1
fi

# ── Container constants ───────────────────────────────────────────────────────
# CONTAINER_NAME is exported by the nix wrapper (test_edb_tde.sh) which owns
# the docker compose lifecycle.  If not set (standalone), discovered via docker ps.
EDB_PORT=5444
# Temp directory used for wrapped-key files inside the running container.
CONTAINER_TMP="/tmp/edb_tde"

# ── State ─────────────────────────────────────────────────────────────────────
TESTS_PASSED=0
TESTS_FAILED=0
TMPDIR="${TMPDIR:-/tmp}"
TEST_WORKDIR=$(mktemp -d "$TMPDIR/edb_tde_test.XXXXXX")
# Resolve container name: nix wrapper exports CONTAINER_NAME; fall back to
# docker ps discovery when running standalone.
if [ -z "${CONTAINER_NAME:-}" ]; then
  CONTAINER_NAME=$(docker ps --filter "name=edb-tde" --format "{{.Names}}" | head -1)
  CONTAINER_NAME="${CONTAINER_NAME:-edb-tde}"
fi

cleanup() {
  rm -rf "$TEST_WORKDIR"
}
trap cleanup EXIT

generate_dek() {
  dd if=/dev/urandom bs=32 count=1 2>/dev/null
}

run_test() {
  local test_name="$1"
  local test_func="$2"
  print_status "Running: $test_name"
  if "$test_func"; then
    print_success "$test_name"
    TESTS_PASSED=$((TESTS_PASSED + 1))
  else
    print_fail "$test_name"
    TESTS_FAILED=$((TESTS_FAILED + 1))
  fi
}

# ─── KMIP client abstraction ──────────────────────────────────────────────────
#
# kmip_wrap   <key_uid> <variant> <out_file>   (reads plaintext from stdin)
# kmip_unwrap <key_uid> <variant> <in_file>    (writes plaintext to stdout)
#
# Both functions use the real edb_tde_kmip_client.py inside the running EDB
# container via `docker exec`.  out_file / in_file are paths INSIDE the
# container (under CONTAINER_TMP).

kmip_wrap() {
  local key_uid="$1" variant="$2" out_file="$3"
  # Pass plaintext on stdin; real client writes wrapped key to out_file
  # (a path inside the container).
  docker exec -i "$CONTAINER_NAME" \
    python3 "$EDB_REAL_CLIENT" encrypt \
    --pykmip-config-file="$EDB_PYKMIP_CONF" \
    --key-uid="$key_uid" --variant="$variant" --out-file="$out_file"
}

kmip_unwrap() {
  local key_uid="$1" variant="$2" in_file="$3"
  # Real client reads in_file (container path) and writes plaintext to stdout.
  docker exec "$CONTAINER_NAME" \
    python3 "$EDB_REAL_CLIENT" decrypt \
    --pykmip-config-file="$EDB_PYKMIP_CONF" \
    --key-uid="$key_uid" --variant="$variant" --in-file="$in_file"
}

# All wrapped-key files live inside the container under CONTAINER_TMP.
wrapped_path() {
  echo "$CONTAINER_TMP/$1"
}

# ─── Setup: login + start EDB Postgres TDE container ─────────────────────────
setup_edb_container() {
  # 1. Master key UID — provided by nix wrapper via env, or create one now.
  local uid="${EDB_MASTER_KEY_UID:-}"
  if [ -n "$uid" ]; then
    print_status "  Using pre-created master key: $uid"
  else
    print_status "  Creating AES-256 master key in Cosmian KMS…"
    uid=$(env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES \
      "$PYTHON_CMD" "$CREATE_KEY_SCRIPT" \
      --pykmip-config-file="$PYKMIP_CONF_HOST" 2>/dev/null)
    if [ -z "$uid" ]; then
      print_error "  Failed to create master key (empty UID returned)"
      return 1
    fi
    print_status "  Master key UID: $uid"
  fi
  echo "$uid" >"$TEST_WORKDIR/master_key_uid.txt"

  # 2. Verify the container is running.
  if ! docker inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
    print_error "  Container '$CONTAINER_NAME' is not running."
    print_error "  Run via: bash .github/scripts/nix.sh --variant non-fips test edb_tde"
    return 1
  fi
  print_status "  Container: $CONTAINER_NAME"

  # 3. Wait for Postgres to accept connections.
  #    initdb with TDE (KMIP key wrap) can take up to 2 minutes on first start.
  local retries=90
  local count=0
  print_status "  Waiting for EDB Postgres to be ready on port ${EDB_PORT}..."
  while ! docker exec "$CONTAINER_NAME" \
    /usr/edb/as17/bin/pg_isready -p "$EDB_PORT" -q 2>/dev/null; do
    count=$((count + 1))
    if [ "$count" -ge "$retries" ]; then
      print_error "  EDB Postgres not ready after $retries attempts"
      docker logs "$CONTAINER_NAME" 2>&1 | tail -40
      return 1
    fi
    sleep 2
  done
  print_status "  EDB Postgres is ready — cluster DEK was sealed by the real KMIP client"

  # 4. Create temp dir inside container for test artefacts.
  docker exec "$CONTAINER_NAME" mkdir -p "$CONTAINER_TMP" 2>/dev/null || true

  return 0
}

# ─── Test: Create master key ──────────────────────────────────────────────────
test_create_master_key() {
  if [ -f "$TEST_WORKDIR/master_key_uid.txt" ]; then
    # Key was already created by setup_edb_container; nothing to do.
    print_status "  Reusing master key from container setup: $(cat "$TEST_WORKDIR/master_key_uid.txt")"
    return 0
  fi

  # Create key now via create_master_key.py.
  local uid
  uid=$(env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES \
    "$PYTHON_CMD" "$CREATE_KEY_SCRIPT" \
    --pykmip-config-file="$PYKMIP_CONF_HOST" --verbose 2>/dev/null)

  if [ -z "$uid" ]; then
    print_error "Failed to create master key (empty UID)"
    return 1
  fi

  echo "$uid" >"$TEST_WORKDIR/master_key_uid.txt"
  print_status "  Master key UID: $uid"
  return 0
}

# ─── Test: pykmip variant roundtrip ──────────────────────────────────────────
test_pykmip_variant_roundtrip() {
  local uid
  uid=$(cat "$TEST_WORKDIR/master_key_uid.txt")

  local dek_file="$TEST_WORKDIR/dek_plain.bin"
  local unwrapped_file="$TEST_WORKDIR/dek_unwrapped_pykmip.bin"
  local wrapped_out
  wrapped_out=$(wrapped_path "dek_wrapped_pykmip.bin")

  generate_dek >"$dek_file"

  if ! kmip_wrap "$uid" pykmip "$wrapped_out" <"$dek_file"; then
    print_error "  Encrypt (pykmip variant) failed"
    return 1
  fi

  if ! kmip_unwrap "$uid" pykmip "$wrapped_out" >"$unwrapped_file"; then
    print_error "  Decrypt (pykmip variant) failed"
    return 1
  fi

  if ! cmp -s "$dek_file" "$unwrapped_file"; then
    print_error "  Roundtrip FAILED: decrypted data does not match original"
    print_error "  Original:  $(xxd -p "$dek_file" 2>/dev/null | head -1 || od -A x -t x1z "$dek_file" | head -1)"
    print_error "  Decrypted: $(xxd -p "$unwrapped_file" 2>/dev/null | head -1 || od -A x -t x1z "$unwrapped_file" | head -1)"
    return 1
  fi

  print_status "  Verified via real edb_tde_kmip_client.py (pykmip variant)"
  return 0
}

# ─── Test: thales variant — wrap OK, decrypt correctly rejected ───────────────
#
# The EDB thales variant (--variant=thales) sends a KMIP Decrypt request where
# the 16-byte IV is prepended to the ciphertext in the Data field, with NO
# IVCounterNonce attribute.  Cosmian KMS rejects such requests with
# Invalid_Message("missing-iv") per the mandatory KMIP requirement CS-BC-M-11.
#
# This test verifies the EXPECTED behaviour:
#   • Wrap (encrypt)   → succeeds (KMS returns IVCounterNonce + Data normally)
#   • Unwrap (decrypt) → is rejected by the KMS (correct; use --variant=pykmip)
#
# Production recommendation: always use --variant=pykmip with Cosmian KMS.
test_thales_variant_roundtrip() {
  local uid
  uid=$(cat "$TEST_WORKDIR/master_key_uid.txt")

  local dek_file="$TEST_WORKDIR/dek_plain_thales.bin"
  local wrapped_out
  wrapped_out=$(wrapped_path "dek_wrapped_thales.bin")

  generate_dek >"$dek_file"

  # Step 1: wrap (encrypt) — must succeed.
  if ! kmip_wrap "$uid" thales "$wrapped_out" <"$dek_file"; then
    print_error "  Encrypt (thales variant) unexpectedly failed"
    return 1
  fi
  print_status "  Thales wrap (encrypt): OK"

  # Step 2: unwrap (decrypt) — MUST BE REJECTED by Cosmian KMS.
  # The real EDB client sends Data=IV||ciphertext without IVCounterNonce;
  # Cosmian KMS returns Invalid_Message("missing-iv") per KMIP CS-BC-M-11.
  if kmip_unwrap "$uid" thales "$wrapped_out" >/dev/null 2>&1; then
    print_error "  Decrypt (thales variant) unexpectedly succeeded"
    print_error "  Expected rejection by Cosmian KMS (missing IVCounterNonce)"
    return 1
  fi
  print_status "  Thales decrypt: correctly rejected by Cosmian KMS (KMIP CS-BC-M-11 compliance)"
  print_status "  NOTE: use --variant=pykmip for production deployments"
  return 0
}

# ─── Test: Key rotation ───────────────────────────────────────────────────────
test_key_rotation() {
  local old_uid
  old_uid=$(cat "$TEST_WORKDIR/master_key_uid.txt")

  local dek_file="$TEST_WORKDIR/dek_rotation.bin"
  local unwrapped="$TEST_WORKDIR/dek_unwrapped_rotation.bin"
  local wrapped_old
  wrapped_old=$(wrapped_path "dek_wrapped_old.bin")
  local wrapped_new
  wrapped_new=$(wrapped_path "dek_wrapped_new.bin")

  generate_dek >"$dek_file"

  if ! kmip_wrap "$old_uid" pykmip "$wrapped_old" <"$dek_file"; then
    print_error "  Wrap with old key failed"
    return 1
  fi

  # Create a new master key for rotation.
  local new_uid
  new_uid=$(env -u LD_LIBRARY_PATH -u OPENSSL_CONF -u OPENSSL_MODULES \
    "$PYTHON_CMD" "$CREATE_KEY_SCRIPT" \
    --pykmip-config-file="$PYKMIP_CONF_HOST" 2>/dev/null)
  if [ -z "$new_uid" ]; then
    print_error "  Failed to create rotated master key"
    return 1
  fi
  print_status "  New master key UID: $new_uid"

  # Re-wrap: unwrap with old key → pipe directly into wrap with new key.
  if ! kmip_unwrap "$old_uid" pykmip "$wrapped_old" |
    kmip_wrap "$new_uid" pykmip "$wrapped_new"; then
    print_error "  Re-wrap (key rotation) failed"
    return 1
  fi

  # Verify: unwrap with new key must yield the original DEK.
  if ! kmip_unwrap "$new_uid" pykmip "$wrapped_new" >"$unwrapped"; then
    print_error "  Unwrap with new key failed"
    return 1
  fi

  if ! cmp -s "$dek_file" "$unwrapped"; then
    print_error "  Key rotation FAILED: re-wrapped DEK does not match original"
    return 1
  fi

  print_status "  Key rotation verified: old_key → new_key roundtrip OK"
  echo "$new_uid" >"$TEST_WORKDIR/rotated_key_uid.txt"
  return 0
}

# ─── Test: Multiple DEK sizes ─────────────────────────────────────────────────
test_multiple_dek_sizes() {
  local uid
  uid=$(cat "$TEST_WORKDIR/master_key_uid.txt")

  # EDB Postgres uses a 32-byte cluster DEK by default; test a range of sizes.
  local sizes=(16 32 48 64 128)

  for size in "${sizes[@]}"; do
    local dek_file="$TEST_WORKDIR/dek_${size}.bin"
    local unwrapped_file="$TEST_WORKDIR/dek_${size}_unwrapped.bin"
    local wrapped_out
    wrapped_out=$(wrapped_path "dek_${size}_wrapped.bin")

    dd if=/dev/urandom bs="$size" count=1 2>/dev/null >"$dek_file"

    if ! kmip_wrap "$uid" pykmip "$wrapped_out" <"$dek_file"; then
      print_error "  Size $size: wrap failed"
      return 1
    fi

    if ! kmip_unwrap "$uid" pykmip "$wrapped_out" >"$unwrapped_file"; then
      print_error "  Size $size: unwrap failed"
      return 1
    fi

    if ! cmp -s "$dek_file" "$unwrapped_file"; then
      print_error "  Size $size FAILED"
      return 1
    fi
  done

  print_status "  All DEK sizes (${sizes[*]}) verified"
  return 0
}

# ─── Test: Verify EDB Postgres TDE is active ──────────────────────────────────
#
# Confirms that the database was initialised with TDE (data_encryption_version=1)
# and that encrypted rows can be written and read back correctly.
test_postgres_tde_verify() {
  print_status "  Verifying TDE: querying data_encryption_version…"
  local tde_version
  tde_version=$(docker exec -i \
    -e PGPASSWORD="${EDB_PGPASSWORD:-kms_test}" "$CONTAINER_NAME" \
    psql -U enterprisedb -d postgres -p "$EDB_PORT" -At \
    -c "SELECT data_encryption_version FROM pg_control_init();" 2>&1)
  local psql_exit=$?

  # Strip any non-numeric output (warnings, notices) to get a clean integer.
  local tde_int
  tde_int=$(echo "$tde_version" | grep -E '^[0-9]+$' | head -1)

  if [ "$psql_exit" != "0" ] || [ -z "$tde_int" ]; then
    print_error "  psql query failed (exit $psql_exit): $tde_version"
    docker logs "$CONTAINER_NAME" 2>&1 | tail -20
    return 1
  fi

  if [ "$tde_int" != "1" ]; then
    print_error "  TDE not active: data_encryption_version=${tde_int} (expected 1)"
    docker logs "$CONTAINER_NAME" 2>&1 | tail -20
    return 1
  fi
  print_status "  TDE active: data_encryption_version=$tde_int"

  print_status "  Creating and querying encrypted test table…"
  docker exec -i \
    -e PGPASSWORD="${EDB_PGPASSWORD:-kms_test}" "$CONTAINER_NAME" \
    psql -U enterprisedb -d postgres -p "$EDB_PORT" -At \
    -c "CREATE TABLE tde_test (id int, secret text);
        INSERT INTO tde_test VALUES (1, 'kmip_secret_data');" 2>/dev/null

  local row_count
  row_count=$(docker exec -i \
    -e PGPASSWORD="${EDB_PGPASSWORD:-kms_test}" "$CONTAINER_NAME" \
    psql -U enterprisedb -d postgres -p "$EDB_PORT" -At \
    -c "SELECT count(*) FROM tde_test WHERE secret='kmip_secret_data';" 2>/dev/null ||
    echo "0")

  if [ "${row_count:-0}" != "1" ]; then
    print_error "  Encrypted row query returned count=${row_count:-0} (expected 1)"
    return 1
  fi
  print_status "  Encrypted row verified: 1/1 row found in TDE-encrypted database"
  return 0
}

# ─── Main ─────────────────────────────────────────────────────────────────────

_run_all() {
  run_test "EDB Postgres TDE: login & start container" setup_edb_container
  run_test "Create master key (AES-256)" test_create_master_key
  run_test "PyKMIP variant: wrap/unwrap DEK" test_pykmip_variant_roundtrip
  run_test "Thales variant: wrap OK, decrypt rejected (KMIP CS-BC-M-11)" test_thales_variant_roundtrip
  run_test "Key rotation (re-wrap with new key)" test_key_rotation
  run_test "Multiple DEK sizes" test_multiple_dek_sizes
  run_test "EDB Postgres TDE: verify encryption active" test_postgres_tde_verify
}

main() {
  local command="${1:-all}"

  echo ""
  echo "╔══════════════════════════════════════════════════════════════╗"
  echo "║  EDB PostgreSQL TDE — KMIP Compliance Test Suite           ║"
  echo "║  Testing against Cosmian KMS                               ║"
  echo "╚══════════════════════════════════════════════════════════════╝"
  echo ""

  case "$command" in
    all)
      _run_all
      ;;
    create)
      run_test "Create master key (AES-256)" test_create_master_key
      ;;
    pykmip)
      run_test "Create master key (AES-256)" test_create_master_key
      run_test "PyKMIP variant: wrap/unwrap DEK" test_pykmip_variant_roundtrip
      ;;
    thales)
      run_test "Create master key (AES-256)" test_create_master_key
      run_test "Thales variant: wrap OK, decrypt rejected (KMIP CS-BC-M-11)" test_thales_variant_roundtrip
      ;;
    rotation)
      run_test "Create master key (AES-256)" test_create_master_key
      run_test "PyKMIP variant: wrap/unwrap DEK" test_pykmip_variant_roundtrip
      run_test "Key rotation (re-wrap with new key)" test_key_rotation
      ;;
    postgres)
      run_test "EDB Postgres TDE: login & start container" setup_edb_container
      run_test "Create master key (AES-256)" test_create_master_key
      run_test "EDB Postgres TDE: verify encryption active" test_postgres_tde_verify
      ;;
    *)
      echo "Usage: $0 [all|create|pykmip|thales|rotation|postgres]"
      exit 1
      ;;
  esac

  echo ""
  echo "════════════════════════════════════════════════════════════════"
  echo "  Client: real edb_tde_kmip_client.py (docker exec into $CONTAINER_NAME)"
  echo "  Results: ${TESTS_PASSED} passed, ${TESTS_FAILED} failed"
  echo "════════════════════════════════════════════════════════════════"

  if [ "$TESTS_FAILED" -gt 0 ]; then
    exit 1
  fi
}

main "$@"
