#!/bin/bash
# EDB Postgres TDE startup script for integration testing.
#
# Used as the docker-compose `command` for the edb-tde service.
# - Runs `initdb` with `--key-wrap-command` / `--key-unwrap-command` on first
#   start (wrapping the cluster DEK via the real edb_tde_kmip_client.py).
# - Sets `data_encryption_key_unwrap_command` in postgresql.conf so postgres
#   can unseal the DEK on every subsequent restart.
# - Starts `postgres` in the foreground so the container stays alive.
#
# Required environment variables (injected by docker-compose):
#   PGDATAKEYWRAPCMD    — shell command for DEK wrapping  (set by compose, includes --out-file=%p)
#   PGDATAKEYUNWRAPCMD  — shell command for DEK unwrapping (set by compose, includes --in-file=%p)
#   EDB_PORT            — Postgres port (default: 5444)

set -eo pipefail

PG_BIN="/usr/edb/as17/bin"
# The postgres server binary is edb-postgres (symlinked as /usr/local/bin/postgres).
PG_SERVER="/usr/local/bin/postgres"
PGDATA="/tmp/pgdata_tde"
PGPORT="${EDB_PORT:-5444}"

echo "=== EDB Postgres TDE Test Startup ==="
echo "    PGPORT:             $PGPORT"
echo "    PGDATA:             $PGDATA"
echo "    WRAP command:       ${PGDATAKEYWRAPCMD:-<not set>}"
echo "    UNWRAP command:     ${PGDATAKEYUNWRAPCMD:-<not set>}"

if [ ! -f "$PGDATA/PG_VERSION" ]; then
  echo ""
  echo "=== Initialising new cluster with TDE ==="
  # Remove any partial data left by a previous failed initdb run.
  rm -rf "$PGDATA"
  mkdir -p "$PGDATA"

  # initdb calls PGDATAKEYWRAPCMD (with %p → temp file path) to seal
  # the freshly-generated cluster DEK against the Cosmian KMS.
  "$PG_BIN/initdb" \
    -y \
    -D "$PGDATA" \
    -U enterprisedb \
    --auth-local=peer \
    --auth-host=trust \
    --key-wrap-command="${PGDATAKEYWRAPCMD}" \
    --key-unwrap-command="${PGDATAKEYUNWRAPCMD}"

  # Also set the GUC in postgresql.conf so postgres uses the correct
  # unwrap command at every startup.
  cat >>"$PGDATA/postgresql.conf" <<PGCONF

# --- EDB TDE integration test settings ---
# Used by postgres to unseal the cluster DEK on startup.
data_encryption_key_unwrap_command = '${PGDATAKEYUNWRAPCMD}'

# Accept connections from docker exec (test environment only).
listen_addresses = '*'
port = ${PGPORT}
PGCONF

  # Allow password-less connections from any host (tests only).
  echo "host all all 0.0.0.0/0 trust" >>"$PGDATA/pg_hba.conf"

  echo "=== initdb with TDE completed successfully ==="
fi

echo ""
echo "=== Starting EDB Postgres on port ${PGPORT} ==="
exec "$PG_SERVER" -D "$PGDATA"
