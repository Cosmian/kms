#!/usr/bin/env bash
#
# setup_oracle_tde.sh — Oracle TDE + Cosmian KMS Docker demo
#
# Usage:  ./setup_oracle_tde.sh [--version 5.18.0]
#
# Run this script from the demo/ directory.
# It will:
#   1. Auto-detect the Oracle container architecture (amd64 / arm64)
#   2. Download the matching Cosmian CLI .deb if not already present
#   3. Extract libcosmian_pkcs11.so
#   4. Create ckms.toml
#   5. Start docker compose (oracle + kms-oracle)
#   6. Wait for Oracle to be healthy
#   7. Install the PKCS#11 library and config inside the Oracle container
#   8. Configure Oracle TDE via run_sql_commands.sh
#   9. Run a quick smoke test (create encrypted table, insert, select)
#  10. Copy the Oracle datafile to oracle/dump/ and prove that the column
#      values are NOT visible in the raw file (TDE encryption at rest)
#

set -euo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────

KMS_VERSION="${1:-5.20.1}"
KMS_VERSION="${KMS_VERSION#--version }"   # strip flag if passed as --version X

ORACLE_IMAGE="container-registry.oracle.com/database/free:latest-lite"
PACKAGE_BASE="https://package.cosmian.com/kms/${KMS_VERSION}"
DEMO_PDB="FREEPDB1"      # PDB where demo tables are created
DEMO_USER="kms_demo"    # local PDB user created for the smoke test
DEMO_PASS="kmsDemo123"  # password for the demo PDB user
DEMO_TS="KMS_DEMO_TS"   # dedicated tablespace (makes a known, small .dbf to dump)
DEMO_DBF="/opt/oracle/oradata/FREE/FREEPDB1/kms_demo_ts01.dbf"

# ── Helpers ───────────────────────────────────────────────────────────────────

log()  { echo "▶  $*"; }
ok()   { echo "✓  $*"; }
err()  { echo "✗  $*" >&2; exit 1; }

run_sql() {
  local sql1="$1" sql2="${2:-}" sql3="${3:-}"
  log "SQL: $sql1"
  cat > /tmp/kms_demo.sql << EOF
WHENEVER SQLERROR EXIT SQL.SQLCODE;
WHENEVER OSERROR EXIT FAILURE;
${sql1}
${sql2}
${sql3}
exit
EOF
  docker cp /tmp/kms_demo.sql oracle:/tmp/kms_demo.sql
  docker exec -u oracle -i oracle bash -c "sqlplus / as sysdba @/tmp/kms_demo.sql"
  sleep 3
}

# ── Step 1 — Detect Oracle container architecture ─────────────────────────────

log "Detecting Oracle container architecture..."
ORACLE_ARCH=$(docker run --rm --platform="" "${ORACLE_IMAGE}" uname -m 2>/dev/null || true)

if [[ -z "$ORACLE_ARCH" ]]; then
  # Fall back to host arch
  HOST_ARCH=$(uname -m)
  ORACLE_ARCH="$HOST_ARCH"
  log "Could not pull image to detect arch, falling back to host arch: ${HOST_ARCH}"
fi

case "$ORACLE_ARCH" in
  aarch64|arm64) DEB_ARCH="arm64" ;;
  x86_64|amd64)  DEB_ARCH="amd64" ;;
  *) err "Unsupported architecture: ${ORACLE_ARCH}" ;;
esac

DEB_FILE="cosmian-kms-cli-non-fips-static-openssl_${KMS_VERSION}_${DEB_ARCH}.deb"
DEB_URL="${PACKAGE_BASE}/deb/${DEB_ARCH}/non-fips/static/${DEB_FILE}"

ok "Oracle container arch: ${ORACLE_ARCH} → using ${DEB_ARCH} package"

# ── Step 2 — Download / verify the .deb ──────────────────────────────────────

if [[ -f "$DEB_FILE" ]]; then
  ok ".deb already present: ${DEB_FILE}"
else
  log "Downloading ${DEB_FILE} ..."
  if command -v curl &>/dev/null; then
    curl -fL --progress-bar -o "${DEB_FILE}" "${DEB_URL}" \
      || err "Download failed. Please download manually from ${DEB_URL}"
  elif command -v wget &>/dev/null; then
    wget -q --show-progress -O "${DEB_FILE}" "${DEB_URL}" \
      || err "Download failed. Please download manually from ${DEB_URL}"
  else
    err "Neither curl nor wget found. Please download manually:\n  ${DEB_URL}"
  fi
  ok "Downloaded ${DEB_FILE}"
fi

# ── Step 3 — Extract libcosmian_pkcs11.so ────────────────────────────────────

log "Extracting libcosmian_pkcs11.so from ${DEB_FILE} ..."
rm -rf extracted
rm -f libcosmian_pkcs11.so
mkdir -p extracted
cd extracted
ar x "../${DEB_FILE}"
tar xf data.tar.*
cd ..
cp extracted/usr/local/lib/libcosmian_pkcs11.so .
ok "libcosmian_pkcs11.so extracted ($(file libcosmian_pkcs11.so | grep -oE 'ELF 64-bit[^,]+,[^,]+'))"

# ── Step 4 — Create ckms.toml ─────────────────────────────────────────────────

cat > ckms.toml << 'EOF'
[http_config]
server_url = "http://kms:9998"
EOF
ok "ckms.toml created"

# ── Step 5 — Prepare KMS data directory ──────────────────────────────────────

mkdir -p oracle/cosmian-kms
ok "oracle/cosmian-kms directory ready"

# ── Step 6 — Start Docker services ───────────────────────────────────────────

log "Starting Docker services (oracle + kms-oracle)..."
docker compose up -d
ok "Containers started"

# ── Step 7 — Wait for Oracle to be healthy ────────────────────────────────────

log "Waiting for Oracle to be healthy (may take up to 3 minutes on first run)..."
TIMEOUT=180
ELAPSED=0
until docker inspect --format='{{.State.Health.Status}}' oracle 2>/dev/null | grep -q "healthy"; do
  if (( ELAPSED >= TIMEOUT )); then
    err "Oracle did not become healthy within ${TIMEOUT}s. Check: docker logs oracle"
  fi
  printf "."
  sleep 10
  (( ELAPSED += 10 ))
done
echo ""
ok "Oracle is healthy"

# ── Step 8 — Install PKCS#11 library inside Oracle ───────────────────────────

log "Installing libcosmian_pkcs11.so and ckms.toml into Oracle container..."
docker cp libcosmian_pkcs11.so oracle:/home/oracle/
docker cp ckms.toml oracle:/home/oracle/
docker cp setup_cosmian_pkcs11.sh oracle:/home/oracle/
docker exec -u root -i oracle bash -c \
  "chmod +x /home/oracle/setup_cosmian_pkcs11.sh && /home/oracle/setup_cosmian_pkcs11.sh"
ok "PKCS#11 library installed"

# Verify the library is loadable inside the container
MISSING=$(docker exec oracle bash -c \
  "ldd /opt/oracle/extapi/64/hsm/Cosmian/libcosmian_pkcs11.so 2>&1 | grep 'not found'" 2>/dev/null || true)
if [[ -n "$MISSING" ]]; then
  err "Library has unresolved dependencies inside Oracle container:\n${MISSING}\nDid you use the correct .deb architecture?"
fi
ok "Library dependencies verified"

# ── Step 9 — Configure Oracle TDE ────────────────────────────────────────────

log "Configuring Oracle TDE (WALLET_ROOT, TDE_CONFIGURATION, keystore open+set key)..."
./run_sql_commands.sh
ok "Oracle TDE configured (CDB)"

# run_sql_commands.sh opens the keystore only in the CDB. FREEPDB1 needs its
# own OPEN + master-key activation so that PDB users can create ENCRYPT columns.
log "Opening TDE wallet and activating master key in ${DEMO_PDB}..."
run_sql \
  "ALTER SESSION SET CONTAINER = ${DEMO_PDB};" \
  "ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN IDENTIFIED BY hsm_identity_pass;" \
  "ADMINISTER KEY MANAGEMENT SET KEY IDENTIFIED BY hsm_identity_pass;"
ok "Oracle TDE configured (${DEMO_PDB})"

# Helper: run SQL in FREEPDB1 as the demo user (TCP EZConnect)
run_sql_pdb() {
  local sql1="$1" sql2="${2:-}" sql3="${3:-}"
  log "SQL (${DEMO_USER}@${DEMO_PDB}): $sql1"
  cat > /tmp/kms_demo.sql << EOF
WHENEVER SQLERROR EXIT SQL.SQLCODE;
WHENEVER OSERROR EXIT FAILURE;
${sql1}
${sql2}
${sql3}
exit
EOF
  docker cp /tmp/kms_demo.sql oracle:/tmp/kms_demo.sql
  docker exec -u oracle -i oracle bash -c \
    "sqlplus ${DEMO_USER}/${DEMO_PASS}@//localhost:1521/${DEMO_PDB} @/tmp/kms_demo.sql"
  sleep 2
}

# ── Step 9.5 — Create demo PDB user with a dedicated tablespace ──────────────
#
# A dedicated tablespace (KMS_DEMO_TS) lets us copy a small, known .dbf file
# in step 11 to prove the column values are encrypted at rest.

log "Creating tablespace ${DEMO_TS} and user ${DEMO_USER} in ${DEMO_PDB}..."
# WHENEVER SQLERROR CONTINUE lets DROP silently fail on first run.
cat > /tmp/kms_pdb_user.sql << EOF
WHENEVER SQLERROR CONTINUE;
ALTER SESSION SET CONTAINER = ${DEMO_PDB};
DROP USER ${DEMO_USER} CASCADE;
DROP TABLESPACE ${DEMO_TS} INCLUDING CONTENTS AND DATAFILES;
WHENEVER SQLERROR EXIT SQL.SQLCODE;
CREATE SMALLFILE TABLESPACE ${DEMO_TS}
  DATAFILE '${DEMO_DBF}' SIZE 10M AUTOEXTEND ON;
CREATE USER ${DEMO_USER} IDENTIFIED BY ${DEMO_PASS}
  DEFAULT TABLESPACE ${DEMO_TS}
  QUOTA UNLIMITED ON ${DEMO_TS};
GRANT CONNECT, RESOURCE TO ${DEMO_USER};
exit
EOF
docker cp /tmp/kms_pdb_user.sql oracle:/tmp/kms_pdb_user.sql
docker exec -u oracle -i oracle bash -c "sqlplus / as sysdba @/tmp/kms_pdb_user.sql"
ok "Tablespace ${DEMO_TS} and user ${DEMO_USER} ready"

# ── Step 10 — Smoke test ──────────────────────────────────────────────────────

log "Running smoke test (create encrypted table, insert rows, select)..."
# TDE encrypted tables cannot be owned by SYS; the kms_demo PDB user owns them.
run_sql_pdb "CREATE TABLE kms_demo_tde (id NUMBER PRIMARY KEY, name VARCHAR2(64) ENCRYPT);"
run_sql_pdb \
  "INSERT INTO kms_demo_tde VALUES (1, 'Thomas');" \
  "INSERT INTO kms_demo_tde VALUES (2, 'Aurelie');" \
  "INSERT INTO kms_demo_tde VALUES (3, 'Chris');"
run_sql_pdb "COMMIT;"
run_sql_pdb "SET LINES 120;" "SELECT * FROM kms_demo_tde;"
ok "Smoke test passed"

# ── Step 11 — Dump Oracle datafile and prove TDE encryption at rest ──────────
#
# Oracle TDE column encryption stores ciphertext directly in the data blocks.
# Copying the raw .dbf datafile and running `strings` on it proves that the
# plaintext values (Thomas, Aurelie, Chris) are nowhere in the binary file.

log "Copying ${DEMO_TS} datafile from Oracle container..."
mkdir -p oracle/dump
# Flush dirty blocks to disk before copying
docker exec -u oracle oracle bash -c \
  "echo 'ALTER SESSION SET CONTAINER = ${DEMO_PDB}; ALTER TABLESPACE ${DEMO_TS} BEGIN BACKUP; ALTER TABLESPACE ${DEMO_TS} END BACKUP; exit' | sqlplus -s '/ as sysdba'" 2>/dev/null || true
docker cp "oracle:${DEMO_DBF}" oracle/dump/kms_demo_ts01.dbf
ok "Datafile copied → oracle/dump/kms_demo_ts01.dbf ($(du -sh oracle/dump/kms_demo_ts01.dbf | cut -f1))"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  PREUVE DU CHIFFREMENT TDE / TDE ENCRYPTION PROOF"
echo ""
echo "  La requête SQL retourne les données en clair (Oracle déchiffre via le KMS) :"
echo "    1  Thomas"
echo "    2  Aurelie"
echo "    3  Chris"
echo ""
echo "  Recherche de ces noms dans le fichier brut oracle/dump/kms_demo_ts01.dbf :"
FOUND=$(strings oracle/dump/kms_demo_ts01.dbf | grep -cE 'Thomas|Aurelie|Chris' || true)
if [[ "$FOUND" -eq 0 ]]; then
  echo "  → Introuvables dans le dump binaire : les données sont CHIFFRÉES ✓"
else
  echo "  → ${FOUND} occurrence(s) trouvée(s) — vérifier la config TDE"
fi
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── Done ──────────────────────────────────────────────────────────────────────

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Oracle TDE + Cosmian KMS demo setup complete."
echo ""
echo "  Connect interactively:"
echo "    docker exec -u oracle -it oracle sqlplus / as sysdba"
echo ""
echo "  Check wallet status:"
echo "    SELECT WRL_TYPE, WRL_PARAMETER, WALLET_TYPE, STATUS"
echo "    FROM V\$ENCRYPTION_WALLET;"
echo ""
echo "  Pour inspecter le dump vous-même :"
echo "    strings oracle/dump/kms_demo_ts01.dbf | grep -E 'Thomas|Aurelie|Chris'"
echo "    hexdump -C oracle/dump/kms_demo_ts01.dbf | grep -A2 -B2 'Thom' || echo '(rien trouvé)'"
echo ""
echo "  Cleanup:"
echo "    docker compose down -v"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
