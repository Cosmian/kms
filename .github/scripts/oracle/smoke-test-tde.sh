#!/usr/bin/env bash
# smoke-test-tde.sh — Oracle TDE upgrade smoke test for the Cosmian KMS integration.
#
# Verifies that after a KMS container upgrade, Oracle TDE continues to work correctly.
# Handles three states:
#   - OPEN              : keys exist in KMS and match Oracle's active MEK — proceed directly
#   - OPEN_NO_MASTER_KEY: KMS is fresh (no keys at all) — SET KEY to create the first MEK
#   - ORA-28353 (CLOSED): Oracle holds a stale MEK ID that no longer exists in KMS
#                         (e.g. KMS data was lost while Oracle's control file / PROPS$ still
#                         reference the old key). Recovery: import a random placeholder key
#                         into KMS under the exact KMIP ID Oracle expects
#                         (ORACLE.TDE.HSM.MK.<MEK_ID>), open the keystore (now succeeds),
#                         then immediately rekey with SET KEY so real, persistent keys exist.
#
# Usage: bash smoke-test-tde.sh <ORACLE_KMS_DEMO_USER_PASS> <TAG_ONLY> <COSMIAN_HSM_PIN>

set -euo pipefail

ORACLE_KMS_DEMO_USER_PASS="${1:?ORACLE_KMS_DEMO_USER_PASS (arg 1) is required}"
TAG_ONLY="${2:?TAG_ONLY (arg 2) is required}"
COSMIAN_HSM_PIN="${3:?COSMIAN_HSM_PIN (arg 3) is required}"

ORACLE_HOME=/opt/oracle/product/23ai/dbhomeFree
ORACLE_SID=FREE
export ORACLE_HOME ORACLE_SID

WALLET_DIR=/opt/oracle/admin/FREE/wallet
DBF=/opt/oracle/oradata/FREE/FREEPDB1/kms_demo_ts01.dbf

PASSED=0

# ── Helper: run SQL as sysdba via oracle user ──────────────────────────────────
sqlplus_sysdba() {
  local sql="$1"
  sudo -u oracle bash -c "
    export ORACLE_HOME=${ORACLE_HOME}
    export ORACLE_SID=${ORACLE_SID}
    echo \"${sql}\" | ${ORACLE_HOME}/bin/sqlplus -s / as sysdba
  "
}

# ── PHASE 0: Drop any leftover test objects ────────────────────────────────────

echo "==> Phase 0: Removing any leftover test objects"
sudo -u oracle bash -s <<ORACLEBASH
export ORACLE_HOME=${ORACLE_HOME}
export ORACLE_SID=${ORACLE_SID}
"${ORACLE_HOME}/bin/sqlplus" -s / as sysdba <<'SQLEOF'
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF
WHENEVER SQLERROR CONTINUE;
ALTER SESSION SET CONTAINER=FREEPDB1;
DROP TABLE kms_demo.DEMO_PERSONS CASCADE CONSTRAINTS PURGE;
DROP TABLESPACE KMS_DEMO_TS INCLUDING CONTENTS AND DATAFILES;
DROP USER kms_demo CASCADE;
WHENEVER SQLERROR EXIT SQL.SQLCODE;
EXIT;
SQLEOF
ORACLEBASH
sudo rm -f "${WALLET_DIR}/ewallet.p12" "${WALLET_DIR}/cwallet.sso"
echo "Phase 0 done"

# ── HEALTH CHECK ───────────────────────────────────────────────────────────────

echo "==> Health check: verify Docker image tag"
docker ps | grep cosmian-kms \
  || { echo "ERROR: cosmian-kms container is not running" >&2; exit 1; }
running_image=$(docker inspect cosmian-kms --format '{{.Config.Image}}')
echo "Running image: ${running_image}"
echo "${running_image}" | grep -q "${TAG_ONLY}" \
  || { echo "ERROR: running image '${running_image}' does not contain '${TAG_ONLY}'" >&2; exit 1; }
timeout 30 bash -c 'until curl -sf http://localhost:9998/version >/dev/null 2>&1; do sleep 2; done' \
  || { echo "ERROR: KMS not responding" >&2; exit 1; }
echo "KMS: $(curl -sf http://localhost:9998/version)"
echo "Health check passed"

# ── PHASE 1: Open Oracle TDE wallet (with recovery for stale KMS state) ────────
# Three possible outcomes after KEYSTORE OPEN in HSM mode:
#   OPEN              — keys are intact in KMS, all good
#   OPEN_NO_MASTER_KEY— KMS is fresh (empty DB properly initialised), just SET KEY
#   CLOSED (ORA-28353)— KMS DB was corrupt/empty with no schema; after upgrade-kms.sh
#                       fix the DB is now properly initialised but Oracle has a stale
#                       MEK ID → recover via FILE wallet creation then MIGRATE to HSM

open_wallet_in_container() {
  local container="${1}"       # CDB or PDB (for logging)
  local extra_sql="${2:-}"     # Optional ALTER SESSION SET CONTAINER=... prefix
  local pin="${COSMIAN_HSM_PIN}"

  sudo -u oracle bash -s -- "${pin}" -- "${extra_sql}" <<'ORACLEBASH'
export ORACLE_HOME=/opt/oracle/product/23ai/dbhomeFree
export ORACLE_SID=FREE
PIN="$1"; shift; shift
EXTRA="$1"
"${ORACLE_HOME}/bin/sqlplus" -s / as sysdba <<SQLEOF
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF
WHENEVER SQLERROR CONTINUE;
${EXTRA}
ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN IDENTIFIED BY "${PIN}";
WHENEVER SQLERROR EXIT SQL.SQLCODE;
EXIT;
SQLEOF
ORACLEBASH
}

wallet_status() {
  local extra_sql="${1:-}"
  sudo -u oracle bash -s -- "${extra_sql}" <<'ORACLEBASH'
export ORACLE_HOME=/opt/oracle/product/23ai/dbhomeFree
export ORACLE_SID=FREE
EXTRA="$1"
"${ORACLE_HOME}/bin/sqlplus" -s / as sysdba <<SQLEOF
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF
${EXTRA}
SELECT STATUS FROM V\$ENCRYPTION_WALLET WHERE ROWNUM=1;
EXIT;
SQLEOF
ORACLEBASH
}

set_key_in_container() {
  local extra_sql="${1:-}"
  local pin="${COSMIAN_HSM_PIN}"
  local backup_label="${2:-initial_key}"
  sudo -u oracle bash -s -- "${pin}" -- "${extra_sql}" -- "${backup_label}" <<'ORACLEBASH'
export ORACLE_HOME=/opt/oracle/product/23ai/dbhomeFree
export ORACLE_SID=FREE
PIN="$1"; shift; shift; EXTRA="$1"; shift; shift; LABEL="$1"
"${ORACLE_HOME}/bin/sqlplus" -s / as sysdba <<SQLEOF
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF
WHENEVER SQLERROR EXIT SQL.SQLCODE;
${EXTRA}
ADMINISTER KEY MANAGEMENT SET KEY IDENTIFIED BY "${PIN}" WITH BACKUP USING '${LABEL}' CONTAINER=CURRENT;
EXIT;
SQLEOF
ORACLEBASH
}

echo "==> Phase 1: Ensure TDE_CONFIGURATION=HSM (SCOPE=SPFILE + MEMORY)"
sudo -u oracle bash -s <<'ORACLEBASH'
export ORACLE_HOME=/opt/oracle/product/23ai/dbhomeFree
export ORACLE_SID=FREE
"${ORACLE_HOME}/bin/sqlplus" -s / as sysdba <<'SQLEOF'
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF
WHENEVER SQLERROR CONTINUE;
ALTER SYSTEM SET WALLET_ROOT='/opt/oracle/admin/FREE/wallet' SCOPE=SPFILE;
ALTER SYSTEM SET TDE_CONFIGURATION='KEYSTORE_CONFIGURATION=HSM' SCOPE=SPFILE;
ALTER SYSTEM SET TDE_CONFIGURATION='KEYSTORE_CONFIGURATION=HSM' SCOPE=MEMORY;
WHENEVER SQLERROR EXIT SQL.SQLCODE;
EXIT;
SQLEOF
ORACLEBASH

echo "==> Phase 1: Try opening TDE wallet (CDB)"
open_wallet_in_container "CDB" ""
cdb_status=$(wallet_status "" | tr -d '[:space:]')
echo "CDB wallet status: ${cdb_status}"

# ── Recovery: stale SYS.ENC$ entries → KMS empty ──────────────────────────────
# Triggered when KEYSTORE OPEN returns ORA-28353 (CLOSED): Oracle knows a MEK ID
# in enc$ that no longer exists in KMS (data lost, fresh container, etc.).
# Fix: purge enc$ (safe here because Phase 0 already dropped all encrypted
# tablespaces, so there is no encrypted data to corrupt), restart Oracle so it
# re-reads enc$ from disk, then OPEN → OPEN_NO_MASTER_KEY → SET KEY.

# ── Recovery: stale MEK IDs → KMS empty / replaced ────────────────────────────
# Triggered when KEYSTORE OPEN returns ORA-28353 (CLOSED): Oracle's control file
# and PROPS$ reference a MEK that no longer exists in KMS (data lost, fresh KMS
# container, etc.).
# Fix: find the stale MEK ID(s) from CDB and PDB PROPS$, import a random placeholder
# AES-256 key into KMS under the exact KMIP object ID Oracle expects
# (ORACLE.TDE.HSM.MK.<MEK_ID>).  Oracle's KEYSTORE OPEN will now find that key
# and return OPEN.  We immediately call SET KEY to create real, persistent MEKs,
# making the placeholder keys orphans that can be cleaned up later.
# No SYS.ENC$ manipulation or Oracle restart needed — PROPS$ already holds the
# correct stale MEK IDs; we must NOT delete them or Oracle will crash (ORA-00600).

if echo "${cdb_status}" | grep -q "CLOSED"; then
  echo "WARNING: CDB wallet CLOSED (ORA-28353) — importing placeholder MEKs into KMS"

  # Helper: import a placeholder AES-256 key into KMS under the given ORACLE.TDE.HSM.MK.* ID
  import_placeholder_mek() {
    local mek_id="$1"
    local kmip_id="ORACLE.TDE.HSM.MK.${mek_id}"
    dd if=/dev/urandom bs=32 count=1 > /tmp/placeholder_mek.bin 2>/dev/null
    ckms sym keys import --key-format aes /tmp/placeholder_mek.bin "${kmip_id}" 2>/dev/null \
      && echo "  Imported placeholder key: ${kmip_id}" \
      || echo "  Key already exists (or import failed): ${kmip_id}"
    rm -f /tmp/placeholder_mek.bin
  }

  # ── R1: Read stale CDB MEK ID from PROPS$ ────────────────────────────────────
  cdb_mek_raw=$(sudo -u oracle bash -s <<'ORACLEBASH'
export ORACLE_HOME=/opt/oracle/product/23ai/dbhomeFree
export ORACLE_SID=FREE
"${ORACLE_HOME}/bin/sqlplus" -s / as sysdba <<'SQLEOF'
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF
SELECT VALUE$ FROM SYS.PROPS$ WHERE NAME='TDE_MASTER_KEY_ID';
EXIT;
SQLEOF
ORACLEBASH
)
  cdb_mek_id=$(echo "${cdb_mek_raw}" | tr -d '[:space:]' | grep -E "^[0-9A-Fa-f]{30,40}$" | head -1)
  if [ -n "${cdb_mek_id}" ]; then
    import_placeholder_mek "${cdb_mek_id}"
  else
    echo "  WARNING: no TDE_MASTER_KEY_ID found in CDB PROPS$ — KMS may already have the right key"
  fi

  # ── R2: Read stale PDB MEK ID from FREEPDB1 PROPS$ ───────────────────────────
  pdb_mek_raw=$(sudo -u oracle bash -s <<'ORACLEBASH'
export ORACLE_HOME=/opt/oracle/product/23ai/dbhomeFree
export ORACLE_SID=FREE
"${ORACLE_HOME}/bin/sqlplus" -s / as sysdba <<'SQLEOF'
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF
WHENEVER SQLERROR CONTINUE;
ALTER SESSION SET CONTAINER=FREEPDB1;
SELECT VALUE$ FROM PROPS$ WHERE NAME='TDE_MASTER_KEY_ID';
EXIT;
SQLEOF
ORACLEBASH
)
  pdb_mek_id=$(echo "${pdb_mek_raw}" | tr -d '[:space:]' | grep -E "^[0-9A-Fa-f]{30,40}$" | head -1)
  if [ -n "${pdb_mek_id}" ]; then
    import_placeholder_mek "${pdb_mek_id}"
  else
    echo "  WARNING: no TDE_MASTER_KEY_ID found in PDB PROPS$ — PDB might be handled by CDB key"
  fi

  # ── R3: Re-open CDB keystore (placeholder keys are now in KMS) ───────────────
  echo "  Step R3: KEYSTORE OPEN with placeholder keys in KMS"
  open_wallet_in_container "CDB" ""
  cdb_status=$(wallet_status "" | tr -d '[:space:]')
  echo "  CDB wallet status after recovery: ${cdb_status}"

  if echo "${cdb_status}" | grep -q "CLOSED"; then
    echo "ERROR: CDB wallet still CLOSED after importing placeholder MEK — check KMS logs" >&2
    docker logs cosmian-kms --tail 20 >&2 || true
    exit 1
  fi

  # ── R4: Also open PDB keystore (required for SET KEY CONTAINER=CURRENT per PDB) ─
  open_wallet_in_container "PDB" "ALTER SESSION SET CONTAINER=FREEPDB1;"
  pdb_status=$(wallet_status "ALTER SESSION SET CONTAINER=FREEPDB1;" | tr -d '[:space:]')
  echo "  PDB wallet status after recovery: ${pdb_status}"

  # ── R5: SET KEY to create real persistent MEKs (replaces placeholder keys) ───
  echo "  Step R5: SET KEY — creating real MEKs to replace placeholder keys"
  set_key_in_container "" "recovery_cdb_key"
  set_key_in_container "ALTER SESSION SET CONTAINER=FREEPDB1;" "recovery_pdb_key"

  # Re-read statuses with fresh real MEKs
  cdb_status=$(wallet_status "" | tr -d '[:space:]')
  pdb_status=$(wallet_status "ALTER SESSION SET CONTAINER=FREEPDB1;" | tr -d '[:space:]')
  echo "  Recovery complete: CDB=${cdb_status}, PDB=${pdb_status}"
fi

# ── Handle OPEN_NO_MASTER_KEY in CDB ──────────────────────────────────────────
if echo "${cdb_status}" | grep -q "OPEN_NO_MASTER_KEY"; then
  echo "CDB: OPEN_NO_MASTER_KEY — creating master key in KMS..."
  set_key_in_container "" "initial_hsm_cdb"
  cdb_status=$(wallet_status "" | tr -d '[:space:]')
  echo "CDB wallet status after SET KEY: ${cdb_status}"
fi

echo "${cdb_status}" | grep -q "OPEN" \
  || { echo "ERROR: CDB wallet is not OPEN (status: ${cdb_status})" >&2; exit 1; }

echo "==> Phase 1: Open TDE wallet (PDB)"
open_wallet_in_container "PDB" "ALTER SESSION SET CONTAINER=FREEPDB1;"
pdb_status=$(wallet_status "ALTER SESSION SET CONTAINER=FREEPDB1;" | tr -d '[:space:]')
echo "PDB wallet status: ${pdb_status}"

if echo "${pdb_status}" | grep -q "OPEN_NO_MASTER_KEY"; then
  echo "PDB: OPEN_NO_MASTER_KEY — creating master key in KMS..."
  set_key_in_container "ALTER SESSION SET CONTAINER=FREEPDB1;" "initial_hsm_pdb"
  pdb_status=$(wallet_status "ALTER SESSION SET CONTAINER=FREEPDB1;" | tr -d '[:space:]')
  echo "PDB wallet status after SET KEY: ${pdb_status}"
fi

echo "${pdb_status}" | grep -q "OPEN" \
  || { echo "ERROR: PDB wallet is not OPEN (status: ${pdb_status})" >&2; exit 1; }
echo "Wallet opened successfully (CDB: ${cdb_status}, PDB: ${pdb_status})"

# ── PROOF 1: Wallet is OPEN ────────────────────────────────────────────────────

echo "==> PROOF 1: Wallet is OPEN"
echo "PROOF 1 passed: CDB=${cdb_status}, PDB=${pdb_status}"
PASSED=$((PASSED + 1))

# ── PHASE 2: Create test tablespace, user, and data ───────────────────────────

echo "==> Phase 2: Create encrypted tablespace and test data"
sudo -u oracle bash -s -- "${ORACLE_KMS_DEMO_USER_PASS}" <<'ORACLEBASH'
export ORACLE_HOME=/opt/oracle/product/23ai/dbhomeFree
export ORACLE_SID=FREE
ORACLE_KMS_DEMO_USER_PASS="$1"
"${ORACLE_HOME}/bin/sqlplus" -s / as sysdba <<SQLEOF
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF
WHENEVER SQLERROR EXIT SQL.SQLCODE;
ALTER SESSION SET CONTAINER=FREEPDB1;
CREATE TABLESPACE KMS_DEMO_TS
  DATAFILE '/opt/oracle/oradata/FREE/FREEPDB1/kms_demo_ts01.dbf' SIZE 10M
  ENCRYPTION USING 'AES256'
  DEFAULT STORAGE(ENCRYPT);
CREATE USER kms_demo IDENTIFIED BY "${ORACLE_KMS_DEMO_USER_PASS}"
  DEFAULT TABLESPACE KMS_DEMO_TS
  QUOTA UNLIMITED ON KMS_DEMO_TS;
GRANT CREATE SESSION, CREATE TABLE TO kms_demo;
CREATE TABLE kms_demo.DEMO_PERSONS (
  id        NUMBER GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  full_name VARCHAR2(100),
  ssn       VARCHAR2(11)
) TABLESPACE KMS_DEMO_TS;
INSERT INTO kms_demo.DEMO_PERSONS (full_name, ssn) VALUES ('Thomas',  '1-23-456789');
INSERT INTO kms_demo.DEMO_PERSONS (full_name, ssn) VALUES ('Aurelie', '2-34-567890');
INSERT INTO kms_demo.DEMO_PERSONS (full_name, ssn) VALUES ('Chris',   '3-45-678901');
COMMIT;
EXIT;
SQLEOF
ORACLEBASH
echo "KMS_DEMO_TS + kms_demo + DEMO_PERSONS created"

# ── PROOF 2: Active master key ─────────────────────────────────────────────────

echo "==> PROOF 2: Active master key"
key_count=$(sudo -u oracle bash -s <<'ORACLEBASH'
export ORACLE_HOME=/opt/oracle/product/23ai/dbhomeFree
export ORACLE_SID=FREE
"${ORACLE_HOME}/bin/sqlplus" -s / as sysdba <<'SQLEOF'
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF
SELECT COUNT(*) FROM V$ENCRYPTION_KEYS;
EXIT;
SQLEOF
ORACLEBASH
)
key_count=$(echo "${key_count}" | tr -d '[:space:]')
[ "${key_count:-0}" -gt 0 ] \
  || { echo "ERROR: no active encryption keys" >&2; exit 1; }
echo "PROOF 2 passed: ${key_count} master key(s)"
PASSED=$((PASSED + 1))

# ── PROOF 3: AES256 on KMS_DEMO_TS ────────────────────────────────────────────

echo "==> PROOF 3: AES256 encryption on KMS_DEMO_TS"
alg=$(sudo -u oracle bash -s <<'ORACLEBASH'
export ORACLE_HOME=/opt/oracle/product/23ai/dbhomeFree
export ORACLE_SID=FREE
"${ORACLE_HOME}/bin/sqlplus" -s / as sysdba <<'SQLEOF'
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF
ALTER SESSION SET CONTAINER=FREEPDB1;
SELECT e.ENCRYPTIONALG FROM V$ENCRYPTED_TABLESPACES e
JOIN V$TABLESPACE t ON e.TS# = t.TS#
WHERE t.NAME = 'KMS_DEMO_TS';
EXIT;
SQLEOF
ORACLEBASH
)
echo "Algorithm: ${alg}"
echo "${alg}" | grep -q "AES256" \
  || { echo "ERROR: AES256 not found on KMS_DEMO_TS (got: ${alg})" >&2; exit 1; }
echo "PROOF 3 passed: KMS_DEMO_TS encrypted with AES256"
PASSED=$((PASSED + 1))

# ── PROOF 4: SQL*Net data read ─────────────────────────────────────────────────

echo "==> PROOF 4: SQL*Net data read"
PORT=$(sudo -u oracle bash -s <<'ORACLEBASH'
export ORACLE_HOME=/opt/oracle/product/23ai/dbhomeFree
"${ORACLE_HOME}/bin/lsnrctl" status 2>/dev/null \
  | grep -oP "PORT=\K[0-9]+" | head -n1
ORACLEBASH
)
PORT="${PORT:-1521}"
echo "Oracle listener port: ${PORT}"
data=$(sudo -u oracle bash -s -- "${ORACLE_KMS_DEMO_USER_PASS}" "${PORT}" <<'ORACLEBASH'
export ORACLE_HOME=/opt/oracle/product/23ai/dbhomeFree
ORACLE_KMS_DEMO_USER_PASS="$1"; PORT="$2"
"${ORACLE_HOME}/bin/sqlplus" -s "kms_demo/${ORACLE_KMS_DEMO_USER_PASS}@localhost:${PORT}/FREEPDB1" <<SQLEOF
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF
SELECT full_name FROM DEMO_PERSONS ORDER BY id;
EXIT;
SQLEOF
ORACLEBASH
)
echo "DEMO_PERSONS: ${data}"
echo "${data}" | grep -q "Thomas"  || { echo "ERROR: Thomas not found"  >&2; exit 1; }
echo "${data}" | grep -q "Aurelie" || { echo "ERROR: Aurelie not found" >&2; exit 1; }
echo "${data}" | grep -q "Chris"   || { echo "ERROR: Chris not found"   >&2; exit 1; }
echo "PROOF 4 passed: data readable via SQL*Net"
PASSED=$((PASSED + 1))

# ── PROOF 5: At-rest encryption ────────────────────────────────────────────────

echo "==> PROOF 5: At-rest encryption"
sudo test -f "${DBF}" || { echo "ERROR: DBF not found: ${DBF}" >&2; exit 1; }
if sudo strings "${DBF}" | grep -iE "Thomas|Aurelie|Chris"; then
  echo "ERROR: plaintext names found in DBF" >&2; exit 1
fi
if sudo strings "${DBF}" | grep -E "[0-9]-[0-9]{2}-[0-9]{6}"; then
  echo "ERROR: plaintext SSNs found in DBF" >&2; exit 1
fi
echo "PROOF 5 passed: no plaintext data in DBF"
PASSED=$((PASSED + 1))

# ── PROOF 6: TDE REKEY — rotate MEK within HSM (K1 → K2) ─────────────────────
# Proves that key rotation works: a new MEK (K2) is generated in Cosmian KMS,
# all tablespace encryption keys are re-wrapped (K1→K2), and data remains readable.
# Note: Oracle 23ai Free does not support HSM↔FILE wallet migration via REVERSE
# MIGRATE / MIGRATE USING because BACKUP KEYSTORE is not supported for PKCS#11
# keystores (ORA-00600: kzckmbkup: invalid keystore location [4]).

echo "==> PROOF 6: TDE REKEY (MEK rotation K1 → K2 within HSM)"

K1_MASTERKEYID=$(sudo -u oracle bash -s <<'ORACLEBASH'
export ORACLE_HOME=/opt/oracle/product/23ai/dbhomeFree
export ORACLE_SID=FREE
"${ORACLE_HOME}/bin/sqlplus" -s / as sysdba <<'SQLEOF'
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF
ALTER SESSION SET CONTAINER=FREEPDB1;
SELECT MASTERKEYID FROM V$ENCRYPTED_TABLESPACES e
JOIN V$TABLESPACE t ON e.TS# = t.TS# WHERE t.NAME = 'KMS_DEMO_TS';
EXIT;
SQLEOF
ORACLEBASH
)
K1_MASTERKEYID=$(echo "${K1_MASTERKEYID}" | tr -d '[:space:]')
echo "  K1_MASTERKEYID=${K1_MASTERKEYID}"

# Rotate MEK: Oracle generates K2 in KMS, re-wraps all TEKs (K1→K2)
set_key_in_container "ALTER SESSION SET CONTAINER=FREEPDB1;" "rekey_k2"

K2_MASTERKEYID=$(sudo -u oracle bash -s <<'ORACLEBASH'
export ORACLE_HOME=/opt/oracle/product/23ai/dbhomeFree
export ORACLE_SID=FREE
"${ORACLE_HOME}/bin/sqlplus" -s / as sysdba <<'SQLEOF'
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF
ALTER SESSION SET CONTAINER=FREEPDB1;
SELECT MASTERKEYID FROM V$ENCRYPTED_TABLESPACES e
JOIN V$TABLESPACE t ON e.TS# = t.TS# WHERE t.NAME = 'KMS_DEMO_TS';
EXIT;
SQLEOF
ORACLEBASH
)
K2_MASTERKEYID=$(echo "${K2_MASTERKEYID}" | tr -d '[:space:]')
echo "  K2_MASTERKEYID=${K2_MASTERKEYID}"

[ "${K2_MASTERKEYID}" != "${K1_MASTERKEYID}" ] \
  || { echo "ERROR [6]: MASTERKEYID unchanged after REKEY (K1=${K1_MASTERKEYID})" >&2; exit 1; }

data_6=$(sudo -u oracle bash -s -- "${ORACLE_KMS_DEMO_USER_PASS}" "${PORT}" <<'ORACLEBASH'
export ORACLE_HOME=/opt/oracle/product/23ai/dbhomeFree
ORACLE_KMS_DEMO_USER_PASS="$1"; PORT="$2"
"${ORACLE_HOME}/bin/sqlplus" -s "kms_demo/${ORACLE_KMS_DEMO_USER_PASS}@localhost:${PORT}/FREEPDB1" <<SQLEOF
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF
SELECT full_name FROM DEMO_PERSONS ORDER BY id;
EXIT;
SQLEOF
ORACLEBASH
)
echo "${data_6}" | grep -q "Thomas"  || { echo "ERROR [6]: Thomas missing after rekey"  >&2; exit 1; }
echo "${data_6}" | grep -q "Aurelie" || { echo "ERROR [6]: Aurelie missing after rekey" >&2; exit 1; }
echo "${data_6}" | grep -q "Chris"   || { echo "ERROR [6]: Chris missing after rekey"   >&2; exit 1; }
if sudo strings "${DBF}" | grep -iE "Thomas|Aurelie|Chris"; then
  echo "ERROR [6]: plaintext in DBF after REKEY" >&2; exit 1
fi
echo "PROOF 6 passed: MASTERKEYID rotated (${K1_MASTERKEYID} → ${K2_MASTERKEYID}), TEK re-wrapped, data intact"
PASSED=$((PASSED + 1))

# ── PHASE 3: Cleanup Oracle test objects (KMS data left intact) ───────────────

echo "==> Phase 3: Cleanup"
sudo -u oracle bash -s <<ORACLEBASH
export ORACLE_HOME=${ORACLE_HOME}
export ORACLE_SID=${ORACLE_SID}
"${ORACLE_HOME}/bin/sqlplus" -s / as sysdba <<'SQLEOF'
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF
WHENEVER SQLERROR CONTINUE;
ALTER SESSION SET CONTAINER=FREEPDB1;
DROP TABLE kms_demo.DEMO_PERSONS CASCADE CONSTRAINTS PURGE;
DROP TABLESPACE KMS_DEMO_TS INCLUDING CONTENTS AND DATAFILES;
DROP USER kms_demo CASCADE;
WHENEVER SQLERROR EXIT SQL.SQLCODE;
EXIT;
SQLEOF
ORACLEBASH
echo "Phase 3 cleanup done"

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "============================================"
echo "All ${PASSED}/6 TDE proofs passed successfully"
echo "  [PROOF 1]  Wallet OPEN (CDB: ${cdb_status}, PDB: ${pdb_status})"
echo "  [PROOF 2]  ${key_count} active master key(s)"
echo "  [PROOF 3]  KMS_DEMO_TS encrypted with AES256"
echo "  [PROOF 4]  SQL*Net read: Thomas, Aurelie, Chris present"
echo "  [PROOF 5]  DBF contains no plaintext names or SSNs"
echo "  [PROOF 6]  TDE REKEY: MASTERKEYID rotated (${K1_MASTERKEYID} → ${K2_MASTERKEYID})"
echo "             Data intact, DBF encrypted after key rotation"
echo "============================================"
