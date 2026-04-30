#!/usr/bin/env bash
# smoke-test-tde.sh — TDE proof script for the Oracle KMS integration
#
# Usage: bash smoke-test-tde.sh <DEMO_PASS> <TAG_ONLY> <ORACLE_WALLET_PASS> <COSMIAN_HSM_PIN>
#
# Runs entirely on the remote Oracle server (copied there via scp).
# Exits non-zero if any proof fails.

set -euo pipefail

DEMO_PASS="${1:?DEMO_PASS (arg 1) is required}"
TAG_ONLY="${2:?TAG_ONLY (arg 2) is required}"
ORACLE_WALLET_PASS="${3:?ORACLE_WALLET_PASS (arg 3) is required}"
COSMIAN_HSM_PIN="${4:?COSMIAN_HSM_PIN (arg 4) is required}"

ORACLE_HOME=/opt/oracle/product/23ai/dbhomeFree
ORACLE_SID=FREE
export ORACLE_HOME ORACLE_SID

PASSED=0

# ── KMS health check ──────────────────────────────────────────────────────────

echo "==> KMS health check (/version)"
docker ps | grep cosmian-kms \
  || { echo "ERROR: cosmian-kms container is not running" >&2; exit 1; }
response=$(curl -sf http://localhost:9998/version)
echo "Version response: ${response}"
echo "${response}" | grep -q "${TAG_ONLY}" \
  || { echo "ERROR: /version response does not contain expected tag '${TAG_ONLY}'" >&2; exit 1; }
echo "Health check passed"
PASSED=$((PASSED + 1))

# ── PROOF 1 — Wallet HSM OPEN (CDB + PDB) ────────────────────────────────────

echo "==> PROOF 1: Wallet HSM OPEN"
output=$(sudo -u oracle bash -s <<'ORACLEBASH'
export ORACLE_HOME=/opt/oracle/product/23ai/dbhomeFree
export ORACLE_SID=FREE
"$ORACLE_HOME/bin/sqlplus" -s / as sysdba <<SQLEOF
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF
SELECT STATUS FROM V\$ENCRYPTION_WALLET;
ALTER SESSION SET CONTAINER=FREEPDB1;
SELECT STATUS FROM V\$ENCRYPTION_WALLET;
EXIT;
SQLEOF
ORACLEBASH
)
echo "Wallet status: ${output}"
echo "${output}" | grep -q "OPEN" \
  || { echo "ERROR: wallet is not OPEN" >&2; exit 1; }
echo "PROOF 1 passed: wallet is OPEN"
PASSED=$((PASSED + 1))

# ── PROOF 2 — Master key active (V$ENCRYPTION_KEYS) ──────────────────────────

echo "==> PROOF 2: Active master key"
count=$(sudo -u oracle bash -s <<'ORACLEBASH'
export ORACLE_HOME=/opt/oracle/product/23ai/dbhomeFree
export ORACLE_SID=FREE
"$ORACLE_HOME/bin/sqlplus" -s / as sysdba <<SQLEOF
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF
SELECT COUNT(*) FROM V\$ENCRYPTION_KEYS;
EXIT;
SQLEOF
ORACLEBASH
)
count=$(echo "${count}" | tr -d '[:space:]')
echo "Encryption key count: ${count}"
[ "${count:-0}" -gt 0 ] \
  || { echo "ERROR: no active encryption keys found" >&2; exit 1; }
echo "PROOF 2 passed: ${count} active master key(s)"
PASSED=$((PASSED + 1))

# ── PROOF 3 — AES256 on KMS_DEMO_TS ──────────────────────────────────────────

echo "==> PROOF 3: AES256 algorithm on KMS_DEMO_TS"
output=$(sudo -u oracle bash -s <<'ORACLEBASH'
export ORACLE_HOME=/opt/oracle/product/23ai/dbhomeFree
export ORACLE_SID=FREE
"$ORACLE_HOME/bin/sqlplus" -s / as sysdba <<SQLEOF
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF
ALTER SESSION SET CONTAINER=FREEPDB1;
SELECT e.ENCRYPTIONALG
FROM V\$ENCRYPTED_TABLESPACES e
JOIN V\$TABLESPACE t ON e.TS# = t.TS#
WHERE t.NAME = 'KMS_DEMO_TS';
EXIT;
SQLEOF
ORACLEBASH
)
echo "Encryption algorithm: ${output}"
echo "${output}" | grep -q "AES256" \
  || { echo "ERROR: AES256 encryption not found on KMS_DEMO_TS" >&2; exit 1; }
echo "PROOF 3 passed: KMS_DEMO_TS is encrypted with AES256"
PASSED=$((PASSED + 1))

# ── PROOF 4 — SQL*Net data read ───────────────────────────────────────────────

echo "==> PROOF 4: SQL*Net data read"
PORT=$(sudo -u oracle bash -s <<'ORACLEBASH'
export ORACLE_HOME=/opt/oracle/product/23ai/dbhomeFree
"$ORACLE_HOME/bin/lsnrctl" status 2>/dev/null \
  | grep -oP "PORT=\K[0-9]+" | head -n1
ORACLEBASH
)
PORT="${PORT:-1521}"
echo "Oracle listener port: ${PORT}"
output=$(sudo -u oracle bash -s -- "${DEMO_PASS}" "${PORT}" <<'ORACLEBASH'
export ORACLE_HOME=/opt/oracle/product/23ai/dbhomeFree
DEMO_PASS="$1"
PORT="$2"
"$ORACLE_HOME/bin/sqlplus" -s "kms_demo/${DEMO_PASS}@localhost:${PORT}/FREEPDB1" <<SQLEOF
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF
SELECT full_name FROM DEMO_PERSONS ORDER BY id;
EXIT;
SQLEOF
ORACLEBASH
)
echo "DEMO_PERSONS output: ${output}"
echo "${output}" | grep -q "Thomas"  || { echo "ERROR: Thomas not found in output"  >&2; exit 1; }
echo "${output}" | grep -q "Aurelie" || { echo "ERROR: Aurelie not found in output" >&2; exit 1; }
echo "${output}" | grep -q "Chris"   || { echo "ERROR: Chris not found in output"   >&2; exit 1; }
echo "PROOF 4 passed: data readable via SQL*Net"
PASSED=$((PASSED + 1))

# ── PROOF 5 — At-rest encryption (names/SSNs absent from DBF) ────────────────

echo "==> PROOF 5: At-rest encryption check"
DBF="/opt/oracle/oradata/FREE/FREEPDB1/kms_demo_ts01.dbf"
[ -f "${DBF}" ] || { echo "ERROR: DBF not found: ${DBF}" >&2; exit 1; }
if sudo strings "${DBF}" | grep -iE "Thomas|Aurelie|Chris"; then
  echo "ERROR: plaintext names found in DBF — data is NOT encrypted at rest" >&2
  exit 1
fi
if sudo strings "${DBF}" | grep -E "[0-9]-[0-9]{2}-[0-9]{2}"; then
  echo "ERROR: plaintext SSN patterns found in DBF — data is NOT encrypted at rest" >&2
  exit 1
fi
echo "PROOF 5 passed: no plaintext names or SSNs found in DBF"
PASSED=$((PASSED + 1))

# ── PROOF 6 — Full wallet migration with key identity verification ────────────

echo "==> PROOF 6: Full wallet migration (Cosmian K1 → Oracle wallet → Cosmian K2)"

# PRE-MIGRATION SETUP: create and open the Oracle software wallet
echo "  Creating Oracle software wallet..."
sudo -u oracle bash -s -- "${ORACLE_WALLET_PASS}" <<'ORACLEBASH'
export ORACLE_HOME=/opt/oracle/product/23ai/dbhomeFree
export ORACLE_SID=FREE
ORACLE_WALLET_PASS="$1"
"$ORACLE_HOME/bin/sqlplus" -s / as sysdba <<SQLEOF
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF
ADMINISTER KEY MANAGEMENT CREATE KEYSTORE '/opt/oracle/admin/FREE/wallet'
  IDENTIFIED BY '${ORACLE_WALLET_PASS}';
ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN
  IDENTIFIED BY '${ORACLE_WALLET_PASS}'
  CONTAINER=ALL;
EXIT;
SQLEOF
ORACLEBASH

[ -n "$(ls /opt/oracle/admin/FREE/wallet/ 2>/dev/null)" ] \
  || { echo "ERROR: Oracle wallet was not created" >&2; exit 1; }
echo "  Oracle wallet created and opened"

# PRE-MIGRATION: capture K1 identity
echo "  Capturing K1 identity..."
K1_KEY_ID=$(sudo -u oracle bash -s <<'ORACLEBASH'
export ORACLE_HOME=/opt/oracle/product/23ai/dbhomeFree
export ORACLE_SID=FREE
"$ORACLE_HOME/bin/sqlplus" -s / as sysdba <<SQLEOF
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF
ALTER SESSION SET CONTAINER=FREEPDB1;
SELECT KEY_ID FROM V\$ENCRYPTION_KEYS
ORDER BY ACTIVATION_TIME DESC FETCH FIRST 1 ROW ONLY;
EXIT;
SQLEOF
ORACLEBASH
)
K1_KEY_ID=$(echo "${K1_KEY_ID}" | tr -d '[:space:]')

K1_KEY_VERSION=$(sudo -u oracle bash -s <<'ORACLEBASH'
export ORACLE_HOME=/opt/oracle/product/23ai/dbhomeFree
export ORACLE_SID=FREE
"$ORACLE_HOME/bin/sqlplus" -s / as sysdba <<SQLEOF
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF
ALTER SESSION SET CONTAINER=FREEPDB1;
SELECT e.KEY_VERSION FROM V\$ENCRYPTED_TABLESPACES e
JOIN V\$TABLESPACE t ON e.TS# = t.TS#
WHERE t.NAME = 'KMS_DEMO_TS';
EXIT;
SQLEOF
ORACLEBASH
)
K1_KEY_VERSION=$(echo "${K1_KEY_VERSION}" | tr -d '[:space:]')

echo "  K1_KEY_ID=${K1_KEY_ID}"
echo "  K1_KEY_VERSION=${K1_KEY_VERSION}"

# ── Step 6a — Migrate FROM Cosmian (K1) TO Oracle software wallet ─────────────

echo "==> PROOF 6a: Cosmian (K1) → Oracle software wallet"
sudo -u oracle bash -s -- "${ORACLE_WALLET_PASS}" "${COSMIAN_HSM_PIN}" <<'ORACLEBASH'
export ORACLE_HOME=/opt/oracle/product/23ai/dbhomeFree
export ORACLE_SID=FREE
ORACLE_WALLET_PASS="$1"
COSMIAN_HSM_PIN="$2"
"$ORACLE_HOME/bin/sqlplus" -s / as sysdba <<SQLEOF
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF
ADMINISTER KEY MANAGEMENT USE KEYSTORE '/opt/oracle/admin/FREE/wallet'
  IDENTIFIED BY '${ORACLE_WALLET_PASS}'
  REVERSE MIGRATE USING '${COSMIAN_HSM_PIN}'
  WITH BACKUP USING 'pre_migration_backup'
  CONTAINER=ALL;
EXIT;
SQLEOF
ORACLEBASH

# Assert 6a: wallet is FILE/OPEN
wallet_6a=$(sudo -u oracle bash -s <<'ORACLEBASH'
export ORACLE_HOME=/opt/oracle/product/23ai/dbhomeFree
export ORACLE_SID=FREE
"$ORACLE_HOME/bin/sqlplus" -s / as sysdba <<SQLEOF
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF
SELECT WRL_TYPE, STATUS FROM V\$ENCRYPTION_WALLET;
EXIT;
SQLEOF
ORACLEBASH
)
echo "  Wallet after 6a: ${wallet_6a}"
echo "${wallet_6a}" | grep -q "FILE" \
  || { echo "ERROR: WRL_TYPE is not FILE after reverse migration" >&2; exit 1; }
echo "${wallet_6a}" | grep -q "OPEN" \
  || { echo "ERROR: STATUS is not OPEN after reverse migration" >&2; exit 1; }

# Assert 6a: data intact under K1
output_6a=$(sudo -u oracle bash -s -- "${DEMO_PASS}" "${PORT}" <<'ORACLEBASH'
export ORACLE_HOME=/opt/oracle/product/23ai/dbhomeFree
DEMO_PASS="$1"
PORT="$2"
"$ORACLE_HOME/bin/sqlplus" -s "kms_demo/${DEMO_PASS}@localhost:${PORT}/FREEPDB1" <<SQLEOF
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF
SELECT full_name FROM DEMO_PERSONS ORDER BY id;
EXIT;
SQLEOF
ORACLEBASH
)
echo "${output_6a}" | grep -q "Thomas"  || { echo "ERROR [6a]: Thomas not found"  >&2; exit 1; }
echo "${output_6a}" | grep -q "Aurelie" || { echo "ERROR [6a]: Aurelie not found" >&2; exit 1; }
echo "${output_6a}" | grep -q "Chris"   || { echo "ERROR [6a]: Chris not found"   >&2; exit 1; }

# Assert 6a: at-rest still encrypted
if sudo strings "${DBF}" | grep -iE "Thomas|Aurelie|Chris"; then
  echo "ERROR [6a]: plaintext names found in DBF after reverse migration" >&2; exit 1
fi
if sudo strings "${DBF}" | grep -E "[0-9]-[0-9]{2}-[0-9]{2}"; then
  echo "ERROR [6a]: plaintext SSN patterns found in DBF after reverse migration" >&2; exit 1
fi

echo "PROOF 6a passed: FILE/OPEN, data intact, DBF encrypted"
PASSED=$((PASSED + 1))

# ── Step 6b — Generate NEW master key K2 in Cosmian ──────────────────────────

echo "==> PROOF 6b: Oracle wallet → New Cosmian K2"
sudo -u oracle bash -s -- "${COSMIAN_HSM_PIN}" "${ORACLE_WALLET_PASS}" <<'ORACLEBASH'
export ORACLE_HOME=/opt/oracle/product/23ai/dbhomeFree
export ORACLE_SID=FREE
COSMIAN_HSM_PIN="$1"
ORACLE_WALLET_PASS="$2"
"$ORACLE_HOME/bin/sqlplus" -s / as sysdba <<SQLEOF
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF
ALTER SYSTEM SET TDE_CONFIGURATION='KEYSTORE_CONFIGURATION=HSM' SCOPE=BOTH;
ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN
  IDENTIFIED BY '${COSMIAN_HSM_PIN}'
  CONTAINER=ALL;
ADMINISTER KEY MANAGEMENT SET ENCRYPTION KEY
  IDENTIFIED BY '${COSMIAN_HSM_PIN}'
  MIGRATE USING '${ORACLE_WALLET_PASS}'
  WITH BACKUP USING 'new_cosmian_key_k2'
  CONTAINER=ALL;
EXIT;
SQLEOF
ORACLEBASH

# Capture K2 identity
K2_KEY_ID=$(sudo -u oracle bash -s <<'ORACLEBASH'
export ORACLE_HOME=/opt/oracle/product/23ai/dbhomeFree
export ORACLE_SID=FREE
"$ORACLE_HOME/bin/sqlplus" -s / as sysdba <<SQLEOF
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF
ALTER SESSION SET CONTAINER=FREEPDB1;
SELECT KEY_ID FROM V\$ENCRYPTION_KEYS
ORDER BY ACTIVATION_TIME DESC FETCH FIRST 1 ROW ONLY;
EXIT;
SQLEOF
ORACLEBASH
)
K2_KEY_ID=$(echo "${K2_KEY_ID}" | tr -d '[:space:]')

K2_KEY_VERSION=$(sudo -u oracle bash -s <<'ORACLEBASH'
export ORACLE_HOME=/opt/oracle/product/23ai/dbhomeFree
export ORACLE_SID=FREE
"$ORACLE_HOME/bin/sqlplus" -s / as sysdba <<SQLEOF
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF
ALTER SESSION SET CONTAINER=FREEPDB1;
SELECT e.KEY_VERSION FROM V\$ENCRYPTED_TABLESPACES e
JOIN V\$TABLESPACE t ON e.TS# = t.TS#
WHERE t.NAME = 'KMS_DEMO_TS';
EXIT;
SQLEOF
ORACLEBASH
)
K2_KEY_VERSION=$(echo "${K2_KEY_VERSION}" | tr -d '[:space:]')

echo "  K2_KEY_ID=${K2_KEY_ID}"
echo "  K2_KEY_VERSION=${K2_KEY_VERSION}"

# Assert 6b: wallet is HSM/OPEN
wallet_6b=$(sudo -u oracle bash -s <<'ORACLEBASH'
export ORACLE_HOME=/opt/oracle/product/23ai/dbhomeFree
export ORACLE_SID=FREE
"$ORACLE_HOME/bin/sqlplus" -s / as sysdba <<SQLEOF
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF
SELECT WRL_TYPE, STATUS FROM V\$ENCRYPTION_WALLET;
EXIT;
SQLEOF
ORACLEBASH
)
echo "  Wallet after 6b: ${wallet_6b}"
echo "${wallet_6b}" | grep -q "HSM" \
  || { echo "ERROR: WRL_TYPE is not HSM after K2 migration" >&2; exit 1; }
echo "${wallet_6b}" | grep -q "OPEN" \
  || { echo "ERROR: STATUS is not OPEN after K2 migration" >&2; exit 1; }

# Assert 6b: key identity changed
[ "${K2_KEY_ID}" != "${K1_KEY_ID}" ] \
  || { echo "ERROR: KEY_ID unchanged — K2 is the same as K1" >&2; exit 1; }

# Assert 6b: TEK re-wrapped (KEY_VERSION incremented)
[ "${K2_KEY_VERSION}" -gt "${K1_KEY_VERSION}" ] \
  || { echo "ERROR: KEY_VERSION not incremented — TEK not re-wrapped under K2" >&2; exit 1; }

# Assert 6b: data still readable under K2
output_6b=$(sudo -u oracle bash -s -- "${DEMO_PASS}" "${PORT}" <<'ORACLEBASH'
export ORACLE_HOME=/opt/oracle/product/23ai/dbhomeFree
DEMO_PASS="$1"
PORT="$2"
"$ORACLE_HOME/bin/sqlplus" -s "kms_demo/${DEMO_PASS}@localhost:${PORT}/FREEPDB1" <<SQLEOF
SET PAGESIZE 0 FEEDBACK OFF VERIFY OFF HEADING OFF ECHO OFF
SELECT full_name FROM DEMO_PERSONS ORDER BY id;
EXIT;
SQLEOF
ORACLEBASH
)
echo "${output_6b}" | grep -q "Thomas"  || { echo "ERROR [6b]: Thomas not found"  >&2; exit 1; }
echo "${output_6b}" | grep -q "Aurelie" || { echo "ERROR [6b]: Aurelie not found" >&2; exit 1; }
echo "${output_6b}" | grep -q "Chris"   || { echo "ERROR [6b]: Chris not found"   >&2; exit 1; }

# Assert 6b: at-rest still encrypted under K2
if sudo strings "${DBF}" | grep -iE "Thomas|Aurelie|Chris"; then
  echo "ERROR [6b]: plaintext names found in DBF after K2 migration" >&2; exit 1
fi
if sudo strings "${DBF}" | grep -E "[0-9]-[0-9]{2}-[0-9]{2}"; then
  echo "ERROR [6b]: plaintext SSN patterns found in DBF after K2 migration" >&2; exit 1
fi

echo "PROOF 6b passed: HSM/OPEN, KEY_ID changed, KEY_VERSION incremented, data intact, DBF encrypted"
PASSED=$((PASSED + 1))

# POST-MIGRATION CLEANUP: remove wallet files to keep the server clean for re-runs
echo "  Cleaning up Oracle wallet files..."
sudo rm -f /opt/oracle/admin/FREE/wallet/ewallet.p12
sudo rm -f /opt/oracle/admin/FREE/wallet/cwallet.sso
echo "  Wallet files removed"

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo "============================================"
echo "All ${PASSED}/7 TDE proofs passed successfully"
echo "  [HEALTH]  KMS /version contains tag '${TAG_ONLY}'"
echo "  [PROOF 1] Wallet is OPEN (CDB + FREEPDB1)"
echo "  [PROOF 2] ${count} active master key(s)"
echo "  [PROOF 3] KMS_DEMO_TS encrypted with AES256"
echo "  [PROOF 4] SQL*Net read: Thomas, Aurelie, Chris present"
echo "  [PROOF 5] DBF contains no plaintext names or SSNs"
echo "  [PROOF 6a] Cosmian → Oracle wallet: FILE/OPEN"
echo "             K1_KEY_ID=${K1_KEY_ID}, data intact, DBF encrypted"
echo "  [PROOF 6b] Oracle wallet → New Cosmian K2: HSM/OPEN"
echo "             KEY_ID changed: ${K1_KEY_ID} → ${K2_KEY_ID}"
echo "             KEY_VERSION incremented: ${K1_KEY_VERSION} → ${K2_KEY_VERSION} (TEK re-wrapped)"
echo "             Data intact under K2, DBF encrypted"
echo "============================================"
