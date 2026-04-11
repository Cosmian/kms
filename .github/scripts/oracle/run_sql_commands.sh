#!/bin/bash

set -e

#
# Setup Oracle TDE for HSM
#
run_sql() {
  SQL="$1"
  SQL2="$2"
  SQL3="$3"
  echo "Running SQL: $SQL"
  cat <<EOF >config.sql
WHENEVER SQLERROR EXIT SQL.SQLCODE;
WHENEVER OSERROR EXIT FAILURE;
$SQL
$SQL2
$SQL3
exit
EOF
  cat config.sql
  docker cp config.sql oracle:/tmp/config.sql
  docker exec -u oracle -i oracle bash -c "sqlplus / as sysdba @/tmp/config.sql"
  rm config.sql
  sleep 3
}

display_wallet() {
  # run_sql "show parameter WALLET_ROOT;" "show parameter TDE_CONFIGURATION;"
  run_sql "COLUMN WRL_PARAMETER FORMAT A50;" "SET LINES 200;" "SELECT WRL_TYPE, WRL_PARAMETER, WALLET_TYPE, STATUS FROM V\$ENCRYPTION_WALLET;"
  run_sql "column name format a40;" "SET LINES 400;" "SELECT KEY_ID,KEYSTORE_TYPE,CREATOR_DBNAME,ACTIVATION_TIME,KEY_USE,ORIGIN FROM V\$ENCRYPTION_KEYS;"
}

# Like run_sql, but treats ORA-28354 (wallet already open, exit code 194)
# as success. Oracle may auto-open the HSM at DB startup when TDE_CONFIGURATION
# includes HSM, so an explicit OPEN can legitimately find it already open.
open_keystore() {
  local SQL="$1"
  echo "Running SQL: $SQL"
  cat <<EOF >config.sql
WHENEVER SQLERROR EXIT SQL.SQLCODE;
WHENEVER OSERROR EXIT FAILURE;
$SQL
exit
EOF
  cat config.sql
  docker cp config.sql oracle:/tmp/config.sql
  local exit_code=0
  docker exec -u oracle -i oracle bash -c "sqlplus / as sysdba @/tmp/config.sql" || exit_code=$?
  rm config.sql
  sleep 3
  if [[ $exit_code -eq 194 ]]; then
    # ORA-28354 (28354 mod 256 = 194): wallet / HSM already open — that is fine.
    echo "Keystore already open (ORA-28354) — continuing."
    return 0
  fi
  return $exit_code
}

run_sql "ALTER SYSTEM SET WALLET_ROOT='/opt/oracle/extapi/64/hsm/Cosmian/libcosmian_pkcs11.so' SCOPE=SPFILE;" "SHUTDOWN IMMEDIATE;" "STARTUP;"
run_sql "ALTER SYSTEM SET TDE_CONFIGURATION='KEYSTORE_CONFIGURATION=HSM' SCOPE=BOTH SID='*';" "SHUTDOWN IMMEDIATE;" "STARTUP;"
open_keystore "ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN IDENTIFIED BY hsm_identity_pass;"
run_sql "ADMINISTER KEY MANAGEMENT SET KEY IDENTIFIED BY hsm_identity_pass;"

display_wallet

#
# ─── Wallet migration tests ───────────────────────────────────────────────────
#
# Verify that libcosmian_pkcs11.so correctly supports Oracle TDE wallet
# migration in both directions (Software Wallet ↔ HSM Wallet).
#
# Important notes about the configuration:
#
#   The initial HSM-only setup above sets WALLET_ROOT to the library path
#   (/opt/oracle/extapi/64/hsm/Cosmian/libcosmian_pkcs11.so).  This tells
#   Oracle 23ai where the PKCS#11 library is in pure-HSM mode.
#
#   For hybrid (HSM|FILE / FILE|HSM) and file-only modes, WALLET_ROOT must be
#   a directory (Oracle stores the ewallet.p12 / cwallet.sso there).  In hybrid
#   mode, Oracle auto-discovers the PKCS#11 library from its standard extapi path:
#     /opt/oracle/extapi/64/hsm/<vendor>/lib<name>.so
#   which is exactly where set_hsm.sh installs the library.
#
#   Test order: we first perform the reverse migration (HSM → SW) since the
#   database is already in HSM mode after the initial setup above.  Oracle
#   forbids setting a new software master key (ORA-28414) while the active key
#   lives in the external keystore, so a plain FILE-mode setup would fail.
#   After the reverse migration succeeds, we are in FILE/SW mode and can test
#   the forward migration (SW → HSM).
#
echo ""
echo "==================================================================="
echo " Migration test 1/2: HSM wallet -> Software wallet (REVERSE MIGRATE)"
echo "==================================================================="

# ── step 1/6: switch WALLET_ROOT from library path to a directory ────────────
#
# WALLET_ROOT must change from the library path (used in pure-HSM mode) to a
# directory before Oracle can create or use a file-based keystore.
# After this change, Oracle auto-discovers the PKCS#11 library via extapi:
#   /opt/oracle/extapi/64/hsm/Cosmian/libcosmian_pkcs11.so
#
run_sql "ALTER SYSTEM SET WALLET_ROOT='/etc/ORACLE/KEYSTORES/FREE' SCOPE=SPFILE;" \
        "SHUTDOWN IMMEDIATE;" "STARTUP;"

# ── step 2/6: create a new empty software keystore ───────────────────────────
#
# The file keystore will receive the migrated master key in step 5.
#
run_sql "ADMINISTER KEY MANAGEMENT CREATE KEYSTORE IDENTIFIED BY sw_keystore_pass;"

# ── step 3/6: switch to FILE|HSM hybrid mode (file keystore as primary) ──────
#
# TDE_CONFIGURATION=FILE|HSM enables both keystores simultaneously.
# Oracle auto-discovers the PKCS#11 library via the extapi path set in step 1.
#
run_sql "ALTER SYSTEM SET TDE_CONFIGURATION='KEYSTORE_CONFIGURATION=FILE|HSM' SCOPE=BOTH SID='*';" \
        "SHUTDOWN IMMEDIATE;" "STARTUP;"

# ── step 4/6: open both keystores ────────────────────────────────────────────
open_keystore "ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN IDENTIFIED BY sw_keystore_pass;"
open_keystore "ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN IDENTIFIED BY hsm_identity_pass;"

# ── step 5/6: reverse migration — generate new software key, re-wrap DEKs ────
#
# Oracle calls C_Decrypt on libcosmian_pkcs11.so to unwrap existing DEKs from
# the current HSM master key, then re-encrypts them under the new software key.
#
run_sql "ADMINISTER KEY MANAGEMENT SET ENCRYPTION KEY IDENTIFIED BY sw_keystore_pass REVERSE MIGRATE USING hsm_identity_pass WITH BACKUP;"
display_wallet

# ── step 6/6: switch to file-only mode and open ──────────────────────────────
run_sql "ALTER SYSTEM SET TDE_CONFIGURATION='KEYSTORE_CONFIGURATION=FILE' SCOPE=BOTH SID='*';" \
        "SHUTDOWN IMMEDIATE;" "STARTUP;"
open_keystore "ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN IDENTIFIED BY sw_keystore_pass;"
display_wallet

echo "==================================================================="
echo " Migration test 1/2 PASSED: HSM wallet -> Software wallet"
echo "==================================================================="

echo ""
echo "==================================================================="
echo " Migration test 2/2: Software wallet -> HSM wallet (MIGRATE)"
echo "==================================================================="

# ── step 1/4: switch to HSM|FILE hybrid mode (HSM keystore as primary) ───────
#
# WALLET_ROOT is already a directory (/etc/ORACLE/KEYSTORES/FREE).
# Oracle auto-discovers libcosmian_pkcs11.so from the extapi path.
#
run_sql "ALTER SYSTEM SET TDE_CONFIGURATION='KEYSTORE_CONFIGURATION=HSM|FILE' SCOPE=BOTH SID='*';" \
        "SHUTDOWN IMMEDIATE;" "STARTUP;"

# ── step 2/4: open both keystores ────────────────────────────────────────────
open_keystore "ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN IDENTIFIED BY hsm_identity_pass;"
open_keystore "ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN IDENTIFIED BY sw_keystore_pass;"

# ── step 3/4: forward migration — generate new HSM master key, re-wrap DEKs ──
#
# Oracle calls C_GenerateKey(CKM_AES_KEY_GEN) on libcosmian_pkcs11.so to
# create the new master key in the KMS, then C_Encrypt to re-wrap any DEKs.
#
run_sql "ADMINISTER KEY MANAGEMENT SET ENCRYPTION KEY IDENTIFIED BY hsm_identity_pass MIGRATE USING sw_keystore_pass WITH BACKUP;"
display_wallet

# ── step 4/4: switch to HSM-only mode and open ───────────────────────────────
run_sql "ALTER SYSTEM SET TDE_CONFIGURATION='KEYSTORE_CONFIGURATION=HSM' SCOPE=BOTH SID='*';" \
        "SHUTDOWN IMMEDIATE;" "STARTUP;"
open_keystore "ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN IDENTIFIED BY hsm_identity_pass;"
display_wallet

echo "==================================================================="
echo " Migration test 2/2 PASSED: Software wallet -> HSM wallet"
echo "==================================================================="
