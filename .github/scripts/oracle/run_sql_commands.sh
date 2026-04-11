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

run_sql "ALTER SYSTEM SET WALLET_ROOT='/opt/oracle/extapi/64/hsm/Cosmian/libcosmian_pkcs11.so' SCOPE=SPFILE;" "SHUTDOWN IMMEDIATE;" "STARTUP;"
run_sql "ALTER SYSTEM SET TDE_CONFIGURATION='KEYSTORE_CONFIGURATION=HSM' SCOPE=BOTH SID='*';" "SHUTDOWN IMMEDIATE;" "STARTUP;"
run_sql "ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN IDENTIFIED BY hsm_identity_pass;"
run_sql "ADMINISTER KEY MANAGEMENT SET KEY IDENTIFIED BY hsm_identity_pass;"

display_wallet

#
# ─── Wallet migration tests ───────────────────────────────────────────────────
#
# Verify that libcosmian_pkcs11.so correctly supports Oracle TDE wallet
# migration in both directions (Software Wallet ↔ HSM Wallet).
#
# Important notes about the configuration change:
#
#   The initial HSM-only setup above sets WALLET_ROOT to the library path
#   (/opt/oracle/extapi/64/hsm/Cosmian/libcosmian_pkcs11.so).  This tells
#   Oracle 23ai where the PKCS#11 library is in pure-HSM mode.
#
#   For hybrid (HSM|FILE / FILE|HSM) and file-only modes, WALLET_ROOT must be
#   a directory (Oracle stores the ewallet.p12 / cwallet.sso there).  In hybrid
#   mode, Oracle then auto-discovers the PKCS#11 library from its standard path:
#     /opt/oracle/extapi/64/hsm/<vendor>/lib<name>.so
#   which is exactly where set_hsm.sh copies the library.
#
echo ""
echo "==================================================================="
echo " Migration test 1/2: Software wallet -> HSM wallet"
echo "==================================================================="

# ── step 1/6: reset to file-only, setting WALLET_ROOT to a directory ─────────
#
# WALLET_ROOT must change from the library path (used by pure HSM above) to a
# directory path before Oracle can create a file-based keystore.
#
run_sql "ALTER SYSTEM SET WALLET_ROOT='/etc/ORACLE/KEYSTORES/FREE' SCOPE=SPFILE;" \
        "SHUTDOWN IMMEDIATE;" "STARTUP;"
run_sql "ALTER SYSTEM SET TDE_CONFIGURATION='KEYSTORE_CONFIGURATION=FILE' SCOPE=BOTH SID='*';" \
        "SHUTDOWN IMMEDIATE;" "STARTUP;"

# ── step 2/6: create software keystore and set an initial TDE master key ──────
#
# This is the starting state: a software (file-based) keystore with one active
# master key — the situation before a production deployment migrates to an HSM.
#
run_sql "ADMINISTER KEY MANAGEMENT CREATE KEYSTORE IDENTIFIED BY sw_keystore_pass;"
run_sql "ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN IDENTIFIED BY sw_keystore_pass;"
run_sql "ADMINISTER KEY MANAGEMENT SET KEY IDENTIFIED BY sw_keystore_pass WITH BACKUP;"
display_wallet

# ── step 3/6: switch to hybrid HSM|FILE mode ──────────────────────────────────
#
# TDE_CONFIGURATION=HSM|FILE enables both keystores simultaneously.
# Oracle auto-discovers the PKCS#11 library via its extapi path:
#   /opt/oracle/extapi/64/hsm/Cosmian/libcosmian_pkcs11.so
#
run_sql "ALTER SYSTEM SET TDE_CONFIGURATION='KEYSTORE_CONFIGURATION=HSM|FILE' SCOPE=BOTH SID='*';" \
        "SHUTDOWN IMMEDIATE;" "STARTUP;"

# ── step 4/6: open both keystores ─────────────────────────────────────────────
run_sql "ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN IDENTIFIED BY hsm_identity_pass;"
run_sql "ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN IDENTIFIED BY sw_keystore_pass;"

# ── step 5/6: forward migration — generate a new HSM master key, re-wrap DEKs ─
#
# Oracle calls C_GenerateKey(CKM_AES_KEY_GEN) on libcosmian_pkcs11.so to
# create the new master key in the KMS, then C_Encrypt to re-wrap any DEKs.
#
run_sql "ADMINISTER KEY MANAGEMENT SET ENCRYPTION KEY IDENTIFIED BY hsm_identity_pass MIGRATE USING sw_keystore_pass WITH BACKUP;"
display_wallet

# ── step 6/6: switch to HSM-only and open ─────────────────────────────────────
run_sql "ALTER SYSTEM SET TDE_CONFIGURATION='KEYSTORE_CONFIGURATION=HSM' SCOPE=BOTH SID='*';" \
        "SHUTDOWN IMMEDIATE;" "STARTUP;"
run_sql "ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN IDENTIFIED BY hsm_identity_pass;"
display_wallet

echo "==================================================================="
echo " Migration test 1/2 PASSED: Software wallet -> HSM wallet"
echo "==================================================================="

echo ""
echo "==================================================================="
echo " Migration test 2/2: HSM wallet -> Software wallet"
echo "==================================================================="

# ── step 1/4: switch to hybrid FILE|HSM mode ──────────────────────────────────
#
# TDE_CONFIGURATION=FILE|HSM puts the file keystore as primary.
# Oracle still auto-discovers libcosmian_pkcs11.so for the HSM component.
# The software keystore (ewallet.p12) from migration test 1 still exists.
#
run_sql "ALTER SYSTEM SET TDE_CONFIGURATION='KEYSTORE_CONFIGURATION=FILE|HSM' SCOPE=BOTH SID='*';" \
        "SHUTDOWN IMMEDIATE;" "STARTUP;"

# ── step 2/4: open both keystores ─────────────────────────────────────────────
run_sql "ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN IDENTIFIED BY sw_keystore_pass;"
run_sql "ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN IDENTIFIED BY hsm_identity_pass;"

# ── step 3/4: reverse migration — generate new software key, unwrap DEKs ──────
#
# Oracle calls C_Decrypt on libcosmian_pkcs11.so to unwrap existing DEKs from
# the current HSM master key, then re-encrypts them under the new software key.
#
run_sql "ADMINISTER KEY MANAGEMENT SET ENCRYPTION KEY IDENTIFIED BY sw_keystore_pass REVERSE MIGRATE USING hsm_identity_pass WITH BACKUP;"
display_wallet

# ── step 4/4: switch to file-only and open ────────────────────────────────────
run_sql "ALTER SYSTEM SET TDE_CONFIGURATION='KEYSTORE_CONFIGURATION=FILE' SCOPE=BOTH SID='*';" \
        "SHUTDOWN IMMEDIATE;" "STARTUP;"
run_sql "ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN IDENTIFIED BY sw_keystore_pass;"
display_wallet

echo "==================================================================="
echo " Migration test 2/2 PASSED: HSM wallet -> Software wallet"
echo "==================================================================="
