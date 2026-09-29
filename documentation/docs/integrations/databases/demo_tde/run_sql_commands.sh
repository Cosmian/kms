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
