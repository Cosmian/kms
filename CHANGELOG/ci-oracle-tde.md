## CI

- Refactor Oracle upgrade CI: extract KMS upgrade logic into `.github/scripts/oracle/upgrade-kms.sh` and TDE smoke test logic into `.github/scripts/oracle/smoke-test-tde.sh` (standalone bash, 6 TDE proofs); inline Oracle remote SSH steps into `test_docker_image.sh` (guarded by `RUN_ORACLE_TESTS`, non-fips amd64 only), removing the separate `upgrade-kms-oracle` job
- Fix `upgrade-kms.sh` WAL threshold: combine `kms.db` + `kms.db-wal` sizes (fixes false-empty detection when all keys live in the WAL file)
- Fix `smoke-test-tde.sh` Phase 1 CLOSED recovery: import placeholder AES-256 keys into KMS using `ckms sym keys import --key-format aes` with KMIP ID `ORACLE.TDE.HSM.MK.<MEK_ID>` read from `PROPS$.VALUE$`; avoids unsafe `SYS.ENC$` manipulation
- Replace Proof 6 (REVERSE MIGRATE HSM→FILE): Oracle 23ai Free does not support `BACKUP KEYSTORE` for PKCS#11 keystores (ORA-00600: kzckmbkup: invalid keystore location [4]); replaced with **TDE REKEY** proof — rotates MEK within HSM (`SET KEY`), verifies `MASTERKEYID` changes in `V$ENCRYPTED_TABLESPACES`, data readable, DBF encrypted
- Remove `ORACLE_TDE_WALLET_PASS` secret from `packaging-docker.yml` and `test_docker_image.sh` (no longer needed after REVERSE MIGRATE removal)
- Validated: all 6/6 proofs pass on Oracle 23ai Free with Cosmian PKCS#11 provider ([#918](https://github.com/Cosmian/kms/pull/918))
