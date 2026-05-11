## CI

- Refactor Oracle upgrade CI: extract KMS upgrade logic into `.github/scripts/oracle/upgrade-kms.sh` and TDE smoke test logic into `.github/scripts/oracle/smoke-test-tde.sh` (standalone bash, 6 TDE proofs including full wallet migration K1→K2 with key identity and TEK re-wrapping verification); inline Oracle remote SSH steps into `test_docker_image.sh` (guarded by `ORACLE_DEMO_PASS`, non-fips amd64 only) via a dedicated `Resolve Oracle secrets` step, removing the separate `upgrade-kms-oracle` job
