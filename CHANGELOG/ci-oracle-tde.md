## CI

- Refactor Oracle upgrade CI: extract KMS upgrade logic into `.github/scripts/oracle/upgrade-kms.sh` and TDE smoke test logic into `.github/scripts/oracle/smoke-test-tde.sh` (standalone bash, 6 TDE proofs including full wallet migration K1→K2 with key identity and TEK re-wrapping verification); `upgrade-kms-oracle` job is inlined directly in `packaging-docker.yml`, triggered after `nix-docker-manifest`
