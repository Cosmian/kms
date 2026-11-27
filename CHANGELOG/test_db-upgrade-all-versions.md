## Testing

### Database upgrade

- One task `mise run test:db:upgrade` replaces `test:upgrade-db`, `test:db:upgrade-all` and `test:db:upgrade-sqlite`: every release from 5.9.0 onwards (Docker images, or one local binary with `--old-kms`) is upgraded to the branch's cargo-built server (or `--new-image`), filled by `populate_db.sh` and re-verified after the upgrade, restart and restore; one gate process per backend runs in parallel.
- New nightly `db:upgrade` CI leg runs every release (schedule, tag and dispatch only, not on PRs); the `packaging-docker.yml` image gate is back on the cheap `nightly` rotation (job timeout 60 minutes).
- `run_db_upgrade_gate.sh` accepts `--new-kms`/`--ckms` (host candidate server) besides `--new-image`; the nightly baseline moves from 5.20.0 to 5.9.0.
- The upgrade verifiers (`verify_db_upgrade.py`, `populate_db.sh verify`) accept the two GetAttributes reporting changes of 5.13.0 for older source releases: `KeyFormatType` is compared in the format a Get returns (`TransparentSymmetricKey` reads `Raw`, `TransparentRSA*` reads `PKCS1`), and `State` accepts `PreActive`/`Deactivated` stored in the JSON by 5.9-5.12 where the enforced column holds `Active`/`Destroyed`. No stored data changes; PostgreSQL and MySQL upgrades from 5.9.0-5.12.1 now pass.
- The per-backend coverage reports are truncated at the start of each gate run instead of accumulating duplicate rows.
- `populate_db.sh`: fix the non-FIPS `ckms pqc keys create`/`pqc sign` calls (the command takes no positional id), and `verify --legacy-state` tolerates a Locate entry whose stored record lacks the tag (Redis 5.12.x re-certified certificates). Redis-with-Findex upgrades from 5.12.0 and 5.12.1 now pass.
- The upgrade gate also runs every cell with a key encryption key configured: the old server creates a KEK, restarts with it and fills the database again, and the candidate, its restart and the restore-phase old server run with the same KEK. Releases before 5.17.0 are started with a PKCS#12 identity (their images reject `--tls-cert-file`), and Redis releases before 5.29.0 tolerate a Locate entry whose stored record lacks the tag.
