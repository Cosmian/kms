## Testing

### Database upgrade

- The `packaging-docker.yml` database upgrade gate runs `test:upgrade-db --old-version all`: every release from 5.9.0 onwards is upgraded to the candidate image on each backend instead of a rotating subset (job timeout 45 to 150 minutes).
- Add `mise run test:db:upgrade-all`: upgrades a database written by every release from 5.9.0 onwards (Docker images) to the branch's cargo-built server, filled by the new `populate_db.sh` (every object kind and KMIP operation reachable through `ckms`/curl) and re-verified after the upgrade, restart and restore.
- `run_db_upgrade_gate.sh` accepts `--new-kms`/`--ckms` (host candidate server) besides `--new-image`; the nightly baseline moves from 5.20.0 to 5.9.0.
- The upgrade verifiers (`verify_db_upgrade.py`, `populate_db.sh verify`) accept the two GetAttributes reporting changes of 5.13.0 for older source releases: `KeyFormatType` is compared in the format a Get returns (`TransparentSymmetricKey` reads `Raw`, `TransparentRSA*` reads `PKCS1`), and `State` accepts `PreActive`/`Deactivated` stored in the JSON by 5.9-5.12 where the enforced column holds `Active`/`Destroyed`. No stored data changes; PostgreSQL and MySQL upgrades from 5.9.0-5.12.1 now pass.
- The per-backend coverage reports are truncated at the start of each gate run instead of accumulating duplicate rows.
- `populate_db.sh`: fix the non-FIPS `ckms pqc keys create`/`pqc sign` calls (the command takes no positional id), and `verify --legacy-state` tolerates a Locate entry whose stored record lacks the tag (Redis 5.12.x re-certified certificates). Redis-with-Findex upgrades from 5.12.0 and 5.12.1 now pass.
