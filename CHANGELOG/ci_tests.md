## Bug Fixes

### CI / Test scripts

- Fix `test_iris.sh` silently assigning empty ports: `kms_pick_free_port` was called without sourcing `.mise/lib/kms_server.sh`,
  causing KMS to fail at startup and the job to time out after 60 s (~20 min total).
  Added the missing `source` directive.
- Fix same missing-source bug in `test_edb_tde.sh` (`kms_pick_free_port` called without `kms_server.sh` being sourced).

## CI

- Gate Windows tests (`windows-2022`) to pull requests and tags only; skip on direct branch pushes to
  avoid spending slow `windows-2022` runner minutes on every intermediate commit.
- `cargo-publish` job no longer depends on `windows-2022`, allowing it to run independently.
- `cleanup` job now runs unconditionally (`if: always()`) so the GitHub cache is pruned even when
  upstream jobs are skipped.

---
