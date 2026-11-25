## Bug Fixes

### Database

- Make scheduled jobs mutually exclusive across Galera nodes: when the database refuses `GET_LOCK` (Percona XtraDB
  Cluster strict mode, MariaDB Galera), a job now takes a committed, replicated 300-second lease on a row of the new
  `kms_cron_leases` table, renewed every 100 seconds while it runs, instead of a node-local row lock. Until now every
  Galera node connected to a different database node ran every job (CRL refresh, key rotation, expiry warnings)
  ([#1511](https://github.com/Cosmian/kms/issues/1511)).
- A job whose holder dies is taken over by another node once its lease expires (at most 300 seconds). During a rolling
  upgrade from a release before 6.0 the exclusion between old and new nodes is degraded until every node runs 6.0.
  The new table is created at startup; an older release ignores it (see `**Downgrade.**` in
  `documentation/docs/configuration/database/tables.md`). The lease uses the clock of the database nodes: keep them
  NTP-synchronised.

---

Closes #1511
