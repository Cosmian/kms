## Features

### Database

- Run PostgreSQL, MySQL, MariaDB, and Percona XtraDB Cluster startup migrations through the versioned runner with cross-instance locks and newer-database refusal ([#1271](https://github.com/Cosmian/kms/issues/1271))

## Bug Fixes

### Database

- Convert PostgreSQL object attributes from `json` to `jsonb` once instead of rebuilding attribute expression indexes under an exclusive lock at every startup
- Clear PostgreSQL databases before data backfills, avoiding unnecessary scans when `--clear-database` is set
- Correct the documented MySQL primary-key schema update version from `5.13.0` to `5.14.0`

---

Closes #1271
