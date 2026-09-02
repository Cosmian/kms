## Bug Fixes

### Database

- Release PostgreSQL pool connections before retry back-off waits ([#1027](https://github.com/Cosmian/kms/issues/1027)).

## Security

- **Fixed an authorization bypass in the Create/Import privileged-user gate (GitHub issue #909, `COSMIAN-2026-020`)**: `"*"` is now a reserved object identifier and can no longer be assigned to a user-created object, tightening object UID validation across all database backends.
