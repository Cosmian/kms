## Security

- **Fixed an authorization bypass in the Create/Import privileged-user gate (GitHub issue #909, `COSMIAN-2026-020`)**: `"*"` is now a reserved object identifier and can no longer be assigned to a user-created object, tightening object UID validation across all database backends.
