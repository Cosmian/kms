## Bug Fixes

### Database

- Release PostgreSQL pool connections before retry back-off waits ([#1027](https://github.com/Cosmian/kms/issues/1027)).
- Fixed a `PgPool` startup deadlock when configured with a single-connection pool (`max_connections = 1`) and database clearing enabled: the migration path no longer holds its only connection while requesting a second one from the same pool.
- Fixed PostgreSQL deadlock/serialization-failure retry detection: the error conversion now preserves the SQLSTATE code and message needed to recognize a retryable failure, instead of collapsing every database-side error to a generic message.

## Security

- **Fixed an authorization bypass in the Create/Import privileged-user gate (GitHub issue #909, `COSMIAN-2026-020`)**: `"*"` is now a reserved object identifier and can no longer be assigned to a user-created object, tightening object UID validation across all database backends.
