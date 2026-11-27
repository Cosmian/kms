## Security

- Stricter `sslmode` handling for `PostgreSQL` connections: `require`, `verify-ca` and `verify-full` fail at startup when a TLS connection cannot be established, and unknown values are rejected. If your URL uses one of these modes, check that the `PostgreSQL` server accepts TLS before upgrading.

- The server now logs a startup warning when the audit `PostgreSQL` connection does not verify the server certificate.

## Bug Fixes

### Database
- Connection strings logged by the server now mask `user`, `password` and `sslpassword` given as URL query parameters.
- `sslrootcert` now trusts only the given CA instead of adding it to the system CAs.
- `sslmode=require` together with `sslrootcert` verifies the server certificate (libpq behaviour).
- `sslmode=verify-ca` no longer checks the server hostname; `verify-full` still does.

## Testing

- Added live `PostgreSQL` TLS tests covering every `sslmode`; the `psql` test task now starts the `postgres-mtls` container.

## Documentation

- Documented `sslmode=allow` (behaves like `prefer`) and the `sslrootcert` trust behaviour in the `PostgreSQL` configuration page.
