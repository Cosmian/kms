## Breaking Changes

### Database
- `sslmode` is now enforced for `PostgreSQL` connections: a URL that requires TLS fails at startup when TLS cannot be established, and unknown `sslmode` values are rejected.
- With `sslrootcert`, only that CA is trusted. `sslmode=require` together with `sslrootcert` also verifies the server certificate (libpq behaviour).

## Bug Fixes

### Database
- `sslmode=verify-ca` no longer checks the server hostname; `verify-full` still does.
- `sslmode=allow` is accepted and behaves like `prefer`.

## Tests

- Added live `PostgreSQL` TLS tests covering every `sslmode`; the `psql` test task now starts the `postgres-mtls` container.

## Documentation

- Updated the `PostgreSQL` `sslmode` reference in the database configuration page.
