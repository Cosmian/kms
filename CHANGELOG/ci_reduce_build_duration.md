## Build

- Reuse the packaged server and CLI outputs when generating SBOMs so they describe the shipped build instead of rebuilding it.
- Stop generating debug information that the development profile already strips.

## Testing

- Run the full workspace suite in SQLite tasks; scope other database tasks to database tests and the packages that start the shared test server. This also changes local `mise run test:psql`, `test:mysql`, `test:percona`, `test:mariadb` and `test:redis` runs.

## CI

- Add small Nix dev-shell, build.rs OpenSSL and Windows vcpkg caches; group short integration suites and split standard UI tests from SSO tests.
- Keep MySQL-family FIPS legs, HSM benchmarks, the full Windows lib suite and compiling publication dry runs in non-PR runs. Pin the package upload host key and preserve packaging's existing Nix substituter behavior.
