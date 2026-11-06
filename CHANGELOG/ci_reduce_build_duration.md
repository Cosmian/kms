## Build

- Reuse the packaged server and CLI outputs when generating SBOMs so they describe the shipped build instead of rebuilding it.
- Stop generating debug information that the development profile already strips.
- Refresh the UI WASM, server, macOS CLI and musl CLI vendor hashes from packaging CI and pristine source builds without changing dependency lockfiles.

## Testing

- Run the full workspace suite in SQLite tasks; scope other database tasks to database tests and the packages that start the shared test server. This also changes local `mise run test:db:psql`, `test:db:mysql`, `test:db:percona`, `test:db:mariadb` and `test:db:redis` runs.
- Regroup the `mise run test:*` tasks by area (`test:db:*`, `test:hsm:*`, `test:pkcs11:*`, `test:interop:*`, `test:pki:*`, `test:obs:*`, `test:ui:*`, `test:cloud:*`, `test:k8s:*`, `test:pkg:*`): for example `test:psql` becomes `test:db:psql`, `test:hsm-softhsm2` becomes `test:hsm:softhsm2`, `test:ocsp` becomes `test:pki:ocsp`, `test:siem-filebeat` becomes `test:obs:filebeat`, `test:wasm` becomes `test:ui:wasm` and `test:secret_aws` becomes `test:cloud:secret-aws`. `test:cef` and `test:siem` become `test:obs`, `test:matrix` becomes `test:hsm:matrix`, and `test:vectors-rekey` becomes `dev:vectors-rekey` and no longer runs as part of `mise run test`.
- Each test task checks its own prerequisites and exits 77 (`skip_test`) when it cannot run on the machine; each group `_default` (`mise run test`, `mise run test:<group>`) runs its adjacent tasks with `run_test_leaves` and prints a PASS/SKIP/FAIL summary with the reason of every skip.
- Split the aggregated tests: `test:ui:standard` no longer runs the auth, OIDC and SAML E2E suites (the `--standard-only` flag is removed; use `test:ui:auth`, `test:ui:oidc`, `test:ui:saml` or `test:ui`), `test:obs:audit` no longer runs the OpenSearch, Splunk and PostgreSQL compatibility checks (use `test:obs:audit-opensearch`, `test:obs:audit-splunk`, `test:obs:audit-postgres` or `test:obs`), and `test:k8s:plugin-mtls` replaces `test:k8s:plugin --mtls` in the Kubernetes group.

## CI

- Add small Nix dev-shell, build.rs OpenSSL and Windows vcpkg caches; group short integration suites and split standard UI tests from SSO tests.
- Keep MySQL-family FIPS legs, HSM benchmarks, the full Windows lib suite and compiling publication dry runs in non-PR runs. Pin the package upload host key and preserve packaging's existing Nix substituter behavior.
- Merge the `hsm` and `hsm-upstream` jobs of `test_all.yml` into `test-nix` and `test-nix-upstream`, list each job's legs in a static `strategy.matrix` (`leg`, `variant`, `exclude`, `include` with the `test:<id>` task ids run in a shell loop), and replace the `run-mise-suites` action with that loop. In CI, an upstream task whose secret is unset fails instead of being skipped, so a green upstream leg proves its tasks ran.
- Connect directly with `hyper-util`'s `HttpConnector` (IPv6/IPv4 happy eyeballs) instead of `TcpStream::connect`: on Windows, `localhost` is believed to resolve to `::1` first, so each new connection to an IPv4-only server waited ~2 s before falling back (to be confirmed by Windows CI timings). The `test_kms_server` vector runner also builds one owner client per vector instead of one per step.
- Run the PKCS#11 support report and `pkcs11-check` once, in the `pkcs11` leg, instead of in the `ase` leg and in every non-fips HSM leg. Stop passing the Google, AWS and Azure test secrets to the `test-nix` job: none of its suites uses them.
