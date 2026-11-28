# Changelog

All notable changes to this project will be documented in this file.

## [5.30.0] - 2026-11-28

Summary release entry. Every item names the archived branch files under [`CHANGELOG/5.30.0/`](CHANGELOG/5.30.0/) that hold the full detail (behaviour, options, client actions, tests). Operator procedure per area: [Upgrading to 5.30](documentation/docs/installation/upgrading/upgrade_to_5_30.md).

The complete text of this entry before it was summarised is kept in [release_notes](CHANGELOG/5.30.0/release_notes.md); use it when a linked file does not cover an item.

### ⚠️ Breaking Changes

- `vault_auth_verifier_url` receives standard Vault paths: the KMS calls `GET <url>/v1/auth/token/lookup-self` and forwards `/v1/auth/*` unchanged. **Upgrade action:** point it at an OpenBao/Vault server or at a Cosmian Auth Verifier that serves `/v1/auth/*`; upgrade an older Auth Verifier together with the KMS ([#863](https://github.com/Cosmian/kms/issues/863), [feat_kv-secret-store](CHANGELOG/5.30.0/feat_kv-secret-store.md))
- Objects wrapped by the server `key_encryption_key` are bound to their database row (vendor attribute `x-cosmian-stored-uid`); the server re-wraps existing objects at start, so no manual migration is needed. **Upgrade action:** stop every 5.29.0 instance before starting 5.30.0; with an RSA-OAEP key encryption key, a 2048-bit KEK limits stored-key UIDs to about 58 characters ([#1519](https://github.com/Cosmian/kms/issues/1519), [fix_bind-sql-objects-to-row-1519](CHANGELOG/5.30.0/fix_bind-sql-objects-to-row-1519.md))

### 🔒 Security

Advisories fixed in 5.30.0; see [SECURITY.md](SECURITY.md) for scope, affected versions and references, and the branch files linked there for the fixes.

- Statically linked OpenSSL 3.6.2 and container runtime packages with fixable CVEs (COSMIAN-2026-049)
- Configured Operator role permitted PKCS#11 administration (COSMIAN-2026-050)
- KMIP payloads written to debug logs (COSMIAN-2026-051)
- KMIP certificate chains and unbounded HSM Locate permitted excessive server work (COSMIAN-2026-052)
- `ReKeyKeyPair` retired another user's linked public key (COSMIAN-2026-053)
- `ReCertify` authorized the issuer key as the certificate owner (COSMIAN-2026-054)
- `Get Attributes` without a Unique Identifier selected another user's newest object (COSMIAN-2026-056)
- Decrypt by keyset name returned wrong-key output in unauthenticated modes (COSMIAN-2026-057)
- Retired HSM key generations remained usable for Encrypt, Sign and MAC (COSMIAN-2026-058)
- HSM keys addressed by their UID skipped the KMIP algorithm policy (COSMIAN-2026-059)
- HSM `ReKey` revealed the existence and type of other users' HSM keys (COSMIAN-2026-060)
- Vault-token-only authentication let requests without credentials run as the default user (COSMIAN-2026-061)
- Server `key_encryption_key` not applied to several object-creation paths (COSMIAN-2026-062)
- Secret KMIP fields written to trace and debug logs (COSMIAN-2026-063)
- Public `GET /health` returned database driver and PKCS#11 error details (COSMIAN-2026-064)
- RUSTSEC-2026-0459 / CVE-2026-119375: bundled SQLite before 3.54 (COSMIAN-2026-065)
- RUSTSEC-2026-0552, -0553, -0554: `actix-http` request framing and keep-alive flaws (COSMIAN-2026-066)
- RUSTSEC-2026-0544 / CVE-2026-85091: `libz-sys` zlib heap buffer overflow (COSMIAN-2026-067)
- RUSTSEC-2026-0543 and -0542: unmaintained `chrono` and `humantime` crates (COSMIAN-2026-068)
- GHSA-g3hv-75wg-m249: `minimatch` denial of service in the Web UI dependency tree (COSMIAN-2026-069)
- Key wrapping with a Certificate skipped the `WrapKey` usage-mask check (COSMIAN-2026-070)
- `DeriveKey` skipped the Create gate, JOSE and SPIRE routes skipped the KMIP algorithm policy, wrapping errors revealed other users' keys (COSMIAN-2026-071)
- Server without authentication started on a non-loopback address (COSMIAN-2026-072)
- Authentication Verifier bearer tokens of the admin realm or another realm accepted (COSMIAN-2026-073)
- KMS identity taken from an unverified `email` claim, shared across identity providers (COSMIAN-2026-074)
- External credential named like `default_username` inherited the default user's identity (COSMIAN-2026-075)
- `POST /ui/login_as` without KMS-side rate limit (COSMIAN-2026-076)
- Web UI session cookie replayable after logout, no server-enforced lifetime (COSMIAN-2026-077)
- Web UI session key derived with the public URL as password; guessable `ui_session_salt` accepted (COSMIAN-2026-078)
- mTLS client certificates never checked against a revocation list (COSMIAN-2026-079)
- A failing database lookup made CRL generation, OCSP and Locate see no certificates (COSMIAN-2026-080)
- CRL Distribution Point fetch accepted unbounded chunked bodies and grew its cache without limit (COSMIAN-2026-081)
- SSRF via DNS names resolving to internal addresses in CRL Distribution Points (COSMIAN-2026-082)
- A CRL fetch error marked an imported certificate Compromised (COSMIAN-2026-083)

### 🚀 Features

- **Multi-node cluster and multi-region**: advisory-lock/named-lock scheduled jobs, `cluster_nodes` heartbeat, `GET /cluster/status`, per-dependency `GET /health`, Web UI Server Health page, `region_role` leader/follower for PostgreSQL logical replication and MySQL Galera, Galera job leases, monotonic lifecycle writes ([#1366](https://github.com/Cosmian/kms/issues/1366), [#1511](https://github.com/Cosmian/kms/issues/1511); [feat_cluster-support-1366](CHANGELOG/5.30.0/feat_cluster-support-1366.md), [feat_health-strict-kmip-1366](CHANGELOG/5.30.0/feat_health-strict-kmip-1366.md), [feat_health-ui](CHANGELOG/5.30.0/feat_health-ui.md), [multi_region](CHANGELOG/5.30.0/multi_region.md), [fix_galera-cron-lease-1511](CHANGELOG/5.30.0/fix_galera-cron-lease-1511.md))
- **Versioned database migration runner** for SQLite, PostgreSQL, MySQL/MariaDB and Redis-with-Findex, the `StoredStateSync` step, PostgreSQL `json` to `jsonb`, and `mise run test:db:upgrade` from every release since 5.9.0 ([#1270](https://github.com/Cosmian/kms/issues/1270), [#1271](https://github.com/Cosmian/kms/issues/1271), [#1272](https://github.com/Cosmian/kms/issues/1272); [feat_db_migration_runner_sqlite](CHANGELOG/5.30.0/feat_db_migration_runner_sqlite.md), [feat_db_migration_runner_pg_mysql](CHANGELOG/5.30.0/feat_db_migration_runner_pg_mysql.md), [feat_db_migration_redis_findex](CHANGELOG/5.30.0/feat_db_migration_redis_findex.md), [feat_state-json-sync](CHANGELOG/5.30.0/feat_state-json-sync.md), [test_db-upgrade-all-versions](CHANGELOG/5.30.0/test_db-upgrade-all-versions.md))
- **Vault-compatible API**: KV v2 secret store over KMIP `SecretData`, short-lived OpenSSH certificates (`/v1/ssh/*`), Vault auto-unseal with `seal "transit"`, `ckms kv|ssh|password` and the matching Web UI pages ([#863](https://github.com/Cosmian/kms/issues/863), [#864](https://github.com/Cosmian/kms/issues/864), [#1365](https://github.com/Cosmian/kms/issues/1365); [feat_kv-secret-store](CHANGELOG/5.30.0/feat_kv-secret-store.md), [feat_kv-ssh-password-clients](CHANGELOG/5.30.0/feat_kv-ssh-password-clients.md), [feat_vault-transit-auto-unseal-1365](CHANGELOG/5.30.0/feat_vault-transit-auto-unseal-1365.md))
- **AES-CMAC and AES-GMAC** in `MAC`/`MACVerify`, `ckms mac`, PKCS#11; FIPS-provider AES-GCM IV generation, per-key invocation counter (`gcm_invocations`), FIPS startup check of the OpenSSL provider ([#1367](https://github.com/Cosmian/kms/issues/1367); [feat_aes-cmac-and-aes-gmac-1367](CHANGELOG/5.30.0/feat_aes-cmac-and-aes-gmac-1367.md), [fix_gcm-invocation-lease](CHANGELOG/5.30.0/fix_gcm-invocation-lease.md))
- **PQC and EdDSA in FIPS builds** (ML-KEM, ML-DSA, SLH-DSA, `X25519MLKEM768`, Ed25519, Ed448) on OpenSSL FIPS provider 3.5.9 ([#1522](https://github.com/Cosmian/kms/issues/1522); [feat_fips-pqc-eddsa-1522](CHANGELOG/5.30.0/feat_fips-pqc-eddsa-1522.md))
- **Idemia SPHERE HSM** model, Windows FIPS installer and Windows HSM tests ([feat_idemia_hsm](CHANGELOG/5.30.0/feat_idemia_hsm.md))
- **HSM**: auto-rotation of HSM-resident keys, `ReKeyKeyPair` on HSM private keys, usage masks derived from PKCS#11 attributes ([#1425](https://github.com/Cosmian/kms/issues/1425), [#1456](https://github.com/Cosmian/kms/issues/1456); [feat_auto-rotate-hsm-resident-keys-1425](CHANGELOG/5.30.0/feat_auto-rotate-hsm-resident-keys-1425.md), [feat_hsm-derive-usage-masks-1456](CHANGELOG/5.30.0/feat_hsm-derive-usage-masks-1456.md))
- **Ansible collection** `cosmian.kms` ([#1372](https://github.com/Cosmian/kms/issues/1372); [feat_ansible-collection-1372](CHANGELOG/5.30.0/feat_ansible-collection-1372.md)) and an **OpenVEX** document for the SBOM ([feat_openvex](CHANGELOG/5.30.0/feat_openvex.md))
- **Observability**: richer `kms.keys.active.count` labels and key-expiry metrics ([#1412](https://github.com/Cosmian/kms/issues/1412); [feat_otel-metrics-attributes-key-expiry-1412](CHANGELOG/5.30.0/feat_otel-metrics-attributes-key-expiry-1412.md))
- **Web UI and WASM**: Activate actions for Pre-Active objects, Covercrypt re-key WASM exports, `GET /ui/config` to hide unavailable sections ([#1356](https://github.com/Cosmian/kms/issues/1356); [feat_activate-pre-active-objects-locate-1356](CHANGELOG/5.30.0/feat_activate-pre-active-objects-locate-1356.md), [dp_wasm-cc-rekey-actions](CHANGELOG/5.30.0/dp_wasm-cc-rekey-actions.md), [feat_ui-limit-visible-directories](CHANGELOG/5.30.0/feat_ui-limit-visible-directories.md))
- **Sensitive value redaction**: `Sensitive<T>` wrapper and redacting `Debug` on secret-bearing types ([#1426](https://github.com/Cosmian/kms/issues/1426); [feat_sensitive-bytes-redacting-type-1426](CHANGELOG/5.30.0/feat_sensitive-bytes-redacting-type-1426.md))
- **Interoperability and benchmarks**: KMIP 2.1 `Ping`, live KMIPKit tests, `bench:compare`, JOSE CEK-switch benchmark, `ckms login oauth --refresh` ([test_kmipkit-interop](CHANGELOG/5.30.0/test_kmipkit-interop.md), [ci_benchmark_regression_report](CHANGELOG/5.30.0/ci_benchmark_regression_report.md), [jose-cek-switch-bench](CHANGELOG/5.30.0/jose-cek-switch-bench.md), [test_cse](CHANGELOG/5.30.0/test_cse.md))

### 🐛 Bug Fixes

- **KMIP**: strict KMIP 2.1 conformance (Result Reasons, lifecycle, batches and batch Undo, attribute and operation rules, encodings, bounds, Locate/Get/Export/Query, Login/Logout, Set Constraints), concurrent re-key protection and atomic Usage Limits accounting, certificate import against a revoked issuer ([#1006](https://github.com/Cosmian/kms/issues/1006), [#1312](https://github.com/Cosmian/kms/issues/1312), [#1313](https://github.com/Cosmian/kms/issues/1313), [#1461](https://github.com/Cosmian/kms/issues/1461); [fix_kmip-conformance-gaps](CHANGELOG/5.30.0/fix_kmip-conformance-gaps.md), [fix_kmip_result_reasons_batch_items_1312_1313](CHANGELOG/5.30.0/fix_kmip_result_reasons_batch_items_1312_1313.md), [fix_kmip-authorization-policy-gaps-1492](CHANGELOG/5.30.0/fix_kmip-authorization-policy-gaps-1492.md), [fix_rotation-optimistic-lock-1006](CHANGELOG/5.30.0/fix_rotation-optimistic-lock-1006.md), [fix_revoked-certificate-import-crl-1461](CHANGELOG/5.30.0/fix_revoked-certificate-import-crl-1461.md), [chore_todo-triage](CHANGELOG/5.30.0/chore_todo-triage.md))
- **Authentication and identities**: fail-closed defaults (no-auth start refused on non-loopback addresses, `email#<issuer>` identities, `default_username` isolation), `X-Vault-Token` counted as authentication, Web UI session revocation, key derivation and in-house cookie ([#1486](https://github.com/Cosmian/kms/issues/1486), [#1487](https://github.com/Cosmian/kms/issues/1487), [#1437](https://github.com/Cosmian/kms/issues/1437); [fix_fail-closed-defaults-user-identity-1486](CHANGELOG/5.30.0/fix_fail-closed-defaults-user-identity-1486.md), [fix_ui-session-revocation-kdf-hardening-1487](CHANGELOG/5.30.0/fix_ui-session-revocation-kdf-hardening-1487.md), [fix_hardening-require-vault-token-auth-1437](CHANGELOG/5.30.0/fix_hardening-require-vault-token-auth-1437.md))
- **Certificates and revocation**: mTLS client revocation (`clients_crl_dir`), CRL fetch safeguards, fail-closed database lookups ([#1493](https://github.com/Cosmian/kms/issues/1493); [fix_certificate-revocation-correctness-1493](CHANGELOG/5.30.0/fix_certificate-revocation-correctness-1493.md))
- **HSM and PKCS#11**: sensitive-by-default HSM keys, HSM UID policy and retired generations, GCM message-API fallback, panic containment in the provider, Oracle TDE objects created Active, non-extractable key export policy in PKCS#11 and CNG ([#1490](https://github.com/Cosmian/kms/issues/1490), [#1491](https://github.com/Cosmian/kms/issues/1491); [fix_enforce-sensitive-extractable-split-hsm-1490](CHANGELOG/5.30.0/fix_enforce-sensitive-extractable-split-hsm-1490.md), [fix_pkcs11-message-gcm-fallback](CHANGELOG/5.30.0/fix_pkcs11-message-gcm-fallback.md), [fix_pkcs11_oracle_tde_active](CHANGELOG/5.30.0/fix_pkcs11_oracle_tde_active.md), [fix_cng-pkcs11-non-extractable-keys-1491](CHANGELOG/5.30.0/fix_cng-pkcs11-non-extractable-keys-1491.md), [feat_FFI_should_not_panic](CHANGELOG/5.30.0/feat_FFI_should_not_panic.md), [fix_hsm-bench-fips-rsa-pkcs](CHANGELOG/5.30.0/fix_hsm-bench-fips-rsa-pkcs.md))
- **Hardening**: bounded pre-authentication and client-controlled KMIP parameters, redacted logs and audited handlers, database TLS and ceremony binding, secret files and `ckms` credential handling, security headers, SCEP renewal default, OTLP endpoint checks, Findex salt, monitoring stack and operator ([#1485](https://github.com/Cosmian/kms/issues/1485), [#1488](https://github.com/Cosmian/kms/issues/1488), [#1489](https://github.com/Cosmian/kms/issues/1489), [#1494](https://github.com/Cosmian/kms/issues/1494), [#1495](https://github.com/Cosmian/kms/issues/1495), [#1497](https://github.com/Cosmian/kms/issues/1497), [#1500](https://github.com/Cosmian/kms/issues/1500); [fix_google-cse-privileged-auth-dke-cors-1485](CHANGELOG/5.30.0/fix_google-cse-privileged-auth-dke-cors-1485.md), [security_1445-kmip14-debug-redaction](CHANGELOG/5.30.0/security_1445-kmip14-debug-redaction.md), [security_1488-bound-preauth-resources](CHANGELOG/5.30.0/security_1488-bound-preauth-resources.md), [security_1489-bound-client-kmip-params](CHANGELOG/5.30.0/security_1489-bound-client-kmip-params.md), [security_1494-logs-errors-audit](CHANGELOG/5.30.0/security_1494-logs-errors-audit.md), [security_1495-db-tls-ceremony-binding](CHANGELOG/5.30.0/security_1495-db-tls-ceremony-binding.md), [security_1497-ckms-secret-files](CHANGELOG/5.30.0/security_1497-ckms-secret-files.md), [security_1500-hardening-notes](CHANGELOG/5.30.0/security_1500-hardening-notes.md), [fix_key-wrapping-certificate-usage-mask-1457](CHANGELOG/5.30.0/fix_key-wrapping-certificate-usage-mask-1457.md))
- **Dependencies**: OpenSSL 3.6.5 and `rusqlite` bumps, RUSTSEC fixes, Web UI supply-chain pinning ([#1349](https://github.com/Cosmian/kms/issues/1349), [#1480](https://github.com/Cosmian/kms/issues/1480); [fix_statically-linked-openssl-critical-cves-1349](CHANGELOG/5.30.0/fix_statically-linked-openssl-critical-cves-1349.md), [fix_rustsec-2026-0459](CHANGELOG/5.30.0/fix_rustsec-2026-0459.md), [fix_rustsec-2026-0594-1480](CHANGELOG/5.30.0/fix_rustsec-2026-0594-1480.md), [feat_npm-supply-chain](CHANGELOG/5.30.0/feat_npm-supply-chain.md))
- **CLI, Web UI, packaging, observability**: Base64 key export no longer lower-cased, `--sensitive` optional value, Web UI form fixes, service kept enabled across Debian/RPM upgrades and `kms.toml` kept on Windows upgrades, root `kms` span removed ([#1499](https://github.com/Cosmian/kms/issues/1499), [#1458](https://github.com/Cosmian/kms/issues/1458); [fix_base64-key-export-lower-cased-1499](CHANGELOG/5.30.0/fix_base64-key-export-lower-cased-1499.md), [fix_ui_problems](CHANGELOG/5.30.0/fix_ui_problems.md), [fix_upgrade-from-5.29](CHANGELOG/5.30.0/fix_upgrade-from-5.29.md), [fix_telemetry-root-kms-span-1458](CHANGELOG/5.30.0/fix_telemetry-root-kms-span-1458.md))

### ♻️ Refactor

- Remove every clippy suppression from non-test code, use safe OpenSSL APIs, split the HSM encryption dispatch and drop unused KMIP 1.4 structs; regroup `.mise/scripts/test/` ([chore_lint-suppression-cleanup](CHANGELOG/5.30.0/chore_lint-suppression-cleanup.md), [feat_regroup-mise-test-scripts-1418](CHANGELOG/5.30.0/feat_regroup-mise-test-scripts-1418.md))

### 🧪 Testing

- OASIS XML vector harness for KMIP 1.0 to 2.1, HSM GCM matrix, PKCS#11 panic test, Web UI session end-to-end tests, multi-region and database upgrade suites ([test_cse](CHANGELOG/5.30.0/test_cse.md), [test_db-upgrade-all-versions](CHANGELOG/5.30.0/test_db-upgrade-all-versions.md), [test_kmipkit-interop](CHANGELOG/5.30.0/test_kmipkit-interop.md))

### ⚙️ Build

- Remove unused dependencies, bump the OpenSSL FIPS provider from 3.1.2 to 3.5.9, build the PKCS#11 library with the `pkcs11-provider` profile, remove the legacy Nix dispatcher, bump the workspace to 5.30.0 ([#1502](https://github.com/Cosmian/kms/issues/1502), [#1420](https://github.com/Cosmian/kms/issues/1420); [chore_prune_dependencies](CHANGELOG/5.30.0/chore_prune_dependencies.md), [chore_remove_chrono](CHANGELOG/5.30.0/chore_remove_chrono.md), [chore_remove_not_mandatory_deps](CHANGELOG/5.30.0/chore_remove_not_mandatory_deps.md), [feat_bump-openssl-fips-provider-1502](CHANGELOG/5.30.0/feat_bump-openssl-fips-provider-1502.md), [feat_remove-legacy-nix-sh-dispatcher-1420](CHANGELOG/5.30.0/feat_remove-legacy-nix-sh-dispatcher-1420.md))

### ⚙️ CI

- Per-path pull-request gating, cheaper CI, Docker Hub rate-limit handling, isolated signing and release jobs without credentials, npm and image scans ([#1498](https://github.com/Cosmian/kms/issues/1498), [#1435](https://github.com/Cosmian/kms/issues/1435); [ci_pr-path-gating](CHANGELOG/5.30.0/ci_pr-path-gating.md), [ci_reduce_build_duration](CHANGELOG/5.30.0/ci_reduce_build_duration.md), [ci_dockerhub-rate-limit](CHANGELOG/5.30.0/ci_dockerhub-rate-limit.md), [ci_nightly-sbom-dispatch-run-id](CHANGELOG/5.30.0/ci_nightly-sbom-dispatch-run-id.md), [feat_security-ci-release-credentials-exposed-1498](CHANGELOG/5.30.0/feat_security-ci-release-credentials-exposed-1498.md), [feat_security-refresh-google-oauth-credentials-1435](CHANGELOG/5.30.0/feat_security-refresh-google-oauth-credentials-1435.md), [fix_ci_npm_audit_signatures](CHANGELOG/5.30.0/fix_ci_npm_audit_signatures.md))

### 📚 Documentation

- Add the [Upgrading the KMS](documentation/docs/installation/upgrading/index.md) landing page and the [Upgrading to 5.30](documentation/docs/installation/upgrading/upgrade_to_5_30.md) guide; define the per-release upgrade page convention in `docs.instructions.md`; document HSM key rotation, KMIP support, CRL and Google CSE options, cluster coordination and high availability, and the database configuration page ([#1136](https://github.com/Cosmian/kms/issues/1136), [#1226](https://github.com/Cosmian/kms/issues/1226))

## [5.29.0] - 2026-10-28

Summary release entry. Every item names the archived branch files under [`CHANGELOG/5.29.0/`](CHANGELOG/5.29.0/) that hold the full detail (behaviour, options, client actions, tests).

The complete text of this entry before it was summarised is kept in [release_notes](CHANGELOG/5.29.0/release_notes.md); use it when a linked file does not cover an item.

### 🔒 Security

- Read-only attributes (`UniqueIdentifier`, `ObjectType`, dates, …) rejected on `SetAttribute` with `Read_Only_Attribute` (COSMIAN-2026-030, [#1004](https://github.com/Cosmian/kms/issues/1004), [#1259](https://github.com/Cosmian/kms/pull/1259), [refactor_attribute-edit-policy](CHANGELOG/5.29.0/refactor_attribute-edit-policy.md))
- All KMIP 2.1 read-only attributes refused on Add/Set/Modify/DeleteAttribute; algorithm policy checked from key material (COSMIAN-2026-044). **Upgrade action:** under a curve allowlist, imported PKCS#8 EC and Ed25519 keys are now curve-checked ([refactor_attribute-edit-policy](CHANGELOG/5.29.0/refactor_attribute-edit-policy.md))
- Role check and algorithm policy applied to every operation of a batched `RequestMessage` (COSMIAN-2026-047). **Audit action:** `Locate` keys the policy forbids created through a batch before the upgrade, then revoke or re-key them
- HSM unwrap/wrap now needs HSM admin rights or an explicit `Decrypt`/`Encrypt` grant (COSMIAN-2026-041, follow-up of COSMIAN-2025-009). **Upgrade action:** grant `Decrypt` on the HSM key to owners of keys wrapped by a non-KEK HSM key, and `Encrypt` to users who create, import or export keys with it ([claude_optimistic-carson-li1owh](CHANGELOG/5.29.0/claude_optimistic-carson-li1owh.md))
- Server `key_encryption_key` no longer usable as a decryption oracle through `Import`/`Register` (COSMIAN-2026-046)
- Grant checked on the selected key for bare keyset UID crypto operations (COSMIAN-2026-042)
- CRL and OCSP count only certificates issued by the CA; HSM-backed CAs supported (COSMIAN-2026-048)
- Authentication Verifier tokens of ended sessions refused via `/whoami` (COSMIAN-2026-043). **Upgrade action:** the KMS must reach `auth_verifier_url` at runtime ([feat_auth-verifier-saml-session](CHANGELOG/5.29.0/feat_auth-verifier-saml-session.md))
- Sensitive Opaque Objects and Split Keys no longer returned in plaintext with a `KeyWrappingSpecification` (COSMIAN-2026-045)
- `Get`/`Export` of a `Fresh` key no longer writes the unwrapped key back to the database (COSMIAN-2026-031)
- KMIP socket server limits, mTLS CN checks and `[aws-xks-service]` CN refusal (COSMIAN-2026-032, COSMIAN-2026-033, COSMIAN-2026-040, [fix_socket-tls-require-client-cert-1276](CHANGELOG/5.29.0/fix_socket-tls-require-client-cert-1276.md))
- JWT verified only against its own issuer's JWKS, with rotation refresh (COSMIAN-2026-034)
- Google CSE `rewrap` SSRF bypass closed (COSMIAN-2026-035)
- Bounds on batch items, PBKDF2 iterations and RSA size; `Item_Not_Found` instead of `Permission_Denied` on crypto operations (COSMIAN-2026-036, COSMIAN-2026-037)
- AWS XKS SigV4 secret masked in logs (COSMIAN-2026-038)
- KMIP-scope CORS on `/v1/crypto/*`, `/tokenize/*`, `/ui/*` and JSON content type required on `POST /kmip/2_1` (COSMIAN-2026-039)
- `PostgreSQL` `sslmode` and certificate verification enforced (COSMIAN-2026-029, [#1262](https://github.com/Cosmian/kms/pull/1262), [fix_pgsql_sslmode_enforcement](CHANGELOG/5.29.0/fix_pgsql_sslmode_enforcement.md)). **Upgrade action:** check the server accepts TLS before upgrading; add `sslrootcert` to `verify-ca` URLs or use `verify-full`

### 🚀 Features

- **Enrollment**: EST ([RFC 7030](https://www.rfc-editor.org/rfc/rfc7030)) and SCEP ([RFC 8894](https://www.rfc-editor.org/rfc/rfc8894)) endpoints, per-endpoint certificate templates, reserved `[enrollment-service]` identity, lockout and replay protection, interop tasks. **Setup action:** `ckms access-rights grant "[enrollment-service]" -i <ca cert uid> certify` (also on the CA private key; `create` with `crypto_officer_users`). FIPS builds accept only RSAES-OAEP key transport ([#1257](https://github.com/Cosmian/kms/pull/1257), [scep](CHANGELOG/5.29.0/scep.md))

#### Audit Logging

- **PostgreSQL audit backend**: alternative to the JSONL file (`--audit-postgres-url`, `--audit-instance-id`), append-only table, seal-and-reanchor on corruption, TLS options, atomic seal-and-roll, `AuditSink` interface, live CI suite ([feat_audit_postgres_backend](CHANGELOG/5.29.0/feat_audit_postgres_backend.md))
- **CLI and logs**: `ckms audit export`/`verify` read PostgreSQL chains, flag fixes; client address read from the rightmost untrusted `X-Forwarded-For` entry; reorganized Audit & SIEM docs; no audit migration needed from 5.28.0 ([#1189](https://github.com/Cosmian/kms/pull/1189), [feat_audit_postgres_cli](CHANGELOG/5.29.0/feat_audit_postgres_cli.md))

- **OpenPGP**: `ckms pgp` command group (non-FIPS), Web UI section with WASM bindings, RFC 9580 subkey checks, OpenSSL RSA operations, `gnupg-card` key discovery, GnuPG interop matrix ([#1240](https://github.com/Cosmian/kms/pull/1240), [feat_kmip_pgp](CHANGELOG/5.29.0/feat_kmip_pgp.md))

- **SAML SSO**: Authentication Verifier SAML realm (`auth_verifier_saml_realm`), SSO and Logout buttons, `_ea_` session cookie accepted with strict startup checks, `test:ui-saml` task ([#1252](https://github.com/Cosmian/kms/pull/1252), [feat_auth-verifier-saml-session](CHANGELOG/5.29.0/feat_auth-verifier-saml-session.md))

#### HSM

- **HSM backends**: Thales Luna and Azure Cloud HSM support, Kubernetes HSM guides and Helm `command` value ([#1275](https://github.com/Cosmian/kms/pull/1275), [#1281](https://github.com/Cosmian/kms/pull/1281), [#1211](https://github.com/Cosmian/kms/pull/1211), [support_luna_hsm](CHANGELOG/5.29.0/support_luna_hsm.md), [azure_dedicated_hsm](CHANGELOG/5.29.0/azure_dedicated_hsm.md), [kubernetes_hsm](CHANGELOG/5.29.0/kubernetes_hsm.md))
- **Delegation**: RSA-PSS, EC, ECDSA, EdDSA signing and RSA `SignatureVerify` delegated to the HSM, MAC, PKCS#11 v3.0 message sign/verify, `ckms bench --hsm` ([#1154](https://github.com/Cosmian/kms/issues/1154), [#1157](https://github.com/Cosmian/kms/issues/1157), [#1263](https://github.com/Cosmian/kms/pull/1263), [#1340](https://github.com/Cosmian/kms/pull/1340), [hsm_delegation](CHANGELOG/5.29.0/hsm_delegation.md), [hsm_delegation_benchs](CHANGELOG/5.29.0/hsm_delegation_benchs.md))
- **Key encryption key**: `key_encryption_key_wrapping_algorithm`, AES-KW/KWP with HSM wrapping keys, startup wrap check ([#1341](https://github.com/Cosmian/kms/pull/1341), [fix_ai-routing-test-servers-gcm-wrap](CHANGELOG/5.29.0/fix_ai-routing-test-servers-gcm-wrap.md))

- **PKCS#11 v3.x**: interface discovery, `C_LoginUser`, profiles, EdDSA message signing, `C_Verify*`, RSA modulus bits ([#1166](https://github.com/Cosmian/kms/pull/1166), [pkcs11_v3](CHANGELOG/5.29.0/pkcs11_v3.md), [pkcs11_v3_rollout](CHANGELOG/5.29.0/pkcs11_v3_rollout.md))

- **CSR generation and HSM CAs**: `POST /certificates/csr`, `ckms certificates generate-csr` and UI page (optional key pair creation), certificates/CRLs/OCSP signed by HSM-held issuer keys, `_serial=<HEX>` system tag added at first start ([#1328](https://github.com/Cosmian/kms/pull/1328), [fix_csr_gen](CHANGELOG/5.29.0/fix_csr_gen.md))

- **JOSE with HSM keys**: RSA-OAEP CEK unwrap through the HSM, public-only RSA import, `cek_kid` in `POST /v1/crypto/encrypt` ([#1338](https://github.com/Cosmian/kms/pull/1338), [feat_jose_and_hsm](CHANGELOG/5.29.0/feat_jose_and_hsm.md))

- **Alpine**: signed `.apk` packages for `cosmian_kms` and `ckms` (x86_64, aarch64), C++ runtime in the Docker image ([#1237](https://github.com/Cosmian/kms/pull/1237), [alpine](CHANGELOG/5.29.0/alpine.md))

- **KMIP**: real RNG reported by `Query`, single attribute edit policy table, `Certify` over KMIP 1.x ([#1335](https://github.com/Cosmian/kms/pull/1335), [refactor_attribute-edit-policy](CHANGELOG/5.29.0/refactor_attribute-edit-policy.md))

- **KEM and curves**: FIPS indicator checks for ML-KEM, ML-DSA, SLH-DSA and hybrid KEM, `RNGSeed` zero entropy credit, non-FIPS `secp192k1` ([#1253](https://github.com/Cosmian/kms/pull/1253), [fix_reuse_kms_rng](CHANGELOG/5.29.0/fix_reuse_kms_rng.md))

### 🐛 Bug Fixes

- **Hybrid KEM**: keys work with an HSM `key_encryption_key`, import/export of `X25519MLKEM768`, `X448MLKEM1024`, `ConfigurableKEM` fixed, usage masks kept ([#1330](https://github.com/Cosmian/kms/pull/1330), [#1268](https://github.com/Cosmian/kms/pull/1268), [fix_hybrid_kem_hsm_lifecycle](CHANGELOG/5.29.0/fix_hybrid_kem_hsm_lifecycle.md), [fix_hybrid_kem_public_key_import](CHANGELOG/5.29.0/fix_hybrid_kem_public_key_import.md))

#### HSM

- **HSM**: Luna `Encrypt` and AES-GCM fixes, capability-driven key dates, delegated signing fixes, session bounds, FIPS AES-GCM IV generated in the HSM, sensitive HSM keys refused on wrapped export, SHA-1 RSA refused on the pre-hashed path in FIPS ([#1169](https://github.com/Cosmian/kms/pull/1169), [#1338](https://github.com/Cosmian/kms/pull/1338), [#1341](https://github.com/Cosmian/kms/pull/1341), [hsm_delegation_benchs_delegated](CHANGELOG/5.29.0/hsm_delegation_benchs_delegated.md), [claude_optimistic-carson-li1owh](CHANGELOG/5.29.0/claude_optimistic-carson-li1owh.md))

- **PKCS#11**: OIDC token PIN cap raised, secp256k1 OID and EdDSA key types, per-session locking, `CKR_BUFFER_TOO_SMALL` handling ([pkcs11_v3_rollout](CHANGELOG/5.29.0/pkcs11_v3_rollout.md))

- **Crypto**: tampered signatures return `Invalid`, deterministic P-256 ECDSA via OpenSSL, AES-GCM unwrap with 128/192-bit KEKs ([#1183](https://github.com/Cosmian/kms/issues/1183), [#1320](https://github.com/Cosmian/kms/pull/1320), [#1341](https://github.com/Cosmian/kms/pull/1341), [hsm_delegation](CHANGELOG/5.29.0/hsm_delegation.md))

- **PKI**: OCSP answers for sub-CAs, CRL regeneration as issuer owner, EC CAs sign with the curve-matching digest. **Upgrade note:** P-384/P-521 CAs now sign with SHA-384/SHA-512 ([#1328](https://github.com/Cosmian/kms/pull/1328), [fix_csr_gen](CHANGELOG/5.29.0/fix_csr_gen.md))

- **Web UI**: PQC, FPE, Anonymize, Covercrypt and OpenPGP hidden in FIPS mode, read-only attributes removed from attribute forms ([refactor_attribute-edit-policy](CHANGELOG/5.29.0/refactor_attribute-edit-policy.md))

- **KMIP**: uniform KEM `Encrypt` response (`Data` carries the tuple), `RNGSeed` limited to Crypto Officers, `Read_Only_Attribute` (0x1D) from `AddAttribute`, ID Placeholder in batched `Certify`. **Upgrade action:** clients unpack KEM `Data` and accept 0x1D ([#1330](https://github.com/Cosmian/kms/pull/1330), [refactor_attribute-edit-policy](CHANGELOG/5.29.0/refactor_attribute-edit-policy.md))

- **REST**: JSON-object protected headers, `text/plain` error responses with `nosniff`, Azure EKM `KeyDisabled`, JWKS `use`/`alg` derived from usage masks, public RSA import. **Upgrade action:** select RSA JWKs by `kid`; omit `kid` when generating keys ([#1338](https://github.com/Cosmian/kms/pull/1338), [feat_jose_and_hsm](CHANGELOG/5.29.0/feat_jose_and_hsm.md))

- **Redis/Findex**: concurrent `Upsert` and stale tag index fixed with a two-phase Lua script (Redis Cluster unsupported), cache invalidation, `crls` cleanup ([#940](https://github.com/Cosmian/kms/issues/940), [#1258](https://github.com/Cosmian/kms/pull/1258), [fix_issue_940_repro](CHANGELOG/5.29.0/fix_issue_940_repro.md))

- **CLI**: bench and `ec sign` fixes; `--cryptographic-algorithm`/`--cryptographic-length` removed from attribute commands and `--authenticated-additional-data` from export ([#1341](https://github.com/Cosmian/kms/pull/1341), [refactor_attribute-edit-policy](CHANGELOG/5.29.0/refactor_attribute-edit-policy.md))

- **Hardening**: KMIP socket client certificate required at handshake, constant-time XKS and MAC comparisons, no hex data in logs, `KmsRng` for all randomness, startup warnings, `CKA_EXTRACTABLE` follows `sensitive` (regenerate existing keys), `/v1/crypto` audited, CSI `objectVersion` enforced ([#1276](https://github.com/Cosmian/kms/issues/1276), [#1278](https://github.com/Cosmian/kms/pull/1278), [#1339](https://github.com/Cosmian/kms/pull/1339), [#1274](https://github.com/Cosmian/kms/pull/1274), [fix_socket-tls-require-client-cert-1276](CHANGELOG/5.29.0/fix_socket-tls-require-client-cert-1276.md), [fix_reuse_kms_rng](CHANGELOG/5.29.0/fix_reuse_kms_rng.md), [hsm_delegation_benchs_delegated](CHANGELOG/5.29.0/hsm_delegation_benchs_delegated.md))

### ♻️ Refactor

- **Refactor**: fewer per-request allocations, dead-code and dependency cleanup, grouped `HsmCapabilities` flags (custom HSM providers must adapt), shared helpers across server, HSM, KMIP, SQL and CLI ([#1280](https://github.com/Cosmian/kms/pull/1280), [#1267](https://github.com/Cosmian/kms/pull/1267), [#1260](https://github.com/Cosmian/kms/pull/1260), [#1340](https://github.com/Cosmian/kms/pull/1340), [#1341](https://github.com/Cosmian/kms/pull/1341), [rust_reduce_allocs](CHANGELOG/5.29.0/rust_reduce_allocs.md), [rust_cleanup](CHANGELOG/5.29.0/rust_cleanup.md), [hsm_delegation_benchs_delegated](CHANGELOG/5.29.0/hsm_delegation_benchs_delegated.md), [refactor_attribute-edit-policy](CHANGELOG/5.29.0/refactor_attribute-edit-policy.md))

### 🧪 Testing

- **Testing**: hybrid KEM, PostgreSQL TLS, PKCS#11 v3.x conformance, HSM, EST/SCEP interop and JOSE-HSM suites; Luna, AWS, GCP and Azure Cloud HSM validated manually only ([#1298](https://github.com/Cosmian/kms/pull/1298), [#1338](https://github.com/Cosmian/kms/pull/1338), [#1340](https://github.com/Cosmian/kms/pull/1340), [#1341](https://github.com/Cosmian/kms/pull/1341), [fix_hybrid_kem_hsm_lifecycle](CHANGELOG/5.29.0/fix_hybrid_kem_hsm_lifecycle.md), [pkcs11_v3](CHANGELOG/5.29.0/pkcs11_v3.md), [scep](CHANGELOG/5.29.0/scep.md), [fix_ai-routing-test-servers-gcm-wrap](CHANGELOG/5.29.0/fix_ai-routing-test-servers-gcm-wrap.md))

### ⚙️ Build

- **Build**: Dependabot bumps, `rustls`, supply-chain pinning (`cargo-vet`, `pip-audit`, `govulncheck`), Alpine musl Nix builds, FIPS provider built from CMVP-validated OpenSSL 3.1.2, `unsafe-libyaml` dropped (server no longer accepts `.yaml`/`.yml` config) ([#1289](https://github.com/Cosmian/kms/pull/1289), [#1297](https://github.com/Cosmian/kms/pull/1297), [#1327](https://github.com/Cosmian/kms/pull/1327), [#1255](https://github.com/Cosmian/kms/pull/1255), [#1253](https://github.com/Cosmian/kms/pull/1253), [#1273](https://github.com/Cosmian/kms/pull/1273), [#1269](https://github.com/Cosmian/kms/pull/1269), [#1338](https://github.com/Cosmian/kms/pull/1338), [fix_ci](CHANGELOG/5.29.0/fix_ci.md), [vet](CHANGELOG/5.29.0/vet.md), [chore_drop_unsafe_libyaml](CHANGELOG/5.29.0/chore_drop_unsafe_libyaml.md), [alpine](CHANGELOG/5.29.0/alpine.md))

### ⚙️ CI

- **CI**: pinned runners, actions and installers, collapsed package-test matrices, new vet/audit jobs, hosted-runner reruns via `/ci-fix` ([#1338](https://github.com/Cosmian/kms/pull/1338), [#1341](https://github.com/Cosmian/kms/pull/1341), [fix_ci](CHANGELOG/5.29.0/fix_ci.md), [vet](CHANGELOG/5.29.0/vet.md))

### 📚 Documentation

- **Documentation**: PKCS#11 v3.x, Alpine, Luna and Kubernetes HSM, EST/SCEP, PostgreSQL `sslmode`, Redis single-node, Azure EKM trust directions, NIST SP 800-227 for KEMs, ADRs, HSM benchmark reports, SPIRE `KeyManager` only ([#1323](https://github.com/Cosmian/kms/pull/1323), [#1253](https://github.com/Cosmian/kms/pull/1253), [#1335](https://github.com/Cosmian/kms/pull/1335), [fix_ekmImproveDocs](CHANGELOG/5.29.0/fix_ekmImproveDocs.md), [kubernetes_hsm](CHANGELOG/5.29.0/kubernetes_hsm.md), [hsm_delegation_benchs](CHANGELOG/5.29.0/hsm_delegation_benchs.md), [support_luna_hsm](CHANGELOG/5.29.0/support_luna_hsm.md))

## [5.28.0] - 2026-09-30

Summary release entry. Every item names the archived branch files under [`CHANGELOG/5.28.0/`](CHANGELOG/5.28.0/) that hold the full detail.

The complete text of this entry before it was summarised is kept in [release_notes](CHANGELOG/5.28.0/release_notes.md); use it when a linked file does not cover an item.

### 🔒 Security

- `Extractable` / `NeverExtractable` not enforced on key export paths ([GHSA-8mmx-f92q-2gq8](https://github.com/Cosmian/kms/security/advisories/GHSA-8mmx-f92q-2gq8), [#1198](https://github.com/Cosmian/kms/pull/1198))
- Reserved UID `*` bypassable via `AtomicOperation::Upsert` and `Certify` destination overwrite ([GHSA-pvw2-jxwc-95xq](https://github.com/Cosmian/kms/security/advisories/GHSA-pvw2-jxwc-95xq), [#1198](https://github.com/Cosmian/kms/pull/1198))
- `Sensitive` / `Extractable` attribute stripping via read-only `Get` grant ([GHSA-c75c-3cmm-48h7](https://github.com/Cosmian/kms/security/advisories/GHSA-c75c-3cmm-48h7), [#1198](https://github.com/Cosmian/kms/pull/1198))
- SPIRE PKI `sign-intermediate` issued CA certificates to any Vault token (COSMIAN-2026-022, [#1234](https://github.com/Cosmian/kms/pull/1234)). **Upgrade action:** `ckms access-rights grant spire:<AppRole name> certify --object-uid <ca-private-key-uid>`; see [claude_wonderful-ptolemy-7u14sz](CHANGELOG/5.28.0/claude_wonderful-ptolemy-7u14sz.md)
- SPIRE transit key substitution via shared tags (COSMIAN-2026-023, [#1234](https://github.com/Cosmian/kms/pull/1234))
- Any user could publish a key on the unauthenticated JWKS endpoint (COSMIAN-2026-024, [#1234](https://github.com/Cosmian/kms/pull/1234))
- JOSE tag endpoints allowed tag changes with any grant (COSMIAN-2026-025, [#1234](https://github.com/Cosmian/kms/pull/1234))
- PKCS#11 module buffer overflows in `C_GetAttributeValue` and `C_Encrypt` (COSMIAN-2026-026, [#1234](https://github.com/Cosmian/kms/pull/1234))
- CRL/OCSP revocation status could be lost, stale or wrong (COSMIAN-2026-027, [#1234](https://github.com/Cosmian/kms/pull/1234))
- SSRF check bypass via `kms_public_url` prefix match in CRL fetching (COSMIAN-2026-028, [#1234](https://github.com/Cosmian/kms/pull/1234))
- Asymmetric `DeriveKey` curve validation hardened against Ed25519/X25519 type confusion ([#1170](https://github.com/Cosmian/kms/pull/1170), see [x25519_ecdh](CHANGELOG/5.28.0/x25519_ecdh.md))
- Unmaintained/unsound transitive dependencies removed: `smol-toml` ([CVE-2026-85730](https://github.com/advisories/GHSA-7w5x-hrqm-74c2)), `axum-server` ([RUSTSEC-2025-0134](https://rustsec.org/advisories/RUSTSEC-2025-0134), [#1180](https://github.com/Cosmian/kms/pull/1180)), `rustls`, `kube`

### 🚀 Features

#### Audit Logging & SIEM Export

- **Audit log**: tamper-evident hash-chained JSONL log of every KMIP operation, per-batch-item events, `ckms audit verify`, CEF serialization, drop detection, trusted-proxy CIDRs, failure mode, always-start recovery, size cap ([#934](https://github.com/Cosmian/kms/pull/934), [#1126](https://github.com/Cosmian/kms/pull/1126)); detail in [feat_audit_and_siem](CHANGELOG/5.28.0/feat_audit_and_siem.md), [feat_audit_integration](CHANGELOG/5.28.0/feat_audit_integration.md), [feat_audit_startup](CHANGELOG/5.28.0/feat_audit_startup.md)

#### SPIFFE / Workload Identity

- **JWT-SVID**: opt-in SPIFFE JWT-SVID authentication, `ckms login spire`, `POST /ui/login_svid`, wizard support ([#1206](https://github.com/Cosmian/kms/pull/1206)); [support_JWT-SVID_auth](CHANGELOG/5.28.0/support_JWT-SVID_auth.md)

#### X25519 ECDH

- **X25519 DeriveKey**: non-FIPS X25519 key agreement in `DeriveKey`, `ckms derive-key --x25519`, WASM export and Web UI method ([#1170](https://github.com/Cosmian/kms/pull/1170)); [x25519_ecdh](CHANGELOG/5.28.0/x25519_ecdh.md), [x25519_ecdh_ui](CHANGELOG/5.28.0/x25519_ecdh_ui.md)

#### JOSE / REST Crypto API

- **ECDH-ES**: ECDH-ES decrypt on `/v1/crypto/decrypt`, `ECDH-ES*` key creation, X25519 keys in JWKS, Concat KDF primitive ([#1033](https://github.com/Cosmian/kms/issues/1033)); [x25519_ecdh_ui_jose](CHANGELOG/5.28.0/x25519_ecdh_ui_jose.md)

#### Database TDE Integrations

- **SAP ASE and IBM Db2 LUW TDE** via `cosmian_pkcs11` and the IBM GSKit KMIP client ([#1162](https://github.com/Cosmian/kms/pull/1162)); [feat_kmip-tde-sybase-db2](CHANGELOG/5.28.0/feat_kmip-tde-sybase-db2.md)

### 🐛 Bug Fixes

- **Database**: PostgreSQL `kms.keys.active.count` metric fixed, Redis TLS (`rediss://`), `(tag, id)` and JSON-expression indexes, faster `Locate`-by-tags ([#1203](https://github.com/Cosmian/kms/pull/1203), [#1195](https://github.com/Cosmian/kms/pull/1195), [#1204](https://github.com/Cosmian/kms/pull/1204), [#1224](https://github.com/Cosmian/kms/pull/1224)); [db_backend_fixes](CHANGELOG/5.28.0/db_backend_fixes.md), [fix_postgresql](CHANGELOG/5.28.0/fix_postgresql.md)
- **Permissions / Access Control**: wildcard-user `*` grants included in `GET /access/obtained` and `Locate`, Redis permission/object mispairing fixed ([#1188](https://github.com/Cosmian/kms/pull/1188)); [test_shared-resource-races](CHANGELOG/5.28.0/test_shared-resource-races.md)
- **Cache**: cross-node cache invalidation with bounded revalidation ([#1199](https://github.com/Cosmian/kms/pull/1199))
- **JOSE**: JWKS no longer publishes `KeyAgreement` EC keys with a signature `use`/`alg`

### ♻️ Refactor

- Audit middleware and single-writer store, audit hashing/CEF helpers, SQL `Locate` query builder, `DeriveKey` identifier fields widened, `concat_kdf` and `ecdh_key_agreement` primitives.

### 🧪 Testing

- SIEM/audit/CEF/monitoring suites, SAP ASE and Db2 TDE suites, X25519/ECDH-ES vectors, SPIFFE JWT-SVID end-to-end, access-control regressions, shared-DB coverage, `mise test` runs every task ([#1115](https://github.com/Cosmian/kms/pull/1115), [#1150](https://github.com/Cosmian/kms/pull/1150), [#1131](https://github.com/Cosmian/kms/pull/1131), [#1162](https://github.com/Cosmian/kms/pull/1162), [#1188](https://github.com/Cosmian/kms/pull/1188)); [test_shared-resource-races](CHANGELOG/5.28.0/test_shared-resource-races.md)

### ⚙️ Build

- Windows installers signed with Azure Trusted Signing, `VERSIONINFO` resources, pnpm/Node setup, UI dependency bumps, SIEM compat tests in `test_all.yml` ([#1101](https://github.com/Cosmian/kms/pull/1101), [#1229](https://github.com/Cosmian/kms/pull/1229), [#1197](https://github.com/Cosmian/kms/pull/1197), [#1163](https://github.com/Cosmian/kms/pull/1163), [#1185](https://github.com/Cosmian/kms/pull/1185), [#1230](https://github.com/Cosmian/kms/pull/1230), [#1231](https://github.com/Cosmian/kms/pull/1231)); [feat_azure-code-signing](CHANGELOG/5.28.0/feat_azure-code-signing.md)

### 📚 Documentation

- Audit-logging, CEF and SIEM references with ADRs, SAP ASE / Db2 TDE guides ([#1162](https://github.com/Cosmian/kms/pull/1162)), SPIFFE and X25519 guides, observability docs reorganized, Windows signing trust model.

## [5.27.1] - 2026-09-08

Summary release entry. Every item names the archived branch files under [`CHANGELOG/5.27.1/`](CHANGELOG/5.27.1/) that hold the full detail.

The complete text of this entry before it was summarised is kept in [release_notes](CHANGELOG/5.27.1/release_notes.md); use it when a linked file does not cover an item.

### ⚡ Performance & Internal Optimizations

- **HSM & PKCS#11 Layer**: long-lived per-slot PKCS#11 session pooling, blocking PKCS#11 FFI calls moved to `spawn_blocking`, redundant key-metadata lookups removed, concurrent-sign scaling regression test; see the branch files below.
- **AWS XKS Authorization** ([#1107](https://github.com/Cosmian/kms/pull/1107), [#1093](https://github.com/Cosmian/kms/issues/1093)): key usage no longer restricted to the creator principal, XKS operations run under a reserved KMS service identity (least privilege, `awsPrincipalArn` kept for audit only, legacy keys migrated), reserved-identity collisions rejected, `ReKey` rejected on `aws-xks`-tagged keys, startup warning when `crypto_officer.users` is empty: [fix_xks-proxy-acl-1093](CHANGELOG/5.27.1/fix_xks-proxy-acl-1093.md), [fix_xks_permissions](CHANGELOG/5.27.1/fix_xks_permissions.md)
- **OCSP**: `GET /ocsp/{base64url-DER}` accepts padded and unpadded base64url input (no more spurious 422).

### 🧪 Testing

- AWS XKS remote-server CI test ([#1114](https://github.com/Cosmian/kms/pull/1114)); Proteccio and Crypt2Pay HSM backends enabled in CI ([#1175](https://github.com/Cosmian/kms/pull/1175)).

### ⚙️ Build

- Fix `build/wasm` MISE task when `ui/src/wasm` is missing ([#1174](https://github.com/Cosmian/kms/pull/1174)); bump `pnpm/action-setup` to 6.1.0 ([#1176](https://github.com/Cosmian/kms/pull/1176)).

### 📚 Documentation

- XKS key lifecycle management is an operator responsibility exercised by a Crypto Officer; never give the reserved XKS identity a real credential: [fix_xks-proxy-acl-1093](CHANGELOG/5.27.1/fix_xks-proxy-acl-1093.md).

## [5.27.0] - 2026-09-05

Summary release entry. Every item names the archived branch files under [`CHANGELOG/5.27.0/`](CHANGELOG/5.27.0/) that hold the full detail.

The complete text of this entry before it was summarised is kept in [release_notes](CHANGELOG/5.27.0/release_notes.md); use it when a linked file does not cover an item.

### 🔒 Security

- SSRF via attacker-controlled CRL Distribution Points in KMIP `Validate`/`Import` (COSMIAN-2026-021, [GHSA-rwc8-xwm6-52xc](https://github.com/Cosmian/kms/security/advisories/GHSA-rwc8-xwm6-52xc), [#987](https://github.com/Cosmian/kms/pull/987))
- `Get` grant on wildcard uid `*` bypassed the Create/Import authorization gate (COSMIAN-2026-020, [#909](https://github.com/Cosmian/kms/issues/909), [#1151](https://github.com/Cosmian/kms/pull/1151))

### 🚀 Features

- **PKI — CRL & OCSP**: automatic `crlDistributionPoints` in issued certificates, CRL generation (`GET /certificates/{issuer_id}/crl`, `ckms certificates generate-crl`, Web UI), public cached CRL endpoint, OCSP responder (`GET /ocsp/...`, `POST /ocsp/`, `[ocsp]` section), `Validate` catches compromised self-signed roots, PQC export as Raw, extra revocation reason codes ([#987](https://github.com/Cosmian/kms/pull/987), [#1164](https://github.com/Cosmian/kms/pull/1164)): [ocsp](CHANGELOG/5.27.0/ocsp.md)
- **Split-Key Ceremony & Two-Role RBAC**: `Operator`/`CryptoOfficer` roles replace `privileged_users`, `CreateSplitKey`/`JoinSplitKey` (XOR n-of-n), Crypto Officer self/peer revocation, matching CLI and Web UI ([#991](https://github.com/Cosmian/kms/pull/991), [#1146](https://github.com/Cosmian/kms/pull/1146)): [feat_split_key](CHANGELOG/5.27.0/feat_split_key.md)
- **Web UI Internationalization**: English / Simplified Chinese / French locales, algorithm names untranslated, `localeRegistry.ts` ([#1113](https://github.com/Cosmian/kms/pull/1113), [#1124](https://github.com/Cosmian/kms/pull/1124), [#1119](https://github.com/Cosmian/kms/pull/1119)): [feat_ui-i18n-zh](CHANGELOG/5.27.0/feat_ui-i18n-zh.md), [feat_french_kms](CHANGELOG/5.27.0/feat_french_kms.md)
- **Authentication**: multiple login methods in the Web UI with ordered `auth_methods` ([#1117](https://github.com/Cosmian/kms/pull/1117)), `ckms login approle`, `ckms login cosmian` with `CosmianAuth` middleware and `/ui/login_as`, BFF rework of the OIDC flow (`/ui/token` renamed `/ui/whoami`): [feat_auth-server-integration](CHANGELOG/5.27.0/feat_auth-server-integration.md)

### 🐛 Bug Fixes

- **PKI / CRL**: CRL freshness enforced, unverifiable HTTP(S) CRLs rejected, revocation reason persisted, `file://` CRL DP handling, KMIP 1.4 `RevocationReason` deserialization, monotonic CRL Number, `cRLSign` enforced, MySQL empty-table panic ([#987](https://github.com/Cosmian/kms/pull/987)): [ocsp](CHANGELOG/5.27.0/ocsp.md)
- **OCSP Responder**: STRIDE-A hardening (batch cap, cache, delegated signer checks), issuer-hash algorithm, nonce handling, `nonce_policy = required` response, serial-number leading zeros ([#1164](https://github.com/Cosmian/kms/pull/1164)): [ocsp](CHANGELOG/5.27.0/ocsp.md)
- **PKCS#11 / OpenSSH**: backend fallback when a `CKA_ID` private key is not in the in-memory store ([#1111](https://github.com/Cosmian/kms/issues/1111), [#1076](https://github.com/Cosmian/kms/issues/1076), [#1112](https://github.com/Cosmian/kms/pull/1112)): [fix_openssh_cannot_find_private_key](CHANGELOG/5.27.0/fix_openssh_cannot_find_private_key.md)
- **Database**: PostgreSQL pool connections released before retry back-off, single-connection pool startup deadlock, SQLSTATE preserved in retry detection ([#1027](https://github.com/Cosmian/kms/issues/1027), [#1152](https://github.com/Cosmian/kms/pull/1152)): [fix_lot_of_fixes](CHANGELOG/5.27.0/fix_lot_of_fixes.md)
- **Web UI / CORS**: `kms_public_url` added to the CORS allow-list by default ([#987](https://github.com/Cosmian/kms/pull/987)): [fix_put_kms_public_url_in_allowed_cors_by_default](CHANGELOG/5.27.0/fix_put_kms_public_url_in_allowed_cors_by_default.md)
- **Docker / Nix packaging**: `grep` added to Docker images ([#1132](https://github.com/Cosmian/kms/issues/1132)), `fakeRootCommands` permission fix ([#1133](https://github.com/Cosmian/kms/pull/1133)): [fix_k8s-kms-pod-ci-test](CHANGELOG/5.27.0/fix_k8s-kms-pod-ci-test.md)

### 🧪 Testing

- CRL/OCSP lifecycle and RFC 5280 suites with black-box `test:ocsp` / `test:pki-revocation` in CI, split-key/RBAC vector, CLI and Playwright tests, PQC Raw export round-trips ([#987](https://github.com/Cosmian/kms/pull/987), [#991](https://github.com/Cosmian/kms/pull/991), [#1164](https://github.com/Cosmian/kms/pull/1164)): [ocsp](CHANGELOG/5.27.0/ocsp.md), [feat_split_key](CHANGELOG/5.27.0/feat_split_key.md)

### ♻️ Refactor

- `crate/crypto` depends on `foreign-types` directly, manual CRL Authority Key Identifier (no SHA-1 fallback), shared `verify_cosmian_jwt_subject()` ([#987](https://github.com/Cosmian/kms/pull/987)): [ocsp](CHANGELOG/5.27.0/ocsp.md), [feat_auth-server-integration](CHANGELOG/5.27.0/feat_auth-server-integration.md)

### ⚙️ Build

- Bump the `authentication` submodule; Windows CI `vcpkg`/Ninja lookup fix ([#991](https://github.com/Cosmian/kms/pull/991)): [feat_auth-server-integration](CHANGELOG/5.27.0/feat_auth-server-integration.md), [feat_split_key](CHANGELOG/5.27.0/feat_split_key.md)

### 📚 Documentation

- PKI CRL/OCSP docs and runbook, Delta CRLs listed as unsupported ([#1164](https://github.com/Cosmian/kms/pull/1164), [#987](https://github.com/Cosmian/kms/pull/987)), key ceremony guide and authorization reference ([#991](https://github.com/Cosmian/kms/pull/991)), Cosmian-auth login test plan, four-layer test rule in `rust.instructions.md`: [ocsp](CHANGELOG/5.27.0/ocsp.md), [feat_split_key](CHANGELOG/5.27.0/feat_split_key.md), [feat_auth-server-integration](CHANGELOG/5.27.0/feat_auth-server-integration.md)

## [5.26.0] - 2026-08-07

Summary release entry. Every item names the archived branch files under [`CHANGELOG/5.26.0/`](CHANGELOG/5.26.0/) that hold the full detail.

The complete text of this entry before it was summarised is kept in [release_notes](CHANGELOG/5.26.0/release_notes.md); use it when a linked file does not cover an item.

### 🔒 Security

- Resolve 8 Dependabot security alerts ([#1083](https://github.com/Cosmian/kms/pull/1083), [fix_dependabot-alerts-2026-07-31](CHANGELOG/5.26.0/fix_dependabot-alerts-2026-07-31.md), [cve](CHANGELOG/5.26.0/cve.md))
- Upgrade `opentelemetry_sdk` 0.29.0 → 0.32.1: SSRF via malicious OTLP endpoint, [GHSA-r74r-p7x6-m97p](https://github.com/advisories/GHSA-r74r-p7x6-m97p), plus React dependency updates ([#1073](https://github.com/Cosmian/kms/pull/1073))
- `AlwaysSensitive` is server-managed: client add/set/modify/delete is rejected with `Attribute_Read_Only` ([#1103](https://github.com/Cosmian/kms/pull/1103))
- Read-only KMIP attributes ("Modifiable by client: No") can no longer be rewritten via `ModifyAttribute`; non-deletable ones are rejected by `DeleteAttribute` ([#1103](https://github.com/Cosmian/kms/pull/1103))

### 🚀 Features

- **SPIRE / Workload Identity**: KMS as Vault-compatible backend for SPIRE `upstream_ca` (PKI sign-intermediate, Transit, AppRole/Kubernetes auth), multi-tenant trust domains, `X-Vault-Token` accepted on all endpoints when `vault_api_enabled = true`, Transit and PKI routes, `ckms vault approle` subcommands, `/v1/auth/*` proxy to the auth-verifier ([#1075](https://github.com/Cosmian/kms/pull/1075), [spire](CHANGELOG/5.26.0/spire.md))
- **Kubernetes / Helm**: KMS v2 provider plugin for etcd secrets, Secrets Store CSI provider, operator with admission webhook and inject mode, Helm chart ([#999](https://github.com/Cosmian/kms/pull/999), [#1048](https://github.com/Cosmian/kms/pull/1048), [feat_k8s-kms-plugin](CHANGELOG/5.26.0/feat_k8s-kms-plugin.md), [feat_helm-chart-k8s-deployment](CHANGELOG/5.26.0/feat_helm-chart-k8s-deployment.md))
- **KMIP**: `AlwaysSensitive` attribute (KMIP 2.1 §4.3), KMIP 1.x attribute version gating (fixes parse failures in Synology DSM, PyKMIP, Percona), `Never Extractable` serialized in 1.x responses ([#1103](https://github.com/Cosmian/kms/pull/1103), [feat_support_alwayssensitive_kmip_attr](CHANGELOG/5.26.0/feat_support_alwayssensitive_kmip_attr.md))
- **Authentication Verifier integration**: login/password with TOTP 2FA (Web UI and `ckms login`), `X-Vault-Token` (AppRole, Kubernetes, Token) ([#1013](https://github.com/Cosmian/kms/pull/1013), [feat_auth-server-integration](CHANGELOG/5.26.0/feat_auth-server-integration.md), [test_plan_cosmian-auth-ui-login](CHANGELOG/5.26.0/test_plan_cosmian-auth-ui-login.md), [test_plan_oidc-session-auth](CHANGELOG/5.26.0/test_plan_oidc-session-auth.md))
- **Other**: richer SBOM metadata ([#1102](https://github.com/Cosmian/kms/pull/1102))

### 🐛 Bug Fixes

- **KMIP Conformance**: `Lease Time` and `RNG Parameters.Cryptographic Length` TTLV types, `DeleteAttribute` response and by-name deletion, `Comment` returned by `GetAttributes` ([#1103](https://github.com/Cosmian/kms/pull/1103), [feat_support_alwayssensitive_kmip_attr](CHANGELOG/5.26.0/feat_support_alwayssensitive_kmip_attr.md))
- **Server & Infrastructure**: OpenSSH authentication (PKCS#11 `C_SignInit` class-aware `CKA_ID`), ckms retry on stale pooled connections, busybox removed from Docker image, mdBook build, AWS XKS update, strict configuration parsing rejecting unknown fields, Nix Rust toolchain upgrade ([#1091](https://github.com/Cosmian/kms/pull/1091), [#1061](https://github.com/Cosmian/kms/pull/1061), [#1099](https://github.com/Cosmian/kms/pull/1099), [#1095](https://github.com/Cosmian/kms/pull/1095), [#1065](https://github.com/Cosmian/kms/pull/1065), [#1053](https://github.com/Cosmian/kms/pull/1053), [#1057](https://github.com/Cosmian/kms/pull/1057), [fix_openssh](CHANGELOG/5.26.0/fix_openssh.md), [fix_stale_connections_in_ckms](CHANGELOG/5.26.0/fix_stale_connections_in_ckms.md))

### 🧪 Testing

- SPIRE PKI capability scenarios and Go-based KMIP 1.0–1.4 compliance tests ([#1110](https://github.com/Cosmian/kms/pull/1110), [#1103](https://github.com/Cosmian/kms/pull/1103), [spire](CHANGELOG/5.26.0/spire.md))

### ⚙️ Build

- lychee replaces linkcheck, CI action bumps ([#1106](https://github.com/Cosmian/kms/pull/1106))

### 📚 Documentation

- mdBook overhaul, TLS wizard, PostgreSQL failover and standby docs, server README cleanup ([#1095](https://github.com/Cosmian/kms/pull/1095), [#1062](https://github.com/Cosmian/kms/pull/1062))

## [5.25.0] - 2026-07-09

Summary release entry. Every item names the archived branch files under [`CHANGELOG/5.25.0/`](CHANGELOG/5.25.0/) that hold the full detail.

The complete text of this entry before it was summarised is kept in [release_notes](CHANGELOG/5.25.0/release_notes.md); use it when a linked file does not cover an item.

### 🚀 Features

- **Key Rotation**: KMIP `ReKey`, `ReKeyKeyPair` and `ReCertify`, keyset resolution (`name@latest`, `name@first`, `name@N`) with try-each-key decryption, state-based key selection and auto-deactivation, HSM keysets, `--keyset-warn-depth`, `ckms` re-key and rotation-policy subcommands, Web UI **Rotation Policy** section ([#968](https://github.com/Cosmian/kms/pull/968)); [feat_key-rotation-ckms-ui](CHANGELOG/5.25.0/feat_key-rotation-ckms-ui.md), [feat_automate_key_rotation](CHANGELOG/5.25.0/feat_automate_key_rotation.md)
- **Auto-rotation Scheduler**: due keys re-keyed automatically (HSM-resident keys skipped), renewal warnings at 30/7/1 days, `kms.key.auto_rotation` OpenTelemetry counter ([#970](https://github.com/Cosmian/kms/pull/970)); [feat_automate_key_rotation](CHANGELOG/5.25.0/feat_automate_key_rotation.md)
- **JWKS Endpoint**: unauthenticated `GET /.well-known/jwks.json` public-key discovery (RFC 7517) with ETag caching, off by default (`--jwks-endpoint-enabled`); [feat_jwks_endpoint](CHANGELOG/5.25.0/feat_jwks_endpoint.md)
- **Performance**: in-memory object cache and JOSE CEK cache, binary TTLV serializer, configurable unwrapped-cache size and HTTP workers, SQLite/PostgreSQL tuning, `ckms bench` ([#1016](https://github.com/Cosmian/kms/pull/1016), [#1020](https://github.com/Cosmian/kms/pull/1020)); [feat_perf](CHANGELOG/5.25.0/feat_perf.md), [perf](CHANGELOG/5.25.0/perf.md)
- **Web UI / Search Objects**: Locate table gains algorithm/length columns, sorting on all columns and larger pagination ([#968](https://github.com/Cosmian/kms/pull/968)); [feat_sort_on_KMIP](CHANGELOG/5.25.0/feat_sort_on_KMIP.md)

### 🐛 Bug Fixes

- **Database**: missing PostgreSQL/MySQL indexes added, PostgreSQL connection recycling and retry logging after failover ([#1039](https://github.com/Cosmian/kms/pull/1039)); [fix_psql_failover_retry](CHANGELOG/5.25.0/fix_psql_failover_retry.md), [fix_migration](CHANGELOG/5.25.0/fix_migration.md)
- **KMIP / Key Rotation**: `ReKeyKeyPair` usage mask in FIPS mode, HSM self-wrap recursion, object lifecycle date transitions ([#968](https://github.com/Cosmian/kms/pull/968)); [feat_automate_key_rotation](CHANGELOG/5.25.0/feat_automate_key_rotation.md)
- **Web UI**: Date column and sorter units, Certificate Issuance option 3 calls `ReCertify` ([#968](https://github.com/Cosmian/kms/pull/968)); [feat_sort_on_KMIP](CHANGELOG/5.25.0/feat_sort_on_KMIP.md)
- **WASM**: build fixed by upgrading to `cosmian_logger 0.7.2` ([#1020](https://github.com/Cosmian/kms/pull/1020)); [develop](CHANGELOG/5.25.0/develop.md)

### 📚 Documentation

- Key auto-rotation spec ([#968](https://github.com/Cosmian/kms/pull/968)), JWKS endpoint guide, object-cache reference ([#1016](https://github.com/Cosmian/kms/pull/1016)), per-component log reference; [docs_key-autorotation-spec](CHANGELOG/5.25.0/docs_key-autorotation-spec.md), [feat_loggingExtendedDocumentation](CHANGELOG/5.25.0/feat_loggingExtendedDocumentation.md)

### ⚙️ CI / Build

- Test script port fixes, Windows tests on pull requests only, `rerun-if-env-changed=CFLAGS` ([#1016](https://github.com/Cosmian/kms/pull/1016)), `log-index-check` job; [ci_tests](CHANGELOG/5.25.0/ci_tests.md)

## [5.24.0] - 2026-06-18

Summary release entry. Every item names the archived branch files under [`CHANGELOG/5.24.0/`](CHANGELOG/5.24.0/) that hold the full detail.

The complete text of this entry before it was summarised is kept in [release_notes](CHANGELOG/5.24.0/release_notes.md); use it when a linked file does not cover an item.

### 🔒 Security

- Upgrade `mysql_async` 0.36→0.37 to remove `proc-macro-error2` (RUSTSEC-2026-0173) (COSMIAN-2026-019) — [fix_RUSTSEC-2026-0173](CHANGELOG/5.24.0/fix_RUSTSEC-2026-0173.md)

### 🚀 Features

- **JOSE / REST Crypto API**: JWK import via `POST /v1/crypto/keys` (oct, EC, RSA, OKP), `POST /v1/crypto/keys/unwrap` for RSA-OAEP CEK unwrapping, `SignatureVerify` on private keys, longer HMAC keys ([#979](https://github.com/Cosmian/kms/pull/979)); [fix_jwe_import_wrapped_key](CHANGELOG/5.24.0/fix_jwe_import_wrapped_key.md)
- **OpenTelemetry Metrics**: 9 new OTLP metrics (database, HTTP, connections, objects, keys, cache, HSM), O(1) Redis counters with cron sync, `OtelHttpMetrics` middleware ([#975](https://github.com/Cosmian/kms/pull/975)); [feat_richOTELmetrics](CHANGELOG/5.24.0/feat_richOTELmetrics.md)
- **Windows / CNG KSP / Intune**: Service Control Manager integration, `Export-IntunePrivateKey` / `Import-IntunePrivateKey`, `ckms cng verify` and `ckms pkcs11 verify`, dynamic `vendor_identification` via KMIP `Query`, default key usages, installer and logging fixes ([#924](https://github.com/Cosmian/kms/pull/924), [#1011](https://github.com/Cosmian/kms/pull/1011)); [intune](CHANGELOG/5.24.0/intune.md), [fix_windows_installers](CHANGELOG/5.24.0/fix_windows_installers.md)
- **CKMS CLI**: `hyper + hyper-openssl` replaces `reqwest` (PQC TLS, ML-DSA-44), IANA TLS 1.2 cipher-suite translation, `ckms activate` subcommand, `ckms fpe` commands ([#1015](https://github.com/Cosmian/kms/pull/1015)); [refactor_compactify](CHANGELOG/5.24.0/refactor_compactify.md), [feature_fpe-kmip](CHANGELOG/5.24.0/feature_fpe-kmip.md), [feat_implement_fpe](CHANGELOG/5.24.0/feat_implement_fpe.md)
- **PKCS#11 / VeraCrypt**: symmetric keys tagged `disk-encryption` exposed as `CKO_DATA` objects, tag retrieval fix in `batch_get`; [veracrypt](CHANGELOG/5.24.0/veracrypt.md)
- **EDB PostgreSQL TDE**: integration with `pykmip` and `thales` KMIP variants; [feat_edb_tde](CHANGELOG/5.24.0/feat_edb_tde.md)
- **Server Configuration**: CPU hardware-acceleration flags logged at startup ([#963](https://github.com/Cosmian/kms/pull/963)), `secret://` URIs for config secrets ([#932](https://github.com/Cosmian/kms/pull/932)); [feat_openssl_cpu_features](CHANGELOG/5.24.0/feat_openssl_cpu_features.md)

### 🐛 Bug Fixes

- **VAST Data / KMIP 1.4**: `GetAttributes` no longer drops vendor attributes, `AddAttribute(OperationPolicyName)` stored and returned, KMIP 1.x vendor attributes overwritable; [fix_vast_reg](CHANGELOG/5.24.0/fix_vast_reg.md)
- **CKMS CLI**: cipher-suite translation, `raw-dylib` BCrypt link ([#1015](https://github.com/Cosmian/kms/pull/1015)); [fix_windows_installers](CHANGELOG/5.24.0/fix_windows_installers.md)
- **HSM**: `C_Finalize` no longer forwarded to the real HSM library, avoiding `CKR_DEVICE_REMOVED` ([#924](https://github.com/Cosmian/kms/pull/924)); [intune](CHANGELOG/5.24.0/intune.md)
- **KMIP / XML**: TTLV XML deserializer and response-comparison fixes, vector runner for MariaDB/Percona; [chore_kmip_submodule](CHANGELOG/5.24.0/chore_kmip_submodule.md)

### ♻️ Refactor

- Shared `ActivateKeyAction`, shared CLI encrypt/decrypt/wrap/derive/HTTP helpers, ~9,100 LOC of duplicate tests removed, unified KMIP XML 1.4/2.1 test infrastructure: [refactor_compactify](CHANGELOG/5.24.0/refactor_compactify.md), [refactor_phase2](CHANGELOG/5.24.0/refactor_phase2.md), [refactor_delete_duplicated_clap_tests](CHANGELOG/5.24.0/refactor_delete_duplicated_clap_tests.md), [chore_kmip_submodule](CHANGELOG/5.24.0/chore_kmip_submodule.md)

### 🧪 Testing

- FPE and anonymization Playwright E2E, FortiGate KMIP 1.0 vectors ([#824](https://github.com/Cosmian/kms/issues/824)), JOSE interoperability with `jwcrypto`, EDB TDE vectors, InterSystems IRIS mTLS ([#965](https://github.com/Cosmian/kms/pull/965)), VeraCrypt PKCS#11, CNG KSP end-to-end, lifecycle tests ported to the `ckms` binary: [feat_implement_fpe](CHANGELOG/5.24.0/feat_implement_fpe.md), [test_fortigate_locate_with_name](CHANGELOG/5.24.0/test_fortigate_locate_with_name.md), [test_jose_interoperability](CHANGELOG/5.24.0/test_jose_interoperability.md), [feat_edb_tde](CHANGELOG/5.24.0/feat_edb_tde.md), [veracrypt](CHANGELOG/5.24.0/veracrypt.md), [ci_build](CHANGELOG/5.24.0/ci_build.md)

### ⚙️ Build

- MISE task runner adoption ([#1001](https://github.com/Cosmian/kms/pull/1001)), `rust-overlay` pinned, Nix `.crate` unpacking fix, CI SSM name collision fix ([#1015](https://github.com/Cosmian/kms/pull/1015)), `test-cng-ksp` job ([#924](https://github.com/Cosmian/kms/pull/924)), vite bump ([#1012](https://github.com/Cosmian/kms/pull/1012)): [chore_mise_adoption](CHANGELOG/5.24.0/chore_mise_adoption.md), [ci_build](CHANGELOG/5.24.0/ci_build.md)

### 📚 Documentation

- EDB TDE, InterSystems IRIS ([#965](https://github.com/Cosmian/kms/pull/965)) and data anonymization guides, Intune PFX workflow and CNG KSP diagrams, JOSE docs regrouped, VAST Data update, tokenize endpoints in OpenAPI ([#907](https://github.com/Cosmian/kms/pull/907)), secret-backends docs fixes ([#1017](https://github.com/Cosmian/kms/pull/1017)): [feat_edb_tde](CHANGELOG/5.24.0/feat_edb_tde.md), [feat_implement_fpe](CHANGELOG/5.24.0/feat_implement_fpe.md), [feature_fpe-kmip](CHANGELOG/5.24.0/feature_fpe-kmip.md), [intune](CHANGELOG/5.24.0/intune.md)

## [5.23.0] - 2026-06-05

Summary release entry. Every item names the archived branch files under [`CHANGELOG/5.23.0/`](CHANGELOG/5.23.0/) that hold the full detail; this entry is a follow-up to the 2026-05-25 entry below and its items come from release commits, not from branch files.

The complete text of this entry before it was summarised is kept in [release_notes](CHANGELOG/5.23.0/release_notes.md); use it when a linked file does not cover an item.

### 🚀 Features

- **FPE and anonymization**: FPE support and anonymization endpoints (#907)
- **Integrations**: Intune (#924)
- **JOSE/JWE**: endpoints to import wrapped keys and JOSE keys (#977, #979)
- **Packaging and startup**: `cosmian_kms` and `ckms` added to PATH, OpenSSL CPU hardware-acceleration flags displayed at startup (#963)

### 🐛 Bug Fixes

- **Logging**: server logging defaults to `/var/log`, then to none

### ♻️ Refactor

- Remove duplicated clap tests in favor of `ckms` tests (#972)

### 🧪 Testing

- FortiGate tests (#976), JOSE interoperability tests with jwcrypto (#984)

### ⚙️ Build

- Merge release/5.23.0 into develop, bump vitest (#978)

### ⚙️ Miscellaneous Tasks

- Dedicated git submodule for KMIP specs (#980), `queue:max` concurrency argument

## [5.23.0] - 2026-05-25

Summary release entry. Every item names the archived branch files under [`CHANGELOG/5.23.0/`](CHANGELOG/5.23.0/) that hold the full detail.

The complete text of this entry before it was summarised is kept in [release_notes](CHANGELOG/5.23.0/release_notes.md); use it when a linked file does not cover an item.

### 🔒 Security

- **COSMIAN-2026-016**: KEK wrapping bypass via attribute operations and `Activate` ([#960](https://github.com/Cosmian/kms/issues/960))
- **COSMIAN-2026-015**: KEK plaintext leak via UsageLimits in decrypt/sign ([#959](https://github.com/Cosmian/kms/pull/959))
- **Attribute-mutation authorization bypass**: attribute operations now require their own permission ([#959](https://github.com/Cosmian/kms/pull/959))
- **HSM key permissions hardening**: admin-only Destroy, Locate/`/access/owned` filtering ([#942](https://github.com/Cosmian/kms/pull/942))
- **COSMIAN-2026-017 / COSMIAN-2026-018**: `ReKey` and `Activate` check ownership and permission
- **ReKey / ReKeyKeyPair**: honour `privileged_users` Create gating
- **GPL dependency removal**: `actix-governor` replaced by `governor` ([#967](https://github.com/Cosmian/kms/pull/967))

### 🚀 Features

- **REST Crypto API (JOSE/JWE)**: `/v1/crypto` encrypt, decrypt, sign, verify, MAC and key management, typed JOSE algorithm enums ([#868](https://github.com/Cosmian/kms/issues/868)), [feat_crypto_JWE_api](CHANGELOG/5.23.0/feat_crypto_JWE_api.md)
- **Multi-HSM**: `[[hsm_instances]]`, prefix routing, `GET /hsm/status`, Web UI HSM Status page, HSM keys sensitive by default ([#942](https://github.com/Cosmian/kms/pull/942)), [feat_multi_hsm_support](CHANGELOG/5.23.0/feat_multi_hsm_support.md)
- **PQC X.509 Certificates**: `Certify` with ML-DSA, SLH-DSA, ML-KEM (RFC 9881/9909/9935/9608) ([#943](https://github.com/Cosmian/kms/pull/943)), [feat_pqc_x509_certificates](CHANGELOG/5.23.0/feat_pqc_x509_certificates.md)
- **ReKeyKeyPair**: KMIP §6.1.47 for RSA, EC, Ed25519, X25519 and PQC, KMIP 1.4 support ([#845](https://github.com/Cosmian/kms/issues/845)), [vast_rekey](CHANGELOG/5.23.0/vast_rekey.md)
- **OpenAPI / Swagger UI**: `/openapi.yaml` and local `/swagger` ([openapi](CHANGELOG/5.23.0/openapi.md))
- **Rebranding**: Cosmian to Eviden in Web UI and docs ([feat_rebrand-ui-and-docs](CHANGELOG/5.23.0/feat_rebrand-ui-and-docs.md))

### 🐛 Bug Fixes

- **VAST Data / KMIP 1.x**: `Invalid_Message` fixes, RFC 3394 default wrap, `DerivationParameters` deserialization, `ReKey` creates a new UID ([#845](https://github.com/Cosmian/kms/issues/845)), [vast](CHANGELOG/5.23.0/vast.md), [vast_rekey](CHANGELOG/5.23.0/vast_rekey.md)
- **Google CSE**: token audience validation, KACLS migration, JWKS refresh retry, `wrapprivatekey` registered ([#947](https://github.com/Cosmian/kms/issues/947)), [fix_cse_token_validation](CHANGELOG/5.23.0/fix_cse_token_validation.md)
- **Multi-HSM**: longest-prefix routing, `Get`/`Export` equivalence, `/access/obtained` join ([#942](https://github.com/Cosmian/kms/pull/942)), [feat_multi_hsm_support](CHANGELOG/5.23.0/feat_multi_hsm_support.md)
- **Certificates / WASM**: `noRevAvail` OID, WASM empty strings, `certificatePolicies` with CPS qualifiers ([fix_openssl_certificate_policies](CHANGELOG/5.23.0/fix_openssl_certificate_policies.md))
- **Misc**: ECDSA verify on corrupted signature, dynamic access-grant operation list, `KmipOperation` serialisation ([#959](https://github.com/Cosmian/kms/pull/959)), `Activate` lifecycle error, OpenAPI spec fixes, test temp-dir collisions
- **UI Encryption**: plain-text server errors ([#966](https://github.com/Cosmian/kms/issues/966)), WASM capacity overflow on large files, 30 MB upload limit ([#967](https://github.com/Cosmian/kms/pull/967)), [fix_ui-encryption-error-display](CHANGELOG/5.23.0/fix_ui-encryption-error-display.md)

### ♻️ Refactor

- Shared macros, lifecycle helpers, `CryptoOpSpec` trait and Web UI `useActionState` hook, about 3 000 lines removed ([#959](https://github.com/Cosmian/kms/pull/959)), [refactor_reduce_loc](CHANGELOG/5.23.0/refactor_reduce_loc.md)

### 🧪 Testing

- KMIP regression vectors, KAT vectors, Certify/PQC, HSM authorization, JOSE and swagger E2E tests ([#953](https://github.com/Cosmian/kms/pull/953), [#942](https://github.com/Cosmian/kms/pull/942), [#929](https://github.com/Cosmian/kms/pull/929), [#845](https://github.com/Cosmian/kms/issues/845)), [test_regression_vectors](CHANGELOG/5.23.0/test_regression_vectors.md)

### ⚙️ CI

- Oracle TDE standalone scripts ([#918](https://github.com/Cosmian/kms/pull/918)), `jose` CI test type ([#929](https://github.com/Cosmian/kms/pull/929)), SBOM license generation ([#967](https://github.com/Cosmian/kms/pull/967)), [ci-oracle-tde](CHANGELOG/5.23.0/ci-oracle-tde.md)

### 📚 Documentation

- JOSE API, multi-HSM, PKI, VAST Data, OpenAPI pages, JOSE audit report, authorization and `TESTS.md` ([#868](https://github.com/Cosmian/kms/issues/868), [#942](https://github.com/Cosmian/kms/pull/942), [#943](https://github.com/Cosmian/kms/pull/943), [#845](https://github.com/Cosmian/kms/issues/845), [#929](https://github.com/Cosmian/kms/pull/929), [#959](https://github.com/Cosmian/kms/pull/959)), [openapi](CHANGELOG/5.23.0/openapi.md), [vast](CHANGELOG/5.23.0/vast.md)

## [5.22.1] - 2026-10-25

### 🔒 Security

- Fix the RUSTSEC advisories published since 5.22.0: `h2` (RUSTSEC-2026-0258, via `actix-web` 4.17), `tokio` (RUSTSEC-2026-0386), `lru` 0.18 (RUSTSEC-2026-0253), `tokio-postgres`/`postgres-protocol` (RUSTSEC-2026-0178/0179/0180, with `aes-kw` 0.3.1), `quick-xml` 0.42 (RUSTSEC-2026-0194/0195) and `mysql_async` 0.37 without the `derive` feature (RUSTSEC-2026-0173)
- Ignore RUSTSEC-2026-0387 (`crypto-bigint` 0.5.5, no 0.5.x patch) in `deny.toml` and `.cargo/audit.toml`, with its reason

### 🐛 Bug Fixes

#### Hybrid KEM keys with an HSM key encryption key ([#1329](https://github.com/Cosmian/kms/pull/1329))

- Hybrid KEM keys (`ConfigurableKEM` and native `X25519MLKEM768` / `X448MLKEM1024`) now work when the server `key_encryption_key` is stored in an HSM: `ckms pqc keys create -a ml-kem-768-p256` no longer fails with `Unsupported key format type: ConfigurableKEMSecretKey`
- Wrap: `ByteString`-only `Raw`, `ConfigurableKEM*` and `CoverCrypt*` asymmetric keys are wrapped as raw bytes instead of going through OpenSSL (Create, Import, Export with a `KeyWrappingSpecification`)
- Unwrap: `ConfigurableKEM*` keys are decoded on unwrap (Encrypt/Decrypt after a restart, `default_unwrap_type`, Export/Import with `NotWrapped`)
- Unwrapping with a KMS wrapping key now works when that wrapping key is itself wrapped (for example by the HSM KEK): it is unwrapped first and its stored usage mask is checked, as already done when wrapping
- Export: a PQC/hybrid KEM key can be exported with its own stored `KeyFormatType`
- TTLV: `ConfigurableKEM*` key material can be deserialized from TTLV, so TTLV-wrapped keys (`ckms keys export --wrap-key-id ... -f json-ttlv`, then import) can be unwrapped and used
- Backport of [#1268](https://github.com/Cosmian/kms/pull/1268): import and export skip the OpenSSL round-trip for `ConfigurableKEM` and native hybrid KEM keys

#### ConfigurableKEM usage rules and algorithm policy ([#1329](https://github.com/Cosmian/kms/pull/1329))

- `ConfigurableKEM` hybrid keys (ML-KEM + P-256/X25519) follow least privilege and the KMIP usage-mask rules: a requested `CryptographicUsageMask` is kept as is instead of being OR-ed with `Unrestricted`; without one, the private key gets `Decrypt` and the public key `Encrypt`. `ckms pqc keys create` no longer requests `Unrestricted`, and existing keys keep their mask
- Per-key `PrivateKeyAttributes`/`PublicKeyAttributes` inherit the `CommonAttributes` (tags, curve, ML-KEM variant) instead of replacing them
- KEM `Encrypt` (ML-KEM, native hybrid, `ConfigurableKEM`) rejects non-empty `Data` instead of silently ignoring it
- Algorithm policy: a `ConfigurableKEM` key is checked on every use, not only at creation, against both its ML-KEM variant and its curve, read from the serialized key rather than from its KMIP attributes, so an imported key with relabelled or stripped attributes cannot bypass the policy. `X25519MLKEM768` and `X448MLKEM1024` are in the policy scope and in the `DEFAULT` allowlist (non-FIPS), where they were previously always denied
- `ckms bench`: the configurable KEM decapsulation benchmark decapsulates the encapsulation component of the packed result instead of the whole tuple

### 🧪 Testing

- Add a SoftHSM2-backed hybrid KEM lifecycle test, TTLV-wrapped import tests (export wrapped by a software AES key, and client-side wrap by the HSM KEK), a wrap/unwrap unit test for `ByteString`-only KEM keys and a TTLV round-trip test for `ConfigurableKEM*` key values
- Add `ConfigurableKEM` server tests (usage masks, encapsulation round trip, plaintext and `Sign` refusal, `Locate`, revocation, policy on use including relabelled and stripped imports); they also pin the `Encrypt` response layout, unchanged since 5.22.0: the serialized `(shared secret, encapsulation)` tuple in `Data` and an empty `IVCounterNonce`. `ckms pqc` KEM tests now compare the decapsulated secret with the encapsulated one
- Fix the stale `test_toml` snapshot (`rate_limit_per_second`, `otlp_allow_insecure`) in `crate/server/src/main.rs`

### ⚙️ Build

- Bump the workspace version to 5.22.1 and pin the internal path dependencies with `=5.22.1`, so that `cargo publish --dry-run` verifies the local 5.22.1 crates instead of newer 5.2x releases already on crates.io (a caret requirement matched them, and `cosmian_kms_crypto` 5.25.0 does not compile against `openssl` 0.10.79)

## [5.22.0] - 2026-05-06

Summary release entry. Every item names the archived branch files under [`CHANGELOG/5.22.0/`](CHANGELOG/5.22.0/) that hold the full detail.

The complete text of this entry before it was summarised is kept in [release_notes](CHANGELOG/5.22.0/release_notes.md); use it when a linked file does not cover an item.

### 🚀 Features

- **HSM Linux aarch64**: softhsm2, smartcardhsm and `other` model on Linux aarch64; proprietary HSMs stay x86_64-only ([#902](https://github.com/Cosmian/kms/issues/902))
- **Docker CORS defaults**: default `KMS_CORS_ALLOWED_ORIGINS` so the bundled Web UI works out-of-the-box on localhost port 9998 ([#926](https://github.com/Cosmian/kms/issues/926))

### 🔒 Security

- Integer overflow checks enabled in release profile ([#921](https://github.com/Cosmian/kms/issues/921))
- OTLP plaintext HTTP endpoints rejected by default; `--otlp-allow-insecure` for dev opt-in
- Sensitive cryptographic material removed from tracing span fields
- SECURITY.md rewritten with the 17-entry disclosure list
- Hardening VULN-01 to VULN-13 (MS DKE authentication, unwrap cache clearing, Google CSE SSRF check, session salt, Activate/Revoke TOCTOU, `/server-info` authentication, generic 5xx, `ServerParams` Debug masking, HSM Locate KEK leak) ([#928](https://github.com/Cosmian/kms/pull/928), [#935](https://github.com/Cosmian/kms/issues/935))

### 🐛 Bug Fixes

- **KMIP Interoperability**: FortiGate / KMIP 1.0–1.4 `Authentication` deserialization and `Locate` name filter ([#824](https://github.com/Cosmian/kms/issues/824), [support_fortigate](CHANGELOG/5.22.0/support_fortigate.md))
- **HSM**: `ModifyAttribute` on non-extractable HSM keys ([#933](https://github.com/Cosmian/kms/issues/933))
- **Server Concurrency & Performance**: span-across-await crash fixed with `tracing::Instrument`, AWS XKS SigV4 and PKCS#11 FFI moved to `spawn_blocking`, unwrap cache optimization, SQLite read/write connection split ([fix_span](CHANGELOG/5.22.0/fix_span.md))
- **Auth / Session**: OIDC/PKCE session cookie `SameSite=Lax`, PKCS#12 skipped in FIPS mode where unsupported ([#928](https://github.com/Cosmian/kms/pull/928))
- **Miscellaneous**: formatting, unused dev-dependency, `delete_attribute` span name

### 🧪 Testing

- Tracing-span non-regression tests, KMIP 1.2 vector for #933, integration test for #935, `test_privileged_users` race fix, KMIP doc generator fix.

### 🔧 Build

- Bump `rand` 0.10 and `actix-http` 3.12.

### ⚙️ CI

- **Crypt2Pay**: resilient CI (self-test failures, OpenVPN, connectivity, CA and port fixes) ([ci_tests_c2p](CHANGELOG/5.22.0/ci_tests_c2p.md))

## [5.21.0] - 2026-04-21

Summary release entry. Every item names the archived branch files under [`CHANGELOG/5.21.0/`](CHANGELOG/5.21.0/) that hold the full detail.

The complete text of this entry before it was summarised is kept in [release_notes](CHANGELOG/5.21.0/release_notes.md); use it when a linked file does not cover an item.

### 🚀 Features

- **PKCS#11**: `cosmian_pkcs11_verify` diagnostic binary (config and server reachability, per-class counts, OIDC/JWT token auth), Oracle TDE wallet migration support (forward and reverse, AES key-gen and CBC mechanisms, token no longer write-protected), standalone signed PKCS#11 ZIP package published to `package.cosmian.com` ([fix_improve_tde](CHANGELOG/5.21.0/fix_improve_tde.md))
- **Web UI**: formalised connection states (DEV, no server, no auth, mTLS, JWT/OIDC, JWT+mTLS), no-auth warning banner, clear mTLS login error instead of a loop ([feat_fix_auth_issues](CHANGELOG/5.21.0/feat_fix_auth_issues.md))

### 🔒 Security

Findings from the OWASP/external audits, without COSMIAN advisory ids; detail in [test_owasp](CHANGELOG/5.21.0/test_owasp.md).

- Denial-of-service limits: HTTP payload cap 10 GB to 64 MB (EXT2-1/A04-1), TTLV binary and XML depth limits of 64 (EXT2-2, EXT2-3), TTLV per-field 64 MiB guard, Locate capped at 1000 items (EXT2-4), optional rate limiting `rate_limit_per_second` (EXT2-5)
- Derived key bytes of `derive_pbkdf2`/`derive_hkdf` zeroized on drop (EXT1-1)
- Restricted CORS to `cors_allowed_origins` (A01-1/A05-1); symmetric JWT algorithms rejected (A07-1); constant-time API-token comparison (A07-2); session cookie `SameSite=Strict` (A07-4)
- Non-HTTPS JWKS URIs stop startup (A07-5); warning when `ui_session_salt` is unset (A08-2)
- Redacted DB URL passwords and TLS P12 passwords (A09-1, A09-2); 401 paths logged at `warn` (A09-3)
- No redirects followed by JWKS and OAuth HTTP clients (A10-2/A10-3); `serde_json::unbounded_depth` banned in `deny.toml` (SSDF PW.5.1)

### 🐛 Bug Fixes

- **Server / Auth**: deterministic session cookie key from the public URL (configure `ui_session_salt` for multi-instance), guard on partial server-info response ([feat_fix_auth_issues](CHANGELOG/5.21.0/feat_fix_auth_issues.md))
- **Web UI**: E2E sitemap race, dev-setup OAuth login crash, OAuth/OIDC fixes ([feat_fix_auth_issues](CHANGELOG/5.21.0/feat_fix_auth_issues.md))
- **Logging**: `HttpConfig::Display` and `ClapConfig::Debug` show the correct `http`/`https` scheme ([test_owasp](CHANGELOG/5.21.0/test_owasp.md))

### ♻️ Refactor

- CLI crates moved to `crate/clients/`, `cosmian_kms_cli` renamed `cosmian_kms_cli_actions` ([chore_move_cli_deps](CHANGELOG/5.21.0/chore_move_cli_deps.md))

### 🧪 Testing

- PKCS#11 OIDC login and wallet migration tests, KMIP wire and XML edge cases, security regression tests, CLI adversarial payloads, HSM test SIGSEGV fix ([fix_improve_tde](CHANGELOG/5.21.0/fix_improve_tde.md), [test_owasp](CHANGELOG/5.21.0/test_owasp.md))

### 🔧 CI

- Automated `release.yml` workflow, PKCS#11 build step before tests, Oracle TDE test fixes, pnpm pinned to `10.17.1`, Windows UI test fixes, `pkcs11-zip` package type, macOS Nix vendor hashes ([automate_release](CHANGELOG/5.21.0/automate_release.md))

### 📚 Documentation

- Oracle TDE / PKCS#11 guide rewritten (diagrams, env vars, OIDC auth, wallet migration) and `configuration/ui.md` connection states ([fix_improve_tde](CHANGELOG/5.21.0/fix_improve_tde.md), [feat_fix_auth_issues](CHANGELOG/5.21.0/feat_fix_auth_issues.md))

## [5.20.0] - 2026-04-03

### 🚀 Features

#### Support Veeam Backup via KMIP 1.x Protocol

- **`KmipUnexpectedTagException` when Veeam Backup decodes a `Get` response for an asymmetric key**: Cosmian KMS was embedding all object-metadata attributes (including `Link`, `UniqueIdentifier`, `State`, `Name`, etc.) inside the `KeyValue` structure of the returned key object. KMIP 1.x clients such as Veeam Backup do not expect these non-cryptographic attributes inside `KeyValue` and fail with `Unexpected Tag 66, expected Attribute`. Fixed by stripping all embedded `KeyValue` attributes for `PublicKey` and `PrivateKey` objects in KMIP 1.x `Get` responses (`perform_response_tweaks` in `routes/kmip.rs`). Cryptographic metadata (algorithm, length) is still exposed at the `KeyBlock` level.

### 📚 Documentation

- **Fix CLI authentication docs**: correct wrong field names (`ssl_client_pem_cert_path` / `ssl_client_pkcs12_path` → `tls_client_*`), add dedicated bearer/access-token section, and link each TOML example to the corresponding `test_data/configs/client/*.toml` reference file in `cli_documentation/docs/authentication.md` ([#895](https://github.com/Cosmian/kms/issues/895))
- **Reorganize storage integration docs**: move `vcenter.md`, `synology_dsm.md`, `veeam.md`, `openssh.md`, `pykmip.md`, `smime.md`, `user_defined_function_for_pyspark_databricks_in_python/`, and `disk_encryption/` from `documentation/docs/integrations/` root into the dedicated `documentation/docs/integrations/storage/` subfolder; update `mkdocs.yml`, `README.md`, `documentation/docs/index.md`, and `CLAUDE.md` accordingly ([#874](https://github.com/Cosmian/kms/pull/874))
- Align README.md with documentation/docs
- Fix refactor and dead links (#898)

### 🐛 Bug Fixes

### KMIP Socket Server

- **TLS session resumption failure with mTLS clients**: the TCP socket server (`cosmian_kms_server::socket_server`) was missing a call to `SSL_CTX_set_session_id_context`. When client certificate verification (`SSL_VERIFY_PEER`) is enabled alongside the default TLS session cache, OpenSSL requires a session ID context to be set; without it any session-resumption attempt aborts with `error:0A000115:SSL routines:ssl_get_prev_session:session id context uninitialized`. Fixed by calling `builder.set_session_id_context(b"cosmian_kms_socket")` in `create_openssl_acceptor` before building the acceptor.

### ⚙️ Miscellaneous Tasks

- Refactoring + deduplicate of the UI codebase (#737)

## [5.19.0] - 2026-04-01

Summary release entry. Every item names the archived branch files under [`CHANGELOG/5.19.0/`](CHANGELOG/5.19.0/) that hold the full detail.

The complete text of this entry before it was summarised is kept in [release_notes](CHANGELOG/5.19.0/release_notes.md); use it when a linked file does not cover an item.

### 🚀 Features

- **PostgreSQL HA**: cluster support with multi-host URLs (#818).
- **OpenSSH PKCS#11**: reliable key material refresh, correct RSA/EC public-key decoding, PKCS#11-compliant `CKA_EC_POINT`, RSA-only attributes guarded, lock-free provider internals.
- **Web UI (sync with ckms)**: DeriveKey page with WASM binding, `/server-info` endpoint and HSM info in header, `--no-ui` / `KMS_UI_ENABLE=false`, "Hyperscalers" menu group, PQC/MAC/Covercrypt entries hidden in FIPS mode ([feat_sync_ui_with_ckms](CHANGELOG/5.19.0/feat_sync_ui_with_ckms.md)).

### 🐛 Bug Fixes

- **JWT authentication**: fix worker panic on first JWT request (`jsonwebtoken` 10.x `rust_crypto` backend), fix `401` when token has `aud` but no audience is configured ([fix_jsonwebtoken](CHANGELOG/5.19.0/fix_jsonwebtoken.md)).
- **Server security and configuration**: reject client certificates with empty or `*` CN (#811); `KMS_HSM_PASSWORD` and `KMS_HSM_SLOT` env variables (#695).
- **CLI / HSM**: `destroy` type-safety pre-flight check and server-side HSM destroy type guard (#763).
- **Web UI**: create/import buttons enabled in no-auth mode (#739).

### 🔧 CI

- **CI**: test scripts protected against a system `/etc/cosmian/kms.toml` ([#810](https://github.com/Cosmian/kms/issues/810)); sbomnix pinned to v1.7.4.

### 📚 Documentation

- **Documentation**: PKCS#11 pages reintegrated with an OpenSSH entry, `CKM_RSA_AES_KEY_WRAP` invocation (#688), benchmarks CI and regression workflow ([#776](https://github.com/Cosmian/kms/issues/776)).

### 🔄 Refactor

- **Refactor**: scripts reorganized under `.github/scripts/` subdirectories; `ckms` TLS parameters and env vars renamed from `ssl_*` to `tls_*` (update scripts and configs).

### ⚙️ Build

- **Dependencies**: bumps of cosign-installer, picomatch, brace-expansion, ghaction-dump-context, actions/checkout, actions/upload-artifact (#831-#836, #865, #872, #873).

## [5.18.0] - 2026-03-25

### 🚀 Features

#### Post-Quantum Cryptography (ML-KEM + ML-DSA + SLH-DSA) ([#787](https://github.com/Cosmian/kms/pull/787))

Full support for NIST post-quantum algorithms via OpenSSL 3.x default provider
(non-FIPS builds only):

- **ML-KEM** (Key Encapsulation Mechanism): ML-KEM-512, ML-KEM-768, ML-KEM-1024 — key pair
  creation, encapsulation, and decapsulation via KMIP Encrypt/Decrypt operations
- **ML-DSA** (Digital Signature Algorithm): ML-DSA-44, ML-DSA-65, ML-DSA-87 — key pair
  creation, signing, and verification via KMIP Sign/SignatureVerify operations
- **SLH-DSA** (Supersingular Isogeny-based Hash-based DSA): SLH-DSA-SHA2-128s, SLH-DSA-SHA2-192s,
  SLH-DSA-SHA2-256s — key pair creation, signing, and verification via KMIP Sign/SignatureVerify
  operations
- New KMIP enumeration values for all six PQC algorithms
- Server dispatch for PQC key creation, encrypt/decrypt (KEM), and sign/verify
- CLI actions: `ckms pqc keys create`, `ckms pqc encapsulate`, `ckms pqc decapsulate`,
  `ckms pqc sign`, `ckms pqc verify`
- WASM bindings: `create_pqc_key_pair_ttlv_request()`, `get_pqc_algorithms()`
- Web UI pages: PQC key creation, ML-KEM encapsulate/decapsulate, ML-DSA sign/verify
- Playwright E2E tests for all PQC UI flows
- CLI integration tests for ML-KEM and ML-DSA roundtrips

#### Configurable Hybrid KEM merged into PQC ([#787](https://github.com/Cosmian/kms/pull/787))

- Merged the standalone `ckms kem` subcommand into `ckms pqc` — the four hybridized KEM
  algorithms (ml-kem-512-p256, ml-kem-768-p256, ml-kem-512-curve25519, ml-kem-768-curve25519)
  are now created, encapsulated, and decapsulated through the standard PQC workflow
- Auto-detection in encapsulate response handles both PQC and ConfigurableKEM response formats
- WASM bindings updated with the 4 hybrid algorithms
- UI branding supports `hiddenPqcAlgorithms` to hide specific algorithms from the PQC dropdown
- CLI and ckms integration tests added for configurable hybrid KEM roundtrips

#### Support of AWS Bring Your Own Key (BYOK)  ([#681](https://github.com/Cosmian/kms/pull/681))

- Introduce 2 CLI actions for AWS BYOK
- Add scripts that automate the AWS BYOK flow, available to download with the documentation

#### Oracle TDE HSM integration on Windows ([#794](https://github.com/Cosmian/kms/pull/794))

- New PowerShell scripts `test_oracle_tde.ps1` and `set_hsm.ps1` install `cosmian_pkcs11.dll`
  and run a full end-to-end Oracle TDE test on a native Windows Oracle installation (no Docker)
- Workarounds for two Oracle 26ai Windows bugs: DLL placed at `C:\opt\oracle\extapi\64\pkcs11\`
  (drive-relative Linux path) and TDE parameters injected via plain PFILE to bypass the
  `ALTER SYSTEM SET pkcs11_library_location` validator that rejects Windows paths

#### PostgreSQL HA cluster support ([#818](https://github.com/Cosmian/kms/pull/818))

PostgreSQL connections now support multi-host connection strings
(e.g. `postgresql://host1:5432,host2:5432/db?target_session_attrs=read-write`)
for automatic failover. Added retry logic with exponential backoff for transient
connection errors during failover, scheme validation for PostgreSQL URLs, and
additional retryable SQLSTATE codes (08001, 08004, 57P02, 57P03).
See the database documentation for configuration details.

#### HSM multi-admin support with wildcard ([#801](https://github.com/Cosmian/kms/pull/801))

`hsm_admin` is now a list of KMS usernames with HSM admin privileges. Use `["*"]` to grant all
authenticated users access to all HSM operations. TOML: `hsm_admin = ["alice", "bob"]`;
CLI: `--hsm-admin alice --hsm-admin bob`; env: `KMS_HSM_ADMIN=alice,bob`.

#### Migration to `jsonwebtoken` crate for JWT validation ([#790](https://github.com/Cosmian/kms/pull/790))

JWT validation: complete migration from `alcoholic_jwt` to `jsonwebtoken` in server middleware,
adding support for multiple algorithms (RS256, ES256, ...).
Update the documentation, Google CSE routes, and OIDC UI auth flow; updated Google CSE tests accordingly.

#### HMAC-SHA-1 and HMAC-SHA-224 Support ([#786](https://github.com/Cosmian/kms/issues/786)) ([#797](https://github.com/Cosmian/kms/pull/797))

NIST SP 800-131A Rev. 2 Table 7 classifies HMAC-SHA-1 and HMAC-SHA-224 as
**Acceptable** algorithms. The KMS server previously blocked them via the
algorithm policy layer. They are now fully supported.

#### Synology DSM NAS Volume Encryption Integration

Cosmian KMS is now validated against Synology DSM 7.x KMIP-based volume
encryption. A Python simulation client (`scripts/synology_dsm_client.py`)
replays the exact KMIP operation sequence performed by DSM when it configures
an external KMS server, and a corresponding CI job (`synology_dsm`) is added
to the test matrix so regressions are caught automatically:

- Simulates all 10 DSM KMIP steps: `DiscoverVersions → Query → Create (AES-256)
  → Activate → GetAttributes → ModifyAttribute → Get → Locate → Revoke → Destroy`
- New documentation page `documentation/docs/synology_dsm.md` covering server
  setup, DSM configuration, and automated CI testing
- `README.md` updated with Synology DSM in the disk encryption compatibility table

- **Synology DSM simulation (PyKMIP): fix `ModifyAttribute` step after issue [#820](https://github.com/Cosmian/kms/issues/820) server fix**:
  `KMIPProxy.send_request_payload()` returns the response *payload* object on success (not a batch
  item), so the returned object has no `result_status` field. Calling `_check_result()` on it
  always returned `False`, causing spurious cleanup (Destroy) even when the server returned
  `SUCCESS`. Fix: drop the `_check_result` call — `send_request_payload` raises
  `OperationFailure` on server errors; reaching the success path without an exception is sufficient.
  Also fixed `test_pykmip.sh` `set -e` preventing simulation output from being visible when the
  script fails. Fixes CI failure for `Test on pykmip - non-fips`. ([#799](https://github.com/Cosmian/kms/pull/799))
- **`OperationPolicyName` round-trip preservation (issue #796)**: KMIP 1.x clients (e.g. Synology
  DSM 7.2.2) include the `OperationPolicyName` attribute in Register/Create requests per the KMIP
  1.0 spec section 3.18. This attribute was deprecated in KMIP 1.3 and removed in KMIP 2.0+. The
  server now emits a `WARN` log entry (useful for tracing legacy clients in server logs) and
  preserves the value internally as a vendor attribute (`KMIP1 / __Operation Policy Name__`) so
  that a subsequent `GetAttributes` request for `"Operation Policy Name"` from the same KMIP 1.x
  client returns the expected value. Additionally, the server correctly ignores `OperationPolicyName`
  when sent via `AddAttribute` to avoid creating a duplicate entry on top of the one already stored
  during Create/Register.
  Fixes ([#796](https://github.com/Cosmian/kms/issues/796))
- **KMIP 1.x → 2.1 attribute conversion fixes**: Several KMIP 1.x attributes were incorrectly
  lost or corrupted during the KMIP 1.x → 2.1 internal conversion:
    - `X509CertificateIdentifier`, `X509CertificateIssuer`, `X509CertificateSubject`, `Digest`,
    and `Pkcs12FriendlyName` all exist in KMIP 2.1 but were being dropped with a `WARN` in the
    bulk conversion path (Create/Register), and mapped to a garbage `Comment` attribute in the
    single-attribute path (AddAttribute/SetAttribute). They are now correctly mapped to their
    KMIP 2.1 equivalents in both paths.
    - `CertificateIdentifier`, `CertificateIssuer`, and `CertificateSubject` (the non-X509 variants
    removed in KMIP 2.0+) are now preserved as `VendorAttribute(KMIP1, ...)` in both paths
    instead of being silently dropped, and are decoded back to their KMIP 1.4 types when a KMIP
    1.x client retrieves them via `GetAttributes`.
    - `StorageStatusMask` in the single-attribute path no longer corrupts the `Comment` attribute
    slot; it is preserved as a `VendorAttribute` with a `WARN`. ([#799](https://github.com/Cosmian/kms/pull/799))
- **`TransparentECPrivateKey`/`TransparentECPublicKey` → KMIP 1.4 conversion**: The
  `TryFrom<kmip_2_1::KeyFormatType> for kmip_1_4::KeyFormatType` conversion previously returned
  an error for these key format types even though KMIP 1.4 defines them with the same numeric
  values (0x14/0x15). They are now correctly converted, enabling KMIP 1.4 clients to retrieve
  EC keys whose format was stored internally by the server using the KMIP 2.1 canonical type. ([#799](https://github.com/Cosmian/kms/pull/799))
- **ModifyAttribute**: Fully implement `ModifyAttribute` operation — attribute changes are now persisted
  and ACL checks enforced; setting `ActivationDate` to a past/present date on a Pre-Active object
  now correctly transitions it to Active (KMIP spec §3.22). Fixes an incompatibility with Synology
  DSM ([#760](https://github.com/Cosmian/kms/issues/760)) ([#788](https://github.com/Cosmian/kms/pull/788))
- **Name attribute stored as VendorExtension instead of standard KMIP attribute**: Setting the `Name`
  attribute via the CLI (`ckms attributes set --name <value>`) or the web UI now correctly stores it
  as the standard KMIP `Name` attribute instead of a `VendorAttribute` (hex-encoded bytes inside
  `VendorExtension`). Fixes ([#746](https://github.com/Cosmian/kms/issues/746)) ([#795](https://github.com/Cosmian/kms/pull/795))

#### KMIP 1.0 XML Non-Regression Test Vectors ([#799](https://github.com/Cosmian/kms/pull/799))

All 84 official OASIS KMIP 1.0 XML conformance test vectors are now parsed and
validated as part of the test suite:

- `mandatory/` – 57 files (19 unique test cases × 3 minor-version variants):
  SKLC-M-1..3 (symmetric key lifecycle), SKFF-M-1..12 (symmetric key
  foundry/factory), AKLC-M-1..3 (asymmetric key lifecycle), OMOS-M-1
  (opaque managed object store)
- `optional/` – 27 files (9 unique test cases × 3 minor-version variants):
  SKLC-O-1, SKFF-O-1..6, AKLC-O-1, OMOS-O-1

As a side effect, the XML deserializer now correctly maps the `SKIPJACK`
enumeration token (`0x0000_0018`) used by `SKFF-O-1..3`, fixing a
previously-unknown parse error for those optional vectors.

#### Microsoft SQL Server External Key Management (EKM) ([#809](https://github.com/Cosmian/kms/pull/809))

- Microsoft SQL Server EKM is now available via a Windows DLL provider that forwards key operations to the Cosmian KMS over mutual TLS.

#### ckms new features

##### `ckms bench` concurrency sweep with time limits ([#816](https://github.com/Cosmian/kms/pull/816))

- **Benchmarks**: Added `scripts/run_benchmarks_load_tests_docker.sh` — Docker-based load test comparison script analogous to `run_benchmarks_docker.sh`; pulls two KMS Docker images, runs `ckms bench --load` against each, and produces a side-by-side markdown diff at `documentation/docs/benchmarks/docker/load-tests-<v1>-vs-<v2>.md`.
- `ckms bench`: added benchmarks for AES-XTS, AES-GCM-SIV, ECIES, Salsa Sealed Box, Covercrypt, and Configurable KEM (ML-KEM-512/768, hybrid variants); `run_benchmarks.sh` now injects `lscpu` output and KMS server version into `documentation/docs/benchmarks.md`
- `ckms bench`: added `--format` option (`text`/`json`); JSON mode collects criterion estimates into `target/criterion/benchmarks.json`
- `ckms bench`: criterion is now a regular dependency (not just dev-dependency)
- `ckms bench`: fixed ChaCha20-Poly1305 benchmarks — changed from `[128, 256]` to `[256]` key sizes (ChaCha20 only supports 256-bit keys)

##### PEM client certificate support in ckms arguments ([#804](https://github.com/Cosmian/kms/issues/804)) ([#829](https://github.com/Cosmian/kms/pull/829))

The `ckms configure` wizard now exposes PEM client certificate authentication in addition to
PKCS#12. Users can select "Client certificate (PEM)" or "Both (PEM cert + token)" and provide
the certificate (`.crt`/`.pem`) and private key (`.key`/`.pem`) paths separately. The
`ssl_client_pem_cert_path` and `ssl_client_pem_key_path` config fields were already supported by
the HTTP client but were not reachable through the interactive wizard.

### 🐛 Bug Fixes

- **AZURE BYOK**: Fix Azure BYOK silent error when exporting a previously wrapped key ([#685](https://github.com/Cosmian/kms/issues/685))
- Fix AWS BYOK silent when exporting a previously wrapped key. ([#681](https://github.com/Cosmian/kms/pull/681))
- **CLI**: `bench` and `markdown` subcommands are now visible in `ckms --help` ([#821](https://github.com/Cosmian/kms/issues/821)) ([#816](https://github.com/Cosmian/kms/pull/816)); both were incorrectly hidden with `#[clap(hide = true)]`.
- **CI**: Fix intermittent ckms config parse error ("missing field `http_config`") caused by a cross-process TOCTOU race when `cargo test --workspace --lib` runs multiple test binaries concurrently; config temp files now include the process ID in their name. Fixes ([#779](https://github.com/Cosmian/kms/issues/779)) ([#812](https://github.com/Cosmian/kms/pull/812))
- **CI (UI FIPS)**: Fix `ERR_OSSL_EVP_UNSUPPORTED` crash when running `nix.sh --variant fips test ui`; pnpm 9.x uses MD4 in `createBase32Hash` which is blocked by the FIPS provider loaded via `LD_PRELOAD` in the Nix shell. `test_ui.sh` now strips `LD_PRELOAD`/`OPENSSL_CONF`/`OPENSSL_MODULES` from all pnpm invocations so Node.js uses the default OpenSSL provider while Rust/cargo builds remain FIPS-mode.

#### HSM related fixes

- **HSM: CKA_ID missing on HSM-created keys**: Keys generated via the HSM PKCS#11 path were stored
  without a `CKA_ID`, making them invisible to some PKCS#11 tools. The KMS now sets `CKA_ID` at
  key creation time for all HSM backends (Proteccio, Utimaco, SoftHSM2). ([#801](https://github.com/Cosmian/kms/pull/801))
- **HSM**: HSM key lookup (`get_object_handle`) now searches by `CKA_ID` first (primary
  path for KMS-created keys) and falls back to `CKA_LABEL` for externally provisioned keys
  that may not have `CKA_ID` set; `get_object_id` follows the same order ([#801](https://github.com/Cosmian/kms/pull/801))
- **HSM**: Non-admin users can now create KMS keys wrapped by the server-level
  `key_encryption_key`; the ownership check is skipped for this shared server resource
  ([#761](https://github.com/Cosmian/kms/issues/761)) ([#801](https://github.com/Cosmian/kms/pull/801))
- **HSM/CLI**: `ckms sym keys unwrap -i hsm::<slot>::<label>` no longer fails with
  "This key is sensitive and cannot be exported from the HSM"; the unwrap is now performed
  server-side through the KMS crypto oracle so the HSM key material is never exported
  ([#762](https://github.com/Cosmian/kms/issues/762)) ([#801](https://github.com/Cosmian/kms/pull/801))
- Fix Locate for mixed HSM + software key environments
    - **Server**: `HsmStore.find()` now returns HSM keys to all authenticated users for read-only listing (previously required HSM admin), and populates basic attributes (algorithm, length, object type) from HSM metadata so Locate and `/access/owned` display key info without a separate `GetAttributes` round-trip.
    - **UI**: Locate page now correctly merges HSM keys (`hsm::` prefix) into results even when they are absent from `/access/owned`; HSM keys default to "Active" state during enrichment.
    - **UI Locate**: Fix "State: Unknown" shown for all objects when clicking "Search Objects" with no filters — state is now resolved from `/access/owned` (software keys) and defaults to "Active" for HSM keys without invoking per-object `GetAttributes`.
    - **UI E2E**: New `locate-hsm.spec.ts` Playwright integration tests run against a real SoftHSM2 KMS; `test_ui.sh` (via `nix.sh test ui`) wires up the full stack (WASM build → KMS server → SoftHSM2 token → pre-created keys → Vite preview → Playwright) on both Linux and macOS. `test_ui.sh` now requires `softhsm2-util` to be installed and errors out with a clear message if it is missing. ([#822](https://github.com/Cosmian/kms/pull/822))

### ⚙️ Build

- *(deps)* Bump pnpm/action-setup from 4 to 5 ([#800](https://github.com/Cosmian/kms/pull/800))
- *(deps)* Bump rustls-webpki in the cargo group across 1 directory ([#815](https://github.com/Cosmian/kms/pull/815))

### 🧪 Testing

- Create integration tests for AWS KMS BYOK using OpenSSL to unwrap locally and mock the AWS infrastructure ([#681](https://github.com/Cosmian/kms/pull/681))

### 📚 Documentation

- Documentation for AWS BYOK on docs.cosmian ([#681](https://github.com/Cosmian/kms/pull/681))

## [5.17.0] - 2026-03-13

### 🚀 Features

#### AWS External Key Store (XKS) v2

Cosmian KMS can now act as an **AWS XKS proxy** ([#644](https://github.com/Cosmian/kms/pull/644)),
enabling transparent integration with AWS KMS External Key Store:

- Implements the full XKS Proxy API — a single endpoint that gives AWS KMS live-proxy coverage
  for all XKS-capable services (S3, EBS, RDS, DynamoDB, Secrets Manager, and more)
- AWS SigV4 request authentication middleware
- XKS endpoints: health status, key metadata retrieval, encrypt, decrypt
- New `--xks-*` server configuration flags
- New `documentation/docs/aws/xks.md` guide

#### Azure External Key Manager (EKM) v0.1-preview

Cosmian KMS now implements the **Azure EKM proxy API v0.1-preview**
([#601](https://github.com/Cosmian/kms/pull/601)):

- Endpoints: info, key metadata, Wrap, Unwrap — faithful to the Azure EKM specification
- mTLS (mutual TLS) authentication
- New `--azure-ekm-*` server configuration flags
- Flexible versioning structure for future API versions
- New `documentation/docs/azure/ekm/ekm.md` guide

#### CLI (`ckms`) moved into this repository

The `cosmian` CLI (previously maintained in a separate `cli` repository) is now co-located
in this repository under `crate/clients/ckms/`:

- The `ckms` binary and its full test suite are now built and tested from this repo
- CLI documentation moved into `cli_documentation/` with its own MkDocs configuration
- Findex server references removed from the CLI documentation and configuration examples
- Nix packaging extended: `nix/cli.nix` and `nix/common.nix` added for building and
  distributing the CLI as a standalone DEB, RPM, and DMG package
- Hardcoded system tag strings (e.g. `"_sk"`, `"_pk"`) replaced with `SYSTEM_TAG_*`
  constants from `cosmian_kmip::kmip_2_1::extra::tagging`
- WASM and UI test scripts hardened against pnpm major-version mismatches between the
  system pnpm and the nix-shell pnpm
- add `--header`/`-H` flag and `custom_headers` config option to forward arbitrary HTTP headers with every request, enabling use behind zero-trust proxies such as Cloudflare Access ([#138](https://github.com/Cosmian/cli/issues/138))

#### HSM signing via Crypto Oracles

- KMIP `Sign` operation is now delegated to HSM Crypto Oracles via PKCS#11 `C_SignInit`/`C_Sign` ([#771](https://github.com/Cosmian/kms/pull/771))

#### White labeling

- The vendor identification string used in KMIP `VendorAttribute` operations is now
  configurable via `--vendor-identification` (env: `KMS_VENDOR_IDENTIFICATION`, default:
  `"cosmian"`); reported back by `QueryServerInformation` responses (#758)
- The WASM module exposes `set_vendor_id(id)` and `query_server_information_ttlv_request()`
  so the UI can synchronize its vendor ID with the server at startup
- New `loginCardColor` field in `branding.json` to control the login card background color
- New blank starter theme at `ui/public/themes/blank/` with SVG placeholder assets

#### Server configure wizard

- New `cosmian_kms configure` interactive wizard to generate a server configuration file (`kms.toml`) and self-signed TLS certificates from the command line

### 🐛 Bug Fixes

- **Signing key**: Fix corrupted GPG public key (`cosmian-kms-public.asc`) that caused CRC
  errors on import with GnuPG ([#785](https://github.com/Cosmian/kms/issues/785))
- **CI**: Fix GCP CMEK FIPS test timeout — strip `LD_PRELOAD`/`LD_LIBRARY_PATH` from `curl`
  in `wait_for_kms` to prevent the FIPS bootstrap shim from breaking HTTP probes
- *(ui)* Add Content-Security-Policy against clickjacking attack (#768)
- Unwrap cache: internalize fingerprint check and seed SipHash (#778)
- Fail KMIP operation when multiple keys are found to process the operation (#771)
- Systemd mitigations (#711)
- **CLI**: `ckms` is now installed to `/usr/local/bin/` instead of `/usr/sbin/`, making it accessible to non-root users without requiring elevated privileges ([cli#136](https://github.com/Cosmian/cli/issues/136))
- **CLI**: FIPS-compliant CLI builds are now published alongside non-FIPS builds ([cli#134](https://github.com/Cosmian/cli/issues/134))
- **Security**: KMIP `Import` with `replace_existing=true` now verifies the caller owns the
  existing object before overwriting it ([#644](https://github.com/Cosmian/kms/pull/644))
- **Packaging**: DEB and RPM removal scripts now clean up `/usr/sbin/cosmian_kms` and
  `/usr/local/cosmian/` on uninstall
- **macOS build**: retry loop in `nix/scripts/package_dmg.sh` handles intermittent
  `hdiutil: create failed - Resource busy` CI errors
- KMIP `Encrypt` and `Sign` now fail with a clear error when multiple eligible keys match the identifier, preventing silent key substitution ([#771](https://github.com/Cosmian/kms/pull/771))

### ⚙️ Build

- Linux packages: README now installed as `README.md` (was `README` — not rendered as
  markdown by package managers)
- `pnpm` version pinned to 10 in `build_ui.sh`
- CI: mirror nixpkgs archives on `package.cosmian.com` with GitHub fallback to avoid 502 errors
- *(deps)* Bump actions/upload-artifact from 6 to 7 (#740)
- *(deps)* Bump actions/download-artifact from 7 to 8 (#741)
- *(deps)* Bump crazy-max/ghaction-import-gpg from 6 to 7 (#747)
- *(deps)* Bump actions/setup-node from 4 to 6 (#755)
- *(deps)* Bump actions/upload-artifact from 4 to 7 (#756)
- *(deps)* Bump docker/login-action from 3 to 4 (#759)
- *(deps)* Bump docker/metadata-action from 5 to 6 (#765)
- *(deps)* Bump docker/setup-buildx-action from 3 to 4 (#766)
- *(deps)* Bump sigstore/cosign-installer from 4.0.0 to 4.1.0 (#774)

### 🧪 Testing

- Add End-to-End (E2E) tests on UI (in browser-tests) (#736)
- Re-enable hsm Proteccio tests (#781)

### 🔒 Security

- **UI** `ajv` updated 6.12.6 → 6.14.0 (vulnerability fix)
- **UI** `minimatch` overridden to `>=10.2.1` (ReDoS CVE)
- **Rust**`lru` 0.14.0 (transitive via `mysql_async 0.36.1`): RUSTSEC-2026-0002 acknowledged in
  `deny.toml` — no upstream fix available yet; severity low (CVSS 2.7)

### 📚 Documentation

- New `openssl_override.md`: how to point Cosmian KMS to a custom OpenSSL build using a
  systemd drop-in override
- New Azure EKM guide (`documentation/docs/azure/ekm/ekm.md`)
- New AWS XKS guide (`documentation/docs/aws/xks.md`)
- HSM operations: added `pkcs11-tool` key creation examples and label uniqueness constraint warning
- UI branding: `loginCardColor` field reference and blank theme usage
- README: new `🔗 Integrations` section covering cloud providers (AWS/Azure/GCP), databases, and HSMs
- Add HAProxy+KeepAlived example

## [5.16.2] - 2026-02-22

### 🐛 Bug Fixes

- [OpenTelemetry] Deduplicate OpenTelemetry export metric (Revoke and Destroy operations) ([#717](https://github.com/Cosmian/kms/pull/717))
- Debug impl of ServerParams was misleading a algorithms restriction ([#719](https://github.com/Cosmian/kms/pull/719))
- Fix non-FIPS `openssl.cnf` provider configuration: the FIPS provider was incorrectly
  activated in non-FIPS builds via `nix/openssl.nix` that now generates
  distinct provider configurations per build variant: FIPS builds use `fips+base`, non-FIPS
  builds use `default+legacy+base`.

### ⚙️ Build

- Refactor OpenSSL provider management into a dedicated `openssl_providers` module in
  `crate/server/src/`, consolidating `safe_openssl_version_info()`, `init_openssl_providers()`
  (production), and `init_openssl_providers_for_tests()` (test environments) into a single place.
- Improve determinism of `nix/openssl.nix` OpenSSL builds:
    - Patch `ENGINESDIR`/`MODULESDIR` in the generated Makefile to fixed
      `/usr/local/cosmian/lib/...` paths, preventing Nix store path embedding in compiled
      `libcrypto` strings.
    - Set `SOURCE_DATE_EPOCH=1` and `ZERO_AR_DATE=1` in build and install phases.
    - Normalize all output file timestamps with `find $out -exec touch --date=@1 {} +`.
- Non-FIPS Nix Linux builds are now bit-for-bit reproducible (`nix-build --check` passes for all four Linux variants: FIPS/non-FIPS × static/dynamic OpenSSL):
    - Removed `${toString ../.}` from RUSTFLAGS `-C remap-path-prefix` — it embedded the machine-specific workspace path into the derivation, causing cross-machine hash divergence.
    - Added `-C strip=symbols` and `-C symbol-mangling-version=v0` to strip residual host-path artefacts from symbol tables.
    - Scrub the Nix-store path from OpenSSL's `buildinf.h` at build time so the OpenSSL derivation hash is identical across machines.
- Pin all `builtins.fetchTarball` calls in `default.nix` with explicit `sha256` hashes (nixpkgs 24.11, rust-overlay, nixpkgs 22.05). Eliminates Nix-version-sensitive evaluation impurity and removes the `NIXPKGS_GLIBC_234_URL` environment variable override.
- Non-FIPS Docker image now ships OpenSSL 3.6.0 provider modules (`legacy.so`, `openssl.cnf`) and sets `OPENSSL_CONF`/`OPENSSL_MODULES` environment variables, matching the FIPS image layout.
- macOS packaging fixes in `nix/scripts/package_dmg.sh` and related CI scripts.
- *(deps)* Bump keccak in the cargo group across 1 directory ([#728](https://github.com/Cosmian/kms/pull/728))

### 📚 Documentation

- Add mTLS database configuration examples ([#727](https://github.com/Cosmian/kms/pull/727))

### 🧪 Testing

- Add React and WASM tests ([#708](https://github.com/Cosmian/kms/pull/708))

## [5.16.1] - 2026-02-15

### 🐛 Bug Fixes

- Add MLKEM algorithms to the predefined DEFAULT KMIP policy ([#716](https://github.com/Cosmian/kms/pull/716))

## [5.16.0] - 2026-02-04

### 🚀 Features

- Add PQC hybridized KEM support via `cosmian_cover_crypt`:
    - The Cosmian KMS supports Post-Quantum Cryptography (PQC) hybridized Key Encapsulation Mechanisms (KEM)
      via the [cosmian_cover_crypt](https://github.com/Cosmian/cover_crypt) crate. This crate provides
      a configurable KEM framework that can operate in pure classical, pure post-quantum, or hybrid mode
      by combining a pre-quantum KEM with a post-quantum KEM through a KEM combiner (using SHA-256).
    - Server supports `CreateKeyPair` for Configurable-KEM and `Encrypt`/`Decrypt` encapsulation/decapsulation flows.
- Add server-side KMIP algorithm policy allowlists (enforcement via `kmip.policy_id` and `[kmip.allowlists]`) [#700](https://github.com/Cosmian/kms/pull/700)
    - `kmip.policy_id` selects a policy (case-insensitive):
        - `DEFAULT`: built-in conservative allowlists (e.g., SHA-2/3, P-256/P-384/P-521 + Curve25519/448, AEAD/wrapping modes, OAEP/PSS/PKCS5, RSA 3072/4096).
        - `CUSTOM`: enforce the allowlists you set under `[kmip.allowlists]`.
    - If `kmip.policy_id` is unset, the KMIP policy layer is disabled.
    - `None` vs `[]` semantics (for each allowlist): `None` means "no restriction", while an empty list `[]` means "deny all" when enforcement is enabled.
- *(UI)* Runtime branding support via `/ui/branding.json` (title, theme, and favicon resolved before React renders)
    - Theme asset support under `/ui/themes/<theme>/...` with Ant Design token overrides
    - Replace the example theme favicons with neutral, non-Cosmian icons
    - *(docs)* Add post-install UI branding / theme override guide (paths under `/usr/local/cosmian/ui/dist/`)
    - *(packaging)* Include nested UI theme assets in linux packages (recursive `dist/**/*` globs)
    - *(nix)* Stage and validate UI `dist/` content during packaging (checks `index.html`, `assets/`, `themes/`, `branding.json`)

### 🐛 Bug Fixes

- Fix SQL Locate request for OpenTelemetry metrics collector (#694):
    - Refactored SQL Locate query building in locate_query.rs to use bound, typed parameters (LocateQuery + LocateParam) instead of interpolating values into SQL (safer + fixes type/cast handling across SQLite/Postgres/MySQL).
    - Updated the SQL backends to consume the new LocateQuery API: crate/server_database/src/stores/sql/{mysql,pgsql,sqlite}.rs.
    - Improved DB test error context in json_access_test.rs to make failures easier to diagnose.
    - OpenTelemetry wiring updates:
        - mod.rs: add OTEL resource attributes (service name/version + optional environment).
        - otel_metrics.rs: ensure active_keys_count time series exists even when 0.
        - cron.rs: fall back to default username if hsm_admin is empty.
- Fix regression on KMIP 1.0 (Fresh and InitialDate attributes) (#689)
- Fix Linux packaging smoke tests when the host has `/etc/cosmian/kms.toml` present by running with an explicit temp config.
- Make OpenTelemetry export tests resilient under FIPS Nix shells by running `curl` in a clean environment (avoid inherited OpenSSL/LD overrides).
- *(ui)* Azure BYOK export (#697)

### ⚙️ Build

- Nix builds now target GLIBC ≤ 2.34 (Rocky Linux 9 compatibility) by updating pins and building Linux OpenSSL/server outputs against a glibc 2.34 stdenv; server vendor hash expectations are split by static/dynamic on Linux.
- SBOM generation improvements:
    - `.github/scripts/nix.sh sbom` strictly validates `--target/--variant/--link`, defaults to generating all combinations, and supports generating a specific server subset.
    - SBOM tooling runs in an isolated workdir to avoid stray repo-root artifacts, keeps only final `sbom.csv` + `vulns.csv` reports per output directory, and deduplicates CVE rows in-place.
- *(deps)* Bump jsonwebtoken in the cargo group across 1 directory (#702)
- *(deps)* Bump bytes in the cargo group across 1 directory (#703)
- *(deps)* Bump time in the cargo group across 1 directory (#706)
- *(deps)* Bump actix-files in the cargo group across 1 directory (#707)

### 📚 Documentation

- Update SBOM documentation to match the generator output layout and behavior.
- Update OpenSSL versions (#713)

## [5.15.0] - 2026-01-21

### 🚀 Features

- Upgrade OpenSSL to 3.6.0 but keep 3.1.2 for FIPS crypto provider [#667](https://github.com/Cosmian/kms/pull/667)
    - Summary of changes:

      | OpenSSL Linkage | FIPS                                                                   | Non‑FIPS                                                         |
      | --------------- | ---------------------------------------------------------------------- | ---------------------------------------------------------------- |
      | Static          | Linkage: OpenSSL 3.6.0; runtime loads FIPS provider from OpenSSL 3.1.2 | Linkage: OpenSSL 3.6.0; runtime uses default/legacy providers    |
      | Dynamic         | Linkage: OpenSSL 3.1.2; ships FIPS configs and provider OpenSSL 3.1.2  | Linkage: OpenSSL 3.6.0; ships `libssl`/`libcrypto` and providers |

- Provide /health endpoint [#690](https://github.com/Cosmian/kms/pull/690)
- Add k256 (RFC6979) curve for sign/verify for non-fips builds [#671](https://github.com/Cosmian/kms/pull/671)
- Download CLI through UI [#678](https://github.com/Cosmian/kms/pull/678)
- Support RFC 3394 (AESKeyWrap with **no** padding) [#658](https://github.com/Cosmian/kms/pull/658)

  **⚠️ WARNING about AES Key Wrap changes**

  Any previously **manually** exported keys in **JSON** format must be manually updated if they have been previously wrapped with AES. This can be done using the following command:

  ```bash
  sed -i 's/NISTKeyWrap/AESKeyWrapPadding/g' your_exported_key.json
  ```

### 🐛 Bug Fixes

- Remove RUSTSEC-2023-0071 about `rsa` dependency and handle database without sqlx [#646](https://github.com/Cosmian/kms/pull/646).
    - Summary of changes:
        - `openidconnect` is removed in favor of manual OIDC implementation
        - `jwt-simple` is replaced by `jsonwebtoken`
        - old crate`cloudproof_findex` (->crypto_core->rsa) has been removed
        - `sqlx` has been replaced by those crates:
            - tokio-postgres
            - deadpool-postgres
            - mysql_async
            - tokio-rusqlite
            - rusqlite

      **⚠️ WARNING about Redis migration:** For KMS server versions less than v5.12, first migrate KMS Redis-Findex database to 5.14 then 5.15. For KMS server versions 5.12 to 5.14, no migration needed to 5.15.

- Fix Docker container issues [#692](https://github.com/Cosmian/kms/issues/692) and [#670](https://github.com/Cosmian/kms/issues/670) thanks to [#667](https://github.com/Cosmian/kms/pull/667)
- Upgrade lru and downgrade yank flat2 to 1.1.5 [#680](https://github.com/Cosmian/kms/pull/680)
- Fix double hash in RSASSAPSS in raw and digest data mode for sign/verify [#677](https://github.com/Cosmian/kms/pull/677)
- RSA signature/verify tests only run on non-fips [#684](https://github.com/Cosmian/kms/pull/684)
- Derive session cookie encryption key from public URL and user-provided salt for load-balanced deployments [#664](https://github.com/Cosmian/kms/pull/664)

### 📚 Documentation

- Add MySQL integration doc [#647](https://github.com/Cosmian/kms/pull/647)
- Update Percona integration doc [#665](https://github.com/Cosmian/kms/pull/665)
- Add AWS ECS Fargate doc [#686](https://github.com/Cosmian/kms/pull/686)

### ⚙️ Build

- *(deps)* Bump react-router from 7.5.3 to 7.12.0 in /ui in the npm_and_yarn group across 1 directory [#673](https://github.com/Cosmian/kms/pull/673)

### ⚙️ Miscellaneous Tasks

- Filter test_all workflow for dependabot branches [#674](https://github.com/Cosmian/kms/pull/674)
- Test packaging on dependabot branch but wo GPG [#675](https://github.com/Cosmian/kms/pull/675)
- Re-enable packaging workflow [#676](https://github.com/Cosmian/kms/pull/676)

## [5.14.1] - 2025-12-26

### 🚀 Features

- Add IDP multiple audiences configuration on [idp_auth] [#656](https://github.com/Cosmian/kms/pull/656). Dehardcode `kacls-migration` audience for Google CSE migration and allow alternative audiences (e.g. for Google Decrypter use)

### ⚠️ WARNING

**Server TOML configuration - kms.toml:** The deprecated [auth] section has been fully removed in favor of [idp_auth]. Usage is:

```toml
...
[idp_auth]
jwt_auth_provider = [
  "https://accounts.google.com,https://www.googleapis.com/oauth2/v3/certs,my-audience,another_client_id",
  "https://auth0.example.com,,my-app",
  "https://keycloak.example.com/auth/realms/myrealm,,audience_1,audience_2"
]
...
```

### 📚 Documentation

- Publish SBOM and vulnerability reports ([#648](https://github.com/Cosmian/kms/pull/648))
- Improve readme ([#645](https://github.com/Cosmian/kms/pull/645))

### 🐛 Bug Fixes

- Sign and verify for raw and digest data - rfc6979 ([#654](https://github.com/Cosmian/kms/pull/654))
- Allow explicitly AGPL-3.0-or-later license

### ⚙️ Miscellaneous Tasks

- Make Github release sequential - fix cargo publish ([#642](https://github.com/Cosmian/kms/pull/642))

## [5.14.0] - 2025-12-15

### 🚀 Features

- Sign and SignatureVerify support across CLI, and UI ([#522](https://github.com/Cosmian/kms/issues/522), [#606](https://github.com/Cosmian/kms/pull/606)):
    - CLI: Added `sign` and `signature_verify` subcommands for RSA and Elliptic Curves (`crate/cli/src/actions/kms/.../sign.rs`, `.../signature_verify.rs`).
    - UI: Added React pages for RSA and EC signing and verification (`ui/src/RsaSign.tsx`, `ui/src/RsaVerify.tsx`, `ui/src/ECSign.tsx`, `ui/src/ECVerify.tsx`), and surfaced object type in Locate.
- Make DB pool max_connections configurable ([#632](https://github.com/Cosmian/kms/pull/632))
- Support sign and verify on CLI/UI + issue 619 ([#606](https://github.com/Cosmian/kms/pull/606))

### 🚜 Refactor

- Server: Consolidate KMIP operations `Sign` and `SignatureVerify` for RSA and Elliptic Curves
  (`crate/server/src/core/operations/sign.rs`, `signature_verify.rs`; routes updated).
  Supported signature schemes: RSASSA-PSS, ECDSA, EdDSA (Ed25519, Ed448).
- Digest (pre-hashed) mode for signing and verification ([#619](https://github.com/Cosmian/kms/issues/619)):
    - Introduced `digested=true` handling so inputs are treated as final digests (no implicit hashing) across RSA and EC paths (crypto + server).
    - RSA: Added verify support using pre-hashed input, including PKCS#1 v1.5 and RSASSA-PSS flows (`crate/crypto/src/crypto/rsa/verify.rs`).
    - EC: Added verify support using pre-hashed input (`crate/crypto/src/crypto/elliptic_curves/verify.rs`).
- Non-FIPS EC deterministic behavior (RFC 6979-like) via RustCrypto P256 implementation in non-FIPS builds.
- RSASSA-PSS: Server respects `salt_len` when specified (including `0`) during `Sign`.

### 🧪 Testing

- Added CLI and crypto tests for sign/verify flows, including digested mode

### 🐛 Bug Fixes

- MySQL schema missing PRIMARY KEY ([#628](https://github.com/Cosmian/kms/pull/628))
- On JWT auth, token was not properly forwarded in requests ([#629](https://github.com/Cosmian/kms/pull/629))
- Support COSMIAN_KMS_CONF env. variable in docker ([#630](https://github.com/Cosmian/kms/pull/630))
- Support AWS ECS Fargate ([#634](https://github.com/Cosmian/kms/pull/634))
- ObjectType Attribute problem ([#588](https://github.com/Cosmian/kms/pull/588))
- *(UI)* Remove in home page the incorrect HSM comment ([#639](https://github.com/Cosmian/kms/pull/639))
- Support mysql TDE while fixing the KMIP 1.x TTLV deserializer ([#631](https://github.com/Cosmian/kms/pull/631))
- Cli needs snake case ([#640](https://github.com/Cosmian/kms/pull/640))

### 📚 Documentation

- Rename .github/README.md
- Update installation instructions ([#635](https://github.com/Cosmian/kms/pull/635))

### ⚙️ Build

- *(deps)* Bump sigstore/cosign-installer from 3.7.0 to 4.0.0 ([#624](https://github.com/Cosmian/kms/pull/624))
- *(deps)* Bump crazy-max/ghaction-dump-context from 1 to 2 ([#625](https://github.com/Cosmian/kms/pull/625))
- *(deps)* Bump actions/setup-node from 4 to 6 ([#626](https://github.com/Cosmian/kms/pull/626))
- *(deps)* Bump actions/download-artifact from 4 to 6 ([#627](https://github.com/Cosmian/kms/pull/627))
- *(deps)* Bump actions/download-artifact from 6 to 7 ([#637](https://github.com/Cosmian/kms/pull/637))
- *(deps)* Bump actions/upload-artifact from 5 to 6 ([#638](https://github.com/Cosmian/kms/pull/638))

### ⚙️ Miscellaneous Tasks

- Rearrange releases ([#636](https://github.com/Cosmian/kms/pull/636))

## [5.13.0] - 2025-12-07

### 🚀 Features

- KMIP XML Vector Conformance (1.4 & 2.1) ([see details](#-kmip-xml-vector-conformance-14--21)) ([#583](https://github.com/Cosmian/kms/pull/583))
- Nix: Reproducible Package Management ([see details](#-nix-reproducible-package-management)) ([#596](https://github.com/Cosmian/kms/pull/596)):
- Create OpenTelemetryConfig to be consumed for server metrics ([#610](https://github.com/Cosmian/kms/pull/610))

### 🐛 Bug Fixes

- Better sql for the Find query ([#618](https://github.com/Cosmian/kms/pull/618))
- HSM unwrapping without permission ([#621](https://github.com/Cosmian/kms/pull/621))

### 📚 Documentation

- Fix UI README.md ([#611](https://github.com/Cosmian/kms/pull/611))
- Add vsphere minimal version ([#612](https://github.com/Cosmian/kms/pull/612))

### 🧪 Testing

- Support official KMIP test vectors 1.4/2.1 ([#583](https://github.com/Cosmian/kms/pull/583))

### ⚙️ Build

- Reproducible Package Management with Nix ([#596](https://github.com/Cosmian/kms/pull/596))
- *(deps)* Bump docker/metadata-action from 4 to 5 ([#613](https://github.com/Cosmian/kms/pull/613))
- *(deps)* Bump actions/checkout from 4 to 6 ([#614](https://github.com/Cosmian/kms/pull/614))
- *(deps)* Bump crazy-max/ghaction-import-gpg from 5 to 6 ([#615](https://github.com/Cosmian/kms/pull/615))
- *(deps)* Bump actions/upload-artifact from 4 to 5 ([#616](https://github.com/Cosmian/kms/pull/616))
- *(deps)* Bump softprops/action-gh-release from 1 to 2 ([#617](https://github.com/Cosmian/kms/pull/617))

### ✅ KMIP XML Vector Conformance (1.4 & 2.1)

- End-to-end alignment with the official KMIP XML test vectors across library, server routing, and CLI: Create, Query/DiscoverVersions, attribute flows, and OpaqueObject revoke/destroy are covered.

#### 🚀 Features

- KMIP crate
    - Operations/types/messages:
        - Expanded Operation enum and message wiring to include: Interop, PKCS11, Check, RNG Retrieve, RNG Seed, GetAttributeList, MACVerify, ModifyAttribute, Log, plus responses.
        - Request/Response batch items are Clone with structured Display for clearer diagnostics.
        - Added Vendor OpaqueDataType; Display impls for CryptographicDomainParameters, ProtectionStorageMasks, StorageStatusMask.
    - TTLV improvements:
        - Deserializer coercions: Integer/Interval→i64, Enumeration/LongInteger→u8; ByteString→hex for ShortUniqueIdentifier.
        - Relaxed Attribute decoding supporting VendorAttribute and AttributeName+Value forms.
        - deserialize_ignored_any no-op to avoid loops in permissive paths.
    - Protocol alignment:
        - DiscoverVersions now uses KMIP 0.x types (protocol_version_major/minor) per spec; Query advertises operations/objects supported.
    - XML support:
        - Added XML serializer/deserializer and parser with tests for 1.4 and 2.1 XML vectors.

- server
    - New KMIP operations exposed and routed: DiscoverVersions, Query, RNG Retrieve, RNG Seed, MACVerify, GetAttributeList, ModifyAttribute, Check.
    - OpaqueObject Revoke/Destroy parity with vectors; deterministic ordering for GetAttributeList.
    - RNG implementation module (ANSI X9.31) with public routing.
    - Optional cascade mechanism for Destroy and Revoke.

- CLI
    - New subcommands: rng (Retrieve/Seed), mac verify, discover-versions, query.
    - New opaque-object subcommands: Create/Import/Export/Revoke/Destroy (no wrap/unwrap).

- kms_client
    - REST client methods added for RNG Retrieve/Seed, MACVerify, Query, DiscoverVersions, Check, GetAttributeList, attribute ops, register, and crypto ops.

- server_database
    - Deterministic GetAttributeList behavior across backends; Locate query refinements; backend adapters updated (MySQL, PostgreSQL, SQLite, Redis-Findex).

- crypto
    - Robustness and consistency improvements to RSA OAEP and wrap/unwrap paths used by KMIP flows.

- interfaces / hsm / access / client_utils
    - Minor interface refinements and HSM integration stability improvements supporting the new routes and attribute flows.

#### 🐛 Bug Fixes

- Export OpaqueObject Raw/Base64 returns opaque bytes (no KeyBlock).
- DiscoverVersions type/field mismatches fixed by switching to KMIP 0.x (major/minor).
- TTLV deserializer: better errors and coercions (u8 from Enumeration/LongInteger; i64 widening from Integer/Interval; vendor Attribute decoding) for XML vector compatibility.
- GetAttributeList: unified, deterministic ordering across environments.

#### 🧪 Testing

- Extensive XML vector tests for 1.4 and 2.1 in the kmip crate (mandatory/optional suites, crypto coverage).
- Added CLI tests: OpaqueObject CRUD (create/import, export json/base64/raw, revoke, destroy), RNG Retrieve/Seed, MAC Verify, Query, and DiscoverVersions.
- Server TTLV tests expanded (e.g., DSA creation/get flows) and vector integrations.

#### 📚 Documentation / Tooling

- Added KMIP specification scaffolding READMEs and a script to generate XML-based support tables.
- Build scripts adjusted for the new test coverage and flows.

### ✅ Nix: Reproducible Package Management

#### 🚀 Features

- **Reproducible builds with Nix**:
    - Full migration to Nix package manager for deterministic, bit-for-bit reproducible builds
    - Automated hash verification system ensuring build artifact integrity across platforms
    - Support for offline/air-gapped builds with complete dependency caching
    - Unified build system replacing platform-specific scripts (`.sh`, `.ps1`)
    - Comprehensive build variants: FIPS/non-FIPS × static/dynamic × vendor/non-vendor
    - Native support for cross-platform builds (Linux x86_64/ARM64, macOS x86_64/ARM64, Windows)

- **Build infrastructure improvements**:
    - New `nix/` directory with reproducible derivations for KMS server, OpenSSL 3.1.2, UI, and Docker images
    - Automated hash tracking system with 400+ expected hashes for all build artifacts and dependencies
    - Deterministic OpenSSL 3.1.2 builds (both FIPS and non-FIPS variants) with static linking support
    - Docker images built entirely through Nix for consistency
    - Package signing infrastructure for Debian (.deb) and RPM packages
    - SBOM (Software Bill of Materials) generation integrated into build process

- **Testing & CI enhancements**:
    - Refactored GitHub workflows with comprehensive reusable components
    - New test suites: `test_all.sh`, `smoke_test_deb.sh`, `smoke_test_rpm.sh`, `smoke_test_dmg.sh`
    - Database-specific test scripts for MySQL, PostgreSQL, Redis, and SQLite backends
    - HSM integration tests for Utimaco, Proteccio, SoftHSM2, and Crypt2pay
    - Google CSE endpoint testing with HSM integration
    - Systemd service file validation tests
    - Docker image smoke tests with health checks

#### 🚜 Refactor

- **CI/CD pipeline reorganization**:
    - New reusable workflow structure: `main.yml` → `main_base.yml`/`packaging.yml`
    - Separated authentication tests by FIPS/non-FIPS variants
    - Modularized test execution with dedicated scripts per component
    - Common utilities consolidated in `.github/scripts/common.sh`

#### 📚 Documentation

- Comprehensive Nix build system documentation with visual diagrams:
    - Build architecture and reproducibility guarantees
    - Hash verification flow and offline build processes
    - Package signing setup and verification procedures
    - Troubleshooting guides and learning resources
- GitHub workflows documentation with complete execution flow diagrams
- Updated Copilot instructions for Nix-based development
- Build and test guide in `.github/copilot-instructions.md`

## [5.12.1] - 2025-11-28

### 🐛 Bug Fixes

- Avoid negative certificate serial number ([#609](https://github.com/Cosmian/kms/pull/609))

### 💼 Other

- Remove useless css in autogenerated doc

### ⚙️ Build

- *(deps)* Bump actions/checkout from 5 to 6 ([#604](https://github.com/Cosmian/kms/pull/604))

## [5.12.0] - 2025-11-19

### 🚀 Features

- Azure byok UI ([#597](https://github.com/Cosmian/kms/pull/597))
- Upgrade Findex from v5 to v8 ([#542](https://github.com/Cosmian/kms/pull/542))
    - *(redis)*: Created a new data storage schema for Redis, using a double-index instead of the "next Keyword".
    - *(redis)*: Developed a migration algorithm to update data under KMSes prior to 5.12.x.
    - *(redis)*: Introduction of strong typing for UserId and ObjectUid to reduce string manipulation errors, and created new types inspired from legacy cloudproof components.
    - Used new crypto core serializations for storage (when applicable)

### 🐛 Bug Fixes

- Automatic key unwrapping depending on ObjectType ([#600](https://github.com/Cosmian/kms/pull/600)):
    - Automatically unwrap keys (that are wrapped) when retrieving keys from database. It can be useful when server is configured with a Key Encryption Key that wraps all new keys. The unwrapped keys stay temporarily in expiring cache.
    - This feature is combined to the parameter default_unwrap_type that filters the ObjectType to unwrap.
    - Possible filters in server configuration are: All, Certificate, CertificateRequest, OpaqueObject, PGPKey, PrivateKey, PublicKey, SecretData, SplitKey, SymmetricKey

### 📚 Documentation

- Rework all the databases migration and represent more easy to read schemas ([#542](https://github.com/Cosmian/kms/pull/542))
- Document migration flows
- Update KMS configuration TOML file with parameter `default_unwrap_type`.

### ⚙️ Build

- *(deps-dev)*: bump js-yaml from 4.1.0 to 4.1.1 in /ui in the npm_and_yarn group across 1 directory

### 🧪 Testing

- *(redis)*: Add two integration tests that migrate from version 5.1.0 and 5.2.0 to ([#542](https://github.com/Cosmian/kms/pull/542))

### ⚙️ Miscellaneous Tasks

- Refactored migration traits between the SQL databases and the Redis one (while possible)
- Deleted a lot of dead code
- Marked the Label parameter as deprecated.
- Updated the `aes_gcm_siv_not_openssl` functions to avoid using deprecated dependencies.

### ⚠️ WARNING

**Redis users:** Starting version 5.12.0,  the KMS will start operating with a new version of Findex (the SSE used with the Redis DB), and a  data migration is necessary :

**🚨 IMPORTANT: Back up your Redis database before upgrading to version 5.12.0.** 🚨

- If you're upgrading from a version prior to 5.0.0 : Please export your keys using standard formats
  (PKCS#8, PEM, etc.) and re-import them after clearing the redis store.
  Databases created with version 4.x.x are not compatible with the automated migration routine and
  won't start if the `db_version` key is unset.
- If you're upgrading from a 5.x DB : A transparent migration process will occur and should typically take less than a minute.

## [5.11.2] - 2025-11-12

### 🐛 Bug Fixes ([#598](https://github.com/Cosmian/kms/pull/598))

- Fix key wrapping where `wrapping-key` is itself wrapped: unwrap it and then use it
- Add an automatic key unwrapping for google_cse key at server startup
- Create a `OnceCell` HSM instance when multiple KMS servers are use - avoiding potential startup error
- Improved handling of wrapped keys, attribute propagation, and TLS cipher suite configuration

### 🧪 Testing ([#598](https://github.com/Cosmian/kms/pull/598))

- Add CLI-tests on Google CSE endpoints (/wrap, /privatekeydecrypt, etc.) and on Google key pair creation - all with the google_cse key wrapped by HSM

### 📚 Documentation ([#598](https://github.com/Cosmian/kms/pull/598))

- Example of configuration file: replace deprecated [auth] section with [idp_auth]

## [5.11.1] - 2025-11-04

### 📚 Documentation

- Rework KMIP support documentation ([#595](https://github.com/Cosmian/kms/pull/595))
- Remove double entry on KMIP Support

### 🧪 Testing

- *(windows)*: Enable test on whole workspace([#593](https://github.com/Cosmian/kms/pull/593))

## [5.11.0] - 2025-10-28

### 🚀 Features

- Add Crypt2pay HSM integration with a dedicated loader crate
- Generic "other" HSM support using Softhsm2 compatibility
- Enable empty (null) password/pin HSM login via special handling in slot management
- Add Windows/macOS installers with cargo packager tool ([#585](https://github.com/Cosmian/kms/pull/585))

### 🐛 Bug Fixes

- *(google_cse)* Load RSA private as PKCS8 or PKCS1 format ([#592](https://github.com/Cosmian/kms/pull/592))

### ⚠️ WARNING

**Gmail CSE users:** Versions 5.8/5.9 and 5.10 contain a blocking issue with Gmail Client-Side Encryption support (issue loading PKCS#8 RSA private key). Please upgrade to version 5.11.0 or later to ensure proper Gmail CSE functionality.

### 📚 Documentation

- Add KMIP current support ([#581](https://github.com/Cosmian/kms/pull/581))

### Build

- *(deps)* Bump esbuild ([#587](https://github.com/Cosmian/kms/pull/587))

## [5.10.0] - 2025-10-21

### 🚀 Features

- Add HSM key search with basic filters ([#552](https://github.com/Cosmian/kms/pull/552))
- Support wrapping SecretData object in export ([#551](https://github.com/Cosmian/kms/pull/551))
- Support DeriveKey KMIP operation ([#554](https://github.com/Cosmian/kms/pull/554))
- Add option to enable automatic unwrapping for Get and Export requests ([#579](https://github.com/Cosmian/kms/pull/579))

### 🐛 Bug Fixes

- Enable workspace clippy lints for all crates ([#553](https://github.com/Cosmian/kms/pull/553))
- Release HSM tests ([#567](https://github.com/Cosmian/kms/pull/567))
- Keep error info on DBerror ([#516](https://github.com/Cosmian/kms/pull/516))
- React CVE deps ([#566](https://github.com/Cosmian/kms/pull/566))
- Remove min_specialization feature ([#569](https://github.com/Cosmian/kms/pull/569))
- HSM key search fails after encountering incompatible key ([#574](https://github.com/Cosmian/kms/pull/574))
- *(windows)* Socket server listen on localhost instead of 0.0.0.0 ([#575](https://github.com/Cosmian/kms/pull/575))

### 📚 Documentation

- Add SmartCard HSM to README.md ([#563](https://github.com/Cosmian/kms/pull/563))
- Added documentation for Smart card HSM and SoftHSM2 ([#570](https://github.com/Cosmian/kms/pull/570))
- Add server configs examples ([#568](https://github.com/Cosmian/kms/pull/568))

### 🧪 Testing

- Filter tests with credentials and prerequisites ([#571](https://github.com/Cosmian/kms/pull/571))
- Enable Google CSE on workspace

### ⚙️ Miscellaneous Tasks

- Add CLA Assistant GitHub Action configuration
- Create CLA.md and CONTRIBUTING.md
- About forks, skip Google CSE tests and docker build
- About dependabot branches, skip Google CSE tests and docker build ([#559](https://github.com/Cosmian/kms/pull/559))
- Move CLA assistant workflow to correct path
- Skip public doc rebuild on forks and dependabot branches
- Skip CLA assistant on dependabot branches
- Integrate CLA signature in main_base.yml workflow - 2
- Trigger on issue comment
- Use an unprotected branch for CLA signing
- Remove trigger on pull_request_target
- Upgrade toolchain to nightly 2025-09-15 ([#564](https://github.com/Cosmian/kms/pull/564))

### Build

- *(deps)* Bump actions/checkout from 4 to 5
- *(deps)* Bump the npm_and_yarn group across 1 directory with 4 updates

## [5.9.0] - 2025-09-15

### 🚀 Features

- Add Smart card HSM support and bug fixes ([#538](https://github.com/Cosmian/kms/pull/538))
- CLI features:
    - added support for SHA1 in RSA key wrapping ([#541](https://github.com/Cosmian/kms/pull/541))
    - add Azure functionality to facilitate BYOK ([#541](https://github.com/Cosmian/kms/pull/541))
    - `attributes get` added support to retrieve Object tags only ([#541](https://github.com/Cosmian/kms/pull/541))
- *tracing*: print function names while using tracing macros. Use cosmian_logger instead of tracing crate ([#536](https://github.com/Cosmian/kms/pull/536))

### 🐛 Bug Fixes

- When wrapped with `No Encoding`, the RSA private key bytes and EC private key bytes are now the PKCS#8 DER bytes ([#541](https://github.com/Cosmian/kms/pull/541))
- CLI: fixed broken `attributes get` ([#541](https://github.com/Cosmian/kms/pull/541))

### 📚 Documentation

- Added Google CSEK and Google CMEK documentation ([#541](https://github.com/Cosmian/kms/pull/541))
- Added Azure BYOK documentation ([#541](https://github.com/Cosmian/kms/pull/541))
- Re-organized documentation ([#541](https://github.com/Cosmian/kms/pull/541))
- Fixing typo in Encrypt/Decrypt requests examples ([#545](https://github.com/Cosmian/kms/pull/545))

### 🧪 Testing

- Enable softhsm2 tests ([#539](https://github.com/Cosmian/kms/pull/539))
- Fix python installation on pykmip-tests GH workflow
- Fix race condition on test_privileged_users
- Add auth test with expired cert ([#547](https://github.com/Cosmian/kms/pull/547))

## [5.8.1] - 2025-09-05

### 🐛 Bug Fixes

- Server crate publish ([#534](https://github.com/Cosmian/kms/pull/534))

## [5.8.0] - 2025-09-05

### 🚀 Features

- Add KMIP operations `Sign` and `VerifySignature` for digital signature support ([#511](https://github.com/Cosmian/kms/pull/511))
- Add TLS cipher suites selection ([#524](https://github.com/Cosmian/kms/pull/524))

### 🐛 Bug Fixes

- *(google_cse)* Further restrict access to CSE privileged unwrap endpoint ([#517](https://github.com/Cosmian/kms/pull/517))
- Fix potential race condition in Google CSE migration key pair creation when multiple servers start simultaneously ([#519](https://github.com/Cosmian/kms/pull/519))
- Simplify clap JWT Auth configuration ([#531](https://github.com/Cosmian/kms/pull/531))
- Add non-fips UI build ([#532](https://github.com/Cosmian/kms/pull/532))
- Fix Credential parsing in KMIP Request Message ([#529](https://github.com/Cosmian/kms/pull/529))
- Use crypto core for db crypto ([#526](https://github.com/Cosmian/kms/pull/526))
- Cloudproof reexports ([#528](https://github.com/Cosmian/kms/pull/528))

### 📚 Documentation

- *(percona)* Add correction to percona doc ([#521](https://github.com/Cosmian/kms/pull/521))
- *(hsm)* Added KMS-HSM integration workflow graph ([#523](https://github.com/Cosmian/kms/pull/523))
- Fixes CLI Key Wrapping documentation on export ([#530](https://github.com/Cosmian/kms/pull/530))
- Clarify Gmail CSE CA authority usage ([#533](https://github.com/Cosmian/kms/pull/533))

### ⚙️ Miscellaneous Tasks

- Uniformize clippy lints on all crates ([#525](https://github.com/Cosmian/kms/pull/525))
- Create SECURITY.md with vulnerability tracking and reporting guidelines ([#527](https://github.com/Cosmian/kms/pull/527))

## [5.7.1] - 2025-08-22

### 🚀 Features

- Add support HTTP forward proxy (for intermediate CLI crate) ([#509](https://github.com/Cosmian/kms/pull/509))

### 📚 Documentation

- PKCS11: move PKCS#11 docs into cli repository ([#510](https://github.com/Cosmian/kms/pull/510))

### ⚙️ Miscellaneous Tasks

- Google CSE: save openssl commands to verify resource hash computation

## [5.7.0] - 2025-08-20

### 🚀 Features

- In JWT auth, change `audience` type from `String` to `Vec<String>`  ([#491](https://github.com/Cosmian/kms/pull/491))
- Support AES-CBC encryption without padding for Oracle TDE support ([#493](https://github.com/Cosmian/kms/pull/493))
- Add support for existing PKCS12 leaf certificates when creating Google CSE keypairs ([#505](https://github.com/Cosmian/kms/pull/505))
- Support debian 10 for old glibc compatibility (required for Oracle TDE) ([#508](https://github.com/Cosmian/kms/pull/508))
- Add GitHub Copilot instructions for KMS development workflow ([#504](https://github.com/Cosmian/kms/pull/504))

### 🐛 Bug Fixes

- Test docker container once generated by ci ([#481](https://github.com/Cosmian/kms/pull/481))

### ⚙️ Miscellaneous Tasks

- Use machete and publish crates on tags ([#499](https://github.com/Cosmian/kms/pull/499))
- Remove test data folder ([#497](https://github.com/Cosmian/kms/pull/497))
- Reorder crates in Cargo.toml
- Fix docker image name in tests ([#500](https://github.com/Cosmian/kms/pull/500))
- Automate CVE resolution (when possible) by mirroring deny.toml in .cargo/audit.toml

## [5.6.2] - 2025-07-29

### 🐛 Bug Fixes

- Remove useless and old UI files ([#487](https://github.com/Cosmian/kms/pull/487))
- Test_kms_server must remain dev-dependency ([#486](https://github.com/Cosmian/kms/pull/486))
- Enable native TLS support for OpenID Connect authentication ([#489](https://github.com/Cosmian/kms/pull/489))

## [5.6.1] - 2025-07-25

### 🚀 Features

- Display CSE information from UI ([#478](https://github.com/Cosmian/kms/pull/478))

### 🐛 Bug Fixes

- Fix outdated UI pkg
- Rocky package must be NON-FIPS ([#482](https://github.com/Cosmian/kms/pull/482))

### 📚 Documentation

- Add MongoDB documentation ([#483](https://github.com/Cosmian/kms/pull/483))
- Improve User Interface documentation

## [5.6.0] - 2025-07-23

### 🐛 Bug Fixes

- Support for TLS 1.3 on the HTTPS port of the KMIP server ([#458](https://github.com/Cosmian/kms/pull/458))
- Fixed RevocationReasonCode in KMIP 1.x ([#460](https://github.com/Cosmian/kms/pull/460))

### 🚀 Features

- Better support of PyKMIP client ([#438](https://github.com/Cosmian/kms/pull/438))
- Support for Percona PostgreSQL TDE (Transparent Data Encryption) ([#464](https://github.com/Cosmian/kms/pull/464))
- Support for Secret Data ([#398](https://github.com/Cosmian/kms/pull/398))

## [5.5.1] - 2025-07-09

### 🐛 Bug Fixes

- Fixed an issue with Locate failing when an HSM is present
- Fixed missing attributes when the wrapped object is not in the cache ([#462](https://github.com/Cosmian/kms/pull/462))
- Added support for SoftHsmV2 ([#457](https://github.com/Cosmian/kms/pull/457))

## [5.5.0] - 2025-07-08

### 🚀 Features

- Implement Register KMIP Operation
- ANSI colors in stdout are now disabled by default but can be re-enabled using a configuration flag
- Handle extension file to define x509 setup extensions for Google CSE keypairs create command

### 🐛 Bug Fixes

- Fix the default path for the `kms.toml` file on Windows
- Full configuration `kms.toml` file for Linux packaged distributions
- Handle KMIP Dates as OffsetDateTime instead of i64

### ⚙️ Miscellaneous Tasks

- Display items ID on Google keypairs creation command

### 📚 Documentation

- Missing documentation on the rolling file appender in the server configuration file
- Update README.md to reflect that the KMS now builds in FIPS mode by default

### 🧪 Testing

- Test custom JWT used from Google CSE migration endpoints
- Test Import and Register KMIP operations

## [5.4.1] - 2025-06-25

### 🐛 Bug Fixes

- Fix error on Google CSE migration authentication

## [5.4.0] - 2025-06-24

### 🚀 Features

- Support for daily rolling log files to a specified directory

### 🐛 Bug Fixes

- Invert fips feature ([#448](https://github.com/Cosmian/kms/pull/448))
- Google CSE - Added support for all algorithms in private_key_decrypt
- Google CSE - Added support for all algorithms in private_key_sign

### ⚙️ Miscellaneous Tasks

- Align UI version with Cargo workspace

## [5.3.3] - 2025-06-12

### 🐛 Bug Fixes

- In UI, fix `IvCounterNonce` ([#446](https://github.com/Cosmian/kms/pull/446))
- *(Linux packages)* Save and restore conf during installation
- Interoperability fixes with PyKMIP

### 📚 Documentation

- Remove reference of cosmian_gui
- Markdown fixes

### ⚙️ Miscellaneous Tasks

- Rename cli repo
- *(windows)* Reduce verbosity

## [5.3.2] - 2025-06-04

### 🐛 Bug Fixes

- Support for MySQL 8.0.42 and higher ([#443](https://github.com/Cosmian/kms/pull/443))

## [5.3.1] - 2025-06-04

### 🐛 Bug Fixes

- Fix clap error on cse keypair command

## [5.3.0] - 2025-06-02

### 🚀 Features

- Support for outbound proxy to fetch the JWKS (JSON Web Key Set) ([#439](https://github.com/Cosmian/kms/pull/439))

## [5.2.0] - 2025-05-27

### 🚀 Features

- Support for JWKS (JSON Web Key Set) that provides JWK not appropriate for OIDC authentication ([#433](https://github.com/Cosmian/kms/pull/433))

## [5.1.1] - 2025-05-23

### 🐛 Bug Fixes

- Safer handling of Google CSE authorization token decoding ([#431](https://github.com/Cosmian/kms/pull/431))

## [5.1.0] - 2025-05-22

### 🚀 Features

- Support custom JWT authentication for external KACLS using an RSA keypair in the Google CSE migration flow
- Expose the RSA public key via the new `/certs` endpoint
- Rewrite `/rewrap` endpoint to fully support the migration flow logic
- Rewrite `/privilegedunwrap` endpoint to properly integrate with the migration process
- Support for PKCE (Proof Key for Code Exchange) authentication from the CLI with the Cosmian KMS
- Concurrent multi-factor authentication with clear cascading rules (OIDC / Client Certificates / API Token)

### 🐛 Bug Fixes

- Unclear cascading rules in multi-factor authentication

### 🚜 Refactor

- Refactor server configuration to include a dedicated google_cse section
- Derive the Google CSE KACLS URL from the public_url configuration value for better flexibility

### ⚙️ Miscellaneous Tasks

- Expose user_id in the response from the /token endpoint for improved UI identification

### 🧪 Testing

- Add unit tests for Google CSE digest computation, validating against Google's official documentation appendix
- Test custom JWT generation and parsing to ensure compatibility and correctness

### 📚 Documentation

- Revise the Google CSE documentation section for clarity and accuracy
- Add a new section on migrating Google CSE data from Drive, including practical steps and examples
- PKCE documentation with configuration examples
- Improved authentication documentation, both client and server side

## [5.0.0] - 2025-05-07

**WARNING**: This is a breaking change release.
Databases created with version 4.x.x are not compatible with version 5.0.0.
Please export your keys using standard formats (PKCS#8, PEM, etc.) and re-import them after upgrading.

### 🚀 Features

- Support for KMIP 1.0, 1.1, 1.2, 1.3, 1.4, 2.0, 2.1 ([#412](https://github.com/Cosmian/kms/pull/412))
- Binary TTLV for all KMIP versions on port 5696
- JSON TTLV for all KMIP versions on port 9998, endpoint /kmip
- VMware support
- Possible automatic key wrapping on Create and Import
- Better telemetry using OTLP and logs to syslog
- Run KMS server with privileged users ([#408](https://github.com/Cosmian/kms/pull/408)):
    - These users can grant or revoke create access rights for other users
    - Without `Create` access right or privileged status, users can't create or import objects to KMS

### 🚜 Refactor

- Rationalize SQL implementation ([#379](https://github.com/Cosmian/kms/issues/379))
- Rust KeyBlock implementation not fully compliant with KMIP 2.1 specs ([#76](https://github.com/Cosmian/kms/issues/76))

### 🐛 Bug Fixes

- Multiple fixes in KMIP 2.1 TTLV formats

### ⚙️ Miscellaneous Tasks

- More extensive coverage of KMIP attributes
- Database schema changes

## [4.24.0] - 2025-04-23

### 🚀 Features

- Add support for Oracle Transparent Database Encryption (TDE) using Oracle Key
  Vault ([#396](https://github.com/Cosmian/kms/pull/396))

### ⚙️ Miscellaneous Tasks

- Add missing artifacts on tags ([#407](https://github.com/Cosmian/kms/pull/407))
- Missing folder assets in DEB/RPM ([#406](https://github.com/Cosmian/kms/pull/406))
- Align Docker build image to the wasm-pack prebuild binary for ARM cross-build

## [4.23.0] - 2025-04-10

### 🚀 Features

- Add digest and MAC KMIP operations ([#370](https://github.com/Cosmian/kms/pull/370))
- Upgrade Covercrypt to v15 ([#382](https://github.com/Cosmian/kms/pull/382))
- Add CBC encryption mode ([#395](https://github.com/Cosmian/kms/pull/395))
- Add UI ([#391](https://github.com/Cosmian/kms/pull/391))

### 🐛 Bug Fixes

- Shrink docker images size using slim-bullseye base image ([#377](https://github.com/Cosmian/kms/pull/377))
- Clean unneeded test files ([#392](https://github.com/Cosmian/kms/pull/392))
- RUSTSEC-2025-0009: `ring`: Some AES functions may panic when overflow checking is enabled.
- RUSTSEC-2025-0022: `openssl`: Use-After-Free in Md::fetch and Cipher::fetch

### 🚜 Refactor

- Move all CLI relative crates on <https://github.com/Cosmian/cli> ([#383](https://github.com/Cosmian/kms/pull/383))

### 📚 Documentation

- Fix Google expected X509 extensions

### 🧪 Testing

- Add HSM tests using Utimaco simulator ([#380](https://github.com/Cosmian/kms/pull/380))

### ⚙️ Miscellaneous Tasks

- Reuse generic Github workflows ([#401](https://github.com/Cosmian/kms/pull/401))

## [4.22.1] - 2025-02-04

### 🧪 CI

- Fix rhel9 artifact name

## [4.22.0] - 2025-02-03

### 🚀 Features

- Utimaco General Purpose HSMs support ([#367](https://github.com/Cosmian/kms/pull/367))

### 🐛 Bug Fixes

- Fixed HSM base code dangling pointer issue in `release` mode
- Fixed unwanted `ValueEnum` in `cosmian sym encrypt`
- Remove ckms linux packages in favor of cosmian packages ([#366](https://github.com/Cosmian/kms/pull/366))
- Rename binary `cosmian_kms_server` to `cosmian_kms` - reuse the same name as marketplace images

### 📚 Documentation

- Clarified installation documentation
- Improved database configuration
- Improved HSM integration documentation

## [4.21.2] - 2025-01-21

### 📚 Documentation

- Add how to release doc ([#361](https://github.com/Cosmian/kms/pull/361))
- Change default port of KMS package from 8080 to 9998 ([#364](https://github.com/Cosmian/kms/pull/364))
- VM marketplace guide examples ([#365](https://github.com/Cosmian/kms/pull/365))
- *(google_cse)* Update authentication section ([#363](https://github.com/Cosmian/kms/pull/363))

### 🧪 CI

- Allow continue on error ([#362](https://github.com/Cosmian/kms/pull/362))

## [4.21.1] - 2025-01-16

### 🚀 Features

- Loading server conf with default system conf. fallback ([#360](https://github.com/Cosmian/kms/pull/360))
- Update crate config_utils ([#358](https://github.com/Cosmian/kms/pull/358))

### 📚 Documentation

- *(google_cse)* Typos in configuring .well-known file ([#359](https://github.com/Cosmian/kms/pull/359))

### ⚙️ Miscellaneous Tasks

- Fix publish on package.cosmian.com

## [4.21.0] - 2025-01-07

### 🚀 Features

- Add server param to disable (if needed) Google CSE JWT token
  validation ([#349](https://github.com/Cosmian/kms/pull/349))
- Add remove option to `Destroy` + Object not found error message fix ([#357](https://github.com/Cosmian/kms/pull/357))

### 🐛 Bug Fixes

- Save configuration file outside of clap actions ([#351](https://github.com/Cosmian/kms/pull/351))
- Fix an incorrect message on 'object not found' ([#353](https://github.com/Cosmian/kms/issues/353))

### 📚 Documentation

- Fix bad links and mkdocs formatting
- Simple review ([#358](https://github.com/Cosmian/kms/pull/358)
- Explain default KMS configuration on CVM ([#359](https://github.com/Cosmian/kms/pull/359)
- Better build with mkdocs; faster Mermaid support and better Katex support

## [4.20.1] - 2024-12-09

### 🚀 Features

- Add CLI bench command ([#348](https://github.com/Cosmian/kms/pull/348))

### 🚜 Refactor

- Re-expose clap actions for other CLIs (cosmian, ckms_gui) ([#339](https://github.com/Cosmian/kms/pull/339))

### 📚 Documentation

- Revisit the mkdocs documentation ([#339](https://github.com/Cosmian/kms/pull/339))

## [4.20.0] - 2024-11-30

### 🚀 Features

- HSM support ([#344](https://github.com/Cosmian/kms/pull/344))
    - support for the Proteccio HSM that provides both
        - the ability to perform the Create, Destroy, Export, Encrypt, and Decrypt operations on the HSM
        - the ability to create keys in the KMS that are wrapped by a key in the HSM
    - the database components are now in a separate crate `server_database`. They are now split in 2 implementations:
      Objects store and Permissions store
    - a new `interfaces` crate gathers interfaces to be implemented by new external components. Interfaces include:
        - Object Store
        - Permissions Store
        - Encryption Oracle
    - key unique identifiers now support prefixes. Object Stores, Permissions stores, and Encryption Oracles can be
      registered against the prefixes.
    - support for the `Sensitive` Attribute in addition to the ability to wrap a key by another key has been added to
      all
      keys creations
- Make keys non revocable on server ([#341](https://github.com/Cosmian/kms/pull/341))
- Docker for Linux ARM and keep support for MacOS Intel ([#343](https://github.com/Cosmian/kms/pull/343))

### 🐛 Bug Fixes

- The macOS-12 environment is now deprecated
- Better permissions checking on wrapping and unwrapping

### 📚 Documentation

- Add benchmarks on simultaneous encryptions/decryptions

## [4.19.3] - 2024-10-29

### 🐛 Bug Fixes

- Maturin build on macos arm - force forward compatibility ([#336](https://github.com/Cosmian/kms/pull/336))

## [4.19.2] - 2024-10-29

### 🐛 Bug Fixes

- Launch encrypted GMeet through GCal ([#334](https://github.com/Cosmian/kms/pull/334))
- **MacOS-maturin**: Upgrade python version from 3.12 to 3.13 ([#333](https://github.com/Cosmian/kms/pull/333))
- Dont panic on indexing slicing ([#331](https://github.com/Cosmian/kms/pull/331))

### 📚 Documentation

- `ckms` installation - specifically for Windows ([#332](https://github.com/Cosmian/kms/pull/332))

## [4.19.1] - 2024-10-11

### 🚀 Features

- Client `ckms`: merge attributes handling (set/get/delete) under `attributes`
  subcommand ([#329](https://github.com/Cosmian/kms/pull/329))

### 🐛 Bug Fixes

- Guard on size of ciphertexts for BulkData ([#330](https://github.com/Cosmian/kms/pull/330))
- KMIP Attributes: fix deletion on Links and Vendor Attributes ([#329](https://github.com/Cosmian/kms/pull/329))

## [4.19.0] - 2024-10-09

### 🚀 Features

- Google Workspace Client-Side-Encryption (CSE)
  updates ([#319](https://github.com/Cosmian/kms/pull/319))
    - Generate Google S/MIME key-pairs and identities and upload them to Gmail API from ckms
      CLI ([#270](https://github.com/Cosmian/kms/issues/270))
    - Server-side, export cert at PKCS7 format
    - Implement missing CSE endpoints
    - Wrap/unwrap CSE elements with authenticated encryption
    - Export wrapped keys from KMS specifying the cipher mode
    - Handle auth for guest users ([#271](https://github.com/Cosmian/kms/issues/271))
- Add SetAttribute/DeleteAttribute KMIP operations ([#303](https://github.com/Cosmian/kms/pull/303))
- Re-enable wrap/unwrap on ckms by linking statically on openssl ([#317](https://github.com/Cosmian/kms/pull/317))
- Added AES GCM-SIV and AES XTS ([#328](https://github.com/Cosmian/kms/pull/328))
- Added the ability to client side encrypt files with `ckms` and a hybrid
  scheme ([#328](https://github.com/Cosmian/kms/pull/328))
- Create Symmetric Key / Private keys with custom unique id ([#326](https://github.com/Cosmian/kms/pull/326))
- Add bulk encrypt / decrypt facility ([#318](https://github.com/Cosmian/kms/pull/318))
- Replace Debug derive trait of KMIP Object by a custom Display impl ([#327](https://github.com/Cosmian/kms/pull/327))

### 📚 Documentation

- Documentation: Migrating emails to Gmail CSE ([#316](https://github.com/Cosmian/kms/pull/316))
- Update CSE documentation (Gmail S/MIME) ([#316](https://github.com/Cosmian/kms/pull/316))
- Update KMS build instructions ([#320](https://github.com/Cosmian/kms/pull/320))

### 🧪 Testing

- Add test on database backends ([#311](https://github.com/Cosmian/kms/pull/311))
- Reduce CI pipeline duration in debug ([#315](https://github.com/Cosmian/kms/pull/315))
- Add CSE endpoints testing ([#319](https://github.com/Cosmian/kms/pull/319))

### ⚙️ Miscellaneous Tasks

- Clippy hardening in crate `kmip` ([#304](https://github.com/Cosmian/kms/pull/304))

## [4.18.0] - 2024-09-17

### 🚀 Features

- Add ReKey KMIP operation ([#294](https://github.com/Cosmian/kms/pull/294))
- Add API token authentication between server and
  clients ([#290](https://github.com/Cosmian/kms/pull/290))
- Build a generic database upgrade mechanism ([#299](https://github.com/Cosmian/kms/pull/299))
- Export of certificates can now be performed using the certificate id (instead of just the private
  key id)
- More intuitive PKCS#12 import ([#306](https://github.com/Cosmian/kms/pull/306))
- Support for export under legacy PKCS#12 format ([#306](https://github.com/Cosmian/kms/pull/306))
- Documentation (S/MIME)

### 🐛 Bug Fixes

- KMIP Attributes:
    - In get_attributes, use attributes from ObjectWithMetadata instead of
      Object.Attributes ([#278](https://github.com/Cosmian/kms/pull/278))
    - When inserting in db, force Object::Attributes to be synced with
      Attributes ([#279](https://github.com/Cosmian/kms/pull/279))
- Certificates handling/tasks:
    - **Validate** KMIP operation:
        - Simplify getting CRLs and get returned
          errors ([#268](https://github.com/Cosmian/kms/pull/268))
        - Validate certificate generation ([#283](https://github.com/Cosmian/kms/pull/283))
        - Use certificate file path in ckms
          arguments ([#292](https://github.com/Cosmian/kms/pull/292))
    - **Certify** KMIP operation: Server must sign x509 after adding X509
      extensions ([#282](https://github.com/Cosmian/kms/pull/282))
- Merge decrypt match in same function ([#295](https://github.com/Cosmian/kms/pull/295))
- Fix Public RSA Key size in get attributes ([#275](https://github.com/Cosmian/kms/pull/275))
- RUSTSEC:
    - **RUSTSEC-2024-0357**: MemBio::get_buf has undefined behavior with empty buffers: upgrade
      crate `openssl` from 1.0.64 to 1.0.66 ([#280](https://github.com/Cosmian/kms/pull/280))
    - **RUSTSEC-2024-0363**: Binary Protocol Misinterpretation caused by Truncating or Overflowing
      Casts: bump sqlx to 0.8.1 ([#291](https://github.com/Cosmian/kms/pull/291)
      and [#297](https://github.com/Cosmian/kms/pull/297))
- CLI doc fixes (certificates certify)
- Fix PKCS#12 export of self-signed cert ([#305](https://github.com/Cosmian/kms/issues/305))
- Fix serialization of `Attributes` in
  `redis-findex`  ([#307](https://github.com/Cosmian/kms/pull/307))

### ⚙️ Miscellaneous Tasks

- **clippy** tasks:
    - Only expose pub functions that need to be
      public ([#277](https://github.com/Cosmian/kms/pull/277))
    - Hardcode clippy lints ([#293](https://github.com/Cosmian/kms/pull/293))
- Rename MacOS artifacts giving CPU architecture
- Configure `ckms` to build reqwest with minimal idle connections
  reuse ([#272](https://github.com/Cosmian/kms/pull/272))
- Do not delete tags if none are provided ([#276](https://github.com/Cosmian/kms/pull/276))
- De-activated Google CSE tests when tokens are not supplied through env. var.
- Cleaned-up and improved certificates import tests
- Made test DB backend selectable using env. var. `KMS_TEST_URL`

## [4.17.0] - 2024-07-05

### 🚀 Features

- Add KMIP operation `Validate` for certificates ([#247](https://github.com/Cosmian/kms/pull/247))
- Added RSA benchmarks ([#251](https://github.com/Cosmian/kms/pull/251))
- Add OpenTelemetry OTLP protocol support to KMS
  server ([#253](https://github.com/Cosmian/kms/pull/253))
- Support for multiple certification scenarios and
  self-signing ([#248](https://github.com/Cosmian/kms/pull/248))

### 🐛 Bug Fixes

- Fix vulnerability RUSTSEC-2024-0336 ([#244](https://github.com/Cosmian/kms/pull/244))
- Fix vulnerability RUSTSEC-2024-0344 ([#254](https://github.com/Cosmian/kms/pull/254))
  and ([#255](https://github.com/Cosmian/kms/pull/255))

### ⚙️ Miscellaneous Tasks

- Create Debian/RPM packages for Ubuntu 2x.04 and RHEL
  9 ([#264](https://github.com/Cosmian/kms/pull/264))
- Drop Centos 7 support ([#265](https://github.com/Cosmian/kms/pull/265))
- Replace `cargo audit` with `cargo deny` ([#245](https://github.com/Cosmian/kms/pull/245))
- Replace Linux cross-compiling for Windows with compiling on Windows Github
  runner ([#249](https://github.com/Cosmian/kms/pull/249))
- Add support for build on MacOS ARM

## [4.16.0] - 2024-05-06

### 🐛 Bug Fixes

- Fixed import of symmetric key tag to '_kk' from '_sk'

### 🚀 Features

- Add support for LUKS via PKCS#11 module
- Add support for CKM_RSA_PKCS (PKCS#1 v1.5) for RSA encryption/decryption

## [4.15.2] - 2024-05-03

### 🚀 Features

- Create Gmail key pairs and identities with `ckms` via Gmail
  API ([#243](https://github.com/Cosmian/kms/pull/243))

### 🐛 Bug Fixes

- Comment out mermaid configuration

## [4.15.1] - 2024-05-02

### 🚀 Features

- Add Google Workspace CSE endpoints for **encrypted Gmail
  ** ([#192](https://github.com/Cosmian/kms/pull/192))

### 🐛 Bug Fixes

- RUSTSEC-2024-0336 ([#244](https://github.com/Cosmian/kms/pull/244))
- Remove everything related to GCP images build ([#241](https://github.com/Cosmian/kms/pull/241))

### 📚 Documentation

- Oauth2 OIDC doc fixes

## [4.15.0] - 2024-04-08

### 🐛 Bug Fixes

- Add license to KMS GCP image ([#235](https://github.com/Cosmian/kms/pull/235))
- Re-enable the validation of JWT Issuer URI
- Fix CSE error status code, propagating the right status code instead of generic server code error

### 🚀 Features

- Handle many identity providers in jwt authentication
- New command line argument `--key-usage` to define key or certificate usage on import
- Exhaustive verification that the key used to perform cryptographic operations is allowed to do
  them
- KMIP object creation can now precisely define the usage of the key it describes

## [4.14.2] - 2024-04-05

### 🧪 CI

- Add standalone workflow to test KMS in Cosmian
  VM ([#233](https://github.com/Cosmian/kms/pull/233))

### 🚀 Features

- Rebase KMS GCP image on Cosmian VM 1.1.0-rc.4

## [4.14.1] - 2024-04-04

### 🧪 CI

- Remove optimization RUSTFLAGS ([#227](https://github.com/Cosmian/kms/pull/227))

### 🚀 Features

- Rebase KMS GCP image on Cosmian VM 1.1.0-rc.3

## [4.14.0] - 2024-03-27

### 🐛 Bug Fixes

- Fixed double quotes problem in cosmian vm test (CI)
- Fixed trailing null byte bug for biguint/bytes
  conversions ([#224](https://github.com/Cosmian/kms/pull/224))
- Make the CLI compile on Windows and macOS (without openssl
  installed) ([#209](https://github.com/Cosmian/kms/pull/209))

### 🚀 Features

- Support Veracrypt PKCS11 provider library ([#208](https://github.com/Cosmian/kms/pull/208))

### Testing

- Update `test_kms.py` to use covercrypt `14.0.0` ([#217](https://github.com/Cosmian/kms/pull/217))

## [4.13.5] - 2024-03-20

### 🐛 Bug Fixes

- Add missing image_licenses in packer for GCP ([#219](https://github.com/Cosmian/kms/pull/219))

## [4.13.4] - 2024-03-18

### 🧪 CI

- Push GCP images based on Cosmian VM 1.1.0-rc2

## [4.13.3] - 2024-03-11

### 🐛 Bug Fixes

- `ckms` needs `kmip` dependency with
  features `openssl` ([#202](https://github.com/Cosmian/kms/pull/202))

### 🧪 CI

- Push GCP images on cosmian-dev and cosmian-public only
  once ([#203](https://github.com/Cosmian/kms/pull/203))

## [4.13.2] - 2024-03-09

### 🧪 CI

- Filter reboot test on GCP/RHEL instance.

## [4.13.1] - 2024-03-08

### 🧪 CI

- Add build of GCP images (ubuntu/redhat) [#191](https://github.com/Cosmian/kms/pull/191).

## [4.13.0] - 2024-03-08

### 🚀 Features

- Save KMIP Attributes in a proper column of `Objects`
  table [#166](https://github.com/Cosmian/kms/pull/166):
    - Remove all custom tags `_cert_spki`, `_cert_cn`, `_cert_issuer` and `_cert_sk`
- Add support for CoverCrypt `rekey`, `prune`, and `Policy` editing
  methods [#179](https://github.com/Cosmian/kms/pull/179):
    - Add CLI commands to perform these actions
- Accurate CryptographicUsageMask for KMIP creation (RSA and EC
  keys) [#189](https://github.com/Cosmian/kms/pull/189)
  and [#187](https://github.com/Cosmian/kms/pull/187).

### Refactor

- Rework utils/crypto [#178](https://github.com/Cosmian/kms/pull/178).

### 🧪 CI

- Add build on RHEL9 [#196](https://github.com/Cosmian/kms/pull/196).
- Add build of GCP images (ubuntu/redhat) [#191](https://github.com/Cosmian/kms/pull/191).

### 🐛 Bug Fixes

- Fixing inconsistent crypto consts [#190](https://github.com/Cosmian/kms/pull/190).
- Fix interpolation in error macros [#184](https://github.com/Cosmian/kms/pull/184).
- Move internal KMIP Objects into `Box` to avoid stack memory
  overflow [#200](https://github.com/Cosmian/kms/pull/200).

## [4.12.0] - 2024-02-08

### 🚀 Features

- Generalize the refresh of JWKS in the middleware [#150](https://github.com/Cosmian/kms/pull/150).
- CI speed up [#173](https://github.com/Cosmian/kms/pull/173).
- Add support for Microsoft Double Key Encryption (DKE)
  endpoints [#170](https://github.com/Cosmian/kms/pull/170).
- Re-organized crypto package by algorithm, removed duplicated
  code [#170](https://github.com/Cosmian/kms/pull/170).
- Add support for FIPS mode for the ckms client [#170](https://github.com/Cosmian/kms/pull/170).
- Documented TOML configuration file for the KMS
  server [#170](https://github.com/Cosmian/kms/pull/170).
- Overall improvements to the documentation on algorithms and FIPS
  mode [#170](https://github.com/Cosmian/kms/pull/170).

## [4.11.3] - 2024-01-26

### 🚀 Features

- CLI: allow multiple operations to be supplied at once for access
  control [#155](https://github.com/Cosmian/kms/pull/155).

### ⚙️ Miscellaneous Tasks

- Business Source License 1.1

## [4.11.2] - 2024-01-23

### 🧪 CI

- Test and deliver in CI missing FIPS binary (fips.so and openssl.cnf for
  FIPS) [#152](https://github.com/Cosmian/kms/issues/153)

## [4.11.1] - 2024-01-18

### 🐛 Bug Fixes

- Load correct openssl provider on run

### 🧪 CI

- Pypi now requires a token to publish [#148](https://github.com/Cosmian/kms/issues/148)

## [4.11.0] - 2024-01-17

### 🐛 Bug Fixes

- Fix AES decryption: tag invalid size [#133](https://github.com/Cosmian/kms/issues/133)
- Remove bootstrap server leftovers [#142](https://github.com/Cosmian/kms/issues/142)

### 🚀 Features

- X509 v3 extensions support [#120](https://github.com/Cosmian/kms/issues/120)
- Dynamic salt for password derivation, resolving
  issue [#124](https://github.com/Cosmian/kms/issues/124) [#128](https://github.com/Cosmian/kms/issues/128)
- Support Cosmian VM [#129](https://github.com/Cosmian/kms/issues/129)
- Make rsa oaep aes a generalized encryption system for use in all kms and not only for key
  wrapping [#130](https://github.com/Cosmian/kms/issues/130)
- ECIES implementation for Hybrid Encryption [#134](https://github.com/Cosmian/kms/issues/134)
- Add pyo3 methods for
  symmetric `create_key`, `encrypt`, `decrypt` [#135](https://github.com/Cosmian/kms/issues/135)
- Add RSA keys create key pair [#137](https://github.com/Cosmian/kms/issues/137)
- Upgrade Rust toolchain to 2024-01-09 [#141](https://github.com/Cosmian/kms/issues/141)
- Support keypair generation for curve448 Montgomery and edwards
  forms [#143](https://github.com/Cosmian/kms/issues/143)

## [4.10.1] - 2023-12-12

### 📚 Documentation

- Fix mkdocs formatting

## [4.10.0] - 2023-12-11

### 🚀 Features

- Support for certificate generation using the Certify KMIP operation and a PKCS#10 or a public key
- Support for most standardized encoding formats on import.export: PKCS#8, PKCS#1, SEC1, X509,
  PKCS#12
- Improvements to the Locate functionality for attributes and tags
- Support for the Get Attributes KMIP operation
- Database: support for atomic operations
- Replaced part of Rust Crypto with openssl for more standardized module support
- Deactivated automatic certificate verification, which will be reallocated
  for the future `Validate` KMIP operation support [#102](https://github.com/Cosmian/kms/issues/102)
- Deactivated the non KMIP compliant certificate "quick create feature",
  which can now be achieved using the `Certify` KMIP
  operation [#103](https://github.com/Cosmian/kms/issues/103)

### 🐛 Bug Fixes

- Redis-Findex: `create` now checks for the pre-existence of the object
- Better KMIP compliance:
    - improved KeyBlock definition [#76](https://github.com/Cosmian/kms/issues/76)
    - enforced KMIP default export formats [#78](https://github.com/Cosmian/kms/issues/78)
    - aligned `Unique Identifier` to KMIP definition but only the `TextString` variant is supported.
    - Use od standards attributes instead of Vendor attributes wherever possible

## [4.9.1] - 2023-11-14

### 🐛 Bug Fixes

- KMIP server operations only support DER format for certificates ([#89](https://github.com/Cosmian/kms/pull/89))

## [4.9.0] - 2023-11-10

### 🐛 Bug Fixes

- fix: migrate to num-bigint-dig for bigint ([#85](https://github.com/Cosmian/kms/pull/85))

### 🧪 CI

- Test KMS inside an SGX machine

### 🚀 Features

- Update Covercrypt version to support Policy V2 ([#63])
- Generalize bulk operations using KMIP `Messages` structure

## [4.8.2] - 2023-10-31

### 🐛 Bug Fixes

- Save certs as DER instead of PEM for KMIP compliance

## [4.8.1] - 2023-10-12

### 🐛 Bug Fixes

- Fix for [#64](https://github.com/Cosmian/kms/issues/64)

## [4.8.0] - 2023-10-07

### 🐛 Bug Fixes

- Fix container build on tags
- Serialize the header for each chunk for Covercrypt bulk encryption ([#59](https://github.com/Cosmian/kms/pull/59))

### 🚀 Features

- KMS running inside TEE (SGX or SEV)
    - review the `verify` subcommand
    - force checking the leaf TLS certificate when querying a KMS running inside a TEE
    - verify RA-TLS certificate before querying the bootstrap server
    - review the TLS certificate generation using the key tied to the TEE
    - remove libsgx and create a new dependence to tee_attestation crate
    - update KMS server argument regarding the TEE and certbot
    - review documentation regarding the KMS usage inside a TEE
- Activate tracing in CLI tests when binary is instrumented ([#56])

### 🧪 CI

- Trigger public_documentation build on tags

## [4.7.0] - 2023-10-02

### 🚀 Features

- Added the wildcard user `*` to grant access rights to all users on an object
- About certificates:
    - add validation of the complete chain instead of the leaf and parent certificates
    - add verifications before using a certificate:
        - check that each certificate is not expired (both chain and leaf certificates)
        - check that no certificate is revoked (both chain and leaf certificates)
        - check that each certificate has a valid signature (both chain and leaf certificates)
        - check that certificate CRL signature is valid
    - add RSA X509 certificate support
    - add Covercrypt bulk encryption
- KMS CLI `ckms`:
    - can import the Mozilla Common CA Database (CCADB)
    - can import a PKCS12 certificate (splitting in 2 KMIP objects: X509 certificate and private
      key)

### 🐛 Bug Fixes

- Improved database data structures using Maps and Sets instead of Vectors where uniqueness is
  required
- Enable bootstrap server for non "enclaves" servers

## [4.6.0] - 2023-09-01

### 🐛 Bug Fixes

- Filter Locate request by object type

### 📚 Documentation

- Remove merge leftovers

### 🚀 Features

- bootstrap: the KMS server now supports bootstrap mode to facilitate the secure input of secret
  components, including the database encryption secret and the HTTPS certificate key, directly into
  the encrypted machine memory, through a secure connection
- Add certificate support:
    - in cosmian_kms_server:
        - implement `Certify` KMIP operation
        - in addition, the KMS server will automatically add:
            - the system tag `_cert` on `Certificate` object
            - the system tag `_cert_uid=<certificate_uid>` where `certificate_uid` is used as the
              link between public/private key objects and the related certificate object
            - the system tag `_cert_spki=<Subject Public Key Info>` on `Certificate` object where
              SPKI refers
              to [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280#section-4.1.2.7). The SPKI
              value identifies uniquely the underlying certificate
            - the system tag `_cert_ca=<Subject Common Name>` on CA `Certificate` object
        - import X509 certificate as PEM and also import private key as PEM
        - export generic KMIP key `wrapped` by X509 certificate
        - import a wrapped key with unwrapping on the fly
        - encrypt with X509 certificate and decrypt with PKCS8 private key
    - in `ckms`, add:
        - create/destroy certificate
        - export/import certificate
        - revoke certificate
- Add the export wrapping with X509 certificate encryption

## [4.5.0] - 2023-08-21

### 🐛 Bug Fixes

- Documentation

### 🚀 Features

- tagging: the KMS server now supports user tagging of objects to facilitate their management.
  Specify as many user tags as needed when creating and importing objects.

In addition, the user server will automatically add a system tag based on the object type:

- `_sk`: for a private key
- `_pk`: for a public key
- `_kk`: for a symmetric key
- `_uk`: for a Covercrypt user decryption key

Use the tags to export objects, locate them, or request data encryption and decryption.

- Added `locate` to the `ckms`client
- Added `Redis-Findex` backend support so that the KMS can encrypt the KMS server data and indexes
  at the application level.
- Added JWE support

## [4.4.3] - 2023-07-17

### 🐛 Bug Fixes

- Remove RUSTFLAGS for docker container and python package

### 🚀 Features

- Update sqlx to 0.7 + bitflags and base64-url to version 2

## [4.4.2] - 2023-06-13

### 🚀 Features

- Support glibc v2.17 when building ckms and cosmian_kms_server

## [4.4.1] - 2023-06-09

### 🐛 Bug Fixes

- Incorrect docker tag

### 📚 Documentation

- Add description on docker usage

## [4.4.0] - 2023-06-06

### 🚀 Features

- Added the ability to manipulate EC and Symmetric Keys
- Added ECIES encryption (using Curve 25519) and AES GCM encryption
- Added support for policy specifications
- Reworked Revoke and Destroy to be closer to KMIP definitions
- Revoking and Destroying a public/private key, revokes or destroy all the related keys
- Upgrading of SQLX
- Upgrading of PKCS12 support
- Removal of Eyre in the CLI
- Use of cloudproof_rust as a dependency rather than Covercrypt and Crypto Core directly to avoid
  version conflicts
- Authentication:
    - support for more JWT providers
    - support for certificate authentication
- Removal of global static conf and use of proper injection (was hindering testing)
- Authorization: re-factor of endpoints and fix delegation issues around revoke and destroy

### 📚 Documentation

- Add link to package.cosmian.com

### 🧪 CI

- Add github ci
- Publish python kms packages

### Refactor

- Refactored the server to simplify traits and separate the operations into smaller files

---

## [4.3.4] - 2023-03-09

### 🚀 Features

- Python KMS client (pyo3): export `database_secret` and `insecure` as parameters

### Testing

- Update cover crypt in python tests

---

## [4.3.3] - 2023-03-02

### 🚀 Features

- Use CoverCrypt v11

### Refactor

- Removed `mysql` crate used for EdgelessDB (compatible with client SSL connection)
- Use workspace dependencies to ease maintenance

---

## [4.3.2] - 2023-02-17

### 📚 Documentation

- mkdocs-merge could not run with `emoji_index` url

---

## [4.3.1] - 2023-02-16

### 🧪 CI

- Remove unused docker builds

---

## [4.3.0] - 2023-02-15

### 📚 Documentation

- Improves the installation doc and details the important options
- Makes wording coherent between doc and code

### 🚀 Features

- adds native HTTP/S support by providing certificates
- improves encrypted SQLite support

### ⚙️ Miscellaneous Tasks

- removes multiple features on the KMS server and makes them command-line options.
- There is now a single docker (115MB) that covers all cases (except SGX, which will come later)
- removes the use of crypto_base and makes use of cover-crypt 10.0

---

## [4.2.0] - 2023-01-30

### 🚀 Features

- Use CoverCrypt v9.0 (post-quantum cryptography) and AbePolicy v3.0
    - Write `Policy` as bytes and `AccessPolicy` as string in Vendor Attributes

### 🧪 CI

- Fix tag matching in `python_publish`

---

## [4.1.0] - 2023-01-19

### Added

- add python interface

### Changed

- CoverCrypt v9 / CryptoCore v5 / AbePolicy v3.0
- CLI Policy interface (format changed with AbePolicy v2.1)

---

## [4.0.1] - 2022-11-29

### Changed

- add authentication data in header too in encrypt operation

---

## [4.0.0] - 2022-11-28

### Added

### Changed

- data to encrypt with CoverCrypt is not a JSON anymore but a custom binary format (
  see `DataToEncrypt` struct)
- decrypted data with CoverCrypt is now a custom binary format (see `DecryptedData` struct)

### Fixed

### Removed

---

## [3.0.2] - 2022-11-16

### Added

### Changed

- Support `cover_crypt` 7.1.0

### Fixed

### Removed

---

## [3.0.1] - 2022-11-14

### Added

### Changed

### Fixed

- Rename KMS URL

### Removed

- Remove AVX flag

---

## [3.0.0] - 2022-11-09

### Added

### Changed

- Update `cover_crypt` to 7.0.1
- Update crates dependencies

### Fixed

### Removed

- GPSW support
- TFHE support
- DMCFE support

---

## [2.3.3] - 2022-10-25

### Added

- Handle CORS request

### Changed

- Update installation documentation

### Fixed

### Removed

---
