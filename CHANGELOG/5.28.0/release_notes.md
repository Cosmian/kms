# 5.28.0 release notes (full text)

Full text of the `## [5.28.0]` entry of `CHANGELOG.md` as it was before it was condensed into a summary.

## [5.28.0] - 2026-09-30

### 🔒 Security

- **`Extractable` / `NeverExtractable` not enforced on key export paths** ([GHSA-8mmx-f92q-2gq8](https://github.com/Cosmian/kms/security/advisories/GHSA-8mmx-f92q-2gq8)): `Get`, `Export`, and PKCS#12 export now enforce `Extractable`/`NeverExtractable`, deny non-extractable keys with `ResultReason::Not_Extractable`, require a non-empty password for sensitive PKCS#12 exports, and unconditionally latch server-managed `NeverExtractable` across creation/import and `ReKey`/`ReKeyKeyPair` rotations ([#1198](https://github.com/Cosmian/kms/pull/1198))
- **Reserved UID `*` bypassable via `AtomicOperation::Upsert` and `Certify` destination overwrite** ([GHSA-pvw2-jxwc-95xq](https://github.com/Cosmian/kms/security/advisories/GHSA-pvw2-jxwc-95xq)): `Database::atomic` now screens both `Create` and `Upsert` against the reserved-UID guard, `Certify` validates/authorizes destination UIDs, and all backends (SQLite, PostgreSQL, MySQL, Redis) atomically enforce ownership on `Upsert` without partial tag mutations ([#1198](https://github.com/Cosmian/kms/pull/1198))
- **`Sensitive` / `Extractable` attribute stripping via read-only `Get` grant** ([GHSA-c75c-3cmm-48h7](https://github.com/Cosmian/kms/security/advisories/GHSA-c75c-3cmm-48h7)): `DeleteAttribute` now rejects server-managed attributes (including `Sensitive` and `Extractable`) under both the by-value and by-tag branches, and mutating these attributes requires explicit operation grants or ownership instead of a read-only `Get` grant ([#1198](https://github.com/Cosmian/kms/pull/1198))
- **SPIRE PKI `sign-intermediate` issues CA certificates to any Vault token** (COSMIAN-2026-022, [#1234](https://github.com/Cosmian/kms/pull/1234)): `POST /v1/{pki_mount}/root/sign-intermediate` now requires the caller's KMS identity (`spire:<AppRole name>`) to hold the `certify` grant on the CA private key; CA keys are looked up only among keys owned by `default_username`, and CSRs requesting `basicConstraints` are rejected to preserve `pathlen:0` (**Upgrade action:** run `ckms access-rights grant spire:<AppRole name> certify --object-uid <ca-private-key-uid>`)
- **SPIRE transit key substitution via shared tags** (COSMIAN-2026-023, [#1234](https://github.com/Cosmian/kms/pull/1234)): transit key resolution (`sign`, `GET /keys/{name}`, list, delete) now restricts lookups to keys owned by the caller, preventing key substitution via shared tags; creating an existing key name is idempotent
- **Any user can publish a key on the unauthenticated JWKS endpoint** (COSMIAN-2026-024, [#1234](https://github.com/Cosmian/kms/pull/1234)): `/.well-known/jwks.json` now publishes only keys owned by `default_username`, preventing unauthorized key injection via shared keys
- **JOSE tag endpoints allow tag changes with any grant** (COSMIAN-2026-025, [#1234](https://github.com/Cosmian/kms/pull/1234)): `POST`/`DELETE /v1/crypto/keys/{kid}/tags` now enforce `add_attribute` / `delete_attribute` permissions instead of general read access
- **PKCS#11 module buffer overflows in `C_GetAttributeValue` and `C_Encrypt`** (COSMIAN-2026-026, [#1234](https://github.com/Cosmian/kms/pull/1234)): caller buffer length is verified before writing output to prevent buffer overflow; returns `CKR_BUFFER_TOO_SMALL`; `C_GenerateKey` now rejects a null `phKey` with `CKR_ARGUMENTS_BAD`
- **CRL/OCSP revocation status could be lost, stale or wrong** (COSMIAN-2026-027, [#1234](https://github.com/Cosmian/kms/pull/1234)): `Destroy` preserves issuer link and revocation metadata so destroyed certificates remain reported as revoked (RFC 5280 §3.3); certificate serials are generated as random 159-bit integers instead of SHA-1(SPKI) to avoid serial collisions on `ReCertify`; OCSP response cache is keyed by full `CertID`, bounded, respects `nextUpdate`, and skips caching `unknown`; OCSP requires CA match for all `CertID`s; automatic CRL regeneration runs on behalf of the CA owner; stored CRL is re-read from the DB every 60 s; wrapped CA keys are unwrapped for CRL/OCSP signing; `Validate`/`Import` CRL cache enforces 5-minute freshness and does not hold locks during network I/O
- **SSRF check bypass via `kms_public_url` prefix match in CRL fetching** (COSMIAN-2026-028, [#1234](https://github.com/Cosmian/kms/pull/1234)): URL comparison in CRL fetching compares parsed scheme, host, port, and base path, rejecting URLs with embedded credentials to prevent SSRF bypass
- Harden asymmetric `DeriveKey` curve validation to check the OpenSSL key `Id` actually constructed from each referenced object's key material, closing an Ed25519/X25519 key-type confusion edge case (both curves share a 32-byte raw key length) ([#1170](https://github.com/Cosmian/kms/pull/1170))
- Remove unmaintained/unsound transitive dependencies: `smol-toml` 1.6.1 → 1.8.0 ([CVE-2026-85730](https://github.com/advisories/GHSA-7w5x-hrqm-74c2)), `axum-server` 0.7 → 0.8 to drop unmaintained `rustls-pemfile` ([RUSTSEC-2025-0134](https://rustsec.org/advisories/RUSTSEC-2025-0134), [#1180](https://github.com/Cosmian/kms/pull/1180)), `rustls` 0.23.43 → 0.23.45, and upgraded `kube` to remove unmaintained deps

### 🚀 Features

#### Audit Logging & SIEM Export

- Add a tamper-evident, cryptographically-chained JSONL audit log of every KMIP operation ([#934](https://github.com/Cosmian/kms/pull/934)): each event carries an `id`, `prev_hash`, and `row_hash` (SHA-256), fsync'd after every write; truncation/reordering/modification breaks the chain and is detected by the new `ckms audit verify` command
- Add per-`BatchItem` audit events with a shared UUID v4 `request_id` (fan-out of batch `RequestMessage` calls) for SIEM/log correlation
- Add a `ckms audit verify --path <file|dir>` CLI command: verifies each `row_hash` and `prev_hash` link, validates every `*.jsonl` chain in a directory, and confirms sealed `audit:reanchor` evidence files still exist and hash-match on disk
- Add Common Event Format (CEF) serialization (`to_cef_line()`) for direct ArcSight/Splunk/QRadar ingestion, with a `devicePayloadId=<uuid>` extension when `request_id` is present
- Add drop-detection: when the bounded audit channel is full, an `audit:eviction` sentinel event is written into the chain so lost events are detectable by `ckms audit verify`
- Add configurable trusted-proxy CIDR validation for `X-Forwarded-For`, preventing client IP spoofing in audit logs (`--audit-trusted-proxy-cidrs`)
- Add configurable audit failure mode (`--audit-failure-mode continue|reject`): `reject` returns HTTP 503 when an event cannot be queued
- Add an always-start recovery model ([#1126](https://github.com/Cosmian/kms/pull/1126)): startup no longer aborts on a corrupted audit tail — torn writes are truncated and continued (with an `audit:torn-write-recovered` sentinel), tampered rows trigger seal-and-roll to a forensic `<name>.<ts>.<hex>.corrupt.<ext>` file plus a fresh `audit:reanchor` chain, the entire hash chain is verified on every boot, a best-effort cross-platform exclusive lock prevents two KMS instances corrupting a shared-volume log, and an unwritable path self-heals via periodic retry
- Add optional `--audit-file-max-size-bytes` write-stop cap (no rotation/retention)

#### SPIFFE / Workload Identity ([#1206](https://github.com/Cosmian/kms/pull/1206))

- Add opt-in SPIFFE JWT-SVID workload authentication (`--jwt-svid-auth` / `KMS_JWT_SVID_AUTH` / `[idp_auth] jwt_svid_auth`): a validated JWT without an `email` claim is accepted when `sub` starts with `spiffe://`, becoming the KMS user/owner (audit method `JwtSvid`); audience is required, and mTLS client-cert CN takes precedence over JWT-SVID
- Add `ckms login spire --audience <aud> [--spiffe-id <id>] [--socket-path <path|uri>]` (SPIRE Agent Workload API)
- Add `POST /ui/login_svid` BFF endpoint and `GET /ui/auth_method` advertising `SPIFFE`; the `kms setup` wizard now asks whether JWT/OIDC providers issue SPIFFE JWT-SVIDs

#### X25519 ECDH ([#1170](https://github.com/Cosmian/kms/pull/1170))

- Add non-FIPS X25519 key agreement to KMIP `DeriveKey`, including repeated base-object identifiers for asymmetric two-key derivation (`DeriveKey::new_single_base` / `new_asymmetric`); shared secrets are stored as non-extractable `SecretData` with reciprocal derivation links
- Add `ckms derive-key --x25519 --private-key-id <ID> --peer-public-key-id <ID>` and a WASM export `derive_key_asymmetric_ttlv_request` for the Web UI
- Add an "X25519 ECDH" derivation method to the Derive Key Web UI page (private-key and peer-public-key selectors, fixed 256-bit `SecretData` output)

#### JOSE / REST Crypto API ([#1033](https://github.com/Cosmian/kms/issues/1033))

- Add ECDH-ES decrypt support to `/v1/crypto/decrypt` (RFC 7518 §4.6): `ECDH-ES`, `ECDH-ES+A128KW`, `ECDH-ES+A256KW` with `A128GCM`/`A192GCM`/`A256GCM` content encryption, over P-256/P-384/P-521 (FIPS) and X25519 (non-FIPS)
- Add `/v1/crypto/keys` key creation for `ECDH-ES*` algorithms (KeyAgreement usage), and publish X25519 static public keys via `/.well-known/jwks.json` (`kty=OKP`)
- Add an `ecdh_key_agreement` primitive and RFC 7518 Appendix C / NIST SP 800-56A Concat KDF to `cosmian_kms_crypto`

#### Database TDE Integrations ([#1162](https://github.com/Cosmian/kms/pull/1162))

- Add SAP ASE (Adaptive Server Enterprise) TDE support via `cosmian_pkcs11`, and IBM Db2 LUW TDE support via the native IBM GSKit KMIP client over mutual TLS

### 🐛 Bug Fixes

#### Database

- Fix `kms.keys.active.count` metric never updating on PostgreSQL (JSONB `?` operator applied to a `VARCHAR` column); now casts `object::jsonb` and logs failures at `warn!` level ([#1203](https://github.com/Cosmian/kms/pull/1203))
- Enable Redis TLS (`rediss://`) for the Redis-findex backend by enabling `tls-native-tls` / `tokio-native-tls-comp` ([#1195](https://github.com/Cosmian/kms/pull/1195), [#1204](https://github.com/Cosmian/kms/pull/1204))
- Add a `(tag, id)` index on all three SQL backends to turn tag-based `Locate` lookups into index-only scans ([#1224](https://github.com/Cosmian/kms/pull/1224))
- Add JSON-expression indexes for keyset resolution (`find_by_rotate_name`), the auto-rotation scheduler, and ObjectType filters on PostgreSQL/SQLite, and make `kms.keys.active.count` filter on the `ObjectType` attribute instead of parsing every row's JSON ([#1224](https://github.com/Cosmian/kms/pull/1224))
- Rewrite `Locate`-by-tags as per-tag `INNER JOIN`s with `EXISTS`-based read-access probes, pushing `LIMIT`/server cap and destroyed-object exclusion into the query so the DB stops after the requested page ([#1224](https://github.com/Cosmian/kms/pull/1224))

#### Permissions / Access Control

- `GET /access/obtained` and KMIP `Locate` now include permissions granted to the wildcard user `*`, consistent with per-object permission checks ([#1188](https://github.com/Cosmian/kms/pull/1188))
- Fix `RedisWithFindex::list_user_operations_granted` mispairing permission entries with objects by `zip`-ing two independently-ordered `HashMap`s instead of joining by object uid ([#1188](https://github.com/Cosmian/kms/pull/1188))

#### Cache

- Fix cross-node cache invalidation: the per-process object cache now performs bounded-revalidation checks against shared state so revoked/destroyed keys are not served stale from a peer node's cache ([#1199](https://github.com/Cosmian/kms/pull/1199))

#### JOSE

- Fix `/.well-known/jwks.json` publishing EC keys authorized for `KeyAgreement` (but not `Verify`) with a signature `use`/`alg` claim (`ES256`/`ES384`) instead of `use=enc` with no `alg`

### ♻️ Refactor

- `crate/server`: introduce the audit middleware/extension-injection architecture and `AuditFileStore` single-writer task, splitting the KMIP route module into `routes/kmip/` (`handlers.rs`, `audit.rs`)
- `crate/access`: add `audit::{event, hash, cef, file_hash}` with canonical event hashing, CEF serialization, and file-tail hash helpers
- `crate/server_database`: rework the SQL `Locate` query builder (`locate_query.rs`) and shared SQL/MySQL/SQLite query files for index-backed lookups and JSONB-aware predicates
- `crate/kmip`: widen `DeriveKey` identifier fields to `Vec` (KMIP 1.4 `unique_identifier` and 2.1 `object_unique_identifier`) for asymmetric derivation
- `crate/crypto`: add `concat_kdf` (RFC 7518 Appendix C) and a generic P-256/P-384/P-521 `ecdh_key_agreement` primitive

### 🧪 Testing

- Add SIEM integration suites: `mise test:audit` (hash-chain integrity, required fields), `mise test:cef` (CEF v27 format + UDP/TCP syslog with RFC 6587 octet-counting), `mise test:siem` (Filebeat/Fluent Bit), `mise test:monitoring` (OTel Collector + VictoriaMetrics + Grafana), plus live-audit-fixture generation and OpenSearch/Splunk JSONL compat checks in CI ([#1115](https://github.com/Cosmian/kms/pull/1115), [#1150](https://github.com/Cosmian/kms/pull/1150), [#1131](https://github.com/Cosmian/kms/pull/1131))
- Add SAP ASE (`test:ase`) and IBM Db2 LUW (`test:db2`) Docker-based TDE integration suites ([#1162](https://github.com/Cosmian/kms/pull/1162))
- Add X25519 `DeriveKey` KMIP vectors, RFC 7518 Appendix C Concat KDF known-answer vectors, and an ECDH-ES test suite (round trips, `kid` link-following, AAD binding, and negative key-confusion/FIPS-rejection cases)
- Add SPIFFE JWT-SVID end-to-end suite (`spire-jwt-svid`) minting an SVID against a live SPIRE server
- Add `always-sensitive` and attribute-read-only security regression tests, plus wildcard-grant and shared-DB (`KMS_TEST_DB=postgresql|mysql|redis-findex`) test coverage — the full external-DB nextest run now passes 2085/2085 ([#1188](https://github.com/Cosmian/kms/pull/1188))
- Expand `mise test` to run every task under `.mise/tasks/test/`, auto-skipping groups whose infra/credentials are unavailable, with a final PASS/SKIP/FAIL summary ([#1188](https://github.com/Cosmian/kms/pull/1188))

### ⚙️ Build

- Sign Windows installers with Azure Trusted Signing ([#1101](https://github.com/Cosmian/kms/pull/1101)); embed Windows `VERSIONINFO` resources in `ckms.exe`, `cosmian_kms.exe`, `cosmian_pkcs11.dll`, and `cosmian_cng.dll`
- Flatten the Windows build artifact for signing ([#1229](https://github.com/Cosmian/kms/pull/1229)); set up pnpm 10 and Node 22 in the Windows packaging workflow ([#1197](https://github.com/Cosmian/kms/pull/1197))
- Bump UI dependencies (`brace-expansion`, `js-yaml`, `nanoid`, `moment`, `@vitest/mocker`) ([#1163](https://github.com/Cosmian/kms/pull/1163), [#1185](https://github.com/Cosmian/kms/pull/1185), [#1230](https://github.com/Cosmian/kms/pull/1230), [#1231](https://github.com/Cosmian/kms/pull/1231))
- Consolidate AWS XKS, Splunk, and OpenSearch audit-compat tests into `test_all.yml`; pin Splunk/OpenSearch images and regenerate live audit fixtures instead of static samples

### 📚 Documentation

- Add audit-logging, CEF-export, and SIEM configuration references (`configuration/audit-logs.md`, `configuration/cef-export.md`, `configuration/siems.md`) with Mermaid sequence diagrams, plus ADRs for the single-writer design, middleware extension injection, CEF export format, always-start recovery, and SPIFFE JWT-SVID authentication
- Add SAP ASE and IBM Db2 LUW TDE integration guides with architecture walkthroughs, and update the README database integration table ([#1162](https://github.com/Cosmian/kms/pull/1162))
- Add SPIFFE guides for the CLI, Web UI gateway/BFF flow, and workload authentication, plus the X25519 → HKDF → `ChaCha20Poly1305` sealing workflow
- Reorganize observability docs (rename `otlp-metrics.md` → `otlp-telemetry.md`) and document the Windows signing-certificate trust model in `kms_clients/installation.md`
