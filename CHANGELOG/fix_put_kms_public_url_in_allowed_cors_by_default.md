# develop

## Features

- **PKI / Auto-inject CRL Distribution Point into issued certificates**: the Certify
  operation now automatically adds a `crlDistributionPoints` extension (RFC 5280 §4.2.1.13)
  pointing to the KMS public CRL endpoint (`{kms_public_url}/public/certificates/{issuer_id}/crl`)
  when `kms_public_url` is configured, the certificate is not self-signed, and neither the
  subject nor the user-supplied extension config already provides a CDP. Self-signed certs
  continue to receive `id-ce-noRevAvail` (RFC 9608) instead. Re-certifications that already
  carry a CDP are not modified.

- **PKI / CRL generation**: add X.509 v2 CRL generation per RFC 5280 §5.
  New REST endpoint `GET /certificates/{issuer_id}/crl` returns a signed CRL
  (DER or PEM) containing all revoked certificates issued by the given CA.
  New CLI command `ckms certificates generate-crl`. Web UI support via
  Certificates → Certs → Generate CRL.

- **PKI / Public CRL Distribution Point**: new unauthenticated endpoint
  `GET /public/certificates/{issuer_id}/crl` serves pre-signed CRL DER bytes
  from an in-memory cache so that any PKI relying party (browser, TLS stack,
  OCSP client) can fetch CDP URIs without KMS credentials (RFC 5280 §3).
  The cache is populated every time the authenticated CRL generation endpoint
  is called. Returns HTTP 404 with a diagnostic message until the cache is primed.

- **PKI / Extended RevocationReasonCode coverage**: `RevocationReasonCode` now
  includes `CertificateHold` (0x8000_0001), `RemoveFromCRL` (0x8000_0002), and
  `AaCompromise` (0x8000_0003) as KMIP vendor-extension codes (8XXXXXXX range per
  KMIP 2.1 §11.48). These correspond to RFC 5280 §5.3.1 reason codes absent from
  the KMIP standard set. `kmip_reason_to_crl_reason()` is now fully exhaustive.

- **PQC key export as Raw bytes**: PQC keys (ML-KEM, ML-DSA, SLH-DSA) stored
  internally as PKCS#8/SPKI can now be exported with `KeyFormatType::Raw`.
  The server performs on-the-fly PKCS#8→Raw conversion using OpenSSL's
  `EVP_PKEY_get_raw_*_key` APIs. Compliant with KMIP v3.0 CSD01 which defines
  no Transparent key structures for PQC algorithms.

## Bug Fixes

- **PKI / CRL freshness**: `verify_crls()` now enforces the `nextUpdate` field
  (RFC 5280 §6.3 §5.1.2.5). Expired CRLs are now hard-rejected with a descriptive
  error message instead of being silently accepted.

- **PKI / HTTP CRL signature enforcement**: CRLs fetched from `http://` or `https://`
  URLs whose signature cannot be verified against any issuer in the chain are now
  rejected with a hard error (previously only a warning). File-path CRLs keep the
  warn-and-continue behavior (trusted local delivery).

- **Revocation persistence**: fix revocation reason not being persisted in object
  attributes when revoking a certificate or key. The reason is now stored in both
  the external attributes and the object's own attributes.

- **CRL cache**: file-path CRLs are no longer cached in memory. Unlike HTTP CRLs,
  file reads are cheap and the file may be updated after a revocation triggers CRL
  regeneration. This ensures that `Validate` always picks up fresh CRL data from disk.

- **CRL validation with file:// URIs**: `file://` URIs in certificate CDP extensions
  were incorrectly treated as web URLs and skipped during CRL validation. They are now
  correctly converted to local filesystem paths via `url.to_file_path()`.

- **TTLV normalizer: AttributeValue collapse for structured types**: fix KMIP 1.4
  `RevocationReason` deserialization failure caused by the TTLV post-serialization
  normalizer incorrectly collapsing single-child `AttributeValue(Structure[...])` nodes
  into bare scalar values. The normalizer's "type wrapper" collapse (step 8) is now
  limited to same-tag wrappers only; the `AttributeValue` case is handled exclusively
  by step 2b which respects TYPE_TAGS boundaries.

- **CORS / Web UI**: when `cors_allowed_origins` is not explicitly configured, `kms_public_url`
  is now automatically included in the in-RAM CORS allow-list alongside the standard loopback
  defaults. This fixes the Web UI being inaccessible after upgrading from 5.16.x to 5.22+ when
  `kms_public_url` was set but `cors_allowed_origins` was absent from the TOML config.
  The configuration wizard already added `kms_public_url` to generated configs; this change
  closes the gap for hand-written configuration files. Explicit `cors_allowed_origins` lists
  are used verbatim — `kms_public_url` is not merged in.

## Documentation

- **PKI / pki.md**: added Delta CRLs (RFC 5280 §5.4) to the "Not supported" section.

## Testing

- **Test data / certificate fixtures**: regenerated `test_data/certificates/csr/intermediate.crt`,
  `leaf.crt`, `leaf.p12`, and `intermediate.p12` without a CRL Distribution Point extension.
  The prior versions embedded an expired CDP URL (`https://package.cosmian.com/kms/crl_tests/…`)
  which caused test failures once CRL freshness enforcement (P1.1) was added.
  Updated `test_data/certificates/openssl/ext.cnf` `[v3_ca]` section to use an LDAP CRL DP
  (skipped by `verify_crls` which only fetches HTTP/HTTPS URLs), so certify-with-extensions
  tests continue to verify that CDP extensions are properly embedded without triggering an
  expired-CRL error.

- **Validate / CRL unreachable soft-fail**: `verify_crls` now catches
  `KmsError::ClientConnectionError` (network/DNS failure fetching a CRL) and
  continues with a warning instead of propagating a 500. Hard errors (expired
  CRL, explicit revocation, bad signature) still propagate as before. This
  ensures that test certificates with a non-live CRL DP (e.g. `http://crl.example.com/…`)
  do not break the Validate operation.

- **Validate / RFC 5280 §6.3 compliance**: `validate.rs` now catches all `verify_crls` errors
  and re-maps them as `KmsError::Certificate` rather than letting `ServerError` variants
  propagate as a 500. An expired or unverifiable CRL correctly surfaces as a certificate
  chain validation failure (consistent with existing revocation-fail behavior).

- **CRL validation lifecycle**: end-to-end test that creates a CA, issues a cert
  with `crlDistributionPoints=URI:file://...`, validates the cert (happy path),
  revokes it, regenerates the CRL, then validates again (expects failure).

- **PQC export Raw roundtrip**: generates PQC key pairs (ML-DSA-44, ML-KEM-768,
  SLH-DSA-SHA2-128s), exports as Raw and as PKCS#8, locally converts PKCS#8→Raw,
  and asserts byte-equality between the two paths.

- **Vector: CRL validation lifecycle** (`test_data/vectors/fips/kmip_operations/crl_validation_lifecycle/`):
  16-step regression vector exercising full CRL validation with dynamic file:// CDP URIs,
  including `AllocTempFile`, `GenerateCrl`, and `{{hex:variable}}` template substitution.

- **Vector: ML-DSA-44 export Raw** (`test_data/vectors/fips/asymmetric/ml_dsa_44_export_raw/`):
  regression vector for PQC key export with `KeyFormatType::Raw`.

- **Vector: ML-KEM-768 export Raw** (`test_data/vectors/fips/asymmetric/ml_kem_768_export_raw/`):
  regression vector for PQC key export with `KeyFormatType::Raw`.

- **Vector runner extensions**: added `AllocTempFile` pseudo-operation, `GenerateCrl` REST
  operation, and `{{hex:variable}}` template substitution to the vector runner framework.

## Refactor

- **`crate/crypto`**: replace direct dependency on `foreign-types-shared 0.1` with
  `foreign-types 0.3` (the crate that re-exports `ForeignType`/`ForeignTypeRef` publicly).
  `foreign-types-shared` is an internal implementation detail of `foreign-types`; depending
  on it directly was an inadvertent coupling to an internal sub-crate.

- **CRL RFC 5280 integration tests** (`crate/test_kms_server/src/crl_tests.rs`): added 7
  new tests covering all RFC 5280 §5 CRL requirements:
    - `test_crl_partial_revocation_exact_count`: 5 certs issued, 3 revoked — asserts count = 3.
    - `test_crl_cross_ca_isolation`: cert issued by CA-B and revoked must not appear in CA-A's CRL.
    - `test_crl_all_revocation_reason_codes`: all 7 RFC 5280 §5.3.1 reason codes each produce one CRL entry.
    - `test_crl_deactivated_and_compromised_states`: certs in both KMIP Deactivated and Compromised states appear in the CRL.
    - `test_crl_incremental_generation_unique_crls`: successive CRL generations produce different DER bytes (CRL Number increments).
    - `test_crl_validity_period`: `nextUpdate - thisUpdate` matches the requested `validity_days` (±1 day tolerance) for 1, 7, and 30 days.
    - `test_crl_required_extensions_aki_and_number`: CRL carries OIDs 2.5.29.35 (`AuthorityKeyIdentifier`) and 2.5.29.20 (`CRLNumber`) per RFC 5280 §5.2.1 and §5.2.3.
  Added `x509-parser` as a dependency of `test_kms_server` for DER-level CRL extension inspection.

- **CRL / AKI FIPS compatibility**: `add_aki_extension` in `crate/crypto/src/openssl/crl.rs` now
  builds the Authority Key Identifier extension manually (RFC 5280 §5.2.1) instead of using
  `X509V3_EXT_nconf_nid` with `keyid`/`keyid:always`. The old approach called `EVP_sha1()` when
  the issuer certificate lacked a `subjectKeyIdentifier` extension, which fails under the FIPS
  provider (SHA-1 is not FIPS-approved for new use). The replacement uses `openssl::sha::Sha1`
  (low-level C interface, bypass the provider mechanism) to hash the issuer's SPKI DER, and
  encodes the AKI DER structure directly — making CRL generation FIPS-safe for all issuer
  certificate types. Fixes `test_crl_required_extensions_aki_and_number` failing on all FIPS DB
  backends in CI.

- **CRL / Windows file:// URI fix**: `test_crl_validation_lifecycle` and the
  `crl_validation_lifecycle` vector now use cross-platform file:// URIs when embedding
  `crlDistributionPoints` in test certificates. On Windows, raw paths like `C:\path\file.pem`
  produced an invalid `file://C:\path\file.pem` URI (OS error 123). The fix converts paths to
  the standard `file:///C:/path/file.pem` form via the new `path_to_file_uri` helper. The
  `AllocTempFile` vector pseudo-step now automatically exposes `{capture_as}_url` alongside
  `{capture_as}` for use in manifest templates. Fixes `crl_tests::test_crl_validation_lifecycle`
  and `vector_runner::tests::test_vec_crl_validation_lifecycle` on Windows CI.

- **`crate/test_kms_server`**: remove redundant direct dependency on `cosmian_kms_crypto`.
  The crate is already reachable via `cosmian_kms_server` → `cosmian_kms_server_database` →
  `reexport::cosmian_kms_crypto`. Replaced with a direct dep on `cosmian_kms_server_database`
  and updated import paths accordingly.

- **OpenAPI / Swagger**: add `GET /certificates/{issuer_id}/crl` endpoint with `Certificates`
  tag, path/query parameters, and DER/PEM response schemas.

## Bug Fixes (PR #987 review)

- **crl.rs: format parameter validation**: the `format` query parameter is now validated;
  non-`"der"` / non-`"pem"` values return HTTP 400 `Invalid Request` instead of silently
  defaulting to DER. ([#987](https://github.com/Cosmian/kms/pull/987))

- **crl.rs: Last-Modified header format**: the `Last-Modified` response header now uses
  RFC 7231 IMF-fixdate format (e.g. `Sun, 06 Nov 1994 08:49:37 GMT`) instead of an
  ISO 8601 timestamp. ([#987](https://github.com/Cosmian/kms/pull/987))

- **validate.rs: misleading CRL comment**: the inline comment incorrectly stated that a
  missing or expired CRL must be treated as a revocation failure (hard-fail). It now correctly
  describes the soft-fail behavior already implemented in `verify_crls()`.
  ([#987](https://github.com/Cosmian/kms/pull/987))

- **vector_runner: Windows path JSON-escaping**: `load_request_json` now JSON-escapes
  captured placeholder values (`\` → `\\`, `"` → `\"`, control chars) before substituting
  them into JSON template strings. On Windows, temp-file paths like
  `C:\Users\…\kms_vector_0.pem` contained unescaped backslashes that made
  `serde_json::from_str` fail with "invalid escape". This was the root cause of the
  `vector_runner::tests::test_vec_crl_validation_lifecycle` failure on Windows CI
  (`job/80099022383`). ([#987](https://github.com/Cosmian/kms/pull/987))

- **build_certificate.rs: DER length overflow**: `encode_der_length` previously silently
  truncated lengths > 65535 bytes. It now returns `KResult<()>` and propagates an
  `InvalidRequest` error for oversized CDP URIs. ([#987](https://github.com/Cosmian/kms/pull/987))

- **generate_crl.rs: CRL Number monotonicity across server restarts** (RFC 5280 §5.2.3): the
  CRL sequence counter was previously seeded only from the UTC Unix timestamp on every startup.
  After restart the new seed could be lower than previously issued CRL Numbers stored in the
  database, violating RFC 5280 §5.2.3 ("subsequent CRLs MUST have a larger CRL number"). Fix:
  - Added `get_max_crl_number()` to the `PermissionsStore` trait and all four backends
    (SQLite, PostgreSQL, MySQL, Redis).
  - `KMS::instantiate` now reads the highest stored CRL Number from the DB and seeds the
    counter as `max(unix_timestamp, db_max + 1)`, guaranteeing strict monotonicity across
    server restarts. ([#987](https://github.com/Cosmian/kms/pull/987))

- **generate_crl.rs: cRLSign keyUsage not enforced** (RFC 5280 §4.2.1.3): OpenSSL's
  `X509_CRL_sign()` does not check the issuer key's `keyUsage` extension. If a CA
  certificate declared `keyUsage` without the `cRLSign` bit, the KMS would silently sign and
  serve a CRL that RFC-conforming relying parties reject during path validation. Fix: added a
  runtime check in `generate_crl()` using `x509_parser` that returns
  `KmsError::InvalidRequest` with an RFC citation when `cRLSign` is absent.
  Also regenerated `test_data/certificates/csr/intermediate.crt` (and `.p12`) to include
  `cRLSign` in the `keyUsage` extension, as the previous fixture lacked it.
  ([#987](https://github.com/Cosmian/kms/pull/987))

- **MySQL: get_max_crl_number panics on empty crls table**: `SELECT MAX(crl_number) FROM crls`
  returns a single row with a `NULL` value when the table is empty. The MySQL implementation
  used `row.take::<i64>(0)` which panics in `mysql_common` on NULL conversion (line 123).
  Fix: changed to `row.take::<Option<i64>, _>(0).flatten()` — returns `None` for NULL,
  `Some(v)` for an actual value. Caught by `tests::test_db_mysql` on CI
  (mariadb non-fips, run `32632202380`). ([#987](https://github.com/Cosmian/kms/pull/987))

## Testing (RFC compliance and role-based CRL)

- **Comprehensive CRL test suite** (`crate/server/src/tests/crl_tests.rs`, 20 tests):
  new dedicated test module covering all four mandatory layers:
  - *Unit*: `test_build_empty_crl`, `test_build_crl_with_entries`,
    `test_crl_reason_asn1_tag_is_enumerated` (asserts the `CRLReason` extension is encoded
    as ASN.1 `ENUMERATED` tag `0x0A`, not `INTEGER` `0x02` — guards against future OpenSSL
    ABI regression).
  - *DB persistence* (`crl_persistence()` helper in `permissions_test.rs`, called from
    every backend test): empty table → `None`, upsert round-trip, `MAX` across multiple
    issuers, upsert-replace, `list_crl_issuers`, counter seed invariant
    (`seed > db_max` always holds).
  - *Functional*: empty CRL; CRL includes cert after revocation; CRL Number increases;
    CRL persisted to DB; DER and PEM both valid; cache consistent with DB; public CDP
    endpoint 404 before generation, valid DER after generation.
  - *Security / non-regression*: `cRLSign` keyUsage enforcement (RFC 5280 §4.2.1.3);
    non-certificate issuer rejected; `removeFromCRL` absent in complete CRL
    (RFC 5280 §5.3.1); CRL Number monotonicity restart invariant; all 8 KMIP
    `RevocationReasonCode` values produce the correct RFC 5280 reason codes with
    ENUMERATED tag verification.

- **CRL completeness with and without Crypto Officer role** (4 tests):
  - *No-CO scenario* (`test_crl_no_co_all_revoked_certs_present`): alice owns the CA;
    alice certifies `leaf_alice` (alice-owned); bob certifies `leaf_bob` via delegated
    access (bob-owned). Alice and bob each self-revoke their own leaf. Alice generates
    the CRL — both serials must be present, proving `find_all` crosses DB ownership
    boundaries.
  - *CO bypass scenario* (`test_crl_co_revokes_cert_owned_by_other_user`): CO=alice;
    bob owns `leaf_bob`. Assert: bob is NOT CO; alice IS CO; bob cannot revoke alice's
    cert (permission denied). Alice (as CO) revokes bob's cert via ownership bypass.
    CRL must contain both (alice's leaf + bob's leaf).
  - *Mixed scenario* (`test_crl_mixed_co_and_non_co_revocations_all_present`): CO=alice,
    regular users bob and charlie. Alice (CO) revokes her own leaf and bob's leaf; charlie
    self-revokes. Incremental CRL check after each event (1 → 2 → 3 entries). Final CRL
    must contain all three serials.
  - *Access control* (`test_crl_non_co_cannot_generate_crl_without_ca_access`): non-owner
    non-CO user cannot generate the CRL for another user's CA.

- **Counting-revoked-certificates tests** (2 tests, `COUNT_CERTS = 5`):
  These are the definitive count-correctness gate. Each test revokes one cert at a time and
  asserts the CRL entry count equals the number of revocations performed so far, with every
  revoked serial present exactly once (no duplicates, no missing entries).
  - `test_crl_counting_revoked_certs_no_co`: `ca_owner` owns the CA; 5 distinct non-CO users
    each certify and self-revoke their own leaf. After every step k: count == k.
  - `test_crl_counting_revoked_certs_with_co`: CO=alice owns CA; 5 distinct non-CO users
    own one leaf each. Alice (CO) revokes each leaf via ownership bypass. Per-step assertion:
    count == k; no duplicate serials. Proves CO bypass produces correct DB state that
    `find_all` collects precisely.

## Process

- **Mandatory test coverage rule** (`.github/instructions/rust.instructions.md`): updated
  the Testing section with a bold mandatory rule requiring four test layers for every new
  Rust feature: (1) unit tests in `#[cfg(test)]` submodule, (2) DB persistence helper
  called from all backend tests, (3) functional tests in a dedicated `<feature>_tests.rs`,
  (4) security/non-regression tests. Includes per-layer content checklists, the CRL test
  suite as the canonical reference implementation, and a template for new test files.
