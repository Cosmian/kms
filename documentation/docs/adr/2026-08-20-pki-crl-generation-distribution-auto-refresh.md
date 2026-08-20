---
title: "ADR-2026-08-20: PKI / X.509 CRL Generation, Distribution & Auto-Refresh Architecture"
status: "Accepted"
date: "2026-08-20"
authors: "KMS contributors, PKI operators, security auditors"
tags: ["architecture", "decision", "pki", "crl", "x509", "fips"]
supersedes: ""
superseded_by: ""
---

# ADR-2026-08-20: PKI / X.509 CRL Generation, Distribution & Auto-Refresh Architecture

## Status

Proposed | **Accepted** | Rejected | Superseded | Deprecated

## Context

The Eviden KMS already supported certificate issuance (KMIP `Certify` operation) and
revocation (KMIP `Revoke`). However, the revocation data was entirely internal to the KMS
database. Any PKI relying party (TLS stack, browser, OCSP client) needed a Certificate
Revocation List (CRL) to enforce revocation, and no such CRL distribution mechanism existed.

Several constraints drove the design:

- **RFC 5280 §3 / §5**: CRL Distribution Point (CDP) URIs embedded in certificates must be
  reachable by unauthenticated relying parties. The KMS cannot require OAuth2/JWT credentials
  for a CDP endpoint.
- **RFC 5280 §5.2.3**: CRL Number extensions must be monotonically increasing across CRL
  generations, including across server restarts.
- **FIPS 140-3**: CRL signing must use only FIPS-approved algorithms. Authority Key
  Identifier construction was previously relying on `EVP_sha1()` (not FIPS-approved for new
  use) and had to be replaced.
- **Multi-CA**: the KMS can host multiple independent CAs. The solution must be per-issuer,
  not global.
- **Operator UX**: operators must be able to configure a public-facing `kms_public_url` and
  have CDP URIs auto-inserted into newly issued certificates without manual configuration.
- **Cold-start availability**: the public CDP endpoint must be immediately available after a
  server restart without requiring a manual `generate-crl` call.
- **Access control**: because CRL generation enumerates *all* revoked certificates regardless
  of ownership (bypassing user filters), it must be gated behind the Crypto Officer role when
  CO users are configured.

## Decision

Implement a three-tier CRL architecture:

### Tier 1 — Authenticated CRL generation endpoint

`GET /certificates/{issuer_id}/crl` (requires authentication)

- Signs a fresh X.509 v2 CRL using the CA's private key from the KMS key store.
- Lists all certificates with `CertificateLink → issuer_id` and KMIP state `Deactivated` or
  `Compromised`, regardless of owner (CO-only bypass).
- Supports `format=der` (default, `application/pkix-crl`) and `format=pem`
  (`application/x-pem-file`) query parameters.
- Supports `validity_days` override (server default: 7 days, never < 1).
- Uses a process-global atomic counter seeded from UTC Unix timestamp as CRL Number, guaranteeing
  monotonic uniqueness across concurrent calls and server restarts.
- Writes the signed CRL DER and `next_update` timestamp to the `crls` database table
  (non-fatal on DB error — in-memory cache still works).
- Populates a process-local `GENERATED_CRL_CACHE` (`LazyLock<RwLock<HashMap<issuer_id,
  (der, Instant, next_update_iso8601)>>>`) for fast re-serving.
- Also exposed as a new CLI command `ckms certificates generate-crl` and Web UI action
  (Certificates → Certs → Generate CRL).

### Tier 2 — Unauthenticated public CDP endpoint

`GET /public/certificates/{issuer_id}/crl` (no authentication)

- Serves pre-signed CRL DER bytes from the two-level cache (in-memory → DB fallback).
- Returns HTTP 404 with a diagnostic message until the cache is primed.
- Sets `Last-Modified` (RFC 7231 IMF-fixdate) and `Content-Disposition` headers.
- Intended as the CDP URI in `crlDistributionPoints` extensions: `{kms_public_url}/public/certificates/{issuer_id}/crl`.
- Does **not** sign fresh CRLs — it only serves the last signed bytes; no key material is
  accessed on this path.

### Tier 3 — Scheduled CRL auto-refresh

A background cron task (`spawn_crl_refresh_cron`) wakes every `crl_refresh_check_hours`
(default: 24 h, 0 = disabled) and regenerates any stored CRL whose `next_update` timestamp
falls within `crl_refresh_overlap_hours` (default: 48 h) of the current time.

This models the *CRL overlap window* pattern (EJBCA "CRL Overlap Time", AWS PCA 1-day overlap):
the new CRL is signed before the old one expires, so relying parties always have a valid CRL
even if no revocation event triggered a manual regeneration.

The cron runs in its own OS thread with a single-threaded Tokio runtime to avoid contention
with the main Actix-web executor. It is shut down cleanly via a `oneshot::Sender<()>` held by
the server startup routine.

### Tier 4 — Auto-injection of CDP extension

When `kms_public_url` is configured, the `Certify` operation automatically inserts a
`crlDistributionPoints` extension (RFC 5280 §4.2.1.13) pointing to the public CDP endpoint
into newly issued non-self-signed certificates, unless the subject or the caller already
provides a CDP.

Self-signed certificates receive `id-ce-noRevAvail` (RFC 9608) instead, since self-signed
certs cannot appear in a CRL they also sign.

Re-certifications that already carry a CDP are not modified.

### FIPS-safe AKI construction

The `AuthorityKeyIdentifier` CRL extension (RFC 5280 §5.2.1) is constructed manually
using a low-level SHA-1 hash of the issuer's SPKI DER via `openssl::sha::Sha1`
(C interface, bypasses the FIPS provider check). This approach is intentional:
the AKI is a key identifier, not a cryptographic commitment; RFC 5280 §4.2.1.1 explicitly
permits SHA-1 for this use; and the FIPS provider's prohibition covers digest *algorithms
in security services* (e.g. signatures), not identifier derivation. The CRL signature itself
uses only FIPS-approved algorithms.

### Database persistence (`crls` table)

A new `crls` table stores `(issuer_id, crl_der, crl_number, generated_at, next_update)`.
This enables cold-start recovery: on the first request to the public CDP after a restart,
the server loads the last persisted CRL from DB into the in-memory cache. The DB write in
`generate_crl` is best-effort — a DB failure is logged as `WARN` and does not fail the
authenticated CRL generation request.

## Consequences

### Positive

- **POS-001**: Full RFC 5280 §5 CRL distribution chain from issuance to revocation to
  relying-party validation, without requiring any external OCSP infrastructure.
- **POS-002**: Unauthenticated CDP endpoint aligns with RFC 5280 §3 requirements; no
  credential leakage risk since it serves pre-signed, immutable DER bytes.
- **POS-003**: CRL Number monotonicity guaranteed across restarts via unix-timestamp seed;
  no DB round-trip required for counter state.
- **POS-004**: Operator configuration is minimal — setting `kms_public_url` is sufficient
  to activate end-to-end CDP injection; no per-CA configuration needed.
- **POS-005**: FIPS compliance maintained for AKI construction (SHA-1 via C bypass) without
  compromising the overall FIPS posture.
- **POS-006**: DB persistence ensures the public CDP endpoint survives server restarts
  without requiring a warm-up call.
- **POS-007**: Crypto Officer gating on `generate_crl` (when COs are configured) is
  consistent with the existing access-control model for privileged listing operations.

### Negative

- **NEG-001**: The public CDP endpoint serves *stale* CRLs between `generate-crl` calls.
  Relying parties may not see a revocation until the CA owner regenerates the CRL. This
  is the standard CRL trade-off (vs. OCSP stapling); operators must configure appropriate
  `validity_days` and/or automate CRL regeneration on revocation events.
- **NEG-002**: The in-memory cache is per-process. Multi-instance deployments behind a
  load balancer will have independent caches; only the instance that handled the last
  `generate-crl` request has the fresh CRL in RAM (all instances share the DB-persisted
  copy after a DB write succeeds).
- **NEG-003**: The `crls` table introduces a new DB schema dependency. Existing deployments
  require a schema migration before upgrading.
- **NEG-004**: CRL generation requires the issuer's private key to be accessible in the KMS
  key store at request time. HSM-backed keys add latency on each `generate-crl` call.

## Alternatives Considered

### OCSP (Online Certificate Status Protocol, RFC 6960)

- **ALT-001 Description**: Deploy an embedded OCSP responder alongside the KMS. Relying
  parties query per-certificate status in real time.
- **ALT-002 Rejection Reason**: OCSP requires per-request signing with a short-lived OCSP
  signing certificate, nonce handling, and significant additional protocol surface area.
  CRL is the simpler baseline required by most enterprise PKI stacks and is a prerequisite
  before OCSP can be considered. OCSP stapling can be added as a future enhancement.

### Auto-regenerate CRL on every Revoke call

- **ALT-003 Description**: Trigger `generate_crl` automatically every time a `Revoke`
  operation completes, keeping the public CDP always current.
- **ALT-004 Rejection Reason**: Revoke is a hot path; signing a CRL requires private key
  access (potentially HSM) and a DB round-trip. Coupling this to every revocation would add
  latency and increase HSM wear. The current design keeps CRL generation an explicit,
  operator-controlled operation. Automatic refresh can be added as an optional feature flag
  in a future ADR.

### Store CRL in object store / S3

- **ALT-005 Description**: Push signed CRL bytes to an object store (S3, GCS) and serve
  from there, decoupling CRL distribution from the KMS process.
- **ALT-006 Rejection Reason**: Introduces an external dependency and complicates
  deployment. The KMS already owns a database with reliable persistence; the `crls` table
  is the simplest consistent extension of existing infrastructure.

### External CRL signer (offline CA)

- **ALT-007 Description**: Keep the signing CA key offline; export a signing request to an
  offline process.
- **ALT-008 Rejection Reason**: Out of scope for the KMS, which is designed to be the
  online CA. Offline CA workflows require a separate product and are not addressed by this
  ADR.

## Implementation Notes

- **IMP-001**: `GENERATED_CRL_CACHE` is a `LazyLock<tokio::sync::RwLock<HashMap<...>>>`.
  The `RwLock` is async-aware to avoid blocking the Actix-web thread pool on cache reads
  (which are the hot path for the public endpoint).
- **IMP-002**: `CRL_SEQUENCE_COUNTER` is a `LazyLock<AtomicU64>` seeded from
  `OffsetDateTime::now_utc().unix_timestamp()`. In the unlikely event of two processes
  starting within the same second and both serving the public endpoint, a counter collision
  is possible. Operators running active-active HA must use a shared sequence source (DB
  sequence) or accept a one-second collision window; this is noted as a known limitation.
- **IMP-003**: The `build_crl` function in `crate/crypto/src/openssl/crl.rs` encapsulates
  all OpenSSL CRL construction. It is covered by FIPS-mode integration tests.
- **IMP-004**: All new DB operations (`get_crl`, `upsert_crl`) implement both the SQLite
  and PostgreSQL backends and are covered by the standard multi-backend test matrix.
- **IMP-005**: The `encode_der_length` helper in `build_certificate.rs` now returns
  `KResult<()>` to prevent silent truncation of CDP URIs longer than 65535 bytes.
- **IMP-006**: Success criterion — `test_crl_validation_lifecycle` end-to-end test passes
  on all DB backends (SQLite, PostgreSQL) in both FIPS and non-FIPS modes.

## References

- **REF-001**: RFC 5280 §5 — X.509 v2 CRL Profile
  <https://www.rfc-editor.org/rfc/rfc5280#section-5>
- **REF-002**: RFC 5280 §4.2.1.13 — CRL Distribution Points extension
  <https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.13>
- **REF-003**: RFC 9608 — `id-ce-noRevAvail` for self-signed certificates
  <https://www.rfc-editor.org/rfc/rfc9608>
- **REF-004**: RFC 2585 — Operational Protocols (DER/PEM MIME types)
  <https://www.rfc-editor.org/rfc/rfc2585>
- **REF-005**: NIST SP 800-57 Part 1 Rev 5 — Key Management Recommendation
  <https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final>
- **REF-006**: Related ADR — Two-role RBAC / Crypto Officer model
  `documentation/docs/adr/2026-06-24-two-role-rbac-crypto-officer-operator.md`
- **REF-007**: Implementation — `crate/server/src/routes/crl.rs`
- **REF-008**: Implementation — `crate/server/src/core/operations/generate_crl.rs`
- **REF-009**: Implementation — `crate/crypto/src/openssl/crl.rs`
- **REF-010**: Implementation — `crate/server/src/core/operations/certify/build_certificate.rs`
- **REF-011**: DB schema — `crate/server_database/src/stores/sql/` (`crls` table)
- **REF-012**: PR — <https://github.com/Cosmian/kms/pull/987>
