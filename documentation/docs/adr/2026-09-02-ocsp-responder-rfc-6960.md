---
title: "ADR-2026-09-02: Add a Built-in OCSP Responder (RFC 6960)"
status: "Accepted"
date: "2026-09-02"
revised: "2026-09-03"
authors: "PKI/CA operators, relying-party integrators, security auditors, KMS contributors"
tags: ["architecture", "decision", "pki", "ocsp", "x509", "fips"]
supersedes: ""
superseded_by: ""
---

# ADR-2026-09-02: Add a Built-in OCSP Responder (RFC 6960)

## Status

Proposed | **Accepted** | Rejected | Superseded | Deprecated

> **Revised 2026-09-02** — closed a gap discovered while stress-testing this feature:
> KMIP `Validate` had no visibility into internal KMS certificate lifecycle state, so a
> **compromised self-signed root CA** was undetectable by `Validate` (a self-signed root
> has no CRL Distribution Point of its own, and `Validate` never consulted OCSP or KMS
> state directly). See "Internal KMS-state cascade in `Validate`" under Decision, and
> IMP-004–IMP-006 below.
>
> **Revised 2026-09-03** — a STRIDE-A threat-model review of this feature (scoped to the
> full `ocsp_responder` branch diff) found and closed 6 hardening gaps: an unauthenticated
> OCSP DoS amplification chain (uncapped batch size + a response cache defeated under the
> documented default configuration + no default rate limiting), a `Validate` raw-bytes
> cross-tenant certificate-state disclosure, an unbounded `Validate` chain length, continued
> use of an independently-compromised delegated OCSP signing key, and a stale OCSP cache
> entry surviving past a certificate's revocation. See "Hardening applied after threat-model
> review" under Decision, POS-006, and IMP-007–IMP-010 below. Full report:
> `threat-model-20260903-060003/` (repository root; gitignored, a local session artifact
> — not committed).

## Context

The Eviden KMS already supported certificate issuance (KMIP `Certify`), revocation
(KMIP `Revoke`), and CRL generation/distribution (see
[ADR-2026-08-20](2026-08-20-pki-crl-generation-distribution-auto-refresh.md)). However,
the documentation explicitly stated that "OCSP is a future enhancement": relying parties
needing real-time, per-certificate revocation status had no option but to stand up and
operate an external OCSP responder, referenced via the certificate's
`authorityInfoAccess` (AIA) extension.

This had two operational costs for customers:

- **Extra infrastructure**: an external OCSP responder is a separate service to deploy,
  secure, and keep in sync with the KMS's own revocation state — a second source of
  truth for the same data the KMS already owns.
- **Staleness**: CRL-based revocation checking is only as fresh as the CRL's refresh
  cadence (`crl_refresh_check_hours`, `crl_refresh_overlap_hours`); OCSP allows a relying
  party to query the current status of a single certificate immediately after revocation.

Constraints driving the design:

- **[RFC 6960], Section 2, "Protocol Overview"**: OCSP response content is public
  information; the endpoint must be reachable without authentication credentials, exactly
  like the existing public CRL endpoint, or it would break standard relying-party tooling
  (`openssl ocsp`, TLS stacks, browsers).
- **[RFC 9654], Section 2.1, "Nonce Extension"**: nonce handling updates
  [RFC 6960], Section 4.4.1 with a wider 1–128 octet bound; the responder must not assume
  the RFC 8954-era 32-octet cap, and must be configurable (`optional` / `required` /
  `ignore`) since not all deployments want to pay the cost of disabling response caching.
- **[RFC 6960], Section 4.2.2.2, "Authorized Responders"**: production CAs frequently
  keep their signing key offline/HSM-only and delegate day-to-day OCSP signing to a
  dedicated, narrowly-scoped certificate (`extKeyUsage: OCSPSigning` +
  `id-pkix-ocsp-nocheck`). The responder must support this without requiring a second,
  separate service.
- **[RFC 5019]** (lightweight profile): to be a good citizen for CDN/proxy caching, the
  responder must set `Cache-Control`, `Last-Modified`, `Expires`, and `ETag`, and should
  avoid re-signing identical responses on every request (signing operations are
  comparatively expensive, especially when backed by an HSM).
- **`openssl-sys` 0.9.x** does not expose the OCSP response-*building* C API
  (`OCSP_basic_add1_status`, `OCSP_basic_sign`, `OCSP_basic_add1_nonce`,
  `OCSP_request_add1_nonce`, `OCSP_check_nonce`, `OCSP_id_get0_info`, ...) — only
  response-*parsing* primitives are wrapped by the `openssl` crate's safe API.

### Post-implementation discovery: KMIP `Validate` could not detect a compromised root CA

While building an adversarial test scenario ("a valid certificate whose CA got
compromised must be invalid") to validate this feature end-to-end, `crate/server/src/
core/operations/validate.rs`'s existing implementation was found to check **only**
CRLs reachable via each certificate's CDP (`verify_crls`). For a `[root-CA, leaf]` or
`[root-CA, intermediate, leaf]` chain:

- An **intermediate** CA's compromise is correctly caught: it appears in the CRL its own
  issuer (the root) publishes.
- A **self-signed root** CA's compromise was **not** catchable by any CDP/CRL mechanism:
  a self-signed root has no issuer of its own to publish a CRL about it (this is exactly
  why self-signed certificates get `id-ce-noRevAvail`, RFC 9608, instead of a CDP — see
  Tier 4 of [ADR-2026-08-20](2026-08-20-pki-crl-generation-distribution-auto-refresh.md)).
  `Validate` had no fallback: it never consulted the KMS's own internal certificate
  lifecycle state, so a root marked `Compromised` via `Revoke` was invisible to any
  chain that referenced it, and any leaf it had issued kept reporting `Valid`.

This gap was specific to the KMIP `Validate` operation. The OCSP responder introduced by
this ADR (see `Database::find_certificate_by_serial`, Decision above) and CRL generation
(ADR-2026-08-20) both already consult internal KMS state and correctly cascade CA
compromise to every certificate the CA issued (RFC 6960 §2.7, "CA Key Compromise").
`Validate` was the one protocol surface that did not.

## Decision

Implement a native OCSP responder directly in the KMS server:

- **Public, unauthenticated endpoints**: `GET /ocsp/{base64url-DER}`
  ([RFC 6960] Appendix A.1, for small requests) and `POST /ocsp/`
  ([RFC 6960] Appendix A.2), registered in `crate/server/src/routes/ocsp/handler.rs` and
  wired in `start_kms_server.rs` alongside the other public routes (public CRL, root
  redirect). Both return `404` when `ocsp_enabled = false` (the default).
- **Certificate status from existing KMS state**: a new
  `Database::find_certificate_by_serial(issuer_uid, serial_hex, vendor_id)` method
  (`crate/server_database/src/core/database_objects.rs`) scans certificate objects across
  all lifecycle states and maps them to OCSP status: `Active`/`PreActive` → `good`;
  `Compromised`/`Destroyed_Compromised` → `revoked`/`keyCompromise`;
  `Deactivated`/`Destroyed` → `revoked`/`cessationOfOperation`; not found → `unknown`. If
  the CA itself is revoked with a compromise reason, every certificate it issued reports
  `revoked`/`cACompromise` regardless of its own state ([RFC 6960], Section 2.7, "CA Key
  Compromise").
- **Dedicated OpenSSL FFI layer**: `crate/crypto/src/openssl/ocsp_ffi.rs` adds the
  missing raw bindings, isolated behind a documented safety policy (every `unsafe` block
  carries a `// SAFETY:` comment; all FFI pointers are null-checked). `ocsp.rs` builds on
  top of these to expose a safe `build_ocsp_response` / `parse_ocsp_request` API to the
  route handler — no `unsafe` code leaks outside the crypto crate.
- **Nonce policy** (`--ocsp-nonce-policy`, [RFC 9654], Section 2.1): `optional` (default,
  echo if present), `required` (reject with a proper `malformedRequest` OCSP response —
  not an HTTP error — if absent), or `ignore` (never echo; unlocks response caching).
- **In-memory response cache** keyed by `(ca_uid, serial)`, TTL = `ocsp_cache_ttl_secs`,
  bypassed whenever the nonce policy could produce a per-request nonce, to avoid
  re-signing identical responses and to guarantee a fresh nonce is never served stale.
- **Delegated signing** (`--ocsp-responder-cert-uid`, [RFC 6960], Section 4.2.2.2):
  optional; falls back to signing with the CA's own key when unset. The signer
  certificate/key pair is resolved the same way CRL signing resolves its signer
  (`PrivateKeyLink` attribute).
- **Archive-cutoff** (`--ocsp-archive-cutoff-secs`, [RFC 6960], Section 4.4.4): optional,
  disabled (`0`) by default.
- **RFC 5019 HTTP caching headers** (`Cache-Control`, `Last-Modified`, `Expires`, `ETag`)
  on every response.

### Internal KMS-state cascade in `Validate` (closing the root-CA-compromise gap)

`validate_operation` (`crate/server/src/core/operations/validate.rs`) now tracks, per
certificate in the chain, whether the KMS has its own tracked lifecycle state for it:

- Certificates supplied **by UID** already carry an authoritative state from their
  `ObjectWithMetadata` — no extra lookup needed.
- Certificates supplied as **raw DER bytes** are matched against the database via a new
  `Database::find_certificate_state_by_der(der_bytes, vendor_id)` method
  (`crate/server_database/src/core/database_objects.rs`): an exact-byte-match scan across
  all lifecycle states (mirroring the byte-identity semantics `Validate` already implies
  for raw-bytes input), so a chain built entirely from externally-supplied bytes still
  benefits from this check whenever the KMS happens to recognize one of the certificates.
- A new `check_internal_certificate_states` check runs after the existing signature and
  date checks and **before** the existing CRL check: any certificate anywhere in the
  (root-first-sorted) chain that is tracked by the KMS and is not `Active`/`PreActive`
  makes the **whole chain** `Invalid`. Since `Validate` returns a single verdict for the
  entire chain, no "cascade" flag is needed — the first non-Active certificate found (the
  chain is walked root-first) already invalidates every descendant.
- `sort_certificates` and `verify_crls` are deliberately left untouched: `verify_crls` is
  also called from `crate/server/src/core/operations/import.rs` on a single certificate
  with no chain context, so changing its signature would have unintended blast radius.
  Certificate bytes are re-associated with their internal state by exact DER-bytes lookup
  after the existing (unchanged) sort.

A pre-existing, independent protection was found to already cover part of this gap: the
per-state retrieval permission matrix in `crate/server/src/core/retrieve_object_utils.rs`
does not allow `KmipOperation::Validate` on objects in `State::Compromised` — so for a
chain supplied **entirely by UID**, retrieval of a `Compromised` ancestor already fails
before the new cascade check would even run. The new check's genuinely necessary
contributions are therefore: (a) `Deactivated`/`Destroyed` ancestors, which that
permission gate explicitly *allows* through for most operations including `Validate`, and
(b) chains supplied as **raw bytes**, which never go through that permission gate at all.

### Hardening applied after threat-model review (2026-09-03)

A STRIDE-A threat-model review of this feature (scoped to the full `ocsp_responder`
branch diff) found and closed 6 gaps, all fixed the same day (see
`threat-inventory.json` in the (gitignored, local) report folder for exact fix-to-finding
mapping):

- **OCSP batch-size cap**: `parse_ocsp_request` (`crate/crypto/src/openssl/ocsp.rs`) now
  rejects any `OCSPRequest` carrying more than `MAX_OCSP_QUERIES_PER_REQUEST` (128)
  `SingleRequest`/`CertID` entries, checked before any per-query database lookup or
  signing work. Previously unbounded (limited only by the 64 MB app-wide HTTP payload
  cap), allowing a single unauthenticated request to force on the order of hundreds of
  thousands of non-indexed, six-lifecycle-state database scans.
- **OCSP cache no longer defeated by the default configuration**: the cache-bypass
  decision (`has_nonce` in `handler.rs`) now checks whether the specific request
  *actually* carries a nonce (`request_has_nonce`), not just whether the configured
  policy is other than `ignore`. Previously, under the documented default
  (`ocsp_nonce_policy = optional`), the cache never activated for *any* request,
  forcing a live signing operation on every single query regardless of nonce presence
  — directly undermining POS-004 below.
- **OCSP cache no longer serves stale status past a CA compromise or a certificate
  revocation**: the cache is now unconditionally bypassed once the CA is compromised
  (so the cascade to `revoked`/`cACompromise` is never masked by a pre-compromise
  cached `good` entry), and `Revoke` now evicts the specific `(ca_uid, serial)` cache
  entry immediately (`evict_ocsp_cache_entry`, called from
  `crate/server/src/core/operations/revoke.rs`) rather than waiting for
  `ocsp_cache_ttl_secs` to elapse.
- **Refuse to sign with an independently-compromised delegated responder key**:
  `retrieve_signer_cert_and_key` now refuses (`InvalidRequest`) when a *distinct*
  delegated responder certificate (`ocsp_responder_cert_uid != ocsp_ca_uid`) has
  itself been marked `Compromised`/`Destroyed_Compromised`. This deliberately does
  **not** apply when the signer is the CA's own key with no delegate configured: RFC
  6960 §2.7 requires the responder to keep truthfully cascading `revoked` for every
  certificate the CA issued once the CA itself is compromised — refusing to sign in
  that specific case would silence the very cascade this feature exists to provide,
  and is exercised end-to-end by `mise run test:ocsp` (step 7).
- **`Validate` chain-length cap**: `validate_operation` now rejects a combined
  `certificate`/`unique_identifier` count above `MAX_VALIDATE_CHAIN_LENGTH` (32),
  checked before any per-certificate database lookup.
- **`Validate` raw-bytes path no longer discloses cross-tenant certificate state**:
  `tag_raw_certificates_with_state` now re-checks ownership/Grant permission
  (`user_has_permission`) on a DER-byte match before exposing its internal lifecycle
  state to the caller; a match the caller may not access is tagged `None` (checked
  only via signature/date/CRL, exactly like a certificate unknown to this KMS).
  Deliberately does not reuse `retrieve_object_for_operation` for this check, since its
  state-vs-operation gate (see "A pre-existing, independent protection", above) would
  incorrectly hide a `Compromised` certificate's state even from its own owner for this
  internal use.

## Consequences

### Positive

- **POS-001**: Relying parties get real-time, per-certificate revocation status without
  the KMS operator needing to deploy or secure a separate OCSP service.
- **POS-002**: Revocation state has a single source of truth (the KMS certificate
  lifecycle state) shared by both CRL and OCSP — no risk of the two diverging.
- **POS-003**: Delegated responder support lets production deployments keep the CA
  private key offline/HSM-only while still serving OCSP with low latency.
- **POS-004**: The in-memory cache keeps signing-key usage low for high-traffic
  deployments, which matters when the key is HSM-backed.
- **POS-005**: KMIP `Validate` now correctly reports `Invalid` for any chain containing a
  compromised or deactivated certificate the KMS tracks — including a self-signed root
  CA, previously the one gap no CDP/CRL/OCSP mechanism could close for that specific
  protocol operation.
- **POS-006**: A same-day threat-model review closed all 6 identified hardening gaps
  before this feature reached a release — an unauthenticated DoS amplification chain,
  a cross-tenant disclosure path, and defense-in-depth gaps around compromised-key
  reuse and cache freshness — with no observed exploitation. Every fix is covered by
  the existing external black-box test suites (`test:ocsp`, `test:pki-revocation`) and
  the full server test suite, both `fips` and `non-fips`.

### Negative

- **NEG-001**: A new `unsafe` FFI surface (`ocsp_ffi.rs`) was introduced to cover gaps in
  `openssl-sys`; it requires ongoing scrutiny on every OpenSSL upgrade (see
  `openssl-build.instructions.md`, sync rule 4.17).
- **NEG-002**: The endpoint is intentionally unauthenticated (per [RFC 6960]); the KMS
  must ensure the OCSP signing key can only be used for OCSP-shaped signatures, not as a
  general-purpose signing oracle — the same threat class already accepted for the public
  CRL endpoint.
- **NEG-003**: The in-memory response cache is per-process and is not shared across a
  multi-instance/load-balanced KMS deployment, so cache hit rates (and therefore signing
  key load) do not improve with horizontal scaling.
- **NEG-004**: The internal-state cascade check only covers certificates the KMS itself
  tracks. A chain built entirely from externally-issued certificates unknown to this KMS
  instance still relies solely on signature, date, and CRL checks — `Validate` cannot
  detect a compromise the KMS has no record of, by design (it is not a general-purpose
  CA-compromise oracle for third-party PKIs).

## Alternatives Considered

### Keep CRL-only revocation, document AIA pointing to an external OCSP responder

- **ALT-001 Description**: Continue to advertise only CRL-based revocation; customers
  wanting OCSP would run a third-party responder and reference it via the
  `authorityInfoAccess` extension, as the pre-existing documentation suggested.
- **ALT-002 Rejection Reason**: Pushes an extra service (deployment, security hardening,
  keeping in sync with KMS-side revocations) onto every customer that wants OCSP, and
  duplicates the KMS's own revocation state in a second system.

### Build OCSP purely on the `openssl` crate's safe wrappers

- **ALT-003 Description**: Avoid raw FFI entirely by using only the `openssl` crate's
  existing safe OCSP types (`OcspRequest`, `OcspResponse`, `OcspCertId`, ...).
- **ALT-004 Rejection Reason**: The safe wrappers only cover request/response *parsing*
  and basic status extraction; the crate does not expose the C API needed to *build* a
  signed `BasicResponse` (`OCSP_basic_add1_status`, `OCSP_basic_sign`,
  `OCSP_basic_add1_nonce`) or to add/check nonces on the request or response side. The
  only alternatives were a third-party OCSP-building crate (unclear FIPS/maintenance
  posture, another dependency to audit) or the raw FFI layer that was chosen.

### Sign every OCSP response with the CA's own key only (no delegation)

- **ALT-005 Description**: Skip [RFC 6960], Section 4.2.2.2 "Authorized Responders"
  support and always sign with the CA certificate/key configured via `ocsp_ca_uid`.
- **ALT-006 Rejection Reason**: Simpler, but forces production CAs that keep their
  private key offline/HSM-only into a choice between exposing that key to a
  high-traffic, unauthenticated endpoint or not offering OCSP at all. Delegated signing
  is a well-established pattern this design supports at low implementation cost.

### For `Validate`, add a "cascade_active" flag distinguishing Compromised from Deactivated

- **ALT-007 Description**: Track whether a non-Active ancestor's state should "cascade"
  to descendants (e.g., `Compromised` cascades, `Deactivated` does not), requiring a
  richer per-certificate result type.
- **ALT-008 Rejection Reason**: `Validate` returns a single `ValidityIndicator` for the
  entire requested chain, not a per-certificate verdict. Since any non-Active ancestor
  already makes the overall result `Invalid` regardless of the specific reason, a cascade
  flag adds complexity without changing the observable outcome. The simpler uniform rule
  (any non-Active/PreActive certificate anywhere in the chain invalidates the whole chain)
  was adopted instead.

## Implementation Notes

- **IMP-001**: `--ocsp-*` CLI flags / `[ocsp]` TOML section
  (`crate/server/src/config/command_line/ocsp_config.rs`): `ocsp_enabled` (default
  `false`), `ocsp_ca_uid`, `ocsp_responder_cert_uid`, `ocsp_cache_ttl_secs` (default
  `86400`), `ocsp_nonce_policy` (default `optional`), `ocsp_include_cert_chain` (default
  `true`), `ocsp_archive_cutoff_secs` (default `0`, disabled).
- **IMP-002**: External-customer black-box test suite (`mise run test:ocsp`,
  `.mise/tasks/test/ocsp`) drives a real KMS server purely through `ckms` (provisioning)
  and `openssl ocsp` / `curl` (querying) — no internal API calls — across 23 assertions:
  status mapping (good/revoked/unknown), GET+POST transport, all three nonce policies,
  RFC 5019 cache headers + cache-hit behaviour, delegated signer + archive-cutoff, and
  the CA-compromise cascade. Wired into `.github/workflows/test_all.yml` for both `fips`
  and `non-fips`.
- **IMP-003**: Success criteria: the mise task suite passes on every PR touching
  `crate/crypto/src/openssl/ocsp*.rs`, `crate/server/src/routes/ocsp/`, or
  `crate/server/src/config/command_line/ocsp_config.rs`; `cargo clippy-all` remains
  zero-warning; unit tests in `ocsp.rs` (crypto layer), `handler.rs` (route layer), and
  `database_objects.rs` (serial-hex extraction) stay green.
- **IMP-004**: `find_certificate_state_by_der` (`crate/server_database/src/core/
  database_objects.rs`) performs an exact-DER-byte-match scan across all certificate
  objects in all lifecycle states, returning `(uid, state)` on a match. Placed directly
  after the pre-existing `find_certificate_by_serial`; covered by 2 new unit tests.
- **IMP-005**: A new self-contained Rust test module,
  `internal_state_and_crl_cascade_tests` in `crate/server/src/tests/test_validate.rs` (5
  tests), replaces two old `#[ignore]`d, network-dependent tests
  (`test_validate_with_certificates_bytes` / `_ids`). All 5 tests use `file://` CRL
  fixtures (`#[cfg(any(test, feature = "insecure"))]`-gated, no network access — the same
  SSRF protection documented as COSMIAN-2026-021) and cover: leaf revocation via CRL,
  intermediate-compromise CRL cascade, root-compromise via the new internal-state check,
  a deactivated (non-compromised) ancestor, and the raw-bytes-supplied-chain path.
- **IMP-006**: `mise run test:pki-revocation` (`.mise/tasks/test/pki-revocation`) is a
  new external, black-box test suite exercising this fix purely through `ckms` and
  `openssl verify -crl_check` / `openssl ocsp`, deliberately not duplicating
  `test:ocsp`'s coverage: (1) a leaf carrying both a CDP and an AIA OCSP URL, valid
  before and correctly reported invalid/revoked via CRL, OCSP, and `Validate` after
  revocation; (2) a 3-level chain where compromising the **intermediate** CA cascades to
  the leaf via the existing CRL mechanism; (3) a 2-level chain where compromising the
  **root** CA is now caught by `Validate` via the new internal-state check, with no
  CDP/CRL/OCSP mechanism involved at all. Wired into `.github/workflows/test_all.yml`
  alongside `ocsp` (both `fips` and `non-fips`, no Docker dependency).
- **IMP-007**: `MAX_OCSP_QUERIES_PER_REQUEST` (128) and `MAX_VALIDATE_CHAIN_LENGTH` (32)
  are `const` values colocated with the code they bound
  (`crate/crypto/src/openssl/ocsp.rs`, `crate/server/src/core/operations/validate.rs`
  respectively) rather than made operator-configurable — both are generous upper bounds
  for legitimate use (RFC 5019 lightweight batches; realistic 2-4-certificate PKI
  chains), and a fixed, code-reviewed constant is simpler to reason about than another
  tunable that could be misconfigured to reintroduce the same amplification risk.
- **IMP-008**: The OCSP in-memory cache's compromise-aware bypass and the
  `evict_ocsp_cache_entry` eviction hook are both process-local, matching the
  pre-existing `OCSP_CACHE` cache's own scope (NEG-003) — a multi-instance deployment
  still relies on `ocsp_cache_ttl_secs` as the upper bound on staleness for whichever
  instance did not handle the triggering `Revoke` call.
- **IMP-009**: `tag_raw_certificates_with_state`'s permission re-check
  (`user_has_permission`) is intentionally **not** the same helper the UID path uses
  (`retrieve_object_for_operation`): the latter also gates retrieval on
  state-vs-operation compatibility (e.g. `Validate` is not itself a permitted operation
  on a `Compromised` object, by design — see "A pre-existing, independent protection"
  above), which is correct for a client-facing UID lookup but would incorrectly hide a
  compromised certificate's state even from its own owner when used internally by this
  helper.
- **IMP-010**: Success criteria for this revision: `cargo clippy-all` remains
  zero-warning; `cargo fmt --all -- --check` remains clean; the full
  `cosmian_kms_server` test suite passes in both `fips` (395 tests) and `non-fips` (572
  tests); `mise run test:ocsp` (23 assertions) and `mise run test:pki-revocation` (12
  assertions) both pass in both variants, including the CA-compromise-cascade scenario
  that the first attempt at the delegated-signer-refusal fix (IMP above) initially broke
  before being narrowed to only apply to a genuinely distinct, independently-compromised
  delegate.

## References

- **REF-001**: [ADR-2026-08-20: PKI / X.509 CRL Generation, Distribution & Auto-Refresh
  Architecture](2026-08-20-pki-crl-generation-distribution-auto-refresh.md) — the
  revocation/CRL foundation this OCSP responder builds on and shares certificate
  lifecycle state with.
- **REF-002**: [RFC 6960](https://www.rfc-editor.org/rfc/rfc6960) — X.509 Internet Public
  Key Infrastructure Online Certificate Status Protocol - OCSP.
- **REF-003**: [RFC 9654](https://www.rfc-editor.org/rfc/rfc9654) — updated OCSP Nonce
  Extension (supersedes RFC 8954).
- **REF-004**: [RFC 5019](https://www.rfc-editor.org/rfc/rfc5019) — Lightweight OCSP
  Profile for High-Volume Environments.
- **REF-005**: [RFC 5280](https://www.rfc-editor.org/rfc/rfc5280) — Internet X.509 Public
  Key Infrastructure Certificate and CRL Profile.
- **REF-006**: Relevant codebase files: `crate/server/src/routes/ocsp/handler.rs`,
  `crate/crypto/src/openssl/ocsp.rs`, `crate/crypto/src/openssl/ocsp_ffi.rs`,
  `crate/server/src/config/command_line/ocsp_config.rs`,
  `crate/server_database/src/core/database_objects.rs`,
  `documentation/docs/use_cases/pki-revocation.md`, `.mise/tasks/test/ocsp`,
  `CHANGELOG/ocsp.md`.
- **REF-007**: `Validate` fix — `crate/server/src/core/operations/validate.rs`
  (`check_internal_certificate_states`, `tag_raw_certificates_with_state`).
- **REF-008**: Retrieval permission matrix —
  `crate/server/src/core/retrieve_object_utils.rs` (`retrieve_object_for_operation`).
- **REF-009**: New external test suite — `.mise/tasks/test/pki-revocation`.
- **REF-010**: New Rust tests — `crate/server/src/tests/test_validate.rs`
  (`internal_state_and_crl_cascade_tests`).
- **REF-011**: Threat-model review (2026-09-03) — `threat-model-20260903-060003/`
  (repository root; gitignored via `/threat-model*`, not committed):
  `0-architecture.md`, `1-dfd.md`, `2-stride-analysis.md`, `3-findings.md`,
  `0-assessment.md`, `threat-inventory.json` (all 6 findings marked `fixed`).
- **REF-012**: Hardening fix locations — `crate/crypto/src/openssl/ocsp.rs`
  (`MAX_OCSP_QUERIES_PER_REQUEST`), `crate/server/src/routes/ocsp/handler.rs`
  (`request_carries_nonce`, `evict_ocsp_cache_entry`, delegated-signer state check),
  `crate/server/src/core/operations/revoke.rs`
  (`extract_serial_hex_for_ocsp_cache`), `crate/server/src/core/operations/validate.rs`
  (`MAX_VALIDATE_CHAIN_LENGTH`, `user_has_permission` re-check in
  `tag_raw_certificates_with_state`).
