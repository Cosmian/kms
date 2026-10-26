---
title: "ADR-2026-10-23: Sign CSRs, Certificates and CRLs Through the Crypto Oracle for HSM-Resident CA Keys, and Tag Certificates by Serial"
status: "Proposed"
date: "2026-10-23"
authors: "PKI operators, security auditors, KMS contributors"
tags: ["architecture", "decision", "pki", "hsm", "x509", "csr", "crl", "tags"]
supersedes: ""
superseded_by: ""
---

# ADR-2026-10-23: Sign CSRs, Certificates and CRLs Through the Crypto Oracle for HSM-Resident CA Keys, and Tag Certificates by Serial

## Status

Proposed

## Context

A customer runs two KMS/PKI instances, both backed by an HSM: an **offline** one holding the root CA and an **online**
one holding a delegated (sub) CA. The blocking requirement is that **no CA private key is ever disclosed or exported**:
the sub-CA key generated on the online instance must stay inside its HSM, and the offline root must sign the sub-CA
CSR with its own HSM key.

Before this change:

- No KMIP or REST operation produced a PKCS#10 CSR from a KMS-held key. The only CSR builder
  (`crate/server/src/config/wizard/cert_gen.rs`) used an ephemeral in-memory OpenSSL key.
- Every X.509 signing path (`Certify`/`ReCertify`, `GenerateCrl`) loaded the issuer private key into process memory
  (`kms.get_unwrapped` + `kmip_private_key_to_openssl`). For a *sensitive* HSM key `HsmStore::retrieve` returns only a
  metadata stub, so these paths could not work; for a *non-sensitive* HSM key they silently exported the key.
- OpenSSL signs only with an in-memory `PKey<Private>`; there is no callback that delegates the signature to an
  HSM or to the KMIP Sign operation without an OpenSSL engine/provider.
- Operators looking for a certificate by serial number had to maintain external scripts that add a serial tag, as the
  serial lived only in the KMIP `CertificateAttributes` structure and was not indexed by Locate.

Constraints: FIPS 140-3 build must keep working; HSM tests run sequentially against PKCS#11 simulators; the
fix must not change the behaviour of existing software (database) keys. Behaviour for HSM CA keys deliberately
changes, see NEG-001.

## Decision

1. **Sign through the crypto oracle, never export.** A new module
   `crate/server/src/core/certificate/oracle_signing.rs` builds the X.509 structure with OpenSSL signed by a throwaway
   P-256 *placeholder* key, decodes the DER with `x509-cert`, sets the real `AlgorithmIdentifier`, signs the TBS
   through the existing `SignOp::execute_oracle` with the **exact HSM UID** and **explicit** KMIP signature parameters,
   re-inserts the signature, and **verifies it against the real public key** before returning.
   It handles `CertReq`, `Certificate`, `CertificateList` and `BasicOCSPResponse`.
2. **`IssuerKey` enum** (`Local(PKey<Private>)` | `Oracle(OracleSigningKey)`) replaces the raw private key in
   `Issuer`. Database keys follow the unchanged in-process path; HSM keys (`ObjectHandle::is_hsm`) use the oracle.
   `build_and_sign_certificate` becomes `async`. `generate_crl` makes the same split.
3. **New CSR operation:** `POST /certificates/csr` (authenticated), `ckms certificates generate-csr`, and a Web UI page.
   Only the `Sign` permission is required on the private key (never `Get`), and the configured KMIP algorithm policy is
   enforced on the key and its public key before signing (as `Certify` does): the public key is read without a per-user
   `Get` check, and the final `csr.verify(public_key)` guards that the pair matches. An extractable HSM key is refused,
   so the non-disclosure guarantee holds from the sub-CA's creation. Database-stored keys of any signing type work:
   RSA and EC use SHA-256, while Ed25519 and ML-DSA/SLH-DSA sign with no digest; HSM keys are limited to RSA, EC and
   (non-FIPS) Ed25519/Ed448. Subjects are parsed by a dedicated DN parser that keeps
   RDN order and repeated attributes.
4. **OCSP signs through the oracle; SCEP fails closed.** The OCSP responder uses the shared `load_issuer_key`
   (`IssuerKey::Local` | `Oracle`). For an HSM signer the `BasicOCSPResponse` is built with a placeholder key and a
   placeholder certificate carrying the signer's name (so `responderID` is correct), then re-signed through the oracle,
   the signer certificate is re-embedded when `ocsp_include_cert_chain` is set, and the signature is verified with
   the signer public key. SCEP keeps the software path and rejects a *sensitive* HSM CA key with `NotSupported`.
   Non-sensitive HSM keys are exportable, so a blanket `is_hsm()` rejection is not needed.
5. **`_serial=<UPPERCASE HEX>` system tag** on every certificate stored by Certify, ReCertify, Import, Register and
   PKCS#12 import, through one helper (`set_certificate_serial_tag`) that first removes any client-supplied or
   inherited `_serial=` tag. Certificates stored before this change are tagged once at startup on every backend
   (SQLite, PostgreSQL, MySQL/MariaDB, Redis-Findex), gated by a `certificate_serial_tag_backfilled` marker; the SQL
   inserts are conflict-tolerant so several nodes may start concurrently. A serial is unique only per issuer, so the
   tag can match several certificates from different CAs; it is unrelated to the enrollment tag
   `_enrolled_serial:{ca_uid}:{HEX}`.
6. **CRL requester.** `generate_crl` takes a `CrlRequester`: `User(&UserId)` (REST, ACL-checked on certificate and
   key) or `Server` (post-Revoke and cron regeneration). Post-Revoke and cron run as the revoking leaf owner or
   `default_username`, who usually have no access to the CA, so the old behaviour left CRLs stale. For `Server`, the
   issuer certificate is read directly (destroyed ones refused), and the signing key is authorized, and unwrapped, as
   the issuer certificate's owner. A regression test covers the case of a user importing a copy of another user's CA
   certificate linked to that user's key: the server does not sign. See NEG-002.
7. **HSM root keeps its key link.** Certifying an HSM public key `<sk>_pk` (self-signed) derives the private key
   `<sk>` for both the issuer lookup and the certificate's `PrivateKeyLink` (`private_key_link_of`); no
   `UpdateObject` is issued for the HSM public key, as HSM objects store no KMIP links.
8. **OCSP issuer-hash fix for sub-CAs.** `verify_issuer_hashes_match_ca` computed the reference `CertID` with the CA
   as OpenSSL's *subject*, hashing the CA's issuer name, so every request for a non-self-signed CA was answered
   `unauthorized`. It now passes a null subject, hashing the CA's own subject name and key. This affects every
   non-root `ocsp_ca_uid`, not only HSM keys.

Signature algorithms for oracle-signed structures are `sha256WithRSAEncryption` (PKCS#1 v1.5),
`ecdsa-with-SHA256` (any curve), and, in non-FIPS builds, `id-Ed25519` / `id-Ed448` (RFC 8410, no parameters). For
RSA and EC the SHA-256 digest of the TBS is signed (`digested_data`, mapped by the HSM layer to `CKM_RSA_PKCS` or raw
`CKM_ECDSA`); for EdDSA the raw TBS is signed (`data`, `CKM_EDDSA`), as the HSM cannot take a digest.

Out of scope: the Auditor role of issue #651 (delivered with the OPA authorization work) and first-year support.

## Consequences

### Positive

- **POS-001**: The CA private key of an HSM-backed sub-CA is never exported or loaded by the server, from CSR
  generation through leaf issuance and CRL signing.
- **POS-002**: The offline root can sign with its own HSM key using the same `Certify` code path.
- **POS-003**: Post-signature verification against the issuer public key makes a key/certificate mismatch (including
  key rotation resolving to another generation) fail closed instead of publishing an invalid certificate or CRL.
- **POS-004**: Operators locate certificates by serial with `ckms locate --tag _serial=…` or the UI, with no KMIP
  knowledge and no custom tagging scripts.
- **POS-005**: Software-key behaviour is unchanged; the existing CRL, revoke, enrollment, certify and OCSP suites pass in
  FIPS and non-FIPS builds.

### Negative

- **NEG-001**: Oracle (HSM) signing supports RSA and EC keys, and Ed25519/Ed448 (non-FIPS builds only). RSA and EC
  always sign with SHA-256 (PKCS#1 v1.5 for RSA, ECDSA for EC, whatever the curve). RSA-PSS keys and any HSM CA key
  that is not RSA, EC or EdDSA are rejected with `NotSupported`. Database-stored keys are not affected.
  **Behaviour change for existing HSM users:** every `hsm::` issuer key now goes through the oracle in `Certify`,
  `ReCertify`, `GenerateCrl` and the OCSP responder, *including non-sensitive keys* that previously signed by export.
  A P-384 HSM CA now signs `ecdsa-with-SHA256` instead of the digest the old path chose.
  Gating the oracle path on `sensitive == Some(true)` would preserve the old behaviour but keep exporting
  non-sensitive CA keys, contradicting the non-disclosure goal.
- **NEG-002**: Automatic CRL regeneration (post-Revoke, refresh cron) reads only the issuer *certificate* without an
  ACL check (a certificate is public; destroyed ones are refused). The signing key is still authorized as the issuer
  certificate's **owner**, never as the caller, because the `PrivateKeyLink` of an imported certificate is
  user-controlled and the server must not sign with a key its owner cannot use. HSM grants are per operation and the
  oracle never exports: CSR generation needs the `Sign` grant on an HSM key, while certificate issuance and CRL
  signing with an HSM CA key need the `Certify` grant (not `Get` or `Export`). Consequence: for an `hsm::` key the
  issuer certificate's owner must be an HSM admin or hold a `Certify` grant on the key, otherwise regeneration fails
  (logged) and the CRL goes stale; this limitation remains.
- **NEG-003**: A throwaway placeholder signature plus DER re-encoding adds a second parser (`x509-cert`) on the signing
  path. `x509-cert` is already in the workspace and the OCSP response types are defined locally with `der`, so no new
  third-party package is introduced.
- **NEG-004**: The `_serial=` tag is not unique across issuers; renewal replaces it. Its backfill is a one-time
  startup write on the first boot after upgrade; a certificate whose serial cannot be read is skipped and left
  untagged. A warning is logged only on the SQL backends (SQLite, PostgreSQL, MySQL/MariaDB), and only when the stored
  object cannot be deserialized; Redis-Findex skips such certificates silently.
- **NEG-005**: ML-DSA and SLH-DSA HSM CA keys are not supported: the HSM layer has no PQC key types, so they are
  rejected with `NotSupported`. Database-stored PQC keys are unaffected.
- **NEG-006**: SCEP cannot use a non-extractable HSM CA key (`NotSupported`, "SCEP cannot use a non-extractable HSM CA
  key"). EST is unaffected: it issues through `Certify`.

## Alternatives Considered

### Export the HSM key and sign in process

- **ALT-001 Description**: Make non-sensitive HSM keys sign like database keys by exporting them.
- **ALT-002 Rejection Reason**: Violates the non-disclosure requirement and cannot work for sensitive keys.

### OpenSSL engine or provider backed by PKCS#11

- **ALT-003 Description**: Let OpenSSL call the HSM directly through a PKCS#11 provider.
- **ALT-004 Rejection Reason**: The KMS already centralizes HSM access and permission checks in the crypto oracle;
  a second path would bypass them and add a FIPS-validated-provider integration risk.

### Hand-assemble the TBS structure and signature

- **ALT-005 Description**: Build the whole CSR/certificate/CRL with `x509-cert` builders.
- **ALT-006 Rejection Reason**: Re-implements extension and name handling already done by OpenSSL builders and
  `build_crl`; the placeholder-then-re-sign approach reuses them and changes only the signature.

### Reuse `CertificateAttributes::parse_subject_line` for CSR subjects

- **ALT-007 Description**: Use the subject parser shared with `certify --subject-name`.
- **ALT-008 Rejection Reason**: It keeps one value per attribute, rejects `organizationIdentifier`/`serialNumber`
  and reorders RDNs, which is unsuitable for a CA distinguished name. Consolidating the two parsers is left as follow-up.

### Serial number as a KMIP attribute search only

- **ALT-009 Description**: Rely on `Locate` by `CertificateAttributes` serial.
- **ALT-010 Rejection Reason**: Not reachable from the CLI/UI tag filters the operators use.

## Implementation Notes

- **IMP-001**: Layered commits per `AGENTS.md`: server (`crate/server`, `crate/kmip`), then CLI (`crate/clients`),
  then UI (`ui`); each builds on its own.
- **IMP-002**: Keep `oracle_sign` free of permission checks; callers authorize the key first (Certify, CRL, CSR, OCSP).
- **IMP-003**: Verification: unit tests for CSR/certificate/CRL/OCSP re-signing (RSA, EC and, non-FIPS, Ed25519/Ed448),
  `sub_ca_tests` (including a cross-user CRL-signing regression), an HSM scenario in `test_hsm_all`
  (`mise run test:hsm-softhsm2`, FIPS and non-FIPS) covering an HSM root, a sub-CA CSR, leaf, CRL and OCSP, and the
  existing suites in FIPS and non-FIPS builds. The serial-tag backfill is tested with a seeded legacy certificate on
  SQLite and Redis only; on PostgreSQL and MySQL the startup backfill ran against an empty certificate set (no legacy
  row seeded).
- **IMP-004**: `Cargo.lock` gains only `x509-cert` and `der` edges for `cosmian_kms_server` (both crates are already
  locked; `der` is needed for the OCSP response types, as no `x509-ocsp` crate is in the workspace). Refresh Nix
  vendor hashes from CI (`.mise/scripts/release/update_hashes.sh`) if the check reports a mismatch.
- **IMP-005**: Document the flow in `documentation/docs/use_cases/pki-sub-ca-csr.md` and the `CHANGELOG/` entry.

## References

- **REF-001**: `documentation/adr/2026-08-20-pki-crl-generation-distribution-auto-refresh.md`
- **REF-002**: RFC 2986 (PKCS#10), RFC 5280 (X.509 certificates and CRLs), RFC 6960 (OCSP), RFC 8017 (PKCS#1 v1.5), RFC 5758 (ECDSA with SHA-2), RFC 8410 (Ed25519/Ed448 in X.509)
- **REF-003**: `crate/server/src/core/certificate/oracle_signing.rs`, `crate/server/src/core/operations/generate_csr.rs`,
  `crate/server/src/core/operations/certify/`, `crate/server/src/core/operations/generate_crl.rs`
- **REF-004**: `crate/kmip/src/kmip_2_1/extra/tagging.rs` (`set_certificate_serial_tag`)
- **REF-005**: Cosmian/kms issue #651 (roles), tracked separately
