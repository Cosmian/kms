# Security Policy

- [Security Policy](#security-policy)
      - [Reporting a Vulnerability](#reporting-a-vulnerability)
      - [Severity Rating](#severity-rating)
      - [Known Vulnerabilities](#known-vulnerabilities)
            - [2026](#2026)
                  - [COSMIAN-2026-055 — Get Attributes without a Unique Identifier selected another user's newest object](#cosmian-2026-055--get-attributes-without-a-unique-identifier-selected-another-users-newest-object)
                  - [COSMIAN-2026-054 — Batch Undo could restore objects of another user](#cosmian-2026-054--batch-undo-could-restore-objects-of-another-user)
                  - [COSMIAN-2026-053 — ReCertify authorized the issuer key as the certificate owner](#cosmian-2026-053--recertify-authorized-the-issuer-key-as-the-certificate-owner)
                  - [COSMIAN-2026-052 — ReKeyKeyPair retired another user's linked public key](#cosmian-2026-052--rekeykeypair-retired-another-users-linked-public-key)
                  - [COSMIAN-2026-051 — KMIP certificate chains and Locate offsets permit excessive server work](#cosmian-2026-051--kmip-certificate-chains-and-locate-offsets-permit-excessive-server-work)
                  - [COSMIAN-2026-050 — KMIP payloads written to debug logs](#cosmian-2026-050--kmip-payloads-written-to-debug-logs)
                  - [COSMIAN-2026-049 — Configured Operator role permitted key output and PKCS#11 administration](#cosmian-2026-049--configured-operator-role-permitted-key-output-and-pkcs11-administration)
                  - [COSMIAN-2026-040 — KMIP socket server accepts the reserved AWS XKS service identity as a client certificate CN](#cosmian-2026-040--kmip-socket-server-accepts-the-reserved-aws-xks-service-identity-as-a-client-certificate-cn)
                  - [COSMIAN-2026-048 — CRL and OCSP trust any certificate linked to the CA](#cosmian-2026-048--crl-and-ocsp-trust-any-certificate-linked-to-the-ca)
                  - [COSMIAN-2026-047 — Batched KMIP `RequestMessage` operations skip the algorithm policy and the role check](#cosmian-2026-047--batched-kmip-requestmessage-operations-skip-the-algorithm-policy-and-the-role-check)
                  - [COSMIAN-2026-046 — Server key encryption key usable as a decryption oracle through pre-wrapped `Import`](#cosmian-2026-046--server-key-encryption-key-usable-as-a-decryption-oracle-through-pre-wrapped-import)
                  - [COSMIAN-2026-045 — Sensitive Opaque Objects and Split Keys exported in plaintext when a wrapping specification is sent](#cosmian-2026-045--sensitive-opaque-objects-and-split-keys-exported-in-plaintext-when-a-wrapping-specification-is-sent)
                  - [COSMIAN-2026-044 — Attribute edits let stored keys escape the KMIP algorithm policy](#cosmian-2026-044--attribute-edits-let-stored-keys-escape-the-kmip-algorithm-policy)
                  - [COSMIAN-2026-043 — Authentication Verifier tokens accepted after logout or session revocation](#cosmian-2026-043--authentication-verifier-tokens-accepted-after-logout-or-session-revocation)
                  - [COSMIAN-2026-042 — Bare HSM keyset identifier bypasses the grant check in crypto operations](#cosmian-2026-042--bare-hsm-keyset-identifier-bypasses-the-grant-check-in-crypto-operations)
                  - [COSMIAN-2026-041 — HSM keys usable to decrypt arbitrary data through `Import` unwrapping](#cosmian-2026-041--hsm-keys-usable-to-decrypt-arbitrary-data-through-import-unwrapping)
                  - [COSMIAN-2026-040 — KMIP socket server accepts the reserved AWS XKS service identity as a client certificate CN](#cosmian-2026-040--kmip-socket-server-accepts-the-reserved-aws-xks-service-identity-as-a-client-certificate-cn)
                  - [COSMIAN-2026-039 — Session-cookie requests accepted from other same-site origins](#cosmian-2026-039--session-cookie-requests-accepted-from-other-same-site-origins)
                  - [COSMIAN-2026-038 — AWS XKS SigV4 secret access key written to the startup log](#cosmian-2026-038--aws-xks-sigv4-secret-access-key-written-to-the-startup-log)
                  - [COSMIAN-2026-037 — Crypto operations reveal the existence and state of other users' keys](#cosmian-2026-037--crypto-operations-reveal-the-existence-and-state-of-other-users-keys)
                  - [COSMIAN-2026-036 — Unbounded per-request work: batch size, PBKDF2 iterations, RSA modulus](#cosmian-2026-036--unbounded-per-request-work-batch-size-pbkdf2-iterations-rsa-modulus)
                  - [COSMIAN-2026-035 — Google CSE `rewrap` SSRF check bypass via redirects, IPv6 literals and DNS](#cosmian-2026-035--google-cse-rewrap-ssrf-check-bypass-via-redirects-ipv6-literals-and-dns)
                  - [COSMIAN-2026-034 — JWT signed by one identity provider accepted for another issuer](#cosmian-2026-034--jwt-signed-by-one-identity-provider-accepted-for-another-issuer)
                  - [COSMIAN-2026-033 — KMIP socket server skips client certificate CN checks](#cosmian-2026-033--kmip-socket-server-skips-client-certificate-cn-checks)
                  - [COSMIAN-2026-032 — KMIP socket server exhaustion: unbounded threads, idle connections and allocation](#cosmian-2026-032--kmip-socket-server-exhaustion-unbounded-threads-idle-connections-and-allocation)
                  - [COSMIAN-2026-031 — `Get`/`Export` Fresh-bit write-back could persist an auto-unwrapped key](#cosmian-2026-031--getexport-fresh-bit-write-back-could-persist-an-auto-unwrapped-key)
                  - [COSMIAN-2026-030 — SetAttribute permits changes to read-only metadata](#cosmian-2026-030--setattribute-permits-changes-to-read-only-metadata)
                  - [GHSA-8mmx-f92q-2gq8 — `Extractable` and `NeverExtractable` not enforced on key export paths](#ghsa-8mmx-f92q-2gq8--extractable-and-neverextractable-not-enforced-on-key-export-paths)
                  - [GHSA-pvw2-jxwc-95xq — Reserved UID `*` bypassable via `AtomicOperation::Upsert` and `Certify` destination overwrite](#ghsa-pvw2-jxwc-95xq--reserved-uid--bypassable-via-atomicoperationupsert-and-certify-destination-overwrite)
                  - [GHSA-c75c-3cmm-48h7 — `Sensitive` and `Extractable` attribute stripping via read-only `Get` grant](#ghsa-c75c-3cmm-48h7--sensitive-and-extractable-attribute-stripping-via-read-only-get-grant)
                  - [COSMIAN-2026-029 — PostgreSQL `sslmode` ignored, connections silently fall back to plaintext](#cosmian-2026-029--postgresql-sslmode-ignored-connections-silently-fall-back-to-plaintext)
                  - [COSMIAN-2026-028 — SSRF check bypass via `kms_public_url` prefix match in CRL fetching](#cosmian-2026-028--ssrf-check-bypass-via-kms_public_url-prefix-match-in-crl-fetching)
                  - [COSMIAN-2026-027 — CRL/OCSP revocation status could be lost, stale or wrong](#cosmian-2026-027--crlocsp-revocation-status-could-be-lost-stale-or-wrong)
                  - [COSMIAN-2026-026 — PKCS#11 module buffer overflows in `C_GetAttributeValue` and `C_Encrypt`](#cosmian-2026-026--pkcs11-module-buffer-overflows-in-c_getattributevalue-and-c_encrypt)
                  - [COSMIAN-2026-025 — JOSE tag endpoints allow tag changes with any grant](#cosmian-2026-025--jose-tag-endpoints-allow-tag-changes-with-any-grant)
                  - [COSMIAN-2026-024 — Any user can publish a key on the unauthenticated JWKS endpoint](#cosmian-2026-024--any-user-can-publish-a-key-on-the-unauthenticated-jwks-endpoint)
                  - [COSMIAN-2026-023 — SPIRE transit key substitution via shared tags](#cosmian-2026-023--spire-transit-key-substitution-via-shared-tags)
                  - [COSMIAN-2026-022 — SPIRE PKI `sign-intermediate` issues CA certificates to any Vault token](#cosmian-2026-022--spire-pki-sign-intermediate-issues-ca-certificates-to-any-vault-token)
                  - [COSMIAN-2026-021 — SSRF via attacker-controlled CRL Distribution Points in KMIP Validate/Import](#cosmian-2026-021--ssrf-via-attacker-controlled-crl-distribution-points-in-kmip-validateimport)
                  - [COSMIAN-2026-020 — `Get` grant on wildcard uid `*` bypasses the Create/Import authorization gate](#cosmian-2026-020--get-grant-on-wildcard-uid--bypasses-the-createimport-authorization-gate)
                  - [COSMIAN-2026-019 — RUSTSEC-2026-0173: `proc-macro-error2` soundness issue via `mysql_async`](#cosmian-2026-019--rustsec-2026-0173-proc-macro-error2-soundness-issue-via-mysql_async)
                  - [COSMIAN-2026-018 — Activate operation uses overly permissive authorization check](#cosmian-2026-018--activate-operation-uses-overly-permissive-authorization-check)
                  - [COSMIAN-2026-017 — ReKey / ReKeyKeyPair authorization bypass via raw object retrieval](#cosmian-2026-017--rekey--rekeykeypair-authorization-bypass-via-raw-object-retrieval)
                  - [COSMIAN-2026-016 — Attribute-mutation authorization bypass via incorrect operation type](#cosmian-2026-016--attribute-mutation-authorization-bypass-via-incorrect-operation-type)
                  - [COSMIAN-2026-015 — KEK plaintext leak via `UsageLimits` persist in Decrypt and Sign](#cosmian-2026-015--kek-plaintext-leak-via-usagelimits-persist-in-decrypt-and-sign)
                  - [COSMIAN-2026-014 — Sensitive configuration values exposed in Debug output](#cosmian-2026-014--sensitive-configuration-values-exposed-in-debug-output)
                  - [COSMIAN-2026-013 — Internal error details leaked in HTTP 5xx responses](#cosmian-2026-013--internal-error-details-leaked-in-http-5xx-responses)
                  - [COSMIAN-2026-012 — `/server-info` endpoint accessible without authentication](#cosmian-2026-012--server-info-endpoint-accessible-without-authentication)
                  - [COSMIAN-2026-011 — Non-atomic state transitions enable TOCTOU races](#cosmian-2026-011--non-atomic-state-transitions-enable-toctou-races)
                  - [COSMIAN-2026-010 — Predictable default session cookie salt](#cosmian-2026-010--predictable-default-session-cookie-salt)
                  - [COSMIAN-2026-009 — Google CSE rewrap SSRF via `original_kacls_url`](#cosmian-2026-009--google-cse-rewrap-ssrf-via-original_kacls_url)
                  - [COSMIAN-2026-008 — Unwrap cache not invalidated on key revocation/destruction](#cosmian-2026-008--unwrap-cache-not-invalidated-on-key-revocationdestruction)
                  - [COSMIAN-2026-007 — MS DKE scope missing authentication middleware](#cosmian-2026-007--ms-dke-scope-missing-authentication-middleware)
                  - [COSMIAN-2026-006 — Server crash under concurrent requests due to tracing span misuse](#cosmian-2026-006--server-crash-under-concurrent-requests-due-to-tracing-span-misuse)
                  - [COSMIAN-2026-005 — JWT decoding race condition causing intermittent authentication bypass](#cosmian-2026-005--jwt-decoding-race-condition-causing-intermittent-authentication-bypass)
                  - [COSMIAN-2026-004 — OTLP telemetry exported over plaintext HTTP leaks encryption queries](#cosmian-2026-004--otlp-telemetry-exported-over-plaintext-http-leaks-encryption-queries)
                  - [COSMIAN-2026-003 — KMIP Import `replace_existing` bypasses ownership verification](#cosmian-2026-003--kmip-import-replace_existing-bypasses-ownership-verification)
                  - [COSMIAN-2026-002 — SipHash key hardcoded to zero in unwrap cache](#cosmian-2026-002--siphash-key-hardcoded-to-zero-in-unwrap-cache)
            - [2025](#2025)
                  - [COSMIAN-2025-003 — glibc CVEs in container base image (CVE-2024-2961, CVE-2024-33600, CVE-2024-33601)](#cosmian-2025-003--glibc-cves-in-container-base-image-cve-2024-2961-cve-2024-33600-cve-2024-33601)
                  - [COSMIAN-2025-012 — Session cookie encryption key randomly regenerated on each restart](#cosmian-2025-012--session-cookie-encryption-key-randomly-regenerated-on-each-restart)
                  - [COSMIAN-2025-011 — RUSTSEC-2023-0071: RSA Marvin Attack timing side-channel](#cosmian-2025-011--rustsec-2023-0071-rsa-marvin-attack-timing-side-channel)
                  - [COSMIAN-2025-004 — OpenSSL 3.x CVEs addressed by upgrade to 3.6.2](#cosmian-2025-004--openssl-3x-cves-addressed-by-upgrade-to-362)
                  - [COSMIAN-2025-010 — JWT authentication token not forwarded to downstream services](#cosmian-2025-010--jwt-authentication-token-not-forwarded-to-downstream-services)
                  - [COSMIAN-2025-009 — HSM unwrap operation bypasses KMS permission checks](#cosmian-2025-009--hsm-unwrap-operation-bypasses-kms-permission-checks)
                  - [COSMIAN-2025-002 — Negative X.509 certificate serial numbers](#cosmian-2025-002--negative-x509-certificate-serial-numbers)
                  - [COSMIAN-2025-008 — Google CSE `privilegedunwrap` endpoint unrestricted access](#cosmian-2025-008--google-cse-privilegedunwrap-endpoint-unrestricted-access)
                  - [COSMIAN-2025-001 — CSE migration key pair race condition](#cosmian-2025-001--cse-migration-key-pair-race-condition)
                  - [COSMIAN-2025-007 — OpenID Connect authentication silently falls back to no-auth on TLS failure](#cosmian-2025-007--openid-connect-authentication-silently-falls-back-to-no-auth-on-tls-failure)
                  - [COSMIAN-2025-006 — Missing PKCE in OAuth2 authentication flow](#cosmian-2025-006--missing-pkce-in-oauth2-authentication-flow)
                  - [COSMIAN-2025-005 — JWT authorization config loop — only first OIDC provider checked](#cosmian-2025-005--jwt-authorization-config-loop--only-first-oidc-provider-checked)
      - [Summary Table](#summary-table)
      - [Security Best Practices](#security-best-practices)
      - [FIPS Compliance](#fips-compliance)
      - [Security Audits](#security-audits)
      - [Contact](#contact)

---

## Reporting a Vulnerability

We take the security of Cosmian KMS seriously. If you discover a security vulnerability, please report it responsibly:

1. **Do not** report security vulnerabilities through public GitHub issues.
2. **GitHub Security Advisories** (preferred): Use the [private vulnerability reporting feature](https://github.com/Cosmian/kms/security/advisories/new).
3. **Email**: Send details to [tech@cosmian.com](mailto:tech@cosmian.com).

**What to include:** A clear description, steps to reproduce, potential impact, and suggested fix if available.

**Response timeline:**

- **Acknowledgement**: within 48 hours
- **Investigation**: within 5 business days
- **Fix**: as quickly as possible, coordinated disclosure with reporter

---

## Severity Rating

| Rating   | Description                                                                                          |
| -------- | ---------------------------------------------------------------------------------------------------- |
| Critical | Directly impacts key confidentiality, integrity, or authentication bypass for any authenticated user |
| High     | Impacts availability or enables privilege escalation under realistic attack conditions               |
| Moderate | Requires specific conditions, limited scope, or no direct key compromise                             |
| Low      | Minimal practical impact or very difficult to exploit                                                |

---

## Known Vulnerabilities

### 2026

#### COSMIAN-2026-055 — Get Attributes without a Unique Identifier selected another user's newest object

| Field      | Value                                                      |
| ---------- | ---------------------------------------------------------- |
| Severity   | Moderate                                                   |
| Published  | Pending                                                    |
| Affected   | before 5.29.0                                              |
| Fixed in   | 5.29.0                                                     |
| Found by   | Security review, 20 October 2026                           |
| References | [Branch changelog](CHANGELOG/fix_kmip-conformance-gaps.md) |

**Summary:** A Get Attributes request without a Unique Identifier and without an ID Placeholder made the server scan every stored object and pick the most recently changed one, preferring the caller's own objects but falling back to any user's. The permission check ran only after that choice, and its "object not found" error named the selected identifier.

**Impact:** A caller who owned no object learned the Unique Identifier of the newest object in the database, whoever owned it. Any authenticated user could also make each such request read the whole object table.

**Mitigation:** Upgrade to 5.29.0. An omitted Unique Identifier now means the ID Placeholder only (KMIP 2.1 §6.1.20); with no placeholder the request fails without selecting or naming any object. Regression test: `test_get_attributes_without_identifier_selects_nothing`.

---

#### COSMIAN-2026-054 — Batch Undo could restore objects of another user

| Field      | Value                                                                 |
| ---------- | --------------------------------------------------------------------- |
| Severity   | Moderate                                                              |
| Published  | Pending                                                               |
| Affected   | unreleased development code only (introduced and fixed before 5.29.0) |
| Fixed in   | 5.29.0                                                                |
| Found by   | Security review, 20 October 2026                                      |
| References | [Branch changelog](CHANGELOG/fix_kmip-conformance-gaps.md)            |

**Summary:** The KMIP Undo batch error option, implemented during the 5.29.0 development cycle, snapshotted each item's target and every object the target linked to, without checking the caller's permissions, and wrote the snapshots back unconditionally after a failure. Links are client-editable, so a user could link one of their own objects to another user's object. Tag, keyset and name handles, re-keys of wrapping keys, Covercrypt cascades and Crypto Officer key splits were reported as undone although their effects remained, and a ceremony split lost its key.

**Impact:** A user could make an Undo batch overwrite another user's object with an earlier state: for example, revert a revocation or bring back key material destroyed concurrently. No released version is affected.

**Mitigation:** Fixed before release. Undo snapshots the target only after the operation's own authorization, and linked objects only when the caller may change them. Each item is reverted in one transaction, and only if every object it touched is still as the item left it. Items the server cannot revert keep `Success`. Each revert is logged, and Undo batches are limited to 1,000 items and 4,000 snapshots. Regression tests: `undo_never_restores_another_users_linked_object`, `undo_leaves_an_object_changed_after_the_item`, `undo_refuses_what_it_cannot_revert`, `undo_batch_size_is_bounded` and `test_undo_keeps_ceremony_split_key_shares`.

---

#### COSMIAN-2026-053 — ReCertify authorized the issuer key as the certificate owner

| Field      | Value                                                      |
| ---------- | ---------------------------------------------------------- |
| Severity   | High                                                       |
| Published  | Pending                                                    |
| Affected   | before 5.29.0                                              |
| Fixed in   | 5.29.0                                                     |
| Found by   | Security review, 20 October 2026                           |
| References | [Branch changelog](CHANGELOG/fix_kmip-conformance-gaps.md) |

**Summary:** `ReCertify` checked the caller's `Certify` (or `Get`) grant on the certificate, then resolved the subject and the issuer CA key and certificate as the certificate's owner. The issuer links, Certificate Request and Certificate Request Unique Identifier come from the request.

**Impact:** A user with only a read or `Certify` grant on a leaf certificate, plus the right to create objects, could have the owner's CA key sign a certificate for a request the user chose. The user owned the issued certificate. The CA key itself was not exposed.

**Mitigation:** Upgrade to 5.29.0. The subject and issuer are now resolved and authorized as the requesting user, and keys linked to the old certificate are relinked only when the user may certify with them. Regression test: `test_recertify_authorizes_issuer_as_requester`.

---

#### COSMIAN-2026-052 — ReKeyKeyPair retired another user's linked public key

| Field      | Value                                                      |
| ---------- | ---------------------------------------------------------- |
| Severity   | High                                                       |
| Published  | Pending                                                    |
| Affected   | before 5.29.0                                              |
| Fixed in   | 5.29.0                                                     |
| Found by   | Security review, 20 October 2026                           |
| References | [Branch changelog](CHANGELOG/fix_kmip-conformance-gaps.md) |

**Summary:** `ReKeyKeyPair` checked the caller's permission on the private key only. It then loaded the public key named by the private key's Public Key Link without any permission check. The owner of a private key can set that link to any identifier.

**Impact:** A user could point their own private key at another user's public key and re-key it. The victim's public key was then deactivated and given a Replacement Object Link to the attacker's new key, and its attributes were copied into a key the attacker owned. This is the same class as COSMIAN-2026-017.

**Mitigation:** Upgrade to 5.29.0. The linked public key now requires the `Rekey` permission and is otherwise reported as `Object_Not_Found`. Editing a Link also requires ownership or an explicit grant of the edit operation. Regression test: `test_rekey_keypair_does_not_retire_another_users_linked_public_key`.

---

#### COSMIAN-2026-051 — KMIP certificate chains and Locate offsets permit excessive server work

| Field      | Value                                                      |
| ---------- | ---------------------------------------------------------- |
| Severity   | Moderate                                                   |
| Published  | Pending                                                    |
| Affected   | before 5.29.0                                              |
| Fixed in   | 5.29.0                                                     |
| Found by   | Security review, 19 October 2026                           |
| References | [Branch changelog](CHANGELOG/fix_kmip-conformance-gaps.md) |

**Summary:** PKCS#12 and PKCS#7 export followed a certificate's `CertificateLink` chain without cycle detection or a depth limit. `Locate` accepted arbitrary positive `OffsetItems`, which was added to the store query limit. When HSMs were configured, a `Locate` by a user who is not an HSM administrator ran without any store limit and enumerated every HSM key and its metadata before discarding the keys not granted to that user.

**Impact:** An authenticated caller able to create or link managed certificates could make an export loop indefinitely. A request with a very large Locate offset could force excessive database work. On a server with HSMs, any authenticated user could make each Locate read the metadata of every key on the HSMs.

**Mitigation:** Upgrade to 5.29.0. Certificate chains reject cycles and chains above 100 certificates. Locate rejects offsets above 1,000 and does not limit destroyed-only results before filtering their storage status. For a user who is not an HSM administrator, Locate resolves the HSM keys granted to that user first and looks up only those, bounded by the requested page. Regression tests: `certificate_chain_cycle_is_rejected`, `locate_rejects_an_excessive_offset`, `destroyed_only_locate_is_not_limited_before_status_filtering`, and `non_hsm_admin_locate_pages_only_granted_hsm_keys`.

---

#### COSMIAN-2026-050 — KMIP payloads written to debug logs

| Field      | Value                                                      |
| ---------- | ---------------------------------------------------------- |
| Severity   | High                                                       |
| Published  | Pending                                                    |
| Affected   | before 5.29.0                                              |
| Fixed in   | 5.29.0                                                     |
| Found by   | Security review, 19 October 2026                           |
| References | [Branch changelog](CHANGELOG/fix_kmip-conformance-gaps.md) |

**Summary:** The binary KMIP handler and message processor logged complete request and response TTLV values, including raw request and response bytes.

**Impact:** Debug logs could contain plaintext key material, wrapped keys, decrypted data, signatures, and client correlation values. Anyone who could read those logs could recover the recorded data.

**Mitigation:** Upgrade to 5.29.0. KMIP logs retain only request metadata and operation names; they no longer emit payloads or encoded bytes. Rotate or restrict access to logs written by earlier versions.

---

#### COSMIAN-2026-049 — Configured Operator role permitted key output and PKCS#11 administration

| Field      | Value                                                      |
| ---------- | ---------------------------------------------------------- |
| Severity   | High                                                       |
| Published  | Pending                                                    |
| Affected   | before 5.29.0                                              |
| Fixed in   | 5.29.0                                                     |
| Found by   | Security review, 19 October 2026                           |
| References | [Branch changelog](CHANGELOG/fix_kmip-conformance-gaps.md) |

**Summary:** When Crypto Officer roles were configured, dispatch let Operators invoke role-disallowed per-object operations and unmapped operations. Object ownership or grants could therefore authorize `Get` and `Export`, and the `PKCS11` management operation bypassed the role policy entirely.

**Impact:** An Operator who owned a key or held an object-level grant could retrieve key material despite the configured role policy. An Operator could also access PKCS#11 administration.

**Mitigation:** Upgrade to 5.29.0. Dispatch now denies all role-disallowed and unmapped operations except the explicitly safe non-lifecycle operations, and regression test `operator_cannot_invoke_key_output_or_administrative_operations` covers the boundary.

---

#### COSMIAN-2026-048 — CRL and OCSP trust any certificate linked to the CA

| Field      | Value                                                                                                                     |
| ---------- | ------------------------------------------------------------------------------------------------------------------------- |
| Severity   | High                                                                                                                      |
| Published  | Pending                                                                                                                   |
| Affected   | from 5.27.0 before 5.29.0                                                                                                 |
| Fixed in   | 5.29.0                                                                                                                    |
| Found by   | Pre-release security review, 28 October 2026                                                                              |
| References | [Regression tests](crate/server/src/tests/revocation_authority_tests.rs), [Release notes](CHANGELOG.md#5290---2026-10-28) |

**Summary:** CRL generation listed every revoked certificate whose `CertificateLink` pointed at the CA certificate, whoever owned it, and the OCSP responder looked a serial up among the same certificates, Active ones first. Neither checked that the CA had issued the certificate. Any user allowed to `Import` could store a certificate carrying the serial of a certificate of the CA (a forgery, or a byte-for-byte copy of the genuine certificate, which is public), link it to the CA at import or later with `AddAttribute`/`SetAttribute`, and then revoke it or keep it active as its owner.

**Impact:** An `Import`-capable user could put the serial of any certificate of a CA on its CRL, so relying parties reject a valid certificate, or make OCSP answer `good` for a revoked certificate, so relying parties accept it.

**Mitigation:** Upgrade to 5.29.0. CRL and OCSP count only certificates whose issuer name is the CA subject and whose signature verifies with the CA public key; a certificate whose signature cannot be checked does not count. When stored copies share a serial, only the copies owned by the CA certificate owner or by a user allowed to issue with the CA private key count (a `Certify` grant, or `Get` on a database key; an explicit grant or HSM admin rights for an HSM key); if no copy has such an owner, all copies count, so a revocation is never silently dropped. A revoked copy wins over an active one: OCSP answers `good` only when no counted copy is revoked, and the CRL lists each serial once with its earliest revocation date. 5.29.0 extends CRL and OCSP signing to HSM-backed CAs, which get the same checks. If the user who issued a certificate loses the grant and no other authorized copy exists, all copies count again. Each CRL generation now reads every certificate linked to the CA once, which can be slow for a CA with a very large number of certificates. After the upgrade, check the CRLs and OCSP answers published before it for serials that the CA owner did not revoke. Regression tests: `crl_lists_only_revocations_of_certificates_the_ca_issued` and `ocsp_ignores_forged_and_copied_certificates_linked_to_the_ca` in `crate/server/src/tests/revocation_authority_tests.rs`, and the copy-and-revoke case of `test_hsm_sub_ca` in `crate/server/src/tests/hsm/sub_ca.rs`. Until then, grant `Import` only to trusted users.

---

#### COSMIAN-2026-047 — Batched KMIP `RequestMessage` operations skip the algorithm policy and the role check

| Field      | Value                                                                                                                                                                  |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Severity   | Moderate                                                                                                                                                               |
| Published  | Pending                                                                                                                                                                |
| Affected   | from 5.16.0 before 5.29.0                                                                                                                                              |
| Fixed in   | 5.29.0                                                                                                                                                                 |
| Found by   | Pre-release security review, fixed on `develop` on 20 October 2026 (#1257)                                                                                             |
| References | [Fix](crate/server/src/core/operations/message.rs), [Regression tests](crate/server/src/tests/security_regression.rs), [Release notes](CHANGELOG.md#5290---2026-10-28) |

**Summary:** The request-time KMIP algorithm policy (`[kmip.policy]`) ran only on the single-operation TTLV path, selected by the name of the root tag. Operations sent inside a KMIP `RequestMessage`, the format of KMIP 1.x and 2.x clients and of the KMIP socket server, skipped it from 5.16.0, and so did a single `MAC` request whose root tag was spelled `Mac`, which the dispatcher accepted but the policy did not match. From 5.27.0, the role check of the `RequestMessage` path also named operations by string with an `Unknown` fallback, which the check let through for every user: a batched `CreateSplitKey` skipped the Crypto Officer restriction that the single-operation path applies. `JoinSplitKey` stays open to every user by design. The policy check on stored keys at use time was not affected.

**Impact:** Any authenticated user could create keys and send request parameters that the configured algorithm policy forbids (for example an RSA key size or block cipher mode refused by `DEFAULT`) by wrapping the operation in a `RequestMessage`, and, once `crypto_officer_users` was configured, a user who is not a Crypto Officer could create split keys.

**Mitigation:** Upgrade to 5.29.0. Every operation of a `RequestMessage` goes through the same role check, keyed by the KMIP operation enumeration, and the same request-time algorithm policy as a single operation, and the policy also matches the `Mac` spelling. After the upgrade, `Locate` the keys whose algorithm, length or curve the policy forbids, created through a `RequestMessage` before the upgrade, and revoke or re-key them, and review split keys created by users who are not Crypto Officers. Regression tests: `test_default_kmip_policy_applies_to_batched_request_messages`, `test_mac_tag_spelling_cannot_bypass_algorithm_policy` and `test_rng_seed_is_restricted_to_crypto_officers` (exercises the role check of the `RequestMessage` path; the `RNGSeed` restriction itself is new in 5.29.0) in `crate/server/src/tests/security_regression.rs`. Until then, grant KMS access only to trusted clients.

---

#### COSMIAN-2026-046 — Server key encryption key usable as a decryption oracle through pre-wrapped `Import`

| Field      | Value                                                                                                            |
| ---------- | ---------------------------------------------------------------------------------------------------------------- |
| Severity   | High                                                                                                             |
| Published  | Pending                                                                                                          |
| Affected   | from 5.13.0 before 5.29.0                                                                                        |
| Fixed in   | 5.29.0                                                                                                           |
| Found by   | Pre-release security review, 27 October 2026                                                                     |
| References | [Regression test](crate/server/src/tests/hsm/fake_hsm_authz.rs), [Release notes](CHANGELOG.md#5290---2026-10-28) |

**Summary:** When a `key_encryption_key` is configured, every key is stored wrapped by it and unwrapped transparently for its owner on `Get`, `Export` and crypto operations. `Import` and `Register` accepted a key block that the request declared as already wrapped by that KEK (or by its `_pk` public key, which unwrapping resolves to the KEK) and stored it as is; the importing user then owned it, and a later `Get` or `Export` with `NotWrapped` unwrapped it with the KEK. A database KEK already required the owner or a `Decrypt` grant on its private key, so only a KEK held in an HSM was exploitable.

**Impact:** Any user allowed to `Import` could have arbitrary ciphertext decrypted by the server KEK, for example key material taken from a database backup or from another user's KEK-wrapped export, and so recover keys of other users protected at rest by the KEK.

**Mitigation:** Upgrade to 5.29.0. `Import` and `Register` of a key block wrapped by the server `key_encryption_key` or its `_pk` alias, and an `Import` that asks the server to unwrap with the KEK, are accepted only from users allowed to decrypt with the KEK: HSM admins or explicit `Decrypt` grantees for an HSM KEK, the existing owner/grant rule for a database KEK (COSMIAN-2026-041). The same applies when the block names the KEK by a numeric uid, or by a public key or certificate whose `PrivateKeyLink` points at the KEK. Everyone else gets `Invalid_Request`. Plain imports are still wrapped by the KEK at rest, and the at-rest exemption that lets every user unwrap with the KEK applies only when the stored key block names the KEK uid or `<kek>_pk` literally: a key reached through a `PrivateKeyLink` must be a private key and needs the usual grant. Regression tests: `test_kek_wrapped_import_is_refused`, `test_hsm_kek_unwraps_at_rest_but_not_on_import`, `test_hsm_kek_alias_is_no_decryption_oracle`, `test_db_kek_alias_is_no_decryption_oracle` and `test_numeric_kek_uid_wrapped_import_is_refused` in `crate/server/src/tests/hsm/fake_hsm_authz.rs`. Until then, restrict `Import` (and `Create`) to trusted users with `crypto_officer_users`.

---

#### COSMIAN-2026-045 — Sensitive Opaque Objects and Split Keys exported in plaintext when a wrapping specification is sent

| Field      | Value                                                                                                              |
| ---------- | ------------------------------------------------------------------------------------------------------------------ |
| Severity   | Moderate                                                                                                           |
| Published  | Pending                                                                                                            |
| Affected   | from 5.13.0 before 5.29.0                                                                                          |
| Fixed in   | 5.29.0                                                                                                             |
| Found by   | Pre-release security review, 27 October 2026                                                                       |
| References | [Regression test](crate/server/src/core/operations/export_get.rs), [Release notes](CHANGELOG.md#5290---2026-10-28) |

**Summary:** `Get` and `Export` refuse a Sensitive object only when the request has no `KeyWrappingSpecification`, on the assumption that a wrapping specification makes the server wrap the object. The export path never wraps Opaque Objects (and, from 5.27.0, Split Keys): it returns them as stored. A request carrying any wrapping specification therefore passed the Sensitive check and received the object in plaintext.

**Impact:** A user holding a `Get` or `Export` grant on a Sensitive Opaque Object or Split Key could read its content in plaintext, which `Sensitive` is meant to prevent.

**Mitigation:** Upgrade to 5.29.0. A wrapping specification no longer counts as protection for Opaque Objects, Split Keys and OpenPGP keys: a Sensitive object is refused with `Sensitive`, and a non-sensitive one requested with a wrapping specification is refused with `Key_Wrap_Type_Not_Supported` instead of being returned unwrapped. Regression test: `test_sensitive_pgp_key_export_ignores_dummy_wrapping` in `crate/server/src/core/operations/export_get.rs`, which exercises, through an OpenPGP key (a type added after 5.28.0), the check shared by the three object types. Until then, do not grant `Get` or `Export` on Sensitive Opaque Objects or Split Keys to users who must not read them.

---

#### COSMIAN-2026-044 — Attribute edits let stored keys escape the KMIP algorithm policy

| Field      | Value                                                                                                                                                                                  |
| ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Severity   | Moderate                                                                                                                                                                               |
| Published  | Pending                                                                                                                                                                                |
| Affected   | from 5.16.0 before 5.29.0                                                                                                                                                              |
| Fixed in   | 5.29.0                                                                                                                                                                                 |
| Found by   | Pre-release security review, 27 October 2026                                                                                                                                           |
| References | [Regression test](crate/server/src/tests/test_set_attribute.rs), [Policy tests](crate/server/src/core/operations/algorithm_policy.rs), [Release notes](CHANGELOG.md#5290---2026-10-28) |

**Summary:** The `[kmip.policy]` allowlists are checked on each use of a stored key from its attributes (`CryptographicAlgorithm`, `CryptographicLength`, `CryptographicDomainParameters`, `CryptographicParameters`). Clients could still add, set, modify or delete most of the attributes that KMIP 2.1 marks read-only, including these (`CryptographicLength` was already refused by Set, Modify and Delete, but not by Add), and the policy skipped a check when the attribute was missing. Imported PKCS#8 EC and Ed25519 keys also skipped the curve check.

**Impact:** A user allowed to edit the attributes of a key, or to import one, could relabel or strip its algorithm or curve attributes and then use a key that the configured algorithm policy forbids (for example a disallowed curve or block cipher mode).

**Mitigation:** Upgrade to 5.29.0. `AddAttribute`, `SetAttribute`, `ModifyAttribute` and `DeleteAttribute` refuse every attribute that KMIP 2.1 marks read-only (Add and Set with `Read_Only_Attribute`, Modify and Delete with `Attribute_Read_Only`). The policy falls back to the values recorded in the key material when an attribute is missing, reads the curve from the key, refuses wrapped keys whose curve cannot be determined, and checks stored `CryptographicParameters` on use. Under a curve allowlist, imported PKCS#8 EC and Ed25519 keys are now curve-checked, so the `DEFAULT` policy refuses an imported Ed25519 key as it already refused a created one; `ckms attributes` no longer offers `--cryptographic-algorithm` and `--cryptographic-length`. Regression tests: `server_managed_attributes_are_rejected` in `crate/server/src/tests/test_set_attribute.rs` and `retrieved_key_curve_is_read_from_key_material` in `crate/server/src/core/operations/algorithm_policy.rs`. Until then, grant attribute-edit operations only to trusted users.

---

#### COSMIAN-2026-043 — Authentication Verifier tokens accepted after logout or session revocation

| Field      | Value                                                                                                                   |
| ---------- | ----------------------------------------------------------------------------------------------------------------------- |
| Severity   | Moderate                                                                                                                |
| Published  | Pending                                                                                                                 |
| Affected   | from 5.26.0 before 5.29.0                                                                                               |
| Fixed in   | 5.29.0                                                                                                                  |
| Found by   | Pre-release security review, 27 October 2026                                                                            |
| References | [Regression test](crate/server/src/middlewares/auth_verifier/token.rs), [Release notes](CHANGELOG.md#5290---2026-10-28) |

**Summary:** The KMS validated Authentication Verifier tokens offline, from their signature and `exp` claim only. Ending the session at the Authentication Verifier (logout, admin revocation or idle timeout) did not affect the token, which the KMS kept accepting as a bearer token until it expired.

**Impact:** A token captured from a client (logs, a shared workstation, a proxy) remained usable against the KMS for its whole lifetime even after the user logged out or an administrator revoked the session.

**Mitigation:** Upgrade to 5.29.0. After the signature check, the KMS asks `GET {auth_verifier_url}/whoami` whether the session is still live, for bearer tokens and for the `_ea_` session cookie (added after 5.28.0, so in no release), and refuses the request otherwise; a live answer is cached for 30 s, and a logout through the KMS drops the entry at once on that instance. The KMS must now reach `auth_verifier_url` at runtime, through the `[proxy]` settings when configured, like the JWKS fetch: requests carrying an Authentication Verifier token are refused while it is unreachable. Regression tests: `token_of_ended_session_is_rejected` in `crate/server/src/middlewares/auth_verifier/token.rs` and `token_of_ended_session_does_not_authenticate` in `crate/server/src/middlewares/auth_verifier/middleware.rs`. Until then, keep the Authentication Verifier token lifetime short.

---

#### COSMIAN-2026-042 — Bare HSM keyset identifier bypasses the grant check in crypto operations

| Field      | Value                                                                                                            |
| ---------- | ---------------------------------------------------------------------------------------------------------------- |
| Severity   | High                                                                                                             |
| Published  | Pending                                                                                                          |
| Affected   | from 5.25.0 before 5.29.0                                                                                        |
| Fixed in   | 5.29.0                                                                                                           |
| Found by   | Pre-release security review, 27 October 2026                                                                     |
| References | [Regression test](crate/server/src/tests/hsm/fake_hsm_authz.rs), [Release notes](CHANGELOG.md#5290---2026-10-28) |

**Summary:** A crypto operation addressed to a keyset name (for example `hsm::<slot>::<name>`) resolved the selected keyset member through a lookup by name, which returns every member whatever the caller, then loaded it and checked only its process window and state. The caller's grant on the selected key was never checked.

**Impact:** Any authenticated user who knew or guessed a keyset name could use its current HSM key for `Encrypt`, `Sign`, `MAC` and the other operations that select a single keyset member, without any grant on it.

**Mitigation:** Upgrade to 5.29.0. The selected member is now checked for ownership, HSM admin rights or an explicit grant before its state, and a caller with no grant gets `Item_Not_Found`, as for any other key (COSMIAN-2026-037). Regression test: `test_bare_hsm_keyset_uid_requires_grant` in `crate/server/src/tests/hsm/fake_hsm_authz.rs`. Until then, do not rely on KMS grants to restrict the use of HSM keysets.

---

#### COSMIAN-2026-041 — HSM keys usable to decrypt arbitrary data through `Import` unwrapping

| Field      | Value                                                                                                                                                                                                        |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Severity   | Critical                                                                                                                                                                                                     |
| Published  | Pending                                                                                                                                                                                                      |
| Affected   | from 5.13.0 before 5.29.0                                                                                                                                                                                    |
| Fixed in   | 5.29.0                                                                                                                                                                                                       |
| Found by   | Pre-release security review, 27 October 2026                                                                                                                                                                 |
| References | [COSMIAN-2025-009](#cosmian-2025-009--hsm-unwrap-operation-bypasses-kms-permission-checks), [Regression test](crate/server/src/tests/hsm/fake_hsm_authz.rs), [Release notes](CHANGELOG.md#5290---2026-10-28) |

**Summary:** The 5.13.0 fix of COSMIAN-2025-009 left the HSM unwrap path without a KMS permission check, on the documented assumption that the HSM enforces access control. When an `Import` asks the server to unwrap a key wrapped by an HSM key, or when a stored key wrapped by an HSM key is read, the server decrypted the wrapped bytes with that HSM key without checking the caller's grant on it. Wrapping a key with an HSM key on `Create`, `Import` or `Export` accepted a mere `Get` grant on the HSM key instead of `Encrypt`, and reads served from the unwrapped-object cache, which all users share, skipped the wrapping-key check that cache misses performed.

**Impact:** Any user allowed to `Import` could submit arbitrary ciphertext as a "wrapped key" naming any HSM key, and read the decrypted bytes back as the imported key: in effect, `Decrypt` with every HSM key, across tenants, including data keys other users had wrapped with them. A user holding only `Get` on an HSM key could also encrypt with it through key wrapping.

**Mitigation:** Upgrade to 5.29.0. Unwrapping with an HSM key now requires HSM admin rights or an explicit `Decrypt` grant on that key, checked before the HSM is called; wrapping with it on `Create`, `Import` or `Export` requires HSM admin rights or an explicit `Encrypt` grant (`Get` no longer suffices); and reads served from the unwrapped-object cache are authorized exactly like uncached reads. The configured `key_encryption_key`, in the HSM or in the database, still unwraps keys at rest for every user, but unwraps through an `Import` only for users allowed to decrypt with it (see COSMIAN-2026-046). Owners of keys wrapped by an HSM key other than the KEK need `Decrypt` on that HSM key to keep using them, and users who create, import or export keys wrapped by such an HSM key need `Encrypt` on it. Regression tests: `test_hsm_unwrap_on_import_requires_decrypt_grant`, `test_hsm_kek_unwraps_at_rest_but_not_on_import`, `test_hsm_wrap_requires_encrypt_grant` and `test_unwrapped_cache_hit_is_authorized_like_a_miss` in `crate/server/src/tests/hsm/fake_hsm_authz.rs`. Until then, restrict `Import` (and `Create`) to trusted users with `crypto_officer_users`.

---

#### COSMIAN-2026-040 — KMIP socket server accepts the reserved AWS XKS service identity as a client certificate CN

| Field      | Value                                                                                                 |
| ---------- | ----------------------------------------------------------------------------------------------------- |
| Severity   | Moderate                                                                                              |
| Published  | Pending                                                                                               |
| Affected   | from 5.27.1 before 5.29.0                                                                             |
| Fixed in   | 5.29.0                                                                                                |
| Found by   | Internal security review                                                                              |
| References | [Regression test](crate/server/src/socket_server.rs), [Release notes](CHANGELOG.md#5290---2026-10-28) |

**Summary:** 5.27.1 moved AWS XKS operations to the reserved identity `[aws-xks-service]` and rejected that name on every HTTPS authentication path, but the KMIP socket server (TLS port 5696) still used the client certificate Common Name as the user without that check.

**Impact:** A client holding a certificate issued by a CA trusted in `clients_ca_cert_file` with `CN=[aws-xks-service]` could call `Encrypt`/`Decrypt` on every AWS XKS key over KMIP, bypassing AWS SigV4. Exploitation requires the socket server to be enabled and a trusted CA willing to issue that Common Name.

**Mitigation:** Upgrade to 5.29.0 when available; the socket server now applies the same certificate-to-user checks as HTTPS mTLS. Until then, disable the socket server (`socket_server_start = false`) when AWS XKS is enabled, or ensure no CA in `clients_ca_cert_file` can issue a certificate with that Common Name.

---

#### COSMIAN-2026-039 — Session-cookie requests accepted from other same-site origins

| Field      | Value                                           |
| ---------- | ----------------------------------------------- |
| Severity   | Low                                             |
| Published  | Pending                                         |
| Affected   | before 5.29.0                                   |
| Fixed in   | 5.29.0                                          |
| Found by   | Threat model (STRIDE-A), 16 October 2026        |
| References | [Release notes](CHANGELOG.md#5290---2026-10-28) |

**Summary:** The web UI session cookie is `SameSite=Lax`, so browsers withhold it on cross-site requests but send it on requests from other origins of the same site (sibling subdomains, other ports of the same host). `/v1/crypto/*`, `/tokenize/*` and the `/ui/*` routes used `Cors::permissive()`, which reflects any origin with `Access-Control-Allow-Credentials: true`, contrary to the documented same-origin policy. `POST /kmip/2_1` accepted any `Content-Type`, so a `text/plain` request needed no CORS preflight.

**Impact:** Script running on another origin of the same site (for example an XSS on a sibling subdomain) could use the session of a logged-in UI user to call `/v1/crypto` and `/tokenize` and read the results, read the user's identity from `GET /ui/whoami`, or submit KMIP requests to `/kmip/2_1` without reading the response.

**Mitigation:** Upgrade to 5.29.0. `/v1/crypto`, `/tokenize` and `/ui` use the same CORS policy as the KMIP scope (same-origin plus `cors_allowed_origins`), and `/kmip/2_1` requires `Content-Type: application/json`. Regression test: `test_kmip_json_endpoint_requires_json_content_type` in `crate/server/src/tests/security_regression.rs`.

---

#### COSMIAN-2026-038 — AWS XKS SigV4 secret access key written to the startup log

| Field      | Value                                           |
| ---------- | ----------------------------------------------- |
| Severity   | High                                            |
| Published  | Pending                                         |
| Affected   | before 5.29.0                                   |
| Fixed in   | 5.29.0                                          |
| Found by   | Threat model (STRIDE-A), 16 October 2026        |
| References | [Release notes](CHANGELOG.md#5290---2026-10-28) |

**Summary:** At every start, `main.rs` logs the whole configuration at `info` level (`info!("Command line / file config: {clap_config:#?}")`), and `ServerParams::try_from` logs it again at `debug`. The `ClapConfig` `Debug` output printed `aws_xks_sigv4_secret_access_key` in clear, once through the derived `Debug` of `AwsXksConfig` and once as an explicit field. COSMIAN-2026-014 had masked the other configuration secrets.

**Impact:** With AWS XKS enabled, the SigV4 secret was in the startup log at the default log level. Anyone able to read the server logs, or the log collection system, obtained it and could sign XKS requests that the KMS accepts as coming from AWS KMS.

**Mitigation:** Upgrade to 5.29.0; the secret is now printed as `********`. Rotate the SigV4 credentials: startup logs written by earlier versions contain them.

---

#### COSMIAN-2026-037 — Crypto operations reveal the existence and state of other users' keys

| Field      | Value                                           |
| ---------- | ----------------------------------------------- |
| Severity   | Low                                             |
| Published  | Pending                                         |
| Affected   | before 5.29.0                                   |
| Fixed in   | 5.29.0                                          |
| Found by   | Threat model (STRIDE-A), 16 October 2026        |
| References | [Release notes](CHANGELOG.md#5290---2026-10-28) |

**Summary:** Key selection for `Encrypt`, `Decrypt`, `Sign`, `MAC` and the other crypto operations returned `Unauthorized` ("does not have permission to use key") for an existing key the caller could not use, and `Item_Not_Found` for a missing one. The lifecycle state was also checked before the permission, so a non-active foreign key returned its UID and state. `Get`, `Export` and attribute operations already answered `Object_Not_Found` in both cases.

**Impact:** An authenticated user could test whether a UID or tag matches another user's key and learn its lifecycle state. Key material and attributes were not exposed.

**Mitigation:** Upgrade to 5.29.0. The permission check now runs first and keys the caller has no grant on are reported exactly like missing keys. Regression test: `test_crypto_op_does_not_reveal_foreign_keys` in `crate/server/src/tests/security_regression.rs`.

---

#### COSMIAN-2026-036 — Unbounded per-request work: batch size, PBKDF2 iterations, RSA modulus

| Field      | Value                                           |
| ---------- | ----------------------------------------------- |
| Severity   | Moderate                                        |
| Published  | Pending                                         |
| Affected   | before 5.29.0                                   |
| Fixed in   | 5.29.0                                          |
| Found by   | Threat model (STRIDE-A), 16 October 2026        |
| References | [Release notes](CHANGELOG.md#5290---2026-10-28) |

**Summary:** Three client-controlled values had no upper bound: the number of batch items in a KMIP `RequestMessage` (run sequentially, within the 64 MiB body limit), the PBKDF2 `IterationCount` of `DeriveKey` (passed straight to OpenSSL), and the RSA modulus size of `CreateKeyPair` (only a FIPS minimum was enforced, and OpenSSL key generation does not cap the size).

**Impact:** One authenticated request could pin a worker thread and database connections for minutes or hours, and a few concurrent ones could make the server unavailable. The rate limiter, which counts requests, does not help.

**Mitigation:** Upgrade to 5.29.0. Requests above 10,000 batch items, 10,000,000 PBKDF2 iterations or a 16,384-bit RSA modulus (OpenSSL's `OPENSSL_RSA_MAX_MODULUS_BITS`, beyond which OpenSSL refuses RSA operations anyway) are now rejected. Regression tests: `test_request_work_limits` in `crate/server/src/tests/security_regression.rs` and `test_create_rsa_rejects_oversized_modulus` in `crate/crypto/src/crypto/rsa/operation.rs`.

---

#### COSMIAN-2026-035 — Google CSE `rewrap` SSRF check bypass via redirects, IPv6 literals and DNS

| Field      | Value                                           |
| ---------- | ----------------------------------------------- |
| Severity   | High                                            |
| Published  | Pending                                         |
| Affected   | from 5.22.0 before 5.29.0                       |
| Fixed in   | 5.29.0                                          |
| Found by   | Threat model (STRIDE-A), 16 October 2026        |
| References | [Release notes](CHANGELOG.md#5290---2026-10-28) |

**Summary:** The COSMIAN-2026-009 fix validates `original_kacls_url` before `rewrap` calls `<original_kacls_url>/privilegedunwrap`, but the check could be bypassed three ways: the call used `reqwest::Client::new()`, which follows up to 10 redirects without re-validating the target; the host was read with `host_str()`, which returns IPv6 literals in brackets, so `https://[::1]/` or `https://[::ffff:169.254.169.254]/` skipped the IP checks; and hostnames were never resolved, so a name pointing to a private address passed.

**Impact:** A caller with Google CSE migration rights could make the server send its signed KACLS-to-KACLS JWT to, and read responses from, internal services such as the cloud metadata endpoint.

**Mitigation:** Upgrade to 5.29.0. The client no longer follows redirects and has a 30 s timeout; IPv4, IPv6 and IPv4-mapped literals are checked against the private, loopback, link-local and unique-local ranges; hostnames are resolved, every resolved address is checked, and the checked address is pinned for the request. Until then, restrict the server's egress to the known KACLS hosts.

---

#### COSMIAN-2026-034 — JWT signed by one identity provider accepted for another issuer

| Field      | Value                                           |
| ---------- | ----------------------------------------------- |
| Severity   | High                                            |
| Published  | Pending                                         |
| Affected   | before 5.29.0                                   |
| Fixed in   | 5.29.0                                          |
| Found by   | Threat model (STRIDE-A), 16 October 2026        |
| References | [Release notes](CHANGELOG.md#5290---2026-10-28) |

**Summary:** All configured identity providers, the Google CSE token issuers and the whitelisted external KACLS shared one JWKS manager. A token was matched to the configuration of its `iss` claim, but its signing key was looked up by `kid` across the keys of every provider.

**Impact:** With two or more identity providers (or Google CSE with an incoming KACLS whitelist), whoever controls the signing key of one of them — a partner IdP, a whitelisted KACLS — could mint tokens with the `iss` of another provider, any `email`, and a `kid` of its own key, and authenticate as any user of that provider, or forge Google CSE authorization tokens.

**Mitigation:** Upgrade to 5.29.0. Each issuer now has its own JWKS manager and Google CSE authorization tokens are only checked against Google's JWKS. A token signed with an unknown key makes the KMS refresh the keys of the token's own issuer, Google CSE authorization keys included, at most once every 60 s. Until then, configure a single identity provider.

---

#### COSMIAN-2026-033 — KMIP socket server skips client certificate CN checks

| Field      | Value                                           |
| ---------- | ----------------------------------------------- |
| Severity   | Moderate                                        |
| Published  | Pending                                         |
| Affected   | before 5.29.0                                   |
| Fixed in   | 5.29.0                                          |
| Found by   | Threat model (STRIDE-A), 16 October 2026        |
| References | [Release notes](CHANGELOG.md#5290---2026-10-28) |

**Summary:** The HTTP mTLS middleware rejects client certificates whose Common Name is empty, `*` or the reserved AWS XKS service user, and trims whitespace. The KMIP socket server (port 5696) used the raw CN as the username without these checks.

**Impact:** A holder of a certificate issued by the trusted client CA with such a CN could act on the socket server as the reserved AWS XKS service identity, which holds `Encrypt`, `Decrypt` and `GetAttributes` grants on every AWS XKS key, or under `*`, the identifier the server reserves for wildcard grants.

**Mitigation:** Upgrade to 5.29.0; both paths now share `client_cert_username`. Until then, make sure the client CA cannot issue such CNs.

---

#### COSMIAN-2026-032 — KMIP socket server exhaustion: unbounded threads, idle connections and allocation

| Field      | Value                                           |
| ---------- | ----------------------------------------------- |
| Severity   | High                                            |
| Published  | Pending                                         |
| Affected   | before 5.29.0                                   |
| Fixed in   | 5.29.0                                          |
| Found by   | Threat model (STRIDE-A), 16 October 2026        |
| References | [Release notes](CHANGELOG.md#5290---2026-10-28) |

**Summary:** The KMIP socket server spawned one OS thread per accepted TCP connection, before the TLS handshake, with no connection limit and no read or write timeout. After the handshake, it allocated a buffer of the size announced in the 4-byte TTLV length header (up to 4 GiB) before reading the body.

**Impact:** Without credentials, opening idle TCP connections exhausted threads and file descriptors. A client holding a valid certificate could also make the server allocate gigabytes per message and get it killed by the OOM killer. Only deployments with `start_socket_server` enabled are affected.

**Mitigation:** Upgrade to 5.29.0. The socket server now accepts at most 1,024 concurrent connections, aborts TLS handshakes not completed within 10 s in total, however slowly the client sends, closes authenticated connections idle or stalled for 120 s, requires each request body to arrive within about 120 s in total (the deadline is checked between reads, so a stalled read can extend it by one more timeout), and rejects messages above 64 MiB (the HTTP limit) before allocating. Raw request bytes in flight share a process-wide 256 MiB budget, reserved before each body is allocated and released before the response is written; the budget bounds the receive buffers only, not decoded request structures. A request that does not fit is refused and its connection closed (regression test `inflight_request_bytes_are_bounded_and_released`). Other regression test: `trickling_handshake_is_cut_at_deadline` in `crate/server/src/socket_server.rs`. Until then, keep the socket server disabled or reachable only from trusted networks.

---

#### COSMIAN-2026-031 — `Get`/`Export` Fresh-bit write-back could persist an auto-unwrapped key

| Field      | Value                                          |
| ---------- | ---------------------------------------------- |
| Severity   | Moderate                                       |
| Published  | Pending                                        |
| Affected   | before 5.29.0                                  |
| Fixed in   | 5.29.0                                         |
| Found by   | Code review of the allocation-reduction change |
| References | —                                              |

**Summary:** When `default_unwrap_types` is configured, `retrieve_object_for_operation` replaces the stored (wrapped) object with its unwrapped form for `Get`/`Export`. `export_get` then snapshotted `owm.object()` as the "DB form" and, on the first unwrapped retrieval of a key with `Fresh = true`, wrote that snapshot back to flip the Fresh bit. The snapshot was already the unwrapped object. Static analysis of the base code shows this path; it was not reproduced on the base commit.

**Impact:** A KEK-wrapped symmetric or private key with `Fresh = true` could be stored in plaintext after one `Get`/`Export`.

**Mitigation:** Upgrade to 5.29.0. `export_get` now reads the stored object from the database (cache) for the write-back, so wrapping is preserved. Regression tests: `test_get_fresh_wrapped_key_preserves_wrapping_in_db` and `test_get_fresh_wrapped_key_explicit_not_wrapped_preserves_wrapping_in_db` in `crate/server/src/tests/security_regression.rs`.

---

#### COSMIAN-2026-030 — SetAttribute permits changes to read-only metadata

| Field      | Value                                                                                                                                                                                           |
| ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Severity   | Low                                                                                                                                                                                             |
| Published  | Pending                                                                                                                                                                                         |
| Affected   | from 4.19.0 before 5.29.0                                                                                                                                                                       |
| Fixed in   | 5.29.0                                                                                                                                                                                          |
| Found by   | Internal code review                                                                                                                                                                            |
| References | [Regression test](crate/server/src/tests/test_set_attribute.rs), [TTLV vector](test_data/vectors/negative/set_attribute/readonly_initial_date), [Release notes](CHANGELOG.md#5290---2026-10-28) |

**Summary:** `SetAttribute` accepted client updates to read-only provenance attributes, including `InitialDate`, `CryptographicLength`, and `Digest`, despite the restrictions already applied by `ModifyAttribute`.

**Impact:** Consumers of the stored attributes could receive incorrect creation dates or key metadata. Every release from 4.19.0, where `SetAttribute` was introduced, through 5.28.0 is affected. The set of read-only attributes it accepted grew over time, for example `Digest` from 5.6.0.

**Mitigation:** Upgrade to 5.29.0 when available. The fix returns `Read_Only_Attribute` before mutation; COSMIAN-2026-044 extends the refusal to every attribute that KMIP 2.1 marks read-only, on `AddAttribute`, `SetAttribute`, `ModifyAttribute` and `DeleteAttribute`. Until then, restrict KMS object access to trusted clients.

---

#### GHSA-8mmx-f92q-2gq8 — `Extractable` and `NeverExtractable` not enforced on key export paths

| Field      | Value                                                                                         |
| ---------- | --------------------------------------------------------------------------------------------- |
| Severity   | High                                                                                          |
| Published  | Pending                                                                                       |
| Affected   | 5.0.0 – 5.27.1                                                                                |
| Fixed in   | 5.28.0                                                                                        |
| Found by   | External reporter (GHSA-8mmx-f92q-2gq8)                                                       |
| References | [GHSA-8mmx-f92q-2gq8](https://github.com/Cosmian/kms/security/advisories/GHSA-8mmx-f92q-2gq8) |

**Summary:** The KMIP `Extractable` and `NeverExtractable` attributes were stored and echoed by the server but never evaluated on output paths (`Get`, `Export`, and PKCS#12 export). A key created or registered with `Extractable=false` could be exported in plaintext by any user holding a `Get` grant. Furthermore, client-supplied `NeverExtractable` values could contradict server-managed latch semantics, and PKCS#12 export routes did not validate that key-wrapping specifications provided non-empty password credentials for sensitive keys.

**Impact:** Compromise of keys intended to remain server-bound. Clients relying on `Extractable=false` to prevent key extraction from the KMS could have plaintext key material retrieved.

**Mitigation:** Upgrade to 5.28.0. The server now checks `check_extractable_and_sensitive` across all `Get`, `Export`, and PKCS#12 export paths (denying non-extractable keys with `ResultReason::Not_Extractable` regardless of wrapping), requires non-empty password information for sensitive PKCS#12 exports, unconditionally initializes server-managed `NeverExtractable` at creation and import time, maintains the latch across lifecycle state transitions and `ReKey`/`ReKeyKeyPair` rotations, requires explicit operation authorization or ownership for mutating `Extractable`, and enforces `NeverExtractable` as strictly server-managed and read-only.

---

#### GHSA-pvw2-jxwc-95xq — Reserved UID `*` bypassable via `AtomicOperation::Upsert` and `Certify` destination overwrite

| Field      | Value                                                                                                                                                                                                         |
| ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Severity   | High                                                                                                                                                                                                          |
| Published  | Pending                                                                                                                                                                                                       |
| Affected   | 5.0.0 – 5.27.1                                                                                                                                                                                                |
| Fixed in   | 5.28.0                                                                                                                                                                                                        |
| Found by   | External reporter (GHSA-pvw2-jxwc-95xq)                                                                                                                                                                       |
| References | [GHSA-pvw2-jxwc-95xq](https://github.com/Cosmian/kms/security/advisories/GHSA-pvw2-jxwc-95xq), [COSMIAN-2026-020](#cosmian-2026-020--get-grant-on-wildcard-uid--bypasses-the-createimport-authorization-gate) |

**Summary:** The COSMIAN-2026-020 reserved UID check screened `AtomicOperation::Create` in `Database::atomic`, but did not screen `AtomicOperation::Upsert`. Operations such as `Certify` write via `Upsert` and take destination UIDs directly from requests without prior destination authorization, allowing re-creation of the reserved `"*"` UID and potential overwrite of existing objects owned by other users. In addition, MySQL lacked the `WHERE objects.owner=$5` SQL guard present in PostgreSQL and SQLite, and tag mutations were not gated on affected row counts.

**Impact:** Privilege escalation via recreation of the sentinel `"*"` UID (bypassing the global `Create` gate), and unauthorized overwrite/partial modification of victim objects.

**Mitigation:** Upgrade to 5.28.0. `Database::atomic` now screens both `AtomicOperation::Create` and `AtomicOperation::Upsert` against `reject_reserved_uid`. `Certify` validates destination UIDs before building atomic operations (rejecting empty or reserved UIDs and requiring ownership to overwrite existing objects or Create rights to create new ones). All backends (SQLite, PostgreSQL, MySQL via `select-object-for-update`, and Redis) atomically enforce ownership on `Upsert` and return `DbError::Unauthorized` without partial mutations.

---

#### GHSA-c75c-3cmm-48h7 — `Sensitive` and `Extractable` attribute stripping via read-only `Get` grant

| Field      | Value                                                                                         |
| ---------- | --------------------------------------------------------------------------------------------- |
| Severity   | High                                                                                          |
| Published  | Pending                                                                                       |
| Affected   | 5.0.0 – 5.27.1                                                                                |
| Fixed in   | 5.28.0                                                                                        |
| Found by   | External reporter (GHSA-c75c-3cmm-48h7)                                                       |
| References | [GHSA-c75c-3cmm-48h7](https://github.com/Cosmian/kms/security/advisories/GHSA-c75c-3cmm-48h7) |

**Summary:** `Sensitive` export enforcement prevents plaintext retrieval of keys flagged sensitive unless wrapped. However, `DeleteAttribute` permitted removal of `Sensitive` and `Extractable` attributes, and `retrieve_object_for_operation`'s permission check allowed any caller with a read-only `Get` grant to invoke `DeleteAttribute`, `SetAttribute`, `ModifyAttribute`, or `AddAttribute` on the target object. A user with read-only access to another user's sensitive key could strip `Sensitive` or toggle `Extractable` and subsequently read the plaintext key material.

**Impact:** Plaintext key compromise by users holding only read-only (`Get`) grants on sensitive keys.

**Mitigation:** Upgrade to 5.28.0. `Tag::Sensitive`, `Tag::Extractable`, `Tag::AlwaysSensitive`, and `Tag::NeverExtractable` are now enforced as read-only under both value and reference variants of `DeleteAttribute`. `SetAttribute`, `ModifyAttribute`, and `AddAttribute` now enforce `user_can_perform_operation` specifically for the requested attribute operation, rejecting changes from callers relying solely on generic `Get` grants.

---

#### COSMIAN-2026-029 — PostgreSQL `sslmode` ignored, connections silently fall back to plaintext

| Field      | Value                                           |
| ---------- | ----------------------------------------------- |
| Severity   | High                                            |
| Published  | Pending                                         |
| Affected   | from 5.15.0 before 5.29.0                       |
| Fixed in   | 5.29.0                                          |
| Found by   | Internal code review                            |
| References | [Release notes](CHANGELOG.md#5290---2026-10-28) |

**Summary:** The `PostgreSQL` object store removed `sslmode` from the connection URL and never passed it to the driver, which then used its default (`prefer`): TLS if the server offers it, plaintext otherwise. `sslmode=require`, `verify-ca` and `verify-full` therefore did not make TLS mandatory. In addition, `verify-ca` also checked the server hostname, `sslrootcert` added its CA to the system CA list instead of replacing it, and unknown `sslmode` values were accepted silently. The `PostgreSQL` audit backend, unreleased at the time, shared the same code and is fixed in the same change.

**Impact:** An operator who configured `sslmode=require` or stricter could still have the KMS-to-database connection (object store traffic, credentials) established without TLS, for example when the server had TLS disabled or an on-path party stripped the TLS negotiation.

**Mitigation:** Upgrade to 5.29.0. `sslmode` is now enforced: `require`, `verify-ca` and `verify-full` fail at startup when TLS is unavailable, `verify-ca` and `verify-full` verify the certificate chain, `sslrootcert` pins the trusted CA (and, as in libpq, is required with `verify-ca`, which does not check the hostname), `verify-full` also checks the hostname, and unknown values are rejected. Until then, enforce TLS on the `PostgreSQL` server side (`hostssl` rules in `pg_hba.conf`) and restrict network access to the database.

---

#### COSMIAN-2026-028 — SSRF check bypass via `kms_public_url` prefix match in CRL fetching

| Field      | Value                                                        |
| ---------- | ------------------------------------------------------------ |
| Severity   | High                                                         |
| Published  | 30 September 2026                                            |
| Affected   | from 5.27.0 before 5.28.0                                    |
| Fixed in   | 5.28.0                                                       |
| Found by   | Internal code review                                         |
| References | [Branch changelog](https://github.com/Cosmian/kms/pull/1234) |

**Summary:** The COSMIAN-2026-021 fix exempted CRL Distribution Point URLs "belonging to the server" from the SSRF check with a raw string test, `uri.starts_with(kms_public_url)`. With `kms_public_url = http://kms.corp`, URLs such as `http://kms.corp@169.254.169.254/...` (userinfo) or `http://kms.corp.attacker.tld/` pass the prefix test while targeting another host.

**Impact:** A user allowed to `Import` or `Validate` certificates could make the server request internal addresses (cloud metadata, internal services), and learn whether they answered from the resulting object state, re-opening the blind SSRF closed by COSMIAN-2026-021.

**Mitigation:** Upgrade to 5.28.0. The exemption now compares parsed URL components (scheme, host, port, base-path prefix) and never applies to URLs carrying credentials. Fetched CRLs are also no longer cached forever, and the cache lock is no longer held across network requests.

---

#### COSMIAN-2026-027 — CRL/OCSP revocation status could be lost, stale or wrong

| Field      | Value                                                        |
| ---------- | ------------------------------------------------------------ |
| Severity   | High                                                         |
| Published  | 30 September 2026                                            |
| Affected   | from 5.27.0 before 5.28.0                                    |
| Fixed in   | 5.28.0                                                       |
| Found by   | Internal code review                                         |
| References | [Branch changelog](https://github.com/Cosmian/kms/pull/1234) |

**Summary:** Several defects in the CRL and OCSP services let relying parties accept revoked certificates: (1) `Destroy` wiped a certificate's attributes, so a revoked-then-destroyed certificate disappeared from the CRL and OCSP answered `unknown`; (2) certificate serials were SHA-1(SPKI), so `ReCertify` reused the serial of the certificate it replaced (the renewed certificate appeared revoked, and OCSP could answer `good` for a revoked serial); (3) the OCSP response cache served entries for twice their lifetime, ignored the `CertID` hash algorithm, answered cached serials of partially cached multi-`CertID` requests as `unknown`, and grew without bound from unauthenticated requests; (4) the OCSP responder accepted a request if any one `CertID` named the CA; (5) OCSP reported `revocationTime = now`; (6) automatic CRL regeneration ran as users who cannot read the CA key and failed silently; (7) nodes kept serving their in-memory CRL copy indefinitely; (8) OCSP/CRL signing failed for CA keys wrapped at rest.

**Impact:** Revoked certificates could be accepted by CRL- and OCSP-checking relying parties; published CRLs could go stale or expire; an unauthenticated client could exhaust server memory through the OCSP cache.

**Mitigation:** Upgrade to 5.28.0. Destroy keeps the issuer link and revocation details, and CRL/OCSP include destroyed revoked certificates; serials are random 159-bit values; the OCSP cache is keyed by the full `CertID`, bounded, never serves past `nextUpdate`, is used only for single-`CertID` requests and never stores `unknown`; every `CertID` must name the CA; OCSP reports the recorded revocation time and reason; automatic regeneration signs on behalf of the CA owner; in-memory CRL copies are re-read from the database every 60 s; signing keys are unwrapped.

---

#### COSMIAN-2026-026 — PKCS#11 module buffer overflows in `C_GetAttributeValue` and `C_Encrypt`

| Field      | Value                                                        |
| ---------- | ------------------------------------------------------------ |
| Severity   | High                                                         |
| Published  | 30 September 2026                                            |
| Affected   | from 5.17.0 before 5.28.0                                    |
| Fixed in   | 5.28.0                                                       |
| Found by   | Internal code review                                         |
| References | [Branch changelog](https://github.com/Cosmian/kms/pull/1234) |

**Summary:** Both functions overwrote the caller-declared buffer length with the output length before comparing the two, so the `CKR_BUFFER_TOO_SMALL` check could never trigger and the full value was written past a smaller caller buffer. `C_GenerateKey` also wrote the new handle through a null `phKey`.

**Impact:** Memory corruption in the host application loading the PKCS#11 module (e.g. database TDE agents, OpenSSH, LUKS tooling) when it supplies a buffer smaller than the value.

**Mitigation:** Upgrade to 5.28.0. The caller's buffer size is checked before anything is written; `CKR_BUFFER_TOO_SMALL` is returned per PKCS#11 v2.40 §5.7, and a null `phKey` returns `CKR_ARGUMENTS_BAD`.

---

#### COSMIAN-2026-025 — JOSE tag endpoints allow tag changes with any grant

| Field      | Value                                                        |
| ---------- | ------------------------------------------------------------ |
| Severity   | Moderate                                                     |
| Published  | 30 September 2026                                            |
| Affected   | from 5.25.0 before 5.28.0                                    |
| Fixed in   | 5.28.0                                                       |
| Found by   | Internal code review                                         |
| References | [Branch changelog](https://github.com/Cosmian/kms/pull/1234) |

**Summary:** `POST`/`DELETE /v1/crypto/keys/{kid}/tags` authorized through `GetAttributes`, which any grant satisfies, then wrote the tag column directly — bypassing the `AddAttribute`/`DeleteAttribute` permissions that KMIP enforces.

**Impact:** A user holding only e.g. an `encrypt` grant (or a `*` grant) could rewrite a key's tags, breaking tag-based lookups, or add/remove the `jwks` tag on a default-user key to publish or unpublish it on the JWKS endpoint.

**Mitigation:** Upgrade to 5.28.0. The endpoints now require `add_attribute` / `delete_attribute` (or ownership / `get`).

---

#### COSMIAN-2026-024 — Any user can publish a key on the unauthenticated JWKS endpoint

| Field      | Value                                                        |
| ---------- | ------------------------------------------------------------ |
| Severity   | High                                                         |
| Published  | 30 September 2026                                            |
| Affected   | from 5.25.0 before 5.28.0                                    |
| Fixed in   | 5.28.0                                                       |
| Found by   | Internal code review                                         |
| References | [Branch changelog](https://github.com/Cosmian/kms/pull/1234) |

**Summary:** `/.well-known/jwks.json` listed every `jwks`-tagged public key that `default_username` owned *or had any grant on*, including `*` grants. Any owner may grant `*`, and REST-created key pairs are auto-tagged `jwks`.

**Impact:** Any user could place a key they control in the server's published key set; relying parties trusting that JWKS would accept tokens the user signs.

**Mitigation:** Upgrade to 5.28.0. Only keys owned by `default_username` are published.

---

#### COSMIAN-2026-023 — SPIRE transit key substitution via shared tags

| Field      | Value                                                        |
| ---------- | ------------------------------------------------------------ |
| Severity   | High                                                         |
| Published  | 30 September 2026                                            |
| Affected   | from 5.26.0 before 5.28.0                                    |
| Fixed in   | 5.28.0                                                       |
| Found by   | Internal code review                                         |
| References | [Branch changelog](https://github.com/Cosmian/kms/pull/1234) |

**Summary:** Vault-compatible transit routes resolved a key name by tag among all keys shared with the caller and used an arbitrary match (`.next()` over unordered results). Creating an existing name also created a duplicate.

**Impact:** A KMS user could share a key tagged with another tenant's transit key name, so that tenant's SPIRE server could sign (e.g. its CA or JWT keys) with a key the attacker controls.

**Mitigation:** Upgrade to 5.28.0. Transit names resolve only to keys owned by the caller (lowest UID on legacy duplicates); creating an existing name is a no-op.

---

#### COSMIAN-2026-022 — SPIRE PKI `sign-intermediate` issues CA certificates to any Vault token

| Field      | Value                                                        |
| ---------- | ------------------------------------------------------------ |
| Severity   | Critical                                                     |
| Published  | 30 September 2026                                            |
| Affected   | from 5.26.0 before 5.28.0                                    |
| Fixed in   | 5.28.0                                                       |
| Found by   | Internal code review                                         |
| References | [Branch changelog](https://github.com/Cosmian/kms/pull/1234) |

**Summary:** `POST /v1/{pki_mount}/root/sign-intermediate` accepted any token validated by the auth-verifier and signed the caller's CSR as a `CA:TRUE` intermediate with the server's PKI CA. Token policies were never checked, `uri_sans` was checked only for non-emptiness, and the CA key lookup also accepted keys merely shared with `default_username`.

**Impact:** Any AppRole (e.g. one meant only for transit) could obtain an intermediate CA certificate chaining to the PKI root and mint X.509-SVIDs for any workload trusting it.

**Mitigation:** Upgrade to 5.28.0. The caller's KMS identity (`spire:<AppRole>`) must hold the `certify` access right on the CA private key; the CA key must be owned by `default_username` (exactly one); CSRs requesting their own `basicConstraints` are rejected. **Upgrade action:** grant `certify` on the CA private key to each SPIRE AppRole identity.

---

#### COSMIAN-2026-021 — SSRF via attacker-controlled CRL Distribution Points in KMIP Validate/Import

| Field      | Value                                                                                                                                                                               |
| ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Severity   | High                                                                                                                                                                                |
| Published  | 17 August 2026                                                                                                                                                                      |
| Affected   | from 5.0.0 before 5.27.0                                                                                                                                                            |
| Fixed in   | 5.27.0                                                                                                                                                                              |
| Found by   | External reporter (GHSA-rwc8-xwm6-52xc)                                                                                                                                             |
| References | [GHSA-rwc8-xwm6-52xc](https://github.com/Cosmian/kms/security/advisories/GHSA-rwc8-xwm6-52xc), [COSMIAN-2026-009](#cosmian-2026-009--google-cse-rewrap-ssrf-via-original_kacls_url) |

**Summary:** Cosmian KMS fetched CRLs from URLs embedded in X.509 CRL Distribution Points (CDPs) during KMIP `Validate` and `Import` operations without applying any SSRF mitigations. The `get_crl_bytes()` function in `crate/server/src/core/operations/validate.rs` accepted arbitrary `http://` URLs (including IPv4 and IPv6 loopback, private/unique-local, and link-local addresses), followed HTTP redirects unconditionally, read the full response body without a size cap, and treated non-URL CDP values as local filesystem paths — allowing arbitrary file reads. A secondary vector existed via `file://` scheme URLs, which were explicitly converted to filesystem paths.

This is a separate code path from COSMIAN-2026-009 (Google CSE `original_kacls_url` SSRF); the fix for that advisory did not cover CRL Distribution Point fetches.

**Impact:** A post-authentication attacker with `Validate` or `Import` permission could:

- Probe internal HTTP services reachable from the KMS host (confirmed blind SSRF via PoC on v5.26.0).
- Access cloud metadata endpoints (e.g. `169.254.169.254`) from cloud-hosted deployments.
- Read arbitrary local files readable by the KMS process via bare filesystem paths or `file://` URIs.
- Cause denial of service via a slow or unbounded HTTP response body (no size cap, no timeout).

**Mitigation:** Upgrade to 5.27.0. The fix adds `validate_crl_url()` in `crate/server/src/core/certificate/mod.rs` (HTTPS and HTTP allowed; IPv4 and IPv6 private/unique-local, loopback, link-local, and unspecified addresses — including IPv4-mapped IPv6 (`::ffff:0:0/96`) — and internal hostnames rejected), applies `reqwest::redirect::Policy::none()` and a 30-second timeout to the CRL-fetch client, caps responses at 10 MiB, and removes filesystem-path and `file://` CRL resolution in production builds (`file://` remains available in `#[cfg(test)]` only). Sixteen regression tests (SR-CRL-01 through SR-CRL-16) cover all mitigations, including the IPv4 and IPv6 address-range checks.

---

#### COSMIAN-2026-020 — `Get` grant on wildcard uid `*` bypasses the Create/Import authorization gate

| Field      | Value                                                                      |
| ---------- | -------------------------------------------------------------------------- |
| Severity   | Critical                                                                   |
| Published  | 28 August 2026                                                             |
| Affected   | from 5.0.0 before 5.27.0                                                   |
| Fixed in   | 5.27.0                                                                     |
| Found by   | Reported in [GitHub issue #909](https://github.com/Cosmian/kms/issues/909) |
| References | [#909](https://github.com/Cosmian/kms/issues/909)                          |

**Summary:** The Create/Import authorization gate (`privileged_users` / `crypto_officer.users` configuration) checks whether the caller holds the `Create` operation on the internal sentinel object identifier `"*"`, under which the global `Create` grant is stored. `"*"` was never reserved as an identifier: any user could `Create`/`Import`/`Register` a real object whose unique identifier is the literal string `"*"`. Because `user_has_permission`'s `Get`-super-privilege fallback treats holding `Get` on an object as satisfying *any* operation check on that same object, a user who owned this collided object could grant another user `Get` on it and thereby hand them the `Create` right — fully bypassing the privileged-user/Crypto-Officer gate.

**Impact:** Full bypass of the Create/Import authorization gate in any deployment that restricts object creation to a configured allow-list (`privileged_users` or `crypto_officer.users`). A non-privileged user who received only a `Get` grant on the attacker-controlled `"*"` object could create and import arbitrary keys, defeating the intended lifecycle control.

**Mitigation:** Upgrade to 5.27.0. `"*"` is now a reserved object identifier rejected at the database layer (`Database::create` and `Database::atomic`, in `crate/server_database/src/core/database_objects.rs`) for every backend — no object can ever be created under this uid, eliminating the collision at the source rather than patching the permission-check symptom.

---

#### COSMIAN-2026-019 — RUSTSEC-2026-0173: `proc-macro-error2` soundness issue via `mysql_async`

| Field      | Value                                                                                                                                          |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| Severity   | Low                                                                                                                                            |
| Published  | 2026                                                                                                                                           |
| Affected   | from 5.0.0 before 5.23.0 (MySQL/Percona/MariaDB backend only)                                                                                  |
| Fixed in   | 5.23.0                                                                                                                                         |
| Found by   | `cargo deny` advisory scanner (RUSTSEC-2026-0173)                                                                                              |
| References | [RUSTSEC-2026-0173](https://rustsec.org/advisories/RUSTSEC-2026-0173.html), [#fix_RUSTSEC-2026-0173](https://github.com/Cosmian/kms/pull/1011) |

**Summary:** `mysql_async` 0.36 pulled in `mysql-common-derive`, which transitively depended on `proc-macro-error2`. `proc-macro-error2` carries RUSTSEC-2026-0173, a soundness issue in its procedural macro machinery (use of `std::mem::transmute` across incompatible lifetime bounds). The advisory affects compile-time macro expansion, not the runtime KMS binary.

**Impact:** Compile-time only. No runtime key confidentiality, integrity, or availability impact. Exploitation would require an attacker to control the build environment (supply-chain attack scenario). Severity is Low for the KMS server binary in production.

**Mitigation:** Upgrade to 5.23.0. `mysql_async` was upgraded from 0.36 to 0.37 with `default-features = false`, which drops the `derive` feature and removes the `mysql-common-derive → proc-macro-error2` chain entirely.

---

#### COSMIAN-2026-018 — Activate operation uses overly permissive authorization check

| Field      | Value                                           |
| ---------- | ----------------------------------------------- |
| Severity   | Moderate                                        |
| Published  | 26 May 2026                                     |
| Affected   | from 5.0.0 before 5.23.0                        |
| Fixed in   | 5.23.0                                          |
| Found by   | Copilot code review (GitHub PR #961)            |
| References | [#961](https://github.com/Cosmian/kms/pull/961) |

**Summary:** The KMIP `Activate` operation passed `KmipOperation::GetAttributes` as the operation type to `retrieve_object_for_operation`. The permission check for `GetAttributes` grants access to any user holding *any* operation grant on the object. This meant a user with only `Encrypt` permission could activate a `PreActive` key, changing its lifecycle state — a security-relevant state transition that should require explicit authorization.

**Impact:** Privilege escalation: a user with a minimal grant (e.g., encrypt-only) could force-activate a key that was intentionally kept in `PreActive` state (e.g., with a future activation date), bypassing the key lifecycle controls set by the key owner.

**Mitigation:** Upgrade to 5.23.0. A new `KmipOperation::Activate` variant is introduced and the `Activate` operation now uses it for the permission check, requiring explicit `Activate` grant, `Get` wildcard, or ownership.

---

#### COSMIAN-2026-017 — ReKey / ReKeyKeyPair authorization bypass via raw object retrieval

| Field      | Value                                           |
| ---------- | ----------------------------------------------- |
| Severity   | Critical                                        |
| Published  | 26 May 2026                                     |
| Affected   | from 5.0.0 before 5.23.0                        |
| Fixed in   | 5.23.0                                          |
| Found by   | Copilot code review (GitHub PR #961)            |
| References | [#961](https://github.com/Cosmian/kms/pull/961) |

**Summary:** The KMIP `ReKey` operation for symmetric keys called `database.retrieve_objects()` without ownership or permission verification. Any authenticated user who knew (or guessed) another user's key UID could invoke `ReKey` to: (1) create a replacement key owned by the attacker, (2) strip the `Name` attribute from the victim's original key, and (3) set cross-links between the old and new key. The `ReKeyKeyPair` operation (Covercrypt) had the same raw retrieval pattern, though downstream `kms.get()` calls provided a secondary authorization barrier.

**Impact:** Full authorization bypass for `ReKey`: any authenticated user can rekey any symmetric key in the system, effectively taking control of the replacement key and disrupting the original key's metadata. For `ReKeyKeyPair`, the impact is limited to information leakage (object existence/type disclosure) since downstream operations enforce authorization.

**Mitigation:** Upgrade to 5.23.0. Both operations now call `user_can_perform_operation()` immediately after object retrieval, verifying that the caller owns the target key or has been explicitly granted the `Rekey` operation.

---

#### COSMIAN-2026-016 — Attribute-mutation authorization bypass via incorrect operation type

| Field      | Value                                             |
| ---------- | ------------------------------------------------- |
| Severity   | Moderate                                          |
| Published  | 25 May 2026                                       |
| Affected   | from 5.0.0 before 5.23.0                          |
| Fixed in   | 5.23.0                                            |
| Found by   | Copilot code review (GitHub PR #959)              |
| References | [#960](https://github.com/Cosmian/kms/issues/960) |

**Summary:** The `SetAttribute`, `ModifyAttribute`, `AddAttribute`, and `DeleteAttribute` KMIP operations all passed `KmipOperation::GetAttributes` as the operation type to `retrieve_object_for_operation`. That function's permission check uses a relaxed "any-permission" policy for `GetAttributes`, so any user holding *any* grant on an object (e.g., `Encrypt`-only) could mutate its attributes — including security-sensitive attributes such as `CryptographicUsageMask` — without the required `Modify` or full-access grant.

**Impact:** Privilege escalation: a user with a limited grant (e.g., encrypt-only) could change key attributes, potentially widening the usage mask, altering sensitive metadata, or compromising the key's intended usage restrictions.

**Mitigation:** Upgrade to 5.23.0. Each attribute-mutation operation now uses its own `KmipOperation` variant (`SetAttribute`, `ModifyAttribute`, `AddAttribute`, `DeleteAttribute`), which enforces the correct permission check (explicit grant or `Get` wildcard required).

---

#### COSMIAN-2026-015 — KEK plaintext leak via `UsageLimits` persist in Decrypt and Sign

| Field      | Value                                           |
| ---------- | ----------------------------------------------- |
| Severity   | High                                            |
| Published  | 25 May 2026                                     |
| Affected   | from 5.0.0 before 5.22.0                        |
| Fixed in   | 5.22.0                                          |
| Found by   | Cosmian engineering                             |
| References | [#959](https://github.com/Cosmian/kms/pull/959) |

**Summary:** The `decrypt.rs` and `sign.rs` operations called `unwrap_and_enforce_policy` on the fetched key object, which decrypted the key material in-place. The subsequent `decrement_usage_limits` call then persisted this modified (plaintext) object back to the database, silently stripping the KEK encryption at rest. Any key with a `UsageLimits` attribute and an active KEK wrapping was vulnerable.

**Impact:** Loss of encryption-at-rest for keys protected by a Key Encryption Key (KEK). After the first Decrypt or Sign operation on such a key, the database stored its plaintext material, making future database-level protection ineffective.

**Mitigation:** Upgrade to 5.22.0. The fix decouples the usage-limit decrement from the unwrapped object path: `decrement_usage_limits` now operates on the original wrapped object fetched directly from the database, never on the in-place-unwrapped copy.

---

#### COSMIAN-2026-014 — Sensitive configuration values exposed in Debug output

| Field      | Value                                           |
| ---------- | ----------------------------------------------- |
| Severity   | Low                                             |
| Published  | 25 April 2026                                   |
| Affected   | from 5.0.0 before 5.22.0                        |
| Fixed in   | 5.22.0                                          |
| Found by   | Cosmian security audit                          |
| References | [#928](https://github.com/Cosmian/kms/pull/928) |

**Summary:** The `ServerParams` struct's `Debug` implementation printed `api_token_id`, `google_cse_migration_key`, and `key_wrapping_key` in plaintext to logs and error messages.

**Impact:** Secrets leaked to log files accessible to operators or log aggregation systems.

**Mitigation:** Upgrade to 5.22.0. Sensitive fields are now masked as `[configured]` in Debug output.

---

#### COSMIAN-2026-013 — Internal error details leaked in HTTP 5xx responses

| Field      | Value                                           |
| ---------- | ----------------------------------------------- |
| Severity   | Moderate                                        |
| Published  | 25 April 2026                                   |
| Affected   | from 5.0.0 before 5.22.0                        |
| Fixed in   | 5.22.0                                          |
| Found by   | Cosmian security audit                          |
| References | [#928](https://github.com/Cosmian/kms/pull/928) |

**Summary:** Server error responses (5xx) included the full internal error message, potentially leaking database connection strings, file paths, internal stack traces, and implementation details.

**Impact:** Information disclosure aiding further exploitation.

**Mitigation:** Upgrade to 5.22.0. 5xx responses now return a generic "Internal server error" message; details are logged server-side only.

---

#### COSMIAN-2026-012 — `/server-info` endpoint accessible without authentication

| Field      | Value                                           |
| ---------- | ----------------------------------------------- |
| Severity   | Low                                             |
| Published  | 25 April 2026                                   |
| Affected   | from 5.0.0 before 5.22.0                        |
| Fixed in   | 5.22.0                                          |
| Found by   | Cosmian security audit                          |
| References | [#928](https://github.com/Cosmian/kms/pull/928) |

**Summary:** The `/server-info` endpoint was registered in the public (unauthenticated) scope, exposing server version, build information, and configuration details to unauthenticated clients.

**Impact:** Information disclosure — attackers can fingerprint the server version and configuration without credentials.

**Mitigation:** Upgrade to 5.22.0. Endpoint moved behind authentication middleware.

---

#### COSMIAN-2026-011 — Non-atomic state transitions enable TOCTOU races

| Field      | Value                                           |
| ---------- | ----------------------------------------------- |
| Severity   | Moderate                                        |
| Published  | 25 April 2026                                   |
| Affected   | from 5.0.0 before 5.22.0                        |
| Fixed in   | 5.22.0                                          |
| Found by   | Cosmian security audit                          |
| References | [#928](https://github.com/Cosmian/kms/pull/928) |

**Summary:** The Activate and Revoke operations performed object update and state change as two separate database calls. A concurrent request between the two calls could observe an inconsistent state (object updated but state unchanged).

**Impact:** Time-of-check-to-time-of-use race condition leading to potential state inconsistencies under concurrent load.

**Mitigation:** Upgrade to 5.22.0. Both operations now use `AtomicOperation` to batch object update and state change in a single transaction.

---

#### COSMIAN-2026-010 — Predictable default session cookie salt

| Field      | Value                                           |
| ---------- | ----------------------------------------------- |
| Severity   | Moderate                                        |
| Published  | 25 April 2026                                   |
| Affected   | from 5.15.0 before 5.22.0                       |
| Fixed in   | 5.22.0                                          |
| Found by   | Cosmian security audit                          |
| References | [#928](https://github.com/Cosmian/kms/pull/928) |

**Summary:** When `ui_session_salt` was not configured, the session cookie encryption key was derived from a hardcoded default salt combined with the public URL. An attacker knowing the deployment URL could compute the session key and forge session cookies.

**Impact:** Session cookie forgery in deployments without explicit salt configuration.

**Mitigation:** Upgrade to 5.22.0. Session key derivation now incorporates private server-side configuration (database connection parameters) so that attackers cannot reproduce the key from publicly known information alone.

---

#### COSMIAN-2026-009 — Google CSE rewrap SSRF via `original_kacls_url`

| Field      | Value                                           |
| ---------- | ----------------------------------------------- |
| Severity   | High                                            |
| Published  | 25 April 2026                                   |
| Affected   | from 5.0.0 before 5.22.0                        |
| Fixed in   | 5.22.0                                          |
| Found by   | Cosmian security audit                          |
| References | [#928](https://github.com/Cosmian/kms/pull/928) |

**Summary:** The Google CSE `rewrap` endpoint accepted an attacker-controlled `original_kacls_url` without validation. An authenticated CSE Migrator could supply `http://169.254.169.254/...` or other internal URLs, causing the server to make requests to internal services (SSRF).

**Impact:** Server-Side Request Forgery — access to cloud metadata services, internal APIs, and private network resources.

**Mitigation:** Upgrade to 5.22.0. URL validation now enforces HTTPS scheme and rejects private/loopback IP ranges and internal hostnames.

---

#### COSMIAN-2026-008 — Unwrap cache not invalidated on key revocation/destruction

| Field      | Value                                           |
| ---------- | ----------------------------------------------- |
| Severity   | High                                            |
| Published  | 25 April 2026                                   |
| Affected   | from 5.0.0 before 5.22.0                        |
| Fixed in   | 5.22.0                                          |
| Found by   | Cosmian security audit                          |
| References | [#928](https://github.com/Cosmian/kms/pull/928) |

**Summary:** When a key was revoked or destroyed, its decrypted material remained in the unwrap cache. Subsequent operations could still use the cached plaintext key material even after the key had been revoked.

**Impact:** Revoked or destroyed keys could continue to be used for cryptographic operations until cache eviction.

**Mitigation:** Upgrade to 5.22.0. Cache is now cleared immediately when key state transitions to Revoked, Destroyed, or Compromised.

---

#### COSMIAN-2026-007 — MS DKE scope missing authentication middleware

| Field      | Value                                           |
| ---------- | ----------------------------------------------- |
| Severity   | High                                            |
| Published  | 25 April 2026                                   |
| Affected   | from 5.0.0 before 5.22.0                        |
| Fixed in   | 5.22.0                                          |
| Found by   | Cosmian security audit                          |
| References | [#928](https://github.com/Cosmian/kms/pull/928) |

**Summary:** The Microsoft DKE route scope was not wrapped with the full authentication middleware stack (JWT, TLS client cert, API token). An attacker with network access could call DKE endpoints without authentication.

**Impact:** Authentication bypass for DKE key unwrap operations.

**Mitigation:** Upgrade to 5.22.0. DKE scope now includes EnsureAuth, JWT, TLS, and API token middleware.

---

#### COSMIAN-2026-006 — Server crash under concurrent requests due to tracing span misuse

| Field      | Value                                           |
| ---------- | ----------------------------------------------- |
| Severity   | High                                            |
| Published  | 25 April 2026                                   |
| Affected   | from 5.17.0 before 5.22.0                       |
| Fixed in   | 5.22.0                                          |
| Found by   | Cosmian engineering                             |
| References | [#928](https://github.com/Cosmian/kms/pull/928) |

**Summary:** The `tracing` crate's `span.enter()` guard was held across `.await` points in asynchronous request handlers. Under concurrent load (~10 parallel requests with valid JWTs), this caused worker thread panics or full server hangs. A stack trace was exposed in the HTTP error response.

**Impact:** Denial of Service. Any authenticated user can crash or hang the server.

**Mitigation:** Upgrade to 5.22.0. The fix replaces `span.enter()` with `tracing::Instrument`.

---

#### COSMIAN-2026-005 — JWT decoding race condition causing intermittent authentication bypass

| Field      | Value                                           |
| ---------- | ----------------------------------------------- |
| Severity   | High                                            |
| Published  | 21 April 2026                                   |
| Affected   | from 5.17.0 before 5.21.0                       |
| Fixed in   | 5.21.0                                          |
| Found by   | Cosmian OWASP security audit                    |
| References | [#916](https://github.com/Cosmian/kms/pull/916) |

**Summary:** ~10% of parallel malicious requests with a valid JWT could bypass authentication due to thread-safety issues and algorithm confusion in the `alcoholic_jwt` library (OWASP A07-1).

**Impact:** Authentication bypass under concurrent load.

**Mitigation:** Upgrade to 5.21.0. Migrated to `jsonwebtoken` crate with strict algorithm validation and rate-limiting via `actix-governor`.

---

#### COSMIAN-2026-004 — OTLP telemetry exported over plaintext HTTP leaks encryption queries

| Field      | Value                                                                   |
| ---------- | ----------------------------------------------------------------------- |
| Severity   | Critical                                                                |
| Published  | 21 April 2026                                                           |
| Affected   | from 5.0.0 before 5.22.0 (when OTLP configured with `http://` endpoint) |
| Fixed in   | 5.22.0                                                                  |
| Found by   | Cosmian security audit                                                  |
| References | [#928](https://github.com/Cosmian/kms/pull/928)                         |

**Summary:** When the OTLP collector is configured with an HTTP (non-TLS) endpoint, all tracing spans — including Encrypt/Decrypt operation parameters — are transmitted in cleartext, leaking query metadata (object IDs, operation types, user identifiers) to network observers.

**Impact:** Complete loss of confidentiality for encryption operation metadata.

**Mitigation:** Upgrade to 5.22.0 which rejects `http://` OTLP endpoints by default. Use `--otlp-allow-insecure` / `KMS_OTLP_ALLOW_INSECURE=true` only for local development.

---

#### COSMIAN-2026-003 — KMIP Import `replace_existing` bypasses ownership verification

| Field      | Value                                           |
| ---------- | ----------------------------------------------- |
| Severity   | Critical                                        |
| Published  | 14 March 2026                                   |
| Affected   | from 5.0.0 before 5.17.0                        |
| Fixed in   | 5.17.0                                          |
| Found by   | Cosmian engineering                             |
| References | [#735](https://github.com/Cosmian/kms/pull/735) |

**Summary:** The KMIP Import operation with `replace_existing=true` did not verify ownership. Any authenticated user could overwrite any key by knowing its unique identifier.

**Impact:** Total key malleability — any authenticated user could replace keys belonging to other users.

**Mitigation:** Upgrade to 5.17.0. Ownership verification added before replacement.

---

#### COSMIAN-2026-002 — SipHash key hardcoded to zero in unwrap cache

| Field      | Value                                           |
| ---------- | ----------------------------------------------- |
| Severity   | Critical                                        |
| Published  | 14 March 2026                                   |
| Affected   | from 5.0.0 before 5.17.0                        |
| Fixed in   | 5.17.0                                          |
| Found by   | Cosmian engineering                             |
| References | [#778](https://github.com/Cosmian/kms/pull/778) |

**Summary:** The unwrap cache used SipHash with a zero key, making the hash function predictable and enabling hash-collision DoS attacks.

**Impact:** Denial of Service via hash flooding and potential cache poisoning.

**Mitigation:** Upgrade to 5.17.0. SipHash now uses a cryptographically random `RandomState`.

---

### 2025

#### COSMIAN-2025-003 — glibc CVEs in container base image (CVE-2024-2961, CVE-2024-33600, CVE-2024-33601)

| Field      | Value                                           |
| ---------- | ----------------------------------------------- |
| Severity   | High                                            |
| Published  | 15 February 2026                                |
| Affected   | from 5.0.0 before 5.16.0                        |
| Fixed in   | 5.16.0                                          |
| Found by   | SBOM vulnerability scan                         |
| References | [#709](https://github.com/Cosmian/kms/pull/709) |

**Summary:** Docker/package builds used glibc 2.28 with CVE-2024-2961 (iconv buffer overflow), CVE-2024-33600/33601 (nscd cache issues).

**Impact:** Potential RCE or DoS via crafted locale conversion or DNS resolution.

**Mitigation:** Upgrade to 5.16.0 (glibc 2.34).

---

#### COSMIAN-2025-012 — Session cookie encryption key randomly regenerated on each restart

| Field      | Value                                           |
| ---------- | ----------------------------------------------- |
| Severity   | High                                            |
| Published  | 22 January 2026                                 |
| Affected   | from 5.0.0 before 5.15.0                        |
| Fixed in   | 5.15.0                                          |
| Found by   | Cosmian engineering                             |
| References | [#664](https://github.com/Cosmian/kms/pull/664) |

**Summary:** Session cookie encryption key was regenerated randomly on each restart. In multi-instance deployments, each instance used a different key, breaking session portability.

**Impact:** Session hijacking in load-balanced deployments; forced session re-creation on restart.

**Mitigation:** Upgrade to 5.15.0. Key now derived from public URL and user-provided salt.

---

#### COSMIAN-2025-011 — RUSTSEC-2023-0071: RSA Marvin Attack timing side-channel

| Field      | Value                                                                                                                  |
| ---------- | ---------------------------------------------------------------------------------------------------------------------- |
| Severity   | High                                                                                                                   |
| Published  | 22 January 2026                                                                                                        |
| Affected   | from 5.0.0 before 5.15.0                                                                                               |
| Fixed in   | 5.15.0                                                                                                                 |
| Found by   | RustSec Advisory Database                                                                                              |
| References | [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071), [#646](https://github.com/Cosmian/kms/pull/646) |

**Summary:** The `rsa` crate was vulnerable to the Marvin Attack — a timing side-channel in PKCS#1 v1.5 signature verification enabling potential key recovery.

**Impact:** RSA private key recovery or signature forgery via timing analysis.

**Mitigation:** Upgrade to 5.15.0. RSA private-key operations use OpenSSL constant-time implementations. The `rsa` crate is still compiled, through `jsonwebtoken` (JWT `RS*` verification) and, in non-FIPS builds from 5.29.0, `pgp`, but only for public-key operations and key parsing, which the Marvin Attack does not affect; OpenPGP RSA private-key operations (decryption, signing, key generation) also use OpenSSL.

---

#### COSMIAN-2025-004 — OpenSSL 3.x CVEs addressed by upgrade to 3.6.2

| Field      | Value                                           |
| ---------- | ----------------------------------------------- |
| Severity   | High                                            |
| Published  | 22 January 2026                                 |
| Affected   | from 5.0.0 before 5.15.0                        |
| Fixed in   | 5.15.0                                          |
| Found by   | OpenSSL project                                 |
| References | [#667](https://github.com/Cosmian/kms/pull/667) |

**Summary:** Bundled OpenSSL upgraded to 3.6.2, addressing multiple upstream CVEs in X.509 parsing, PKCS#7 processing, and TLS handling.

**Impact:** Various — DoS via malformed certificates to potential RCE. See [OpenSSL advisories](https://openssl-library.org/news/vulnerabilities/).

**Mitigation:** Upgrade to 5.15.0.

---

#### COSMIAN-2025-010 — JWT authentication token not forwarded to downstream services

| Field      | Value                                           |
| ---------- | ----------------------------------------------- |
| Severity   | High                                            |
| Published  | 15 December 2025                                |
| Affected   | from 5.0.0 before 5.14.0                        |
| Fixed in   | 5.14.0                                          |
| Found by   | Cosmian engineering                             |
| References | [#629](https://github.com/Cosmian/kms/pull/629) |

**Summary:** JWT token was not forwarded to downstream services (HSM backends, delegated stores), causing them to operate without access control.

**Impact:** Privilege escalation — downstream services bypassed tenant isolation.

**Mitigation:** Upgrade to 5.14.0.

---

#### COSMIAN-2025-009 — HSM unwrap operation bypasses KMS permission checks

| Field      | Value                                                                                                                                                       |
| ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Severity   | Critical                                                                                                                                                    |
| Published  | 7 December 2025                                                                                                                                             |
| Affected   | from 5.0.0 before 5.13.0                                                                                                                                    |
| Fixed in   | 5.13.0                                                                                                                                                      |
| Found by   | Cosmian engineering                                                                                                                                         |
| References | [#621](https://github.com/Cosmian/kms/pull/621), [COSMIAN-2026-041](#cosmian-2026-041--hsm-keys-usable-to-decrypt-arbitrary-data-through-import-unwrapping) |

**Summary:** HSM-backed key unwrap operations did not enforce KMS-level permission checks. Any authenticated user could unwrap any HSM key.

**Impact:** Complete bypass of KMS authorization for HSM-backed keys across all tenants.

**Mitigation:** Upgrade to 5.29.0. The 5.13.0 fix was incomplete: the unwrap performed by `Import`, and by reads of stored keys wrapped by an HSM key, still skipped the KMS permission check until 5.29.0 (COSMIAN-2026-041).

---

#### COSMIAN-2025-002 — Negative X.509 certificate serial numbers

| Field      | Value                                           |
| ---------- | ----------------------------------------------- |
| Severity   | Moderate                                        |
| Published  | 19 November 2025                                |
| Affected   | from 5.0.0 before 5.12.1                        |
| Fixed in   | 5.12.1                                          |
| Found by   | Cosmian engineering                             |
| References | [#609](https://github.com/Cosmian/kms/pull/609) |

**Summary:** KMS could generate X.509 certificates with negative serial numbers (non-compliant with RFC 5280), causing validation failures in strict TLS implementations.

**Impact:** Certificate interoperability failures.

**Mitigation:** Upgrade to 5.12.1.

---

#### COSMIAN-2025-008 — Google CSE `privilegedunwrap` endpoint unrestricted access

| Field      | Value                                           |
| ---------- | ----------------------------------------------- |
| Severity   | Critical                                        |
| Published  | 5 September 2025                                |
| Affected   | from 5.0.0 before 5.8.0                         |
| Fixed in   | 5.8.0                                           |
| Found by   | Cosmian engineering                             |
| References | [#517](https://github.com/Cosmian/kms/pull/517) |

**Summary:** The Google CSE `privilegedunwrap` endpoint (administrative key recovery) was not properly guarded. Any CSE-authenticated user could invoke it.

**Impact:** Privilege escalation — any CSE user could unwrap any CSE-protected key.

**Mitigation:** Upgrade to 5.8.0. Access restricted to users with administrative permissions.

---

#### COSMIAN-2025-001 — CSE migration key pair race condition

| Field      | Value                                           |
| ---------- | ----------------------------------------------- |
| Severity   | Moderate                                        |
| Published  | 5 September 2025                                |
| Affected   | from 5.0.0 before 5.8.0                         |
| Fixed in   | 5.8.0                                           |
| Found by   | Cosmian engineering                             |
| References | [#519](https://github.com/Cosmian/kms/pull/519) |

**Summary:** Concurrent Google CSE key migration requests could produce inconsistent or duplicated key pairs.

**Impact:** Data loss — documents encrypted during the race window may become permanently undecryptable.

**Mitigation:** Upgrade to 5.8.0.

---

#### COSMIAN-2025-007 — OpenID Connect authentication silently falls back to no-auth on TLS failure

| Field      | Value                                           |
| ---------- | ----------------------------------------------- |
| Severity   | High                                            |
| Published  | 23 July 2025                                    |
| Affected   | from 5.0.0 before 5.6.2                         |
| Fixed in   | 5.6.2                                           |
| Found by   | Cosmian engineering                             |
| References | [#489](https://github.com/Cosmian/kms/pull/489) |

**Summary:** If the OIDC IDP's TLS certificate was not in the system trust store, discovery silently failed and the server operated without authentication.

**Impact:** Complete authentication bypass — unauthenticated access to all KMS operations.

**Mitigation:** Upgrade to 5.6.2. Server now fails hard on TLS errors with configurable CA certificates.

---

#### COSMIAN-2025-006 — Missing PKCE in OAuth2 authentication flow

| Field      | Value                                           |
| ---------- | ----------------------------------------------- |
| Severity   | High                                            |
| Published  | 23 May 2025                                     |
| Affected   | from 5.0.0 before 5.1.0                         |
| Fixed in   | 5.1.0                                           |
| Found by   | Cosmian engineering                             |
| References | [#429](https://github.com/Cosmian/kms/pull/429) |

**Summary:** OAuth2 flow did not implement PKCE, making authorization codes vulnerable to interception and replay.

**Impact:** Token theft via authorization code interception.

**Mitigation:** Upgrade to 5.1.0. PKCE with S256 challenge method implemented.

---

#### COSMIAN-2025-005 — JWT authorization config loop — only first OIDC provider checked

| Field      | Value                                           |
| ---------- | ----------------------------------------------- |
| Severity   | High                                            |
| Published  | 23 May 2025                                     |
| Affected   | from 5.0.0 before 5.1.1                         |
| Fixed in   | 5.1.1                                           |
| Found by   | Cosmian engineering                             |
| References | [#431](https://github.com/Cosmian/kms/pull/431) |

**Summary:** Only the first JWT/OIDC configuration was checked during authorization. Multi-provider setups could allow bypass.

**Impact:** Authorization bypass in multi-provider deployments.

**Mitigation:** Upgrade to 5.1.1. All configured providers are now iterated.

---

## Summary Table

| ID                  | Severity | Affected                | Fixed in | Title                                                                                               |
| ------------------- | -------- | ----------------------- | -------- | --------------------------------------------------------------------------------------------------- |
| COSMIAN-2026-055    | Moderate | before 5.29.0           | 5.29.0   | Get Attributes without a Unique Identifier selected another user's newest object                    |
| COSMIAN-2026-054    | Moderate | unreleased              | 5.29.0   | Batch Undo could restore objects of another user                                                    |
| COSMIAN-2026-053    | High     | before 5.29.0           | 5.29.0   | ReCertify authorized the issuer key as the certificate owner                                        |
| COSMIAN-2026-052    | High     | before 5.29.0           | 5.29.0   | ReKeyKeyPair retired another user's linked public key                                               |
| COSMIAN-2026-051    | Moderate | before 5.29.0           | 5.29.0   | KMIP certificate chains and Locate offsets permit excessive server work                             |
| COSMIAN-2026-050    | High     | before 5.29.0           | 5.29.0   | KMIP payloads written to debug logs                                                                 |
| COSMIAN-2026-049    | High     | before 5.29.0           | 5.29.0   | Configured Operator role permitted key output and PKCS#11 administration                            |
| COSMIAN-2026-048    | High     | 5.27.0 – 5.28.0         | 5.29.0   | CRL and OCSP trust any certificate linked to the CA                                                 |
| COSMIAN-2026-047    | Moderate | 5.16.0 – 5.28.0         | 5.29.0   | Batched KMIP `RequestMessage` operations skip the algorithm policy and the role check               |
| COSMIAN-2026-046    | High     | 5.13.0 – 5.28.0         | 5.29.0   | Server key encryption key usable as a decryption oracle through pre-wrapped `Import`                |
| COSMIAN-2026-045    | Moderate | 5.13.0 – 5.28.0         | 5.29.0   | Sensitive Opaque Objects and Split Keys exported in plaintext when a wrapping specification is sent |
| COSMIAN-2026-044    | Moderate | 5.16.0 – 5.28.0         | 5.29.0   | Attribute edits let stored keys escape the KMIP algorithm policy                                    |
| COSMIAN-2026-043    | Moderate | 5.26.0 – 5.28.0         | 5.29.0   | Authentication Verifier tokens accepted after logout or session revocation                          |
| COSMIAN-2026-042    | High     | 5.25.0 – 5.28.0         | 5.29.0   | Bare HSM keyset identifier bypasses the grant check in crypto operations                            |
| COSMIAN-2026-041    | Critical | 5.13.0 – 5.28.0         | 5.29.0   | HSM keys usable to decrypt arbitrary data through `Import` unwrapping                               |
| COSMIAN-2026-040    | Moderate | 5.27.1 – 5.28.0         | 5.29.0   | KMIP socket server accepts the reserved AWS XKS service identity as a client certificate CN         |
| COSMIAN-2026-039    | Low      | before 5.29.0           | 5.29.0   | Session-cookie requests accepted from other same-site origins                                       |
| COSMIAN-2026-038    | High     | before 5.29.0           | 5.29.0   | AWS XKS SigV4 secret access key written to the startup log                                          |
| COSMIAN-2026-037    | Low      | before 5.29.0           | 5.29.0   | Crypto operations reveal the existence and state of other users' keys                               |
| COSMIAN-2026-036    | Moderate | before 5.29.0           | 5.29.0   | Unbounded per-request work: batch size, PBKDF2 iterations, RSA modulus                              |
| COSMIAN-2026-035    | High     | 5.22.0 – 5.28.0         | 5.29.0   | Google CSE `rewrap` SSRF check bypass via redirects, IPv6 literals and DNS                          |
| COSMIAN-2026-034    | High     | before 5.29.0           | 5.29.0   | JWT signed by one identity provider accepted for another issuer                                     |
| COSMIAN-2026-033    | Moderate | before 5.29.0           | 5.29.0   | KMIP socket server skips client certificate CN checks                                               |
| COSMIAN-2026-032    | High     | before 5.29.0           | 5.29.0   | KMIP socket server exhaustion: unbounded threads, idle connections and allocation                   |
| COSMIAN-2026-031    | Moderate | before 5.29.0           | 5.29.0   | `Get`/`Export` Fresh-bit write-back could persist an auto-unwrapped key                             |
| COSMIAN-2026-030    | Low      | 4.19.0 – 5.28.0         | 5.29.0   | SetAttribute permits changes to read-only metadata                                                  |
| GHSA-8mmx-f92q-2gq8 | High     | 5.0.0 – 5.27.1          | 5.28.0   | `Extractable` and `NeverExtractable` not enforced on key export paths                               |
| GHSA-pvw2-jxwc-95xq | High     | 5.0.0 – 5.27.1          | 5.28.0   | Reserved UID `*` bypassable via `AtomicOperation::Upsert` and `Certify` destination overwrite       |
| GHSA-c75c-3cmm-48h7 | High     | 5.0.0 – 5.27.1          | 5.28.0   | `Sensitive` and `Extractable` attribute stripping via read-only `Get` grant                         |
| COSMIAN-2026-029    | High     | 5.15.0 – 5.28.0         | 5.29.0   | PostgreSQL `sslmode` ignored, connections silently fall back to plaintext                           |
| COSMIAN-2026-028    | High     | 5.27.0 – 5.27.1         | 5.28.0   | SSRF check bypass via `kms_public_url` prefix match in CRL fetching                                 |
| COSMIAN-2026-027    | High     | 5.27.0 – 5.27.1         | 5.28.0   | CRL/OCSP revocation status could be lost, stale or wrong                                            |
| COSMIAN-2026-026    | High     | 5.17.0 – 5.27.1         | 5.28.0   | PKCS#11 module buffer overflows in `C_GetAttributeValue` and `C_Encrypt`                            |
| COSMIAN-2026-025    | Moderate | 5.25.0 – 5.27.1         | 5.28.0   | JOSE tag endpoints allow tag changes with any grant                                                 |
| COSMIAN-2026-024    | High     | 5.25.0 – 5.27.1         | 5.28.0   | Any user can publish a key on the unauthenticated JWKS endpoint                                     |
| COSMIAN-2026-023    | High     | 5.26.0 – 5.27.1         | 5.28.0   | SPIRE transit key substitution via shared tags                                                      |
| COSMIAN-2026-022    | Critical | 5.26.0 – 5.27.1         | 5.28.0   | SPIRE PKI `sign-intermediate` issues CA certificates to any Vault token                             |
| COSMIAN-2026-021    | High     | 5.0.0 – 5.26.x          | 5.27.0   | SSRF via CRL Distribution Points in KMIP Validate/Import                                            |
| COSMIAN-2026-020    | Critical | 5.0.0 – 5.26.0          | 5.27.0   | `Get` grant on wildcard uid `*` bypasses Create/Import gate                                         |
| COSMIAN-2026-019    | Low      | 5.0.0 – 5.22.x          | 5.23.0   | RUSTSEC-2026-0173: proc-macro-error2 via mysql_async (compile-time)                                 |
| COSMIAN-2026-018    | Moderate | 5.0.0 – 5.22.x          | 5.23.0   | Activate uses overly permissive authorization check                                                 |
| COSMIAN-2026-017    | Critical | 5.0.0 – 5.22.x          | 5.23.0   | ReKey / ReKeyKeyPair authorization bypass                                                           |
| COSMIAN-2026-016    | Moderate | 5.0.0 – 5.22.x          | 5.23.0   | Attribute-mutation authorization bypass via incorrect op type                                       |
| COSMIAN-2026-015    | High     | 5.0.0 – 5.21.x          | 5.22.0   | KEK plaintext leak via UsageLimits persist in Decrypt/Sign                                          |
| COSMIAN-2026-014    | Low      | 5.0.0 – 5.21.0          | 5.22.0   | Sensitive config values exposed in Debug output                                                     |
| COSMIAN-2026-013    | Moderate | 5.0.0 – 5.21.0          | 5.22.0   | Internal error details leaked in HTTP 5xx responses                                                 |
| COSMIAN-2026-012    | Low      | 5.0.0 – 5.21.0          | 5.22.0   | `/server-info` endpoint accessible without authentication                                           |
| COSMIAN-2026-011    | Moderate | 5.0.0 – 5.21.0          | 5.22.0   | Non-atomic state transitions enable TOCTOU races                                                    |
| COSMIAN-2026-010    | Moderate | 5.15.0 – 5.21.0         | 5.22.0   | Predictable default session cookie salt                                                             |
| COSMIAN-2026-009    | High     | 5.0.0 – 5.21.0          | 5.22.0   | Google CSE rewrap SSRF via `original_kacls_url`                                                     |
| COSMIAN-2026-008    | High     | 5.0.0 – 5.21.0          | 5.22.0   | Unwrap cache not invalidated on key revocation/destruction                                          |
| COSMIAN-2026-007    | High     | 5.0.0 – 5.21.0          | 5.22.0   | MS DKE scope missing authentication middleware                                                      |
| COSMIAN-2026-006    | High     | 5.17.0 – 5.21.0         | 5.22.0   | Server crash via tracing span misuse                                                                |
| COSMIAN-2026-005    | High     | 5.17.0 – 5.20.1         | 5.21.0   | JWT race condition / algorithm confusion                                                            |
| COSMIAN-2026-004    | Critical | 5.0.0+ (with HTTP OTLP) | 5.22.0   | Plaintext OTLP export leaks encryption query metadata                                               |
| COSMIAN-2026-003    | Critical | 5.0.0 – 5.16.2          | 5.17.0   | Import `replace_existing` ownership bypass                                                          |
| COSMIAN-2026-002    | Critical | 5.0.0 – 5.16.2          | 5.17.0   | SipHash key hardcoded to zero                                                                       |
| COSMIAN-2025-012    | High     | 5.0.0 – 5.14.1          | 5.15.0   | Session cookie key randomly regenerated on restart                                                  |
| COSMIAN-2025-011    | High     | 5.0.0 – 5.14.1          | 5.15.0   | RUSTSEC-2023-0071: RSA Marvin Attack timing side-channel                                            |
| COSMIAN-2025-010    | High     | 5.0.0 – 5.13.0          | 5.14.0   | JWT token not forwarded to downstream services                                                      |
| COSMIAN-2025-009    | Critical | 5.0.0 – 5.12.0          | 5.13.0   | HSM unwrap bypasses KMS permission checks                                                           |
| COSMIAN-2025-008    | Critical | 5.0.0 – 5.7.0           | 5.8.0    | Google CSE `privilegedunwrap` unrestricted access                                                   |
| COSMIAN-2025-007    | High     | 5.0.0 – 5.6.1           | 5.6.2    | OIDC silently falls back to no-auth on TLS failure                                                  |
| COSMIAN-2025-006    | High     | 5.0.0 – 5.0.0           | 5.1.0    | Missing PKCE in OAuth2 authentication flow                                                          |
| COSMIAN-2025-005    | High     | 5.0.0 – 5.1.0           | 5.1.1    | JWT config loop — only first OIDC provider checked                                                  |
| COSMIAN-2025-004    | High     | 5.0.0 – 5.14.1          | 5.15.0   | OpenSSL 3.x CVEs (upgrade to 3.6.2)                                                                 |
| COSMIAN-2025-003    | High     | 5.0.0 – 5.15.0          | 5.16.0   | glibc CVEs in container base image                                                                  |
| COSMIAN-2025-002    | Moderate | 5.0.0 – 5.12.0          | 5.12.1   | Negative X.509 certificate serial numbers                                                           |
| COSMIAN-2025-001    | Moderate | 5.0.0 – 5.7.0           | 5.8.0    | CSE migration key pair race condition                                                               |

---

## Security Best Practices

When using Cosmian KMS, we recommend:

1. **Keep Updated**: Always use the latest supported version
2. **Secure Configuration**: Follow the security configuration guidelines in our documentation
3. **Network Security**: Deploy KMS behind appropriate network security controls
4. **Access Control**: Implement proper authentication and authorization mechanisms
5. **Monitoring**: Enable logging and monitoring for security events
6. **TLS Everywhere**: Use TLS for all endpoints including OTLP collectors
7. **Audit log saturation**: The tamper-evident audit log uses a bounded in-memory
   channel (default capacity: 4 096 events). Under sustained high load, events that
   cannot be enqueued are dropped and an `error!` is emitted to the server log — the
   compliance record is incomplete for that burst. To detect saturation, monitor the
   server log for `"AuditFileStore: channel full"` messages and alert on any
   occurrence. Tune the capacity with `--audit-channel-capacity` (env:
   `KMS_AUDIT_CHANNEL_CAPACITY`); reduce request concurrency or raise the capacity
   to stay within the write throughput of the underlying storage.

## FIPS Compliance

Cosmian KMS supports FIPS 140-3 compliance when built with FIPS features enabled. KMS links against OpenSSL 3.6.2, but the FIPS build still uses the OpenSSL 3.1.2 FIPS provider for cryptographic operations because it is the official FIPS provider version available today (no more recent FIPS provider version).

## Security Audits

This project undergoes regular security assessments. The configuration files `.cargo/audit.toml` and `deny.toml` are maintained to track and manage security advisories affecting our dependencies.

## Contact

For general security questions or concerns, please contact us at [tech@cosmian.com](mailto:tech@cosmian.com).

For immediate security issues, please use the private reporting methods described above.
