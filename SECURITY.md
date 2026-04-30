# Security Policy

- [Security Policy](#security-policy)
  - [Reporting a Vulnerability](#reporting-a-vulnerability)
  - [Severity Rating](#severity-rating)
  - [Known Vulnerabilities](#known-vulnerabilities)
    - [2026](#2026)
    - [2025](#2025)
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
| Moderate | Requires specific conditions, limited scope, or no direct key compromise                            |
| Low      | Minimal practical impact or very difficult to exploit                                                |

---

## Known Vulnerabilities

### 2026

#### COSMIAN-2026-006 — Server crash under concurrent requests due to tracing span misuse

| Field        | Value                                                                       |
| ------------ | --------------------------------------------------------------------------- |
| Severity     | High                                                                        |
| Published    | 25 April 2026                                                               |
| Affected     | from 5.17.0 before 5.21.1                                                   |
| Fixed in     | 5.21.1 (pending release)                                                    |
| Found by     | Cosmian engineering                                                          |
| References   | [#928](https://github.com/Cosmian/kms/pull/928)                             |

**Summary:** The `tracing` crate's `span.enter()` guard was held across `.await` points in asynchronous request handlers. Under concurrent load (~10 parallel requests with valid JWTs), this caused worker thread panics or full server hangs. A stack trace was exposed in the HTTP error response.

**Impact:** Denial of Service. Any authenticated user can crash or hang the server.

**Mitigation:** Upgrade to 5.21.1. The fix replaces `span.enter()` with `tracing::Instrument`.

---

#### COSMIAN-2026-005 — JWT decoding race condition causing intermittent authentication bypass

| Field        | Value                                                                       |
| ------------ | --------------------------------------------------------------------------- |
| Severity     | High                                                                        |
| Published    | 21 April 2026                                                               |
| Affected     | from 5.17.0 before 5.21.0                                                   |
| Fixed in     | 5.21.0                                                                      |
| Found by     | Cosmian OWASP security audit                                                |
| References   | [#916](https://github.com/Cosmian/kms/pull/916)                             |

**Summary:** ~10% of parallel malicious requests with a valid JWT could bypass authentication due to thread-safety issues and algorithm confusion in the `alcoholic_jwt` library (OWASP A07-1).

**Impact:** Authentication bypass under concurrent load.

**Mitigation:** Upgrade to 5.21.0. Migrated to `jsonwebtoken` crate with strict algorithm validation and rate-limiting via `actix-governor`.

---

#### COSMIAN-2026-004 — OTLP telemetry exported over plaintext HTTP leaks encryption queries

| Field        | Value                                                                       |
| ------------ | --------------------------------------------------------------------------- |
| Severity     | Critical                                                                    |
| Published    | 21 April 2026                                                               |
| Affected     | from 5.0.0 before 5.21.1 (when OTLP configured with `http://` endpoint)    |
| Fixed in     | 5.21.1 (pending release)                                                    |
| Found by     | Cosmian security audit                                                      |
| References   | [#928](https://github.com/Cosmian/kms/pull/928)                             |

**Summary:** When the OTLP collector is configured with an HTTP (non-TLS) endpoint, all tracing spans — including Encrypt/Decrypt operation parameters — are transmitted in cleartext, leaking query metadata (object IDs, operation types, user identifiers) to network observers.

**Impact:** Complete loss of confidentiality for encryption operation metadata.

**Mitigation:** Upgrade to 5.21.1 which rejects `http://` OTLP endpoints by default. Use `--otlp-allow-insecure` / `KMS_OTLP_ALLOW_INSECURE=true` only for local development.

---

#### COSMIAN-2026-003 — KMIP Import `replace_existing` bypasses ownership verification

| Field        | Value                                                                       |
| ------------ | --------------------------------------------------------------------------- |
| Severity     | Critical                                                                    |
| Published    | 14 March 2026                                                               |
| Affected     | from 5.0.0 before 5.17.0                                                    |
| Fixed in     | 5.17.0                                                                      |
| Found by     | Cosmian engineering                                                          |
| References   | [#735](https://github.com/Cosmian/kms/pull/735)                             |

**Summary:** The KMIP Import operation with `replace_existing=true` did not verify ownership. Any authenticated user could overwrite any key by knowing its unique identifier.

**Impact:** Total key malleability — any authenticated user could replace keys belonging to other users.

**Mitigation:** Upgrade to 5.17.0. Ownership verification added before replacement.

---

#### COSMIAN-2026-002 — SipHash key hardcoded to zero in unwrap cache

| Field        | Value                                                                       |
| ------------ | --------------------------------------------------------------------------- |
| Severity     | Critical                                                                    |
| Published    | 14 March 2026                                                               |
| Affected     | from 5.0.0 before 5.17.0                                                    |
| Fixed in     | 5.17.0                                                                      |
| Found by     | Cosmian engineering                                                          |
| References   | [#778](https://github.com/Cosmian/kms/pull/778)                             |

**Summary:** The unwrap cache used SipHash with a zero key, making the hash function predictable and enabling hash-collision DoS attacks.

**Impact:** Denial of Service via hash flooding and potential cache poisoning.

**Mitigation:** Upgrade to 5.17.0. SipHash now uses a cryptographically random `RandomState`.

---

### 2025

#### COSMIAN-2025-012 — Session cookie encryption key randomly regenerated on each restart

| Field        | Value                                                                       |
| ------------ | --------------------------------------------------------------------------- |
| Severity     | High                                                                        |
| Published    | 22 January 2026                                                             |
| Affected     | from 5.0.0 before 5.15.0                                                    |
| Fixed in     | 5.15.0                                                                      |
| Found by     | Cosmian engineering                                                          |
| References   | [#664](https://github.com/Cosmian/kms/pull/664)                             |

**Summary:** Session cookie encryption key was regenerated randomly on each restart. In multi-instance deployments, each instance used a different key, breaking session portability.

**Impact:** Session hijacking in load-balanced deployments; forced session re-creation on restart.

**Mitigation:** Upgrade to 5.15.0. Key now derived from public URL and user-provided salt.

---

#### COSMIAN-2025-011 — RUSTSEC-2023-0071: RSA Marvin Attack timing side-channel

| Field        | Value                                                                       |
| ------------ | --------------------------------------------------------------------------- |
| Severity     | High                                                                        |
| Published    | 22 January 2026                                                             |
| Affected     | from 5.0.0 before 5.15.0                                                    |
| Fixed in     | 5.15.0                                                                      |
| Found by     | RustSec Advisory Database                                                   |
| References   | [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071), [#646](https://github.com/Cosmian/kms/pull/646) |

**Summary:** The `rsa` crate was vulnerable to the Marvin Attack — a timing side-channel in PKCS#1 v1.5 signature verification enabling potential key recovery.

**Impact:** RSA private key recovery or signature forgery via timing analysis.

**Mitigation:** Upgrade to 5.15.0. The `rsa` crate was removed entirely; RSA operations use OpenSSL constant-time implementations.

---

#### COSMIAN-2025-010 — JWT authentication token not forwarded to downstream services

| Field        | Value                                                                       |
| ------------ | --------------------------------------------------------------------------- |
| Severity     | High                                                                        |
| Published    | 15 December 2025                                                            |
| Affected     | from 5.0.0 before 5.14.0                                                    |
| Fixed in     | 5.14.0                                                                      |
| Found by     | Cosmian engineering                                                          |
| References   | [#629](https://github.com/Cosmian/kms/pull/629)                             |

**Summary:** JWT token was not forwarded to downstream services (HSM backends, delegated stores), causing them to operate without access control.

**Impact:** Privilege escalation — downstream services bypassed tenant isolation.

**Mitigation:** Upgrade to 5.14.0.

---

#### COSMIAN-2025-009 — HSM unwrap operation bypasses KMS permission checks

| Field        | Value                                                                       |
| ------------ | --------------------------------------------------------------------------- |
| Severity     | Critical                                                                    |
| Published    | 7 December 2025                                                             |
| Affected     | from 5.0.0 before 5.13.0                                                    |
| Fixed in     | 5.13.0                                                                      |
| Found by     | Cosmian engineering                                                          |
| References   | [#621](https://github.com/Cosmian/kms/pull/621)                             |

**Summary:** HSM-backed key unwrap operations did not enforce KMS-level permission checks. Any authenticated user could unwrap any HSM key.

**Impact:** Complete bypass of KMS authorization for HSM-backed keys across all tenants.

**Mitigation:** Upgrade to 5.13.0.

---

#### COSMIAN-2025-008 — Google CSE `privilegedunwrap` endpoint unrestricted access

| Field        | Value                                                                       |
| ------------ | --------------------------------------------------------------------------- |
| Severity     | Critical                                                                    |
| Published    | 5 September 2025                                                            |
| Affected     | from 5.0.0 before 5.8.0                                                     |
| Fixed in     | 5.8.0                                                                       |
| Found by     | Cosmian engineering                                                          |
| References   | [#517](https://github.com/Cosmian/kms/pull/517)                             |

**Summary:** The Google CSE `privilegedunwrap` endpoint (administrative key recovery) was not properly guarded. Any CSE-authenticated user could invoke it.

**Impact:** Privilege escalation — any CSE user could unwrap any CSE-protected key.

**Mitigation:** Upgrade to 5.8.0. Access restricted to users with administrative permissions.

---

#### COSMIAN-2025-007 — OpenID Connect authentication silently falls back to no-auth on TLS failure

| Field        | Value                                                                       |
| ------------ | --------------------------------------------------------------------------- |
| Severity     | High                                                                        |
| Published    | 23 July 2025                                                                |
| Affected     | from 5.0.0 before 5.6.2                                                     |
| Fixed in     | 5.6.2                                                                       |
| Found by     | Cosmian engineering                                                          |
| References   | [#489](https://github.com/Cosmian/kms/pull/489)                             |

**Summary:** If the OIDC IDP's TLS certificate was not in the system trust store, discovery silently failed and the server operated without authentication.

**Impact:** Complete authentication bypass — unauthenticated access to all KMS operations.

**Mitigation:** Upgrade to 5.6.2. Server now fails hard on TLS errors with configurable CA certificates.

---

#### COSMIAN-2025-006 — Missing PKCE in OAuth2 authentication flow

| Field        | Value                                                                       |
| ------------ | --------------------------------------------------------------------------- |
| Severity     | High                                                                        |
| Published    | 23 May 2025                                                                 |
| Affected     | from 5.0.0 before 5.1.0                                                     |
| Fixed in     | 5.1.0                                                                       |
| Found by     | Cosmian engineering                                                          |
| References   | [#429](https://github.com/Cosmian/kms/pull/429)                             |

**Summary:** OAuth2 flow did not implement PKCE, making authorization codes vulnerable to interception and replay.

**Impact:** Token theft via authorization code interception.

**Mitigation:** Upgrade to 5.1.0. PKCE with S256 challenge method implemented.

---

#### COSMIAN-2025-005 — JWT authorization config loop — only first OIDC provider checked

| Field        | Value                                                                       |
| ------------ | --------------------------------------------------------------------------- |
| Severity     | High                                                                        |
| Published    | 23 May 2025                                                                 |
| Affected     | from 5.0.0 before 5.1.1                                                     |
| Fixed in     | 5.1.1                                                                       |
| Found by     | Cosmian engineering                                                          |
| References   | [#431](https://github.com/Cosmian/kms/pull/431)                             |

**Summary:** Only the first JWT/OIDC configuration was checked during authorization. Multi-provider setups could allow bypass.

**Impact:** Authorization bypass in multi-provider deployments.

**Mitigation:** Upgrade to 5.1.1. All configured providers are now iterated.

---

#### COSMIAN-2025-004 — OpenSSL 3.x CVEs addressed by upgrade to 3.6.0

| Field        | Value                                                                       |
| ------------ | --------------------------------------------------------------------------- |
| Severity     | High                                                                        |
| Published    | 22 January 2026                                                             |
| Affected     | from 5.0.0 before 5.15.0                                                    |
| Fixed in     | 5.15.0                                                                      |
| Found by     | OpenSSL project                                                             |
| References   | [#667](https://github.com/Cosmian/kms/pull/667)                             |

**Summary:** Bundled OpenSSL upgraded to 3.6.0, addressing multiple upstream CVEs in X.509 parsing, PKCS#7 processing, and TLS handling.

**Impact:** Various — DoS via malformed certificates to potential RCE. See [OpenSSL advisories](https://openssl-library.org/news/vulnerabilities/).

**Mitigation:** Upgrade to 5.15.0.

---

#### COSMIAN-2025-003 — glibc CVEs in container base image (CVE-2024-2961, CVE-2024-33600, CVE-2024-33601)

| Field        | Value                                                                       |
| ------------ | --------------------------------------------------------------------------- |
| Severity     | High                                                                        |
| Published    | 15 February 2026                                                            |
| Affected     | from 5.0.0 before 5.16.0                                                    |
| Fixed in     | 5.16.0                                                                      |
| Found by     | SBOM vulnerability scan                                                     |
| References   | [#709](https://github.com/Cosmian/kms/pull/709)                             |

**Summary:** Docker/package builds used glibc 2.28 with CVE-2024-2961 (iconv buffer overflow), CVE-2024-33600/33601 (nscd cache issues).

**Impact:** Potential RCE or DoS via crafted locale conversion or DNS resolution.

**Mitigation:** Upgrade to 5.16.0 (glibc 2.34).

---

#### COSMIAN-2025-002 — Negative X.509 certificate serial numbers

| Field        | Value                                                                       |
| ------------ | --------------------------------------------------------------------------- |
| Severity     | Moderate                                                                    |
| Published    | 19 November 2025                                                            |
| Affected     | from 5.0.0 before 5.12.1                                                    |
| Fixed in     | 5.12.1                                                                      |
| Found by     | Cosmian engineering                                                          |
| References   | [#609](https://github.com/Cosmian/kms/pull/609)                             |

**Summary:** KMS could generate X.509 certificates with negative serial numbers (non-compliant with RFC 5280), causing validation failures in strict TLS implementations.

**Impact:** Certificate interoperability failures.

**Mitigation:** Upgrade to 5.12.1.

---

#### COSMIAN-2025-001 — CSE migration key pair race condition

| Field        | Value                                                                       |
| ------------ | --------------------------------------------------------------------------- |
| Severity     | Moderate                                                                    |
| Published    | 5 September 2025                                                            |
| Affected     | from 5.0.0 before 5.8.0                                                     |
| Fixed in     | 5.8.0                                                                       |
| Found by     | Cosmian engineering                                                          |
| References   | [#519](https://github.com/Cosmian/kms/pull/519)                             |

**Summary:** Concurrent Google CSE key migration requests could produce inconsistent or duplicated key pairs.

**Impact:** Data loss — documents encrypted during the race window may become permanently undecryptable.

**Mitigation:** Upgrade to 5.8.0.

---

## Summary Table

| ID               | Severity | Affected                      | Fixed in | Title                                                          |
| ---------------- | -------- | ----------------------------- | -------- | -------------------------------------------------------------- |
| COSMIAN-2026-006 | High     | 5.17.0 – 5.21.0              | 5.21.1   | Server crash via tracing span misuse                           |
| COSMIAN-2026-005 | High     | 5.17.0 – 5.20.1              | 5.21.0   | JWT race condition / algorithm confusion                       |
| COSMIAN-2026-004 | Critical | 5.0.0+ (with HTTP OTLP)      | 5.21.1   | Plaintext OTLP export leaks encryption query metadata          |
| COSMIAN-2026-003 | Critical | 5.0.0 – 5.16.2               | 5.17.0   | Import `replace_existing` ownership bypass                     |
| COSMIAN-2026-002 | Critical | 5.0.0 – 5.16.2               | 5.17.0   | SipHash key hardcoded to zero                                  |
| COSMIAN-2025-012 | High     | 5.0.0 – 5.14.1               | 5.15.0   | Session cookie key randomly regenerated on restart             |
| COSMIAN-2025-011 | High     | 5.0.0 – 5.14.1               | 5.15.0   | RUSTSEC-2023-0071: RSA Marvin Attack timing side-channel       |
| COSMIAN-2025-010 | High     | 5.0.0 – 5.13.0               | 5.14.0   | JWT token not forwarded to downstream services                 |
| COSMIAN-2025-009 | Critical | 5.0.0 – 5.12.0               | 5.13.0   | HSM unwrap bypasses KMS permission checks                      |
| COSMIAN-2025-008 | Critical | 5.0.0 – 5.7.0                | 5.8.0    | Google CSE `privilegedunwrap` unrestricted access               |
| COSMIAN-2025-007 | High     | 5.0.0 – 5.6.1                | 5.6.2    | OIDC silently falls back to no-auth on TLS failure             |
| COSMIAN-2025-006 | High     | 5.0.0 – 5.0.0                | 5.1.0    | Missing PKCE in OAuth2 authentication flow                     |
| COSMIAN-2025-005 | High     | 5.0.0 – 5.1.0                | 5.1.1    | JWT config loop — only first OIDC provider checked             |
| COSMIAN-2025-004 | High     | 5.0.0 – 5.14.1               | 5.15.0   | OpenSSL 3.x CVEs (upgrade to 3.6.0)                           |
| COSMIAN-2025-003 | High     | 5.0.0 – 5.15.0               | 5.16.0   | glibc CVEs in container base image                             |
| COSMIAN-2025-002 | Moderate | 5.0.0 – 5.12.0               | 5.12.1   | Negative X.509 certificate serial numbers                      |
| COSMIAN-2025-001 | Moderate | 5.0.0 – 5.7.0                | 5.8.0    | CSE migration key pair race condition                          |

---

## Security Best Practices

When using Cosmian KMS, we recommend:

1. **Keep Updated**: Always use the latest supported version
2. **Secure Configuration**: Follow the security configuration guidelines in our documentation
3. **Network Security**: Deploy KMS behind appropriate network security controls
4. **Access Control**: Implement proper authentication and authorization mechanisms
5. **Monitoring**: Enable logging and monitoring for security events
6. **TLS Everywhere**: Use TLS for all endpoints including OTLP collectors

## FIPS Compliance

Cosmian KMS supports FIPS 140-3 compliance when built with FIPS features enabled. KMS links against OpenSSL 3.6.0, but the FIPS build still uses the OpenSSL 3.1.2 FIPS provider for cryptographic operations because it is the official FIPS provider version available today (no more recent FIPS provider version).

## Security Audits

This project undergoes regular security assessments. The configuration files `.cargo/audit.toml` and `deny.toml` are maintained to track and manage security advisories affecting our dependencies.

## Contact

For general security questions or concerns, please contact us at [tech@cosmian.com](mailto:tech@cosmian.com).

For immediate security issues, please use the private reporting methods described above.
