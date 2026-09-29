# Threat Model Analysis Principles

Core analytical principles for identifying, evaluating, and prioritizing threats in the Eviden KMS.

## 1. Verify Before Flagging

**Rule**: For every potential threat, locate the specific code that would need to be exploited. If you cannot find evidence in the codebase, mark the finding as "no evidence — not confirmed."

**Process**:

1. Form a hypothesis: "I think X could lead to Y"
2. Search for the relevant code: `rg "function_name" crate/`
3. Read the actual implementation
4. Confirm or refute the hypothesis
5. Only flag confirmed vulnerabilities

Never hallucinate findings. A "no evidence" result is useful data.

## 2. Security Infrastructure Inventory

Before classifying any potential threat, check whether a control already exists:

**Authentication controls** (check `crate/server/src/middlewares/`):

- `JwtAuth` — Bearer token validation
- `SslAuth` — mTLS client certificate validation
- `ApiTokenAuth` — API token validation
- `EnsureAuth` — enforces at least one auth method is configured per scope

**Authorization controls** (check `crate/access/`):

- Object ownership check before Get/Export/Decrypt
- Grant/Revoke permission management
- `Locate` result filtering by owner

**Crypto controls** (check `crate/crypto/src/`):

- OpenSSL FIPS provider enforcement
- Algorithm allow-list in FIPS mode
- Key size enforcement

**Input validation** (check `crate/kmip/src/`):

- TTLV deserializer rejects malformed messages
- Enum values validated against KMIP spec

If a control exists, credit it — then evaluate whether it is correct, complete, and consistently applied.

## 3. STRIDE-A Threat Categories

Apply STRIDE-A systematically to each component and data flow:

### Spoofing

Could an attacker claim to be someone they are not?

- User identity spoofing: weak JWT validation, missing signature check
- Service spoofing: no mTLS for server-to-HSM communication
- Clock manipulation affecting JWT `exp` checks

### Tampering

Could an attacker modify data?

- TTLV message in transit (without TLS)
- Database records (if DB has insufficient access controls)
- Log file tampering (no append-only enforcement)
- Configuration file tampering before server start

### Repudiation

Could an attacker deny performing an action?

- Missing audit log for key operations (Create, Destroy, Export)
- Audit log without user identity correlation
- No log integrity protection

### Information Disclosure

Could an attacker read data they should not?

- Key material returned without access control check (**highest priority for KMS**)
- Error messages revealing internal object UIDs
- `Locate` returning objects the caller cannot access
- Key metadata (labels, attributes) leaked to unauthorized users
- Sensitive data in server logs (`trace!` with key bytes)

### Denial of Service

Could an attacker degrade availability?

- Unbounded KMIP batch request (no max batch size enforcement)
- Expensive crypto operations without rate limiting
- HSM token exhaustion via rapid key generation
- DB connection exhaustion

### Elevation of Privilege

Could an attacker gain higher permissions?

- Grant operation without ownership verification
- Admin bypass via `insecure` feature in production deployments
- Object UID prediction enabling access to other users' keys
- `Locate` returning all objects when it should be scoped

### Abuse

Could a legitimate user misuse the system in unintended ways?

- Bulk key export for data exfiltration
- Creating excessive key objects (no quota)
- Using `Wrap` operation to export another user's key via a shared wrapping key

## 4. OWASP Top 10:2025 Mapping

| OWASP | Applicable to KMS |
|-------|------------------|
| A01: Broken Access Control | Missing `is_allowed()` check in KMIP operations |
| A02: Cryptographic Failures | Non-FIPS algorithms outside non-fips gate; weak RNG for keys |
| A03: Injection | Log injection via KMIP text fields; path traversal in SQLite path |
| A04: Insecure Design | Missing rate limiting; no key quota; predictable UIDs |
| A05: Security Misconfiguration | `insecure` feature in production; default TLS not enforced |
| A06: Vulnerable Components | Outdated crypto crates with CVEs |
| A07: Auth Failures | JWT `alg:none`; missing expiry check; API token in URL |
| A08: Software Integrity Failures | Nix hash not verified for dependencies; supply chain |
| A09: Logging/Monitoring Failures | No audit log for key operations; insufficient log detail |
| A10: SSRF | Cloud provider callback URL validation (AWS XKS, Azure EKM) |

## 5. Exploitability Tiers

Use these tiers when assigning CVSS 4.0 scores:

| Tier | Attack Vector | Privileges Required | User Interaction | Typical CVSS |
|------|--------------|--------------------|--------------------|-------------|
| Network, no auth | Network | None | None | 9.0–10.0 |
| Network, auth required | Network | Low | None | 7.0–8.9 |
| Network, high priv | Network | High | None | 5.0–6.9 |
| Local / adjacent | Local/Adjacent | Low | None | 3.0–5.9 |
| Physical access needed | Physical | None | None | 1.0–3.9 |

## 6. KMS-Specific Risk Amplifiers

These factors increase effective severity for this codebase:

- **FIPS compliance**: Any finding that causes a non-approved algorithm to be used in FIPS mode is automatically elevated to CRITICAL (compliance violation, not just security risk)
- **Key escrow liability**: Any finding that allows exporting key material without the key owner's consent is CRITICAL
- **Multi-tenant exposure**: Any finding that leaks one tenant's objects to another is CRITICAL
- **HSM boundary**: Any finding in HSM communication paths is elevated by +1 severity tier (hardware trust anchors are high-value targets)
- **Cloud provider routes**: Vulnerabilities in AWS XKS, Azure EKM, Google CSE, MS DKE routes affect the customer's cloud encryption and are CRITICAL

## 7. False Positive Avoidance

Common false positives in this codebase:

- **`#[cfg(feature = "insecure")]` code**: This is explicitly a dev/test feature; its presence is not a vulnerability unless it is compiled into a production binary. Check `Cargo.toml` default features.
- **`#[cfg(feature = "non-fips")]` code**: Intentionally non-FIPS; the gating itself is the control. Only flag if the gating is missing or incorrectly placed (inline instead of at function level).
- **Test credentials in `test_data/`**: Test fixtures with fake key material are expected and intentional.
- **Error details in server logs**: Detailed errors logged at `debug!`/`trace!` level are appropriate for operators. Only flag if sensitive data appears at `info!` level or higher.
- **`unwrap()` in tests**: Expected. Only flag in `src/` (production) code.
