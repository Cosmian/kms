# ANSSI Compliance

## Reference document

This page analyses Cosmian KMS against the French National Cybersecurity Agency (ANSSI) guide
**"Règles et recommendations concernant le choix et le dimensionnement de mécanismes
cryptographiques"** — version 3.00 (published March 2026).

The document is available from the ANSSI portal:
[https://messervices.cyber.gouv.fr/guides/mecanismes-cryptographiques](https://messervices.cyber.gouv.fr/guides/mecanismes-cryptographiques)

!!! note "Scope"
    This compliance analysis covers:

    - **FIPS mode** (default build) — cryptographic primitives enforced by the OpenSSL FIPS
      provider.
    - **Non-FIPS mode** (`--features non-fips`) — full algorithm set including PQC and ChaCha20.
    - **DEFAULT KMIP policy** (`kmip.policy_id = "DEFAULT"`) — the server-side allowlist that
      restricts which algorithms, key sizes, modes, and hash functions clients may request.

    Enabling the DEFAULT KMIP policy is strongly recommended in production environments to ensure
    ANSSI conformance. Without it, the policy layer is inactive and clients may request deprecated
    or weak parameters.

---

## Terminology

The ANSSI guide distinguishes two types of rules:

| Term | Meaning |
|------|---------|
| **Règle (R)** | Mandatory rule — must be respected for any product subject to French regulatory requirements |
| **Recommendation (Rec)** | Best-practice aligned with the state of the art |

The analysis below uses ✅ (compliant), ⚠️ (partially compliant / caveat), and ❌
(non-compliant) to indicate the posture of Cosmian KMS for each rule.

---

## Chapter 1 — Minimum security level

### RG1 — 128-bit minimum security level

> *Every cryptographic mechanism must provide at least 128 bits of security.*

| Mode | Status | Notes |
|------|--------|-------|
| FIPS | ✅ | OpenSSL FIPS provider enforces NIST-approved algorithms with ≥ 128-bit security |
| Non-FIPS + DEFAULT policy | ✅ | All allowlisted algorithms meet the 128-bit threshold |
| Non-FIPS without policy | ⚠️ | No restriction — clients could request weak parameters if policy is disabled |

The DEFAULT policy explicitly excludes SHA-1, MD5, DES, 3-DES, RC4, and all other sub-128-bit
mechanisms via a hard denylist combined with conservative allowlists.

### RG2 — Standardised mechanisms only

All algorithms exposed by the KMS are standardised: AES (FIPS 197), RSA (PKCS#1), EC (NIST SP
800-186), ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205), SHA-2/SHA-3 (FIPS 180-4 /
FIPS 202), HMAC (FIPS 198-1), HKDF (RFC 5869), PBKDF2 (NIST SP 800-132).

### RG6 — Cryptographic agility

> *A cryptographic mechanism must be replaceable without major architectural rework.*

✅ The KMS exposes a fully algorithm-agnostic KMIP 2.1 API. Algorithms, key sizes, modes, and
hash functions are all parameters of KMIP requests. The DEFAULT and CUSTOM policy mechanisms
allow administrators to update the approved algorithm set without code changes.

---

## Chapter 3 — Symmetric encryption

### Allowed algorithm

> *Rule: Only AES is authorised for symmetric encryption in new systems.*

✅ The KMS supports only AES for symmetric encryption. DES, 3-DES, RC4, and Blowfish are in
the hard denylist and are rejected regardless of configuration.

### AES key sizes

| Key size | ANSSI status | KMS DEFAULT policy | KMS FIPS mode |
|----------|-------------|-------------------|---------------|
| AES-128 | ✅ Recommended | ✅ Allowed | ✅ Allowed |
| AES-192 | ✅ Recommended | ✅ Allowed | ✅ Allowed |
| AES-256 | ✅ Recommended (PQ-preferred) | ✅ Allowed | ✅ Allowed |

Source: `crate/crypto/src/crypto/symmetric/symmetric_ciphers.rs` —
`AES_128_GCM_KEY_LENGTH = 16`, `AES_256_GCM_KEY_LENGTH = 32`.

### Modes of operation

| Mode | ANSSI status | KMS DEFAULT policy | Notes |
|------|-------------|-------------------|-------|
| GCM | ✅ Recommended (AEAD) | ✅ Allowed | Primary symmetric mode |
| CCM | ✅ Recommended (AEAD) | ✅ Allowed | AEAD mode |
| GCM-SIV | ✅ Recommended (deterministic) | ✅ Allowed | Non-FIPS only |
| XTS | ✅ Authorised (disk encryption) | ✅ Allowed | Non-FIPS only; double-size key required |
| NIST Key Wrap — RFC 3394 | ✅ Authorised | ✅ Allowed | Key wrapping only (NIST SP 800-38F) |
| AES Key Wrap Padded — RFC 5649 | ✅ Authorised | ✅ Allowed | Key wrapping with padding |
| CBC | ⚠️ Authorised without authentication | ❌ Not in DEFAULT allowlist | Excluded to prevent unauthenticated use |
| ECB | ❌ **Forbidden** | ❌ Not in DEFAULT allowlist | Hard-forbidden; excluded from DEFAULT policy |

!!! warning "ECB and CBC modes"
    **ECB mode** provides no semantic security (identical plaintext blocks produce identical
    ciphertext blocks) and is **forbidden** by ANSSI rule.

    **CBC mode** is authorised only when combined with a MAC; the KMS does not enforce this
    combination at the API level.

    Both modes are **excluded from the DEFAULT KMIP policy** and cannot be requested when
    `kmip.policy_id = "DEFAULT"` is configured. This is the recommended production posture.

### GCM nonce and tag parameters

> *Rule: GCM IV must be 96 bits. Authentication tag must be at least 96 bits (128 bits
> recommended).*

✅ The KMS uses a **96-bit (12-byte) IV** and a **128-bit (16-byte) authentication tag** for all
AES-GCM variants — satisfying both the minimum requirement and the recommendation.

Source: `crate/crypto/src/crypto/symmetric/symmetric_ciphers.rs`:

```text
AES_128_GCM_IV_LENGTH  = 12  (96 bits)   ← ANSSI required
AES_128_GCM_MAC_LENGTH = 16  (128 bits)  ← ANSSI recommended
AES_256_GCM_IV_LENGTH  = 12  (96 bits)
AES_256_GCM_MAC_LENGTH = 16  (128 bits)
```

### GCM nonce uniqueness

> *Rule: GCM nonces must never be reused with the same key.*

✅ Nonces are generated by `random_nonce()` which calls `openssl::rand::rand_bytes()` — the
OpenSSL CSPRNG — for every encryption operation.

---

## Chapter 4 — Hash functions

### Allowed hash functions

| Algorithm | Output | Collision security | ANSSI status | KMS DEFAULT policy |
|-----------|--------|--------------------|-------------|-------------------|
| SHA-256 | 256 bits | 128 bits | ✅ Recommended | ✅ Allowed |
| SHA-384 | 384 bits | 192 bits | ✅ Recommended | ✅ Allowed |
| SHA-512 | 512 bits | 256 bits | ✅ Recommended | ✅ Allowed |
| SHA-3-256 | 256 bits | 128 bits | ✅ Recommended | ✅ Allowed |
| SHA-3-384 | 384 bits | 192 bits | ✅ Recommended | ✅ Allowed |
| SHA-3-512 | 512 bits | 256 bits | ✅ Recommended | ✅ Allowed |
| SHAKE128 | variable | ≥ 128 bits | ✅ Recommended | ✅ Allowed (non-FIPS) |
| SHAKE256 | variable | ≥ 256 bits | ✅ Recommended | ✅ Allowed (non-FIPS) |
| SHA-224 | 224 bits | 112 bits | ⚠️ Tolerated | ❌ Not in DEFAULT allowlist |
| SHA-1 | 160 bits | 80 bits | ❌ Forbidden (new apps) | ❌ Hard-denied |
| MD5 | 128 bits | 64 bits | ❌ Forbidden | ❌ Hard-denied |
| MD4 / MD2 | — | — | ❌ Forbidden | ❌ Hard-denied |

The hard denylist in `algorithm_policy.rs` rejects MD2, MD4, MD5, and SHA-1 for all hash
operations regardless of the configured policy.

### Minimum output length

> *Rule: Hash output must be at least 256 bits when used standalone.*

✅ The DEFAULT policy allowlist includes only SHA-256 and above.

---

## Chapter 5 — Message Authentication Codes (MAC / HMAC)

### HMAC

| Construction | ANSSI status | KMS DEFAULT policy |
|-------------|-------------|-------------------|
| HMAC-SHA-256 | ✅ Recommended | ✅ Allowed |
| HMAC-SHA-384 | ✅ Recommended | ✅ Allowed |
| HMAC-SHA-512 | ✅ Recommended | ✅ Allowed |
| HMAC-SHA-1 | ❌ Forbidden (new apps) | ❌ Hard-denied for all MAC operations |
| HMAC-SHA-224 | ⚠️ Tolerated | ❌ Hard-denied for all MAC operations |
| HMAC-MD5 | ❌ Forbidden | ❌ Hard-denied |

✅ HMAC-SHA-1 and HMAC-SHA-224 are **hard-denied** in `validate_hashing_algorithm_for_mac()` —
they cannot be used regardless of policy configuration, aligning with ANSSI's strict stance for
new applications.

### Tag size

> *Rule: HMAC tag must not be truncated below 128 bits.*

✅ The KMS does not truncate HMAC outputs; the full digest is produced.

---

## Chapter 6 — Asymmetric algorithms

### 6.1 RSA

#### Key sizes

| Key size | ANSSI status | KMS DEFAULT policy | KMS hard floor |
|----------|-------------|-------------------|----------------|
| 4096 bits | ✅ Recommended (long term) | ✅ Allowed | — |
| 3072 bits | ✅ Recommended (new systems) | ✅ Allowed | — |
| 2048 bits | ⚠️ Tolerated until 2030 (legacy only) | ❌ **Not in DEFAULT allowlist** | — |
| < 2048 bits | ❌ Forbidden | ❌ Always rejected | < 2048 always rejected |

!!! success "RSA-2048 excluded from the DEFAULT policy"
    The DEFAULT policy restricts RSA to **3072 and 4096 bits only**, aligning with ANSSI's
    requirement that new systems use at least 3072-bit RSA keys. Although RSA-2048 is tolerated
    for legacy maintenance until 2030, it is intentionally excluded from the DEFAULT allowlist
    to encourage migration to stronger keys.

Source: `KmipAllowlistsConfig::conservative()` — `rsa_key_sizes: Some([Rsa3072, Rsa4096])`.

#### Public exponent

> *Rule: Public exponent e must be odd and ≥ 65537. e = 3 is forbidden.*

✅ RSA key generation delegates to OpenSSL, which enforces e = 65537 by default.

#### Padding schemes

| Scheme | ANSSI status | KMS support |
|--------|-------------|-------------|
| RSA-PSS (signatures) | ✅ Recommended | ✅ Supported; DEFAULT allows PSS |
| RSA-OAEP (encryption) | ✅ Recommended | ✅ Supported; DEFAULT allows OAEP |
| RSA-PKCS#1 v1.5 (encryption) | ❌ **Forbidden** — Bleichenbacher | ❌ Hard-denied; not in any allowlist |
| RSA-PKCS#1 v1.5 (signature) | ⚠️ Tolerated (backward compat) | ✅ Supported; excluded from DEFAULT |

RSA-PKCS#1 v1.5 **encryption** is **hard-denied** across all policy configurations because it
is vulnerable to the Bleichenbacher (1998) adaptive chosen-ciphertext attack.

### 6.2 Elliptic curves — ECDSA / ECDH

| Curve | Security level | ANSSI status | KMS DEFAULT policy |
|-------|---------------|-------------|-------------------|
| P-256 (secp256r1) | 128 bits | ✅ Recommended | ✅ Allowed |
| P-384 (secp384r1) | 192 bits | ✅ Recommended | ✅ Allowed |
| P-521 (secp521r1) | 260 bits | ✅ Recommended | ✅ Allowed |
| Curve25519 (X25519) | 128 bits | ✅ Recommended (key exchange) | ✅ Allowed |
| Curve448 (X448) | 224 bits | ✅ Recommended (key exchange) | ✅ Allowed |
| Ed25519 (EdDSA) | 128 bits | ✅ Recommended (signature) | ✅ Allowed (non-FIPS) |
| Ed448 (EdDSA) | 224 bits | ✅ Recommended (signature) | ✅ Allowed |
| secp192r1 (P-192) and smaller | < 96 bits | ❌ Forbidden | ❌ Hard-denied (non-FIPS only) |
| ANSI X9.62 weak curves | weak | ❌ Forbidden | ❌ Hard-denied |

> **Note:** Brainpool curves (RFC 5639) are not supported by Cosmian KMS. ECDSA/ECDH operations
> are limited to NIST curves (P-256, P-384, P-521) and EdDSA/X curves (Curve25519, Curve448).

#### ECDSA nonce

> *Rule: The ECDSA nonce k must never be reused with the same key.*

✅ ECDSA signing is performed by OpenSSL, which generates a fresh random nonce per operation.

### 6.3 Key exchange and forward secrecy

> *Rule: Key exchange must ensure forward secrecy (PFS) wherever possible.*

✅ All KMS TLS connections use ECDHE or DHE key exchange, providing forward secrecy.

---

## Chapter 7 — Key derivation functions (KDF)

### Password-based key derivation

| Mode | KDF used | Parameters | ANSSI alignment |
|------|----------|-----------|-----------------|
| FIPS | PBKDF2-HMAC-SHA-512 | 210 000 iterations, 16-byte random salt | ✅ Compliant |
| Non-FIPS | Argon2id | Default: m=19 456 KiB, t=2, p=1 | ✅ Recommended |

Source: `crate/crypto/src/crypto/password_derivation.rs`:

```rust
pub const FIPS_MIN_SALT_SIZE: usize = 16;   // 128-bit salt
pub const FIPS_MIN_ITER:      usize = 210_000;  // OWASP SHA-512 recommendation
```

### KMIP DeriveKey operation

The KMIP `DeriveKey` operation supports both PBKDF2 and HKDF (RFC 5869):

| Method | Default iterations | ANSSI alignment |
|--------|-------------------|-----------------|
| PBKDF2-HMAC-SHA-256 | 600 000 (OWASP 2023) | ✅ Compliant |
| HKDF-SHA-256/384/512 | — | ✅ Recommended |

Source: `crate/server/src/core/operations/derive_key.rs`:
`DEFAULT_PBKDF2_ITERATIONS = 600_000`.

### Prohibition on raw DH output as key material

> *Rule: The output of a DH or ECDH exchange must never be used directly as a session key
> — it must pass through a KDF.*

✅ The KMS uses HKDF to derive symmetric keys from ECDH shared secrets in all ECIES-style
operations and key agreement flows.

---

## Chapter 8 — Random number generation

> *Rule: All cryptographic randomness must be produced by a CSPRNG seeded from a physical
> entropy source.*

✅ The KMS uses exclusively `openssl::rand::rand_bytes()` for all random material (nonces,
symmetric keys, salts, EC nonces).

| Mode | CSPRNG implementation |
|------|-----------------------|
| FIPS | OpenSSL FIPS provider SP 800-90A CTR-DRBG (AES-256) |
| Non-FIPS | OpenSSL default provider, seeded from OS entropy (`getrandom()` / `/dev/urandom` on Linux; `BCryptGenRandom` on Windows) |

Both satisfy the ANSSI requirement for a hardware-entropy-seeded CSPRNG. The Dual_EC_DRBG
(forbidden by ANSSI) is not used.

---

## Chapter 9 — Post-quantum cryptography

The ANSSI guide requires **hybrid mode** (classical + PQC) during the transition period.
The recommended strategy is to combine a classical and a post-quantum mechanism such that
security is no lower than the classical mechanism alone.

### ML-KEM (CRYSTALS-Kyber) — FIPS 203

| Variant | NIST level | ANSSI status | KMS DEFAULT policy (non-FIPS) |
|---------|-----------|-------------|-------------------------------|
| ML-KEM-1024 | 5 | ✅ Recommended | ✅ Allowed |
| ML-KEM-768 | 3 | ✅ Recommended (minimum) | ✅ Allowed |
| ML-KEM-512 | 1 | ⚠️ **Hybrid mode only** | ❌ **Excluded from DEFAULT** |

!!! success "ML-KEM-512 excluded from DEFAULT policy"
    The DEFAULT policy now allows only **ML-KEM-768 and ML-KEM-1024**, which satisfy ANSSI's
    standalone security requirements. ML-KEM-512 is excluded because ANSSI requires it to be
    used only in hybrid mode (combined with a classical KEM). Users who need ML-KEM-512 can
    allow it via a CUSTOM policy together with mandatory classical key exchange.

### ML-DSA (CRYSTALS-Dilithium) — FIPS 204

| Variant | NIST level | ANSSI status | KMS DEFAULT policy (non-FIPS) |
|---------|-----------|-------------|-------------------------------|
| ML-DSA-87 | 5 | ✅ Recommended (preferred) | ✅ Allowed |
| ML-DSA-65 | 3 | ✅ Recommended (minimum) | ✅ Allowed |
| ML-DSA-44 | 2 | ⚠️ **Tolerated in hybrid only** | ❌ **Excluded from DEFAULT** |

!!! success "ML-DSA-44 excluded from DEFAULT policy"
    The DEFAULT policy allows only **ML-DSA-65 and ML-DSA-87**. ML-DSA-44 is excluded because
    ANSSI only tolerates it when combined with a classical signature. Users who need ML-DSA-44
    can allow it via a CUSTOM policy.

### SLH-DSA (SPHINCS+) — FIPS 205

| Variant | ANSSI status | KMS support |
|---------|-------------|-------------|
| All SLH-DSA variants | ✅ Recommended | ✅ Supported (non-FIPS) |

SLH-DSA is a hash-based, stateless signature scheme. It does not require hybridisation during
the transition period.

---

## Chapter 10 — Digital signatures

| Scheme | ANSSI status | KMS support | Notes |
|--------|-------------|-------------|-------|
| ECDSA P-256/P-384/P-521 with SHA-256/384/512 | ✅ Recommended | ✅ | |
| EdDSA Ed25519 | ✅ Recommended | ✅ Non-FIPS | Deterministic; resistant to nonce misuse |
| EdDSA Ed448 | ✅ Recommended | ✅ | |
| RSA-PSS (≥ 3072 bits) | ✅ Recommended | ✅ | DEFAULT policy: PSS + 3072/4096 |
| RSA-PKCS#1 v1.5 signature (≥ 3072 bits) | ⚠️ Tolerated (compat.) | ✅ | Not in DEFAULT allowlist |
| ML-DSA-65/87 | ✅ Recommended (PQC) | ✅ Non-FIPS | |
| ML-DSA-44 | ⚠️ Hybrid only | ❌ Excluded from DEFAULT | See §9.2 |
| SLH-DSA | ✅ Recommended (PQC) | ✅ Non-FIPS | |
| DSA (finite field) | ❌ Deprecated | ❌ Hard-denied | `DSA` in hard denylist |
| ECDSA with SHA-1 | ❌ Forbidden | ❌ Hard-denied | `ECDSAWithSHA1` in hard denylist |

---

## Chapter 12 — Transport Layer Security (TLS)

> *TLS 1.3 is recommended; TLS 1.2 is tolerated with AEAD suites only.
> TLS 1.1, 1.0, and SSL are forbidden.*

| Version | ANSSI status | KMS server |
|---------|-------------|-----------|
| TLS 1.3 | ✅ Recommended | ✅ Supported |
| TLS 1.2 (AEAD suites only) | ⚠️ Tolerated | ✅ Supported |
| TLS 1.1 / 1.0 | ❌ Forbidden | ❌ Not supported (OpenSSL 3.6 disables by default) |
| SSL 3.0 / 2.0 | ❌ Forbidden | ❌ Not supported |

The KMS server uses OpenSSL 3.6.x, which sets TLS 1.2 as the minimum supported version.
Cipher suites are configurable via
[`tls_cipher_suites`](../configuration/server.md).

ANSSI-recommended TLS 1.2 AEAD suites supported by the KMS:

```text
TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
```

---

## Memory security — zeroization

> *ANSSI Rust programming guidelines require sensitive data (keys, plaintexts) to be zeroed
> after use.*

✅ Cosmian KMS implements memory zeroization for all sensitive key material and plaintext
data. See [Zeroization](zeroization.md) for full details.

---

## Consolidated compliance summary

| Category | Mechanism | ANSSI requirement | KMS (DEFAULT policy) | Status |
|----------|-----------|------------------|---------------------|--------|
| Symmetric | AES-128/192/256 | Required | ✅ | ✅ |
| Symmetric | AES-GCM IV — 96 bits | Required | 12 bytes | ✅ |
| Symmetric | AES-GCM tag — 128 bits | Recommended | 16 bytes | ✅ |
| Symmetric | ECB mode | Forbidden | Excluded from DEFAULT | ✅ |
| Symmetric | CBC without MAC | Discouraged | Excluded from DEFAULT | ✅ |
| Symmetric | DES / 3-DES / RC4 | Forbidden | Hard-denied | ✅ |
| Hash | SHA-256/384/512 | Recommended | ✅ Allowed | ✅ |
| Hash | SHA-1 / MD5 | Forbidden | Hard-denied | ✅ |
| Hash | Output ≥ 256 bits | Required | DEFAULT enforces ≥ 256 | ✅ |
| MAC | HMAC-SHA-256/384/512 | Recommended | ✅ Allowed | ✅ |
| MAC | HMAC-SHA-1 | Forbidden (new) | Hard-denied | ✅ |
| RSA | Key ≥ 3072 bits (new systems) | Required | 3072, 4096 only | ✅ |
| RSA | Key < 2048 bits | Forbidden | Hard-denied | ✅ |
| RSA | OAEP encryption | Recommended | ✅ Allowed | ✅ |
| RSA | PKCS#1 v1.5 encryption | Forbidden | Hard-denied | ✅ |
| RSA | PSS signatures | Recommended | ✅ Allowed | ✅ |
| EC | P-256, P-384, P-521 | Recommended | ✅ Allowed | ✅ |
| EC | secp192r1 and smaller | Forbidden | Hard-denied | ✅ |
| KDF | HKDF-SHA-256/512 | Recommended | ✅ | ✅ |
| KDF | PBKDF2-HMAC-SHA-512 210 000 iter | Recommended | ✅ | ✅ |
| KDF | Raw DH output as key | Forbidden | HKDF wraps DH output | ✅ |
| RNG | CSPRNG (SP 800-90A CTR-DRBG) | Required | ✅ OpenSSL FIPS DRBG | ✅ |
| PQC | ML-KEM-768/1024 | Recommended | ✅ Allowed | ✅ |
| PQC | ML-KEM-512 standalone | Forbidden | ❌ Excluded from DEFAULT | ✅ |
| PQC | ML-DSA-65/87 | Recommended | ✅ Allowed | ✅ |
| PQC | ML-DSA-44 standalone | Tolerated hybrid only | ❌ Excluded from DEFAULT | ✅ |
| PQC | SLH-DSA | Recommended | ✅ Allowed | ✅ |
| Memory | Zeroization of key material | Required | ✅ | ✅ |
| TLS | TLS 1.2 minimum (AEAD), TLS 1.3 preferred | Required | ✅ | ✅ |
| Agility | Algorithm agility | Required | KMIP + configurable policy | ✅ |

---

## Recommended configuration for strict ANSSI conformance

### Step 1 — Enable the DEFAULT KMIP policy

```toml
# kms.toml
[kmip]
policy_id = "DEFAULT"
```

This enforces the conservative allowlist that excludes ECB, CBC, SHA-1, MD5,
RSA-2048, RSA-PKCS#1v1.5 encryption, HMAC-SHA-1, ML-KEM-512, ML-DSA-44, and all other
deprecated mechanisms.

### Step 2 — Configure TLS with AEAD cipher suites

```toml
# kms.toml — prefer TLS 1.3; restrict TLS 1.2 to AEAD suites
[tls]
tls_cipher_suites = "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384"
```

### Step 3 — Optional: further restrict via CUSTOM policy

For deployments requiring explicit control over each allowed parameter:

```toml
[kmip]
policy_id = "CUSTOM"

[kmip.allowlists]
algorithms = [
  "AES", "RSA", "ECDSA", "ECDH", "EC",
  "HMACSHA256", "HMACSHA384", "HMACSHA512",
  # PQC — ANSSI-recommended levels only
  "MLKEM768", "MLKEM1024",
  "MLDSA65",  "MLDSA87",
  "SLHDSA"
]
rsa_key_sizes      = ["Rsa3072", "Rsa4096"]
aes_key_sizes      = ["Aes128", "Aes192", "Aes256"]
hashes             = ["SHA256", "SHA384", "SHA512", "SHA3256", "SHA3384", "SHA3512"]
curves             = ["P256", "P384", "P521", "CURVE25519", "CURVE448"]
block_cipher_modes = ["GCM", "CCM", "NISTKeyWrap", "AESKeyWrapPadding"]
padding_methods    = ["OAEP", "PSS"]
```

---

## References

- [ANSSI — Règles et recommendations concernant le choix et le dimensionnement de mécanismes cryptographiques v3.00](https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-mecanismes-crypto-3.00.pdf)
- [ANSSI — Guide de sélection d'algorithms cryptographiques v1.0](https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-selection_crypto-1.0.pdf)
- [NIST FIPS 197 — AES](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf)
- [NIST SP 800-38D — GCM mode of operation](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [NIST FIPS 203 — ML-KEM (Kyber)](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 — ML-DSA (Dilithium)](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205 — SLH-DSA (SPHINCS+)](https://csrc.nist.gov/pubs/fips/205/final)
- [NIST SP 800-132 — Password-Based Key Derivation](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf)
- [RFC 5869 — HMAC-based Extract-and-Expand Key Derivation Function (HKDF)](https://www.rfc-editor.org/rfc/rfc5869)
- [Cosmian KMS — KMIP algorithm policy](cryptographic_algorithms/kmip_policy.md)
- [Cosmian KMS — FIPS 140-3](fips.md)
- [Cosmian KMS — Zeroization](zeroization.md)
