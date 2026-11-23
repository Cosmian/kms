# Algorithm Compliance Checklist

Per-algorithm cross-standard compliance matrix for algorithms used in the Eviden KMS.
This table is a reference for the `/standards-review` and `/cryptography-review` skills.

> **Maintenance**: update this table when a standard is revised or a new algorithm is added to the KMS.
> Status values: ✅ Approved | ⚠️ Deprecated | ❌ Forbidden | — Not covered | 🆕 Pending

---

## Symmetric Encryption

| Algorithm | FIPS 140-3 | BSI TR-02102-1 (2024) | ANSSI (2021) | SP 800-131A r2 (2019) | Governing RFC/SP |
|-----------|-----------|----------------------|--------------|----------------------|------------------|
| AES-128-GCM | ✅ | ✅ | ✅ | ✅ | SP 800-38D |
| AES-256-GCM | ✅ | ✅ | ✅ | ✅ | SP 800-38D |
| AES-128-CBC | ✅ | ✅ (with HMAC) | ✅ | ✅ | SP 800-38A |
| AES-256-CBC | ✅ | ✅ (with HMAC) | ✅ | ✅ | SP 800-38A |
| AES-128-CTR | ✅ | ✅ | ✅ | ✅ | SP 800-38A |
| AES-256-CTR | ✅ | ✅ | ✅ | ✅ | SP 800-38A |
| AES-KW (128/256) | ✅ | ✅ | ✅ | ✅ | SP 800-38F, RFC 3394 |
| AES-KWP (128/256) | ✅ | ✅ | ✅ | ✅ | SP 800-38F, RFC 5649 |
| AES-XTS | ✅ (FIPS) | ✅ | ✅ | ✅ | SP 800-38E (non-fips in KMS) |
| AES-ECB | ✅ (FIPS) | ❌ | ❌ | ⚠️ | SP 800-38A (not recommended) |
| ChaCha20-Poly1305 | ❌ | ✅ | ✅ | — | RFC 8439 (non-fips in KMS) |
| 3DES | ⚠️ Deprecated | ❌ | ❌ | ⚠️ Disallowed after 2023 | SP 800-67 r2 |

## Asymmetric Encryption / Key Establishment

| Algorithm | FIPS 140-3 | BSI TR-02102-1 (2024) | ANSSI (2021) | SP 800-131A r2 | Governing RFC/SP |
|-----------|-----------|----------------------|--------------|----------------|------------------|
| RSA-2048 (OAEP) | ✅ | ⚠️ Acceptable until 2028 | ✅ (until 2030) | ✅ | RFC 8017, SP 800-56B r2 |
| RSA-3072 (OAEP) | ✅ | ✅ | ✅ | ✅ | RFC 8017, SP 800-56B r2 |
| RSA-4096 (OAEP) | ✅ | ✅ | ✅ | ✅ | RFC 8017, SP 800-56B r2 |
| ECDH P-256 | ✅ | ✅ | ✅ | ✅ | SP 800-56A r3, RFC 5480 |
| ECDH P-384 | ✅ | ✅ | ✅ | ✅ | SP 800-56A r3 |
| ECDH P-521 | ✅ | ✅ | ✅ | ✅ | SP 800-56A r3 |
| X25519 | ❌ | ✅ | ✅ | — | RFC 7748 (non-fips in KMS) |
| ML-KEM-512 | ✅ | ✅ (hybrid) | 🆕 | 🆕 | FIPS 203 |
| ML-KEM-768 | ✅ | ✅ (hybrid) | 🆕 | 🆕 | FIPS 203 |
| ML-KEM-1024 | ✅ | ✅ (hybrid) | 🆕 | 🆕 | FIPS 203 |

## Digital Signatures

| Algorithm | FIPS 140-3 | BSI TR-02102-1 (2024) | ANSSI (2021) | SP 800-131A r2 | Governing RFC/SP |
|-----------|-----------|----------------------|--------------|----------------|------------------|
| RSA-PSS 2048 | ✅ | ⚠️ Acceptable until 2028 | ✅ (until 2030) | ✅ | RFC 8017, FIPS 186-5 |
| RSA-PSS 3072+ | ✅ | ✅ | ✅ | ✅ | RFC 8017, FIPS 186-5 |
| RSA-PKCS1v15 2048+ | ✅ | ⚠️ PSS preferred | ✅ | ✅ | RFC 8017, FIPS 186-5 |
| ECDSA P-256 | ✅ | ✅ | ✅ | ✅ | FIPS 186-5, RFC 6979 |
| ECDSA P-384 | ✅ | ✅ | ✅ | ✅ | FIPS 186-5 |
| ECDSA P-521 | ✅ | ✅ | ✅ | ✅ | FIPS 186-5 |
| Ed25519 | ✅ (signing) | ✅ | ✅ | — | RFC 8032 |
| Ed448 | ✅ (signing) | ✅ | ✅ | — | RFC 8032 |
| ML-DSA-44 | ✅ | ✅ (hybrid) | 🆕 | 🆕 | FIPS 204 |
| ML-DSA-65 | ✅ | ✅ (hybrid) | 🆕 | 🆕 | FIPS 204 |
| ML-DSA-87 | ✅ | ✅ (hybrid) | 🆕 | 🆕 | FIPS 204 |
| SLH-DSA (all 12) | ✅ | ✅ (hybrid) | 🆕 | 🆕 | FIPS 205 |

## Hash Functions

| Algorithm | FIPS 140-3 | BSI TR-02102-1 (2024) | ANSSI (2021) | SP 800-131A r2 | Governing standard |
|-----------|-----------|----------------------|--------------|----------------|-------------------|
| SHA-256 | ✅ | ✅ | ✅ | ✅ | FIPS 180-4 |
| SHA-384 | ✅ | ✅ | ✅ | ✅ | FIPS 180-4 |
| SHA-512 | ✅ | ✅ | ✅ | ✅ | FIPS 180-4 |
| SHA-3-256 | ✅ | ✅ | ✅ | ✅ | FIPS 202 |
| SHA-3-384 | ✅ | ✅ | ✅ | ✅ | FIPS 202 |
| SHA-3-512 | ✅ | ✅ | ✅ | ✅ | FIPS 202 |
| SHA-1 | ⚠️ Legacy | ❌ Signatures | ❌ | ⚠️ Disallowed for signatures | FIPS 180-4 |
| MD5 | ❌ | ❌ | ❌ | ❌ | RFC 1321 (broken) |

## MAC (Message Authentication Code)

| Algorithm | FIPS 140-3 | BSI TR-02102-1 (2024) | ANSSI (2021) | SP 800-131A r2 | Governing standard |
|-----------|-----------|----------------------|--------------|----------------|-------------------|
| HMAC-SHA-256 | ✅ | ✅ | ✅ | ✅ | FIPS 198-1, RFC 2104 |
| HMAC-SHA-384 | ✅ | ✅ | ✅ | ✅ | FIPS 198-1 |
| HMAC-SHA-512 | ✅ | ✅ | ✅ | ✅ | FIPS 198-1 |
| AES-GMAC | ✅ | ✅ | ✅ | ✅ | SP 800-38D |
| AES-CMAC | ✅ | ✅ | ✅ | ✅ | SP 800-38B |
| HMAC-SHA-1 | ⚠️ Legacy | ⚠️ Deprecated | ❌ | ⚠️ | FIPS 198-1 |

## Key Derivation Functions

| Algorithm | FIPS 140-3 | BSI TR-02102-1 (2024) | ANSSI (2021) | SP 800-131A r2 | Governing standard |
|-----------|-----------|----------------------|--------------|----------------|-------------------|
| HKDF (SHA-256+) | ✅ | ✅ | ✅ | ✅ | RFC 5869, SP 800-56C r2 |
| PBKDF2 (SHA-256+) | ✅ | ✅ (≥ 10,000 iter) | ✅ (≥ 100,000 iter) | ✅ | SP 800-132, RFC 8018 |
| SP 800-108 KBKDF | ✅ | ✅ | ✅ | ✅ | SP 800-108 r1 |

## Non-Standard / Proprietary (require `non-fips` feature flag)

| Algorithm | FIPS 140-3 | BSI | ANSSI | Notes |
|-----------|-----------|-----|-------|-------|
| Covercrypt | ❌ | — | — | Cosmian proprietary ABE scheme |
| Redis-findex | ❌ | — | — | Cosmian searchable encryption |

---

## Key Size Minimums (cross-standard)

| Algorithm | FIPS minimum | BSI minimum (2024) | ANSSI minimum (2021) | SP 800-131A r2 |
|-----------|-------------|-------------------|---------------------|----------------|
| RSA | 2048 bits | 3072 bits | 2048 bits | 2048 bits |
| EC | P-256 (256 bits) | P-256 (256 bits) | P-256 (256 bits) | P-256 |
| AES | 128 bits | 128 bits | 128 bits | 128 bits |
| HMAC key | 112 bits | 128 bits | 128 bits | 112 bits |
| PBKDF2 iterations | 210,000 (OWASP) | 10,000 | 100,000 | — |
| PBKDF2 salt | 128 bits (SP 800-132) | 128 bits | 128 bits | — |
