# KMIP Algorithm Policy (ANSSI-first)

This document describes the sources and the (current) enforcement rules implemented by the Cosmian KMS KMIP server algorithm policy.

## Goal

- Provide an optional, configurable KMIP policy via parameter-specific **allowlists** (`[kmip.allowlists]`).
- Always **reject deprecated / broken algorithms and weak sizes by default**, even if no whitelist is configured.
- Enforce the policy at **KMIP operation entry points** (request payload validation), before performing any crypto.

## Configuration

In `kms.toml`:

```toml
[kmip]

# Gate KMIP algorithm policy enforcement.
# - false (default): allowlists are not enforced.
# - true: allowlists below (or their defaults) are enforced.
enforce = false

# Parameter-specific allowlists.
# These are matched case-insensitively against KMIP enum Display names.
#
# If you omit `[kmip.allowlists]`, Cosmian KMS uses conservative defaults.
# To relax/tighten, override individual lists.
[kmip.allowlists]
algorithms = ["AES", "RSA", "ECDSA", "ECDH", "EC", "HMACSHA256", "HMACSHA384", "HMACSHA512"]
hashes = ["SHA256", "SHA384", "SHA512"]
signature_algorithms = ["SHA256WithRSAEncryption", "SHA384WithRSAEncryption", "SHA512WithRSAEncryption", "RSASSAPSS", "ECDSAWithSHA256", "ECDSAWithSHA384", "ECDSAWithSHA512"]
curves = ["P256", "P384", "P521", "CURVE25519"]
block_cipher_modes = ["GCM", "CCM", "XTS", "NISTKeyWrap", "AESKeyWrapPadding", "GCMSIV"]
padding_methods = ["OAEP", "PSS", "PKCS5", "PKCS1v15"]
mgf_hashes = ["SHA256", "SHA384", "SHA512"]

# Allowed key sizes (in bits). When enforcement is enabled, these are matched
# against the KMIP `CryptographicLength` attribute.
rsa_key_sizes = [3072, 4096]
aes_key_sizes = [256]
```

Notes:

- The allowlists are matched case-insensitively against KMIP enum Display names.
- Prefer using the canonical KMIP tokens (e.g., `AESKeyWrapPadding`, `RSASSAPSS`).
- Some checks are *structural* (e.g., minimum RSA size), not just "name allowlist".

### Key-size allowlists

When `kmip.enforce = true`, the server can additionally enforce allowed key sizes:

- `rsa_key_sizes`: allowed RSA key sizes in bits (e.g., `[3072, 4096]`)
- `aes_key_sizes`: allowed AES key sizes in bits (e.g., `[256]`)

These lists are matched against the KMIP attribute `CryptographicLength`.

### ECIES gating (non-FIPS builds)

ECIES is a composite scheme (KEM/KDF/DEM/MAC) and is not fully representable through
standard KMIP request fields in a portable way.

In this repository, the ECIES code paths are only compiled when the server is built
with `--features non-fips`.

To avoid accidental enablement, ECIES is gated by the *general* curve allowlist:

- If `kmip.allowlists.curves` is missing or empty, ECIES is treated as disabled.
- If the key is X25519, ECIES requires `CURVE25519` to be allowed.
- If the key is an `EC` key, OpenSSL does not expose the exact NIST curve through
    `PKey::id()`, so ECIES is allowed only when curves are already constrained at
    key creation/import time.

### Summary table (sizes & standards)

This table is a quick crosswalk of key-size constraints used by common standards bodies.
It is **not** a replacement for the full documents linked below.

| Algorithm | ANSSI (deprecated / recommended) | NIST (deprecated / recommended) | FIPS (deprecated / recommended) | UK NCSC (deprecated / recommended) | Germany BSI (deprecated / recommended) | Official documentation links |
|---|---|---|---|---|---|---|
| RSA | Deprecated: <2048 bits. Recommended: >=2048 bits (3072 for higher margin). | Deprecated: <2048 bits. Recommended: >=2048 bits (3072/4096 for higher margin). | Deprecated: <2048 bits in approved-mode profiles. Recommended: >=2048 bits. | Deprecated: <2048 bits. Recommended: >=2048 bits. | Deprecated: <2048 bits. Recommended: >=2048 bits (often 3072 for long-term). | ANSSI (see sources below); NIST SP 800-131A: <https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final> ; NIST SP 800-57: <https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final> ; FIPS 186-5: <https://csrc.nist.gov/publications/detail/fips/186/5/final> |
| ECDSA (P-256/P-384/P-521) | Deprecated: P-192/P-224. Recommended: P-256/P-384/P-521. | Deprecated: P-192/P-224. Recommended: P-256/P-384/P-521. | Deprecated: P-192/P-224 in approved-mode profiles. Recommended: P-256/P-384/P-521. | Deprecated: P-192/P-224. Recommended: P-256/P-384 (P-521 less common operationally). | Deprecated: P-192/P-224. Recommended: P-256/P-384/P-521. | NIST SP 800-131A: <https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final> ; FIPS 186-5: <https://csrc.nist.gov/publications/detail/fips/186/5/final> ; ANSSI mechanisms guide: <https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-mecanismes_crypto-2.04.pdf> |
| ECDH (P-256/P-384/P-521) | Deprecated: P-192/P-224. Recommended: P-256/P-384/P-521. | Deprecated: P-192/P-224. Recommended: P-256/P-384/P-521. | Deprecated: P-192/P-224 in approved-mode profiles. Recommended: P-256/P-384/P-521. | Deprecated: P-192/P-224. Recommended: P-256/P-384. | Deprecated: P-192/P-224. Recommended: P-256/P-384/P-521. | NIST SP 800-56A: <https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final> ; NIST SP 800-131A: <https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final> ; ANSSI mechanisms guide: <https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-mecanismes_crypto-2.04.pdf> |
| X25519 | Key size: N/A (fixed curve). Guidance varies by profile. | Key size: N/A (fixed curve). Not a NIST prime curve; check system policy. | Key size: N/A. Not generally part of classic FIPS-approved curve sets; check module scope. | Key size: N/A. Commonly recommended for modern protocols where permitted. | Key size: N/A. Depends on TR/profile; check latest BSI guidance. | RFC 7748: <https://www.rfc-editor.org/rfc/rfc7748> ; UK NCSC cryptography collection: <https://www.ncsc.gov.uk/collection/cryptography> |
| Ed25519 | Key size: N/A (fixed curve). Guidance varies by profile. | Key size: N/A (fixed curve). Not a NIST prime curve; check system policy. | Key size: N/A. Not generally part of classic FIPS-approved curve sets; check module scope. | Key size: N/A. Often recommended for modern protocols where permitted. | Key size: N/A. Depends on TR/profile; check latest BSI guidance. | RFC 8032: <https://www.rfc-editor.org/rfc/rfc8032> ; UK NCSC cryptography collection: <https://www.ncsc.gov.uk/collection/cryptography> |
| Ed448 | Key size: N/A (fixed curve). Guidance varies by profile. | Key size: N/A (fixed curve). Not a NIST prime curve; check system policy. | Key size: N/A. Not generally part of classic FIPS-approved curve sets; check module scope. | Key size: N/A. Often recommended for modern protocols where permitted. | Key size: N/A. Depends on TR/profile; check latest BSI guidance. | RFC 8032: <https://www.rfc-editor.org/rfc/rfc8032> ; UK NCSC cryptography collection: <https://www.ncsc.gov.uk/collection/cryptography> |
| AES | Deprecated: other sizes. Recommended: 128/192/256-bit keys only. | Deprecated: other sizes. Recommended: 128/192/256-bit keys only. | Deprecated: other sizes. Recommended: 128/192/256-bit keys only. | Deprecated: other sizes. Recommended: 128/256-bit keys (192 acceptable depending on profile). | Deprecated: other sizes. Recommended: 128/192/256-bit keys only. | FIPS 197: <https://csrc.nist.gov/publications/detail/fips/197/final> ; NIST SP 800-57: <https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final> |
| HMAC-SHA2 (HMAC-SHA256/384/512) | Key size: N/A (depends on keying; choose >= hash output for many uses). Deprecated: HMAC-MD5/HMAC-SHA1. | Key size: N/A. Deprecated: HMAC-SHA1 for many uses. Recommended: HMAC-SHA256/384/512. | Key size: N/A. Recommended: HMAC with approved hashes (SHA-2/SHA-3). | Key size: N/A. Deprecated: MD5/SHA-1 based. Recommended: HMAC-SHA256/384/512. | Key size: N/A. Deprecated: MD5/SHA-1 based. Recommended: HMAC-SHA256/384/512. | FIPS 198-1: <https://csrc.nist.gov/publications/detail/fips/198/1/final> ; FIPS 180-4: <https://csrc.nist.gov/publications/detail/fips/180/4/final> |
| SHA-2 (SHA-256/384/512) | Key size: N/A. Deprecated: SHA-1 and older. | Key size: N/A. Deprecated: SHA-1 and older. | Key size: N/A. Deprecated: SHA-1 and older. | Key size: N/A. Deprecated: SHA-1. | Key size: N/A. Deprecated: SHA-1. | FIPS 180-4: <https://csrc.nist.gov/publications/detail/fips/180/4/final> |
| SHA-3 (SHA3-256/384/512) | Key size: N/A. Recommended where allowed by profile. | Key size: N/A. Recommended where allowed by profile. | Key size: N/A. Recommended where allowed by profile. | Key size: N/A. Recommended where allowed by profile. | Key size: N/A. Recommended where allowed by profile. | FIPS 202: <https://csrc.nist.gov/publications/detail/fips/202/final> |
| ChaCha20-Poly1305 | Key size: 256-bit (fixed). Guidance varies by profile. | Key size: 256-bit (fixed). Not part of classic NIST/FIPS primitive set; widely deployed in IETF protocols. | Key size: 256-bit (fixed). Often not in approved-mode profiles; depends on module scope. | Key size: 256-bit (fixed). Recommended in modern protocols where available. | Key size: 256-bit (fixed). Depends on TR/profile; check latest BSI guidance. | RFC 8439: <https://www.rfc-editor.org/rfc/rfc8439> ; UK NCSC cryptography collection: <https://www.ncsc.gov.uk/collection/cryptography> |

## Sources (links)

### ANSSI (primary)

- ANSSI – *Guide de sélection d'algorithms cryptographiques* (v1.0)
    - <https://www.ssi.gouv.fr/> (search: "guide selection algorithms cryptographiques")
    - Provided copy: <https://www.arcsi.fr/doc/anssi-guide-selection_crypto-1.0.pdf>

- ANSSI – *Guide des mécanismes cryptographiques* (v2.04)
    - <https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-mecanismes_crypto-2.04.pdf>

- Key length overview (secondary reference)
    - <https://www.keylength.com/fr/5/>

### NIST (secondary)

- NIST SP 800-57 Part 1 Rev. 5 – *Key Management* (security strength / key sizes)
    - <https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final>

- NIST SP 800-56A Rev. 3 – *Pair-Wise Key Establishment Using Discrete Logarithm Cryptography*
    - <https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final>

- NIST SP 800-131A Rev. 2 – *Transitioning the Use of Cryptographic Algorithms and Key Lengths*
    - <https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final>

### UK / Germany (tertiary)

- UK NCSC guidance (algorithm and TLS recommendations)
    - <https://www.ncsc.gov.uk/collection/cryptography>

- Germany BSI recommendations / TRs (cryptography guidance)
    - <https://www.bsi.bund.de/EN/Topics/Cryptography/cryptography_node.html>

### FIPS (used to fill gaps when guidance is not specific)

When the above documents are not explicit enough for a precise allow/deny rule, we fall back to constraints implied by FIPS validations/approved-mode restrictions.

- NIST CMVP / FIPS 140-3 program and references:
    - <https://csrc.nist.gov/projects/cryptographic-module-validation-program>

- FIPS 140-3 – Security Requirements for Cryptographic Modules:
    - <https://csrc.nist.gov/publications/detail/fips/140/3/final>

- FIPS 197 – Advanced Encryption Standard (AES):
    - <https://csrc.nist.gov/publications/detail/fips/197/final>

- FIPS 180-4 – Secure Hash Standard (SHA):
    - <https://csrc.nist.gov/publications/detail/fips/180/4/final>

- FIPS 202 – SHA-3 Standard:
    - <https://csrc.nist.gov/publications/detail/fips/202/final>

- FIPS 186-5 – Digital Signature Standard (DSS) (RSA/ECDSA requirements):
    - <https://csrc.nist.gov/publications/detail/fips/186/5/final>

- FIPS 198-1 – The Keyed-Hash Message Authentication Code (HMAC):
    - <https://csrc.nist.gov/publications/detail/fips/198/1/final>

- Key-length transition guidance (used to set conservative minimums):
    - NIST SP 800-131A Rev. 2: <https://csrc.nist.gov/publications/detail/sp/800-131a/rev-2/final>
    - NIST SP 800-56A Rev. 3: <https://csrc.nist.gov/publications/detail/sp/800-56a/rev-3/final>
    - NIST SP 800-56B Rev. 2: <https://csrc.nist.gov/publications/detail/sp/800-56b/rev-2/final>

## Implemented rules (current)

Implemented in: `crate/server/src/core/operations/algorithm_policy.rs`.

### Default-deny (deprecated/broken or out-of-scope)

Rejected by default:

- Symmetric: `DES`, `THREE_DES`, `RC2`, `RC4`, `RC5`, `IDEA`, `CAST5`, `Blowfish`, `SKIPJACK`, `MARS`, `OneTimePad`
- MAC: `HMACMD5`
- Asymmetric: `DSA`, `ECMQV`

Additionally rejected as "out-of-scope" for this feature's v1:

- Anything not in { AES, RSA, ECDSA/ECDH/EC, SHA-2/SHA-3, HMAC-SHA2/HMAC-SHA3, ChaCha20-Poly1305 }

### Hashes

Rejected by default:

- `MD2`, `MD4`, `MD5`, `SHA1`

FIPS-aligned tightening:

- `SHA224` is also rejected (the enforced profile is SHA-256/384/512 and SHA-3 only).

### Key size constraints

- RSA: allowed sizes (default allowlist): **3072** and **4096** bits.
- AES: allowed sizes (default allowlist): **256** bits only.

### Curves

Conservative allow-list:

- Allowed: `P256`, `P384`, `P521`, `CURVE25519`
- Rejected: `P192`, `P224` and legacy ANSI X9.62 curves `ANSIX9P192V2/V3`, `ANSIX9P239V1/V2/V3`

## ECIES combinations / special cases

KMIP itself doesn't expose all ECIES component choices as first-class, standardized request fields.
In this repo, ECIES appears as a server-side implementation used from `Encrypt` (`crate/server/src/core/operations/encrypt.rs`).

This means:

- The policy blocks weak/unsupported algorithms via KMIP `CryptographicAlgorithm` / `HashingAlgorithm` / `DigitalSignatureAlgorithm` / curve checks.
- In `--features non-fips` builds, ECIES usage is gated as described in "ECIES gating (non-FIPS builds)" above.

If you need strict "ECIES must use *these specific* KDF/DEM/MAC combos", we can extend the validator once the chosen components are surfaced in the KMIP request (or via explicit vendor attributes).

User-stated combinations to watch out for (to be mapped to concrete names/encodings next):

- "salsa20 + x25519"
- letsi
- ANSI X9.63
