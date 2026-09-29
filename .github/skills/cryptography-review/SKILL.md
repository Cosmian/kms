---
name: cryptography-review
description: 'Comprehensive cryptographic audit: FIPS 140-3, BSI TR-02102, ANSSI, NIST SP 800-series compliance, algorithm allow-list, key sizes, feature-flag gating, OpenSSL provider init, key lifecycle, multi-standard matrix, and academic cryptanalysis cross-check. Use when touching crate/crypto/, algorithm selection, or key management code.'
---

# Cryptographic Review

Comprehensive cryptographic audit covering FIPS 140-3 compliance, European standards
(BSI, ANSSI), NIST Special Publications, key management lifecycle, and academic
cryptanalysis research. Supersedes the former `/fips-audit` skill with broader multi-standard coverage.

## When to Use

- Before merging any change to `crate/crypto/src/` or `crate/server/src/core/operations/`
- When adding a new algorithm or key type
- When modifying `#[cfg(feature = "non-fips")]` boundaries
- When changing `crate/server/src/openssl_providers.rs`
- When modifying key lifecycle state transitions or key management policies
- When evaluating algorithm choices against international compliance requirements

## Step 0 — Load Anti-Hallucination Discipline

Read `.github/skills/shared/anti-hallucination.md` **before any analysis**. All rules in
that file are mandatory for this skill. Do not proceed to Step 1 until you have read it.

## Scope Resolution

If a path was provided, scan only that scope. Otherwise scan:

1. `crate/crypto/src/` — cryptographic primitives
2. `crate/server/src/core/operations/` — per-operation crypto usage
3. `crate/server/src/openssl_providers.rs` — provider init
4. `crate/kmip/src/` — algorithm identifier types
5. `crate/clients/clap/src/` — CLI algorithm selection
6. `crate/clients/wasm/src/` — WASM crypto calls

---

## Step 1 — Algorithm Inventory

Identify every cryptographic algorithm used in the scanned code. For each:

- Algorithm name and key size
- Where it is used (encrypt, sign, derive, hash, MAC, key-wrap, key-encapsulate)
- Whether it is gated with `#[cfg(feature = "non-fips")]`

## Step 2 — Multi-Standard Algorithm Checklist

### FIPS 140-3 / NIST Approved (allowed without non-fips gate)

| Category | Approved algorithms | Governing standard |
|----------|--------------------|--------------------|
| Symmetric encryption | AES-128, AES-192, AES-256 (GCM, CCM, CBC, CTR, KW, KWP, XTS*) | FIPS 197, SP 800-38A/D/F |
| Asymmetric encryption | RSA-2048+, EC P-256, P-384, P-521 | FIPS 186-5, SP 800-56A r3 |
| Digital signatures | ECDSA (P-256/384/521), RSA-PSS, RSA-PKCS1v15, ML-DSA (FIPS 204), SLH-DSA (FIPS 205) | FIPS 186-5, FIPS 204, FIPS 205 |
| Key encapsulation | ML-KEM (FIPS 203) | FIPS 203 |
| Hash functions | SHA-256, SHA-384, SHA-512, SHA-3 variants | FIPS 180-4, FIPS 202 |
| MAC | HMAC-SHA-256/384/512, AES-GMAC, CMAC | FIPS 198-1, SP 800-38B |
| KDF | HKDF, PBKDF2, SP 800-108 (Counter, Feedback, Pipeline) | SP 800-56C r2, SP 800-132, SP 800-108 r1 |
| Key establishment | ECDH (SP 800-56A r3), RSA-KEM (SP 800-56B r2) | SP 800-56A r3, SP 800-56B r2 |
| RNG | CTR_DRBG, HASH_DRBG (via OpenSSL FIPS provider) | SP 800-90A r1 |

*AES-XTS is non-FIPS in this codebase (`non-fips` feature).

### BSI TR-02102-1 (2024) — Algorithm Recommendations

Cross-check each algorithm found in Step 1 against BSI recommendations:

| Category | BSI-recommended | BSI notes |
|----------|----------------|-----------|
| Symmetric | AES-128+ (GCM, CCM, CBC with HMAC), no ECB | 3DES deprecated since 2023 |
| Hash | SHA-256+, SHA-3-256+ | SHA-1 forbidden for signatures, allowed for HMAC only until 2025 |
| MAC | HMAC-SHA-256+, CMAC-AES | HMAC-SHA-1 deprecated |
| RSA | ≥ 3000 bits (BSI recommends 3072+) | 2048 acceptable until 2025 only |
| EC | P-256, P-384, P-521, Brainpool | Curve25519 acceptable for key agreement |
| PQC | ML-KEM, ML-DSA, SLH-DSA | Recommended for hybrid schemes |

> **Reference**: BSI TR-02102-1 (2024) — <https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.pdf>

### ANSSI — Recommendations mécanismes cryptographiques (2021)

Cross-check each algorithm against ANSSI requirements:

| Category | ANSSI-recommended | ANSSI notes |
|----------|------------------|-------------|
| Symmetric | AES-128+ | 3DES forbidden |
| Hash | SHA-256+, SHA-3-256+ | SHA-1 forbidden for all security purposes |
| RSA | ≥ 2048 bits (recommended 3072+ beyond 2030) | Key sizes below 2048 forbidden |
| EC | P-256, P-384, P-521 | FRP256v1 (French curve) also accepted |
| KDF | HKDF, PBKDF2 (≥ 100,000 iterations) | SP 800-108 acceptable |

> **Reference**: ANSSI guide (2021) — <https://cyber.gouv.fr/publications/mecanismes-cryptographiques>

### NOT Approved (must be gated with `#[cfg(feature = "non-fips")]`)

- MD5, SHA1 for any security purpose
- DES, 3DES, RC4, Blowfish, ChaCha20
- AES-XTS (not in FIPS 140-3 approved mode list for this provider)
- Covercrypt, Redis-findex (non-standard, non-FIPS)
- PQC algorithms beyond ML-KEM/ML-DSA/SLH-DSA (pre-standardization)
- EC curves outside P-256/P-384/P-521 (e.g. Curve25519, secp256k1)

## Step 3 — Feature Flag Gating Audit

For every non-approved algorithm found:

- [ ] Is it gated at the **function or module level** with `#[cfg(feature = "non-fips")]`? (correct)
- [ ] Is the gate **inline inside a function body**? (wrong — must be at function level)
- [ ] Is the corresponding route registration in `start_kms_server.rs` wrapped in `#[cfg(feature = "non-fips")] { ... }`?
- [ ] Is the dispatch arm in `dispatch.rs` gated if the operation is non-FIPS-only?
- [ ] Are CLI actions gated in `crate/clients/clap/src/`?
- [ ] Are WASM bindings gated in `crate/clients/wasm/src/wasm.rs`?

Flag any gate that is placed **inside a function body** rather than on the function itself:

```rust
// WRONG — gate is inline inside function body
fn do_crypto() {
    #[cfg(feature = "non-fips")]
    let _ = md5::compute(data);  // ← wrong position
}

// CORRECT — gate is at function level
#[cfg(feature = "non-fips")]
fn do_crypto_non_fips() {
    let _ = md5::compute(data);
}
```

## Step 4 — Key Size Enforcement

Check all key generation and import operations in `crate/server/src/core/operations/`:

| Algorithm | Minimum key size (FIPS) | BSI minimum | ANSSI minimum | Check location |
|-----------|------------------------|-------------|---------------|----------------|
| RSA | 2048 bits | 3072 bits (2024) | 2048 bits | `create.rs`, `import.rs` |
| AES | 128 bits | 128 bits | 128 bits | `create.rs` |
| EC | P-256 (256 bits) | P-256 (256 bits) | P-256 (256 bits) | `create.rs` |
| HMAC keys | 112 bits (SP 800-131A) | 128 bits | 128 bits | `create.rs` |

Flag any operation that accepts key sizes below these minimums without rejecting them.

> For BSI compliance, emit a **warning** (not a blocking finding) for RSA-2048 keys — BSI
> recommends 3072+ since 2024 but does not yet forbid 2048.

## Step 5 — OpenSSL Provider Init

Review `crate/server/src/openssl_providers.rs`:

- [ ] Is `apply_openssl_dir_env_if_needed()` called **before** any `Provider::try_load()` call?
- [ ] Is the FIPS provider loaded via `OnceLock` (single initialization)?
- [ ] Is the legacy provider loaded only when `non-fips` feature is active?
- [ ] Are `OPENSSL_MODULES` and `OPENSSL_CONF` env vars set before provider init?
- [ ] Is there a fallback or error if the FIPS provider fails to load in FIPS mode?

## Step 6 — Entropy / RNG

- [ ] Is `rand::rngs::OsRng` (or OpenSSL's CSPRNG) used for all key generation? Flag any use of `rand::thread_rng()` or `rand::random()` for security-sensitive operations.
- [ ] Are IVs / nonces generated from the CSPRNG, not hardcoded or derived from deterministic sources?
- [ ] Are salts for KDFs randomly generated per operation?

## Step 7 — CBOM / SBOM Currency

If `crate/crypto/build.rs` was changed (OpenSSL version update):

- [ ] `cbom/cbom.cdx.json` updated with new algorithm identifiers?
- [ ] `sbom/` SBOM updated?

## Step 8 — Key Management Lifecycle (SP 800-57)

Review key lifecycle state management against NIST SP 800-57 Part 1, Rev. 5:

- **State machine completeness**: verify the key lifecycle covers all states:
  Pre-Activation → Active → Deactivated → Compromised → Destroyed / Destroyed-Compromised
- **State transitions**: verify `can_transition_to()` (or equivalent) is used to enforce valid transitions — no direct state mutation bypassing the state machine
- **Cryptoperiod enforcement**: check that keys have configurable cryptoperiods and that expired keys are automatically deactivated (or at minimum, flagged)
- **No indefinitely-valid keys**: keys without an explicit `Deactivation Date` or cryptoperiod policy should be flagged as a finding
- **Destruction completeness**: verify `Destroy` operation performs cryptographic erasure (zeroization) and not just metadata deletion

> **Reference**: NIST SP 800-57 Part 1, Rev. 5 — Key Management Recommendation

## Step 9 — Multi-Standard Compliance Matrix

For each algorithm found in the inventory (Step 1), produce this table:

```markdown
| Algorithm | FIPS 140-3 | BSI TR-02102-1 (2024) | ANSSI (2021) | SP 800-131A r2 | Notes |
|-----------|-----------|----------------------|--------------|----------------|-------|
| AES-256-GCM | ✅ Approved | ✅ Recommended | ✅ Approved | ✅ Current | — |
| RSA-2048 | ✅ Approved | ⚠️ Deprecated (2024) | ✅ Approved (until 2030) | ⚠️ Legacy use | BSI recommends 3072+ |
| ... | ... | ... | ... | ... | ... |
```

Flag any algorithm that is:

- Approved by FIPS but **deprecated** by BSI or ANSSI
- Used in a non-approved mode (e.g., AES-ECB, RSA without padding)
- Missing from one standard's coverage entirely (note as "Not covered")

## Step 10 — Academic Research Flags

Cross-reference the algorithms found in the codebase against known cryptanalytic results.

**Methodology**: search `documentation/pandoc/cryptobib/crypto.bib` for bib entries related
to each algorithm. Only cite bib keys that are **actually found** via grep — never invent references.

Known attack patterns to check for in the code:

| Attack | Applies when | What to check |
|--------|-------------|---------------|
| PKCS#1 v1.5 padding oracle (Bleichenbacher) | RSA PKCS#1 v1.5 decryption | Error messages must not distinguish padding from decryption failures |
| Marvin Attack | RSA PKCS#1 v1.5 (timing) | Constant-time RSA decryption; see `RUSTSEC-2023-0071` in `SECURITY.md` |
| CBC padding oracle (Lucky13) | AES-CBC decryption | MAC-then-decrypt must be constant-time; error must not distinguish padding |
| GCM nonce reuse | AES-GCM encryption | Nonce must be unique per key; check for counter management or random nonce |
| Sweet32 | 3DES / Blowfish (64-bit block) | Should already be non-FIPS gated; verify gate exists |
| ROBOT | RSA key exchange (TLS) | Not directly applicable if TLS is handled by Actix/rustls, but check cloud routes |

For each flag raised: cite the specific source (bib key from `crypto.bib` if found, or
`SECURITY.md` entry, or RustSec advisory ID). Never cite a paper that was not found in the
bibliography or fetched via URL in this session.

## Report Format

```markdown
## Cryptographic Review: [scope]

### Summary
| Check | Status |
|-------|--------|
| Algorithm inventory | ✅ / ⚠️ N issues |
| Multi-standard checklist | ✅ / ⚠️ N issues |
| Feature flag gating | ✅ / ⚠️ N issues |
| Key size enforcement | ✅ / ⚠️ N issues |
| OpenSSL provider init | ✅ / ⚠️ N issues |
| Entropy / RNG | ✅ / ⚠️ N issues |
| CBOM / SBOM currency | ✅ / ⚠️ N issues / ⏭ N/A |
| Key management lifecycle | ✅ / ⚠️ N issues |
| Multi-standard matrix | ✅ / ⚠️ N divergences |
| Academic research flags | ✅ / ⚠️ N flags |

### Multi-Standard Compliance Matrix
[Table from Step 9]

### Findings
[Severity + description + file + line + fix for each issue]

### Unverified Items
[Items marked REQUIRES MANUAL VERIFICATION per anti-hallucination rules]
```

**Never auto-apply fixes — present for review.**
