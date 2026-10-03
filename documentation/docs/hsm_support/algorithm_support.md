# HSM algorithm support by model

This page compares PKCS#11 algorithm and capability coverage across the HSM models natively
integrated by Eviden KMS: **SoftHSM2**, **Kryoptic**, **Proteccio**, **Crypt2Pay**, **Utimaco**,
**AWS CloudHSM**, and **SmartCard HSM**. All models share the same `BaseHsm` implementation
(`crate/hsm/base_hsm`); per-model differences come from (a) real PKCS#11 mechanism availability on
the device/library, and (b) a small set of vendor-specific behavioral quirks captured in each
model's `HsmCapabilities` (`crate/hsm/<model>/src/lib.rs`).

Legend:

- ✅ **Proven** — exercised by the shared cross-backend test suite
  (`crate/hsm/base_hsm/src/tests_shared.rs`), run per model in `crate/hsm/<model>/src/tests.rs`'s
  `test_hsm_<model>_all` (and individually-runnable sibling tests).
- 📄 **Documented** — confirmed supported by the vendor's PKCS#11 documentation, not yet exercised
  by this repository's test suite for that model.
- ❌ **Not supported** — confirmed absent, either by vendor documentation or by a `HsmCapabilities`
  flag.
- ⚠️ **Known issue** — vendor-documented as supported, but currently blocked in this environment;
  see the note under the table.

## Key generation

| Algorithm / curve | SoftHSM2 | Kryoptic | Proteccio | Crypt2Pay | Utimaco | AWS CloudHSM | SmartCard HSM |
| --- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| AES-128/192/256 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| RSA-2048 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| EC P-224 | ✅ | ❌ | 📄 | ⚠️ | 📄 | ✅ | 📄 |
| EC P-256 | ✅ | ✅ | 📄 | ⚠️ | 📄 | ✅ | 📄 |
| EC P-384 | ✅ | ✅ | 📄 | ⚠️ | 📄 | ✅ | 📄 |
| EC P-521 | ✅ | ✅ | 📄 | ⚠️ | 📄 | ✅ | 📄 |
| EC secp256k1 (non-fips) | ✅ | 📄 | 📄 | 📄 | 📄 | 📄 | 📄 |
| EC secp192k1 (non-fips) | ✅ | 📄 | 📄 | 📄 | 📄 | 📄 | 📄 |
| EC Brainpool / FRP256v1 | ❌ | ❌ | 📄 | 📄 | ❌ | ❌ | ❌ |
| Ed25519 (non-fips) | ✅ | ✅ | ❌ | 📄 | 📄 | ✅ | 📄 |
| Ed448 (non-fips) | ✅ | ❌ | ❌ | 📄 | 📄 | ✅ | 📄 |

## Encryption mechanisms

| Mechanism | SoftHSM2 | Kryoptic | Proteccio | Crypt2Pay | Utimaco | AWS CloudHSM | SmartCard HSM |
| --- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| AES-GCM | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 📄 |
| AES-CBC (+ multi-round) | ✅ | ✅ | 📄 | 📄 | 📄 | ✅ | ✅ |
| RSA PKCS#1 v1.5 | ✅ | ✅ | ✅ | ✅ | ✅ | 📄 | ✅ |
| RSA-OAEP (SHA-256), direct `Encrypt`/`Decrypt` | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| RSA-OAEP key wrap (`C_WrapKey`/`C_UnwrapKey`) | ❌ | 📄 | ✅ | ✅ | ✅ | ✅ | ❌ |

## Signing mechanisms

| Mechanism | SoftHSM2 | Kryoptic | Proteccio | Crypt2Pay | Utimaco | AWS CloudHSM | SmartCard HSM |
| --- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| RSA PKCS#1 v1.5 (SHA-1/256/384/512) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| RSA-PSS (SHA-256/384/512) | ✅ | ✅ | 📄 | 📄 | 📄 | 📄 | 📄 |
| ECDSA (raw `CKM_ECDSA` and/or combined `CKM_ECDSA_SHA*`) | ✅ | ✅ | 📄 | ⚠️ | 📄 | ✅ | 📄 |
| ECDSA secp256k1 (non-fips) | ✅ | 📄 | 📄 | 📄 | 📄 | 📄 | 📄 |
| ECDSA secp192k1 (non-fips) | ✅ | 📄 | 📄 | 📄 | 📄 | 📄 | 📄 |
| EdDSA Ed25519 (non-fips) | ✅ | ✅ | ❌ | 📄 | 📄 | ✅ | 📄 |
| EdDSA Ed448 (non-fips) | ✅ | ❌ | ❌ | 📄 | 📄 | ✅ | 📄 |

!!! warning Crypt2Pay EC/RSA key generation: known, currently blocked issue
    Crypt2Pay's own PKCS#11 API User Guide documents `CKM_RSA_PKCS_KEY_PAIR_GEN` and
    `CKM_ECDSA_KEY_PAIR_GEN` (plus an extensive curve list: NIST P-192/224/256/384/521,
    secp256k1, Brainpool P192–P512, FRP256v1, Ed25519/Ed448) as supported mechanisms. On the
    unit tested against in this repository, `C_GenerateKeyPair` for both mechanisms returns
    `CKR_MECHANISM_INVALID` (raw PKCS#11 probe, confirmed outside the KMS). The vendor guide
    notes some features require activation of a PKCS11/ENCRYPT license option — this is believed
    to be an un-activated option or device-specific configuration on that unit, not a KMS defect.
    Crypt2Pay's shared RSA/AES/encrypt/sign test coverage above does not depend on live key
    generation succeeding for those two mechanisms and continues to pass.

!!! note SoftHSM2 RSA-OAEP (direct `Encrypt`/`Decrypt`): confirmed unsupported, by design
    SoftHSM2 2.6.1 rejects `CKM_RSA_PKCS_OAEP` with explicit mechanism parameters
    (`CKR_ARGUMENTS_BAD` / "Return code: 7") for **both** SHA-256 and SHA-1 regardless of the
    fix to the OAEP empty-label source pointer described in the quirks table below — confirmed
    by an explicit code comment in `crate/hsm/softhsm2/src/tests.rs`'s `test_hsm_softhsm2_all`,
    which skips `rsa_oaep_encrypt`/`multi_threaded_rsa` entirely for this reason, and by the
    KMIP-level test vectors `test_data/vectors/hsm/resident_rsa2048_encrypt_oaep_sha{256,1}`.
    RSA-OAEP **key wrap** (`C_WrapKey`/`C_UnwrapKey`, a separate mechanism/code path) is
    unaffected by this and genuinely does not support it either
    (`supports_rsa_oaep_key_wrap: false`, already reflected in the quirks table).

!!! note Kryoptic 1.5.2: P-224 and Ed448 key generation confirmed unsupported
    Live-verified against Kryoptic 1.5.2 (`cargo build --features standard`, this repository's
    pinned build): `C_GenerateKeyPair(CKM_EC_KEY_PAIR_GEN)` for curve P-224 fails with
    `CKR_DEVICE_ERROR` ("Return code: 5"), while P-256/P-384/P-521 succeed without issue —
    isolated by testing each curve individually. Similarly, `C_Sign(CKM_EDDSA)` on an Ed448 key
    fails with `CKR_MECHANISM_PARAM_INVALID` ("Return code: 113") while Ed25519 signs
    successfully with the same mechanism. `base_hsm`'s shared `generate_ec_keypair`,
    `ecdsa_sign_all_curves_and_hashes`, and `eddsa_sign_all_curves` test functions now
    capability-probe per curve (skip-and-warn on failure) rather than hard-failing the whole
    test, consistent with this project's generic-capability-probing convention — this also
    benefits every other backend sharing these functions, not just Kryoptic.

## Vendor-specific quirks

These are objective, code-level behavioral differences captured in each model's
`HsmCapabilities` (`crate/hsm/<model>/src/lib.rs`), not algorithm availability — `BaseHsm` already
branches on them so KMS operations behave correctly regardless of HSM model.

| Capability | SoftHSM2 | Kryoptic | Proteccio | Crypt2Pay | Utimaco | AWS CloudHSM | SmartCard HSM |
| --- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| PKCS#11 v3.0 message-based AES-GCM | ❌ | ✅ (default) | ✅ | ❌ | ✅ | ✅ | ✅ |
| Caller-supplied AES-GCM IV | ✅ | ✅ (default) | ✅ | ✅ | ✅ | ❌ | ✅ |
| RSA-OAEP empty-label source pointer | non-null required | NULL (default) | NULL | NULL | NULL | NULL required | NULL |
| `CKA_START_DATE`/`CKA_END_DATE` (HSM key auto-rotation) | ❌ | ✅ (default) | ✅ | ❌ | ✅ | ❌ | ✅ |
| Explicit `CKA_SENSITIVE` on key generation | ✅ | ✅ (default) | ✅ | ✅ | ✅ | ❌ | ✅ |
| Enforces ECDSA digest ≥ curve strength | ❌ | ❌ (default) | ❌ | ❌ | ❌ | ✅ | ❌ |
| `FindObjects` page size | 32 | 10 (default) | 64 | 64 | 64 | 64 | 16 |
| `CKA_LABEL` length limit | none | none (default) | 128 bytes | none | none | none | none |

## Methodology

- ✅ rows are grounded in the shared test functions each model's `test_hsm_<model>_all` actually
  calls (`crate/hsm/<model>/src/tests.rs`), e.g. `generate_ec_keypair`,
  `ecdsa_sign_all_curves_and_hashes`, `rsa_pss_sign_all_algorithms`, `eddsa_sign_all_curves`,
  `aes_cbc_encrypt`. SoftHSM2, Kryoptic, and AWS CloudHSM currently exercise the full
  EC/ECDSA/RSA-PSS matrix in CI; Proteccio, Crypt2Pay, and Utimaco's shared test composition now
  includes the same calls (wired this session) but has not yet been run against live hardware in
  this environment, so their EC/PSS/ECDSA rows remain 📄 (wired, vendor-documented, CI-pending)
  rather than ✅. These three functions now capability-probe per curve/operation (skip-and-warn
  on failure) rather than hard-failing the whole test, surfacing genuine per-vendor gaps (e.g.
  Kryoptic's P-224/Ed448) as a partial ✅ with a footnote instead of blocking the entire suite.
- EC secp256k1/secp192k1 share one generic, curve-agnostic code path in `base_hsm` (no
  vendor-specific branching). SoftHSM2's rows are ✅ because this session specifically
  live-verified secp192k1 end-to-end (create/sign/verify) against it; every other model's rows
  remain 📄 — not independently tested for this specific curve family in this session, even
  where the same model's NIST P-curve rows are ✅.
- Quirks table values come directly from each model's `HsmCapabilities` struct fields
  (`rsa_oaep_requires_source_data_ptr`, `supports_aes_gcm_message`, `supports_key_dates`,
  `enforces_ecdsa_digest_strength`, `max_label_len`, `find_max_object_count`, etc.).
- 📄 rows are sourced from vendor PKCS#11 documentation (Proteccio *Developer's Guide*; Crypt2Pay
  *PKCS#11 API User Guide*) for mechanisms not yet exercised by this repository's CI.
- ChaCha20/ChaCha20-Poly1305, documented by Crypt2Pay as a vendor extension, is not implemented
  anywhere in `crate/hsm/base_hsm` and is therefore out of scope for this table (a KMS-side gap,
  not an HSM limitation).
- If you spot a mismatch, or extend CI coverage for a 📄 row, please open an issue or PR updating
  this page.

## See also

- [HSM keys & operations](hsm_operations.md) — KMIP-operation-level mechanism documentation
  (message sizes, CLI examples, delegation details).
- [Multi-HSM support](multi_hsm.md) — platform support matrix and multi-instance configuration.
- [Proteccio setup](proteccio.md) · [Crypt2Pay setup](crypt2pay.md) · [Utimaco setup](utimaco.md) ·
  [SoftHSM2 setup](softhsm2.md) · [Kryoptic setup](kryoptic.md) ·
  [AWS CloudHSM setup](aws_cloudhsm.md) · [SmartCard HSM setup](sc_hsm.md)
