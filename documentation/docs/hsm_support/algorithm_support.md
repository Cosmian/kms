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
| EC P-224 | ✅ | 📄 | 📄 | ⚠️ | 📄 | ✅ | 📄 |
| EC P-256 | ✅ | 📄 | 📄 | ⚠️ | 📄 | ✅ | 📄 |
| EC P-384 | ✅ | 📄 | 📄 | ⚠️ | 📄 | ✅ | 📄 |
| EC P-521 | ✅ | 📄 | 📄 | ⚠️ | 📄 | ✅ | 📄 |
| EC secp256k1 | 📄 | 📄 | 📄 | 📄 | 📄 | 📄 | 📄 |
| EC Brainpool / FRP256v1 | ❌ | ❌ | 📄 | 📄 | ❌ | ❌ | ❌ |
| Ed25519 / Ed448 (non-fips) | ✅ | 📄 | ❌ | 📄 | 📄 | ✅ | 📄 |

## Encryption mechanisms

| Mechanism | SoftHSM2 | Kryoptic | Proteccio | Crypt2Pay | Utimaco | AWS CloudHSM | SmartCard HSM |
| --- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| AES-GCM | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 📄 |
| AES-CBC (+ multi-round) | ✅ | ✅ | 📄 | 📄 | 📄 | ✅ | ✅ |
| RSA PKCS#1 v1.5 | ✅ | ✅ | ✅ | ✅ | ✅ | 📄 | ✅ |
| RSA-OAEP (SHA-256), direct `Encrypt`/`Decrypt` | ⚠️ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| RSA-OAEP key wrap (`C_WrapKey`/`C_UnwrapKey`) | ❌ | 📄 | ✅ | ✅ | ✅ | ✅ | ❌ |

## Signing mechanisms

| Mechanism | SoftHSM2 | Kryoptic | Proteccio | Crypt2Pay | Utimaco | AWS CloudHSM | SmartCard HSM |
| --- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| RSA PKCS#1 v1.5 (SHA-1/256/384/512) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| RSA-PSS (SHA-256/384/512) | ✅ | 📄 | 📄 | 📄 | 📄 | 📄 | 📄 |
| ECDSA (raw `CKM_ECDSA` and/or combined `CKM_ECDSA_SHA*`) | ✅ | 📄 | 📄 | ⚠️ | 📄 | ✅ | 📄 |
| EdDSA (non-fips) | ✅ | 📄 | ❌ | 📄 | 📄 | ✅ | 📄 |

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

!!! warning SoftHSM2 RSA-OAEP-SHA256: conflicting evidence, not yet reconciled
    A KMIP-level test vector in this repository
    (`test_data/vectors/hsm/resident_rsa2048_encrypt_oaep_sha256`) asserts that direct
    `Encrypt`/`Decrypt` with RSA-OAEP-SHA256 against a SoftHSM2-resident key **fails** with
    `CKR_ARGUMENTS_BAD` ("Failed to initialize encryption. Return code: 7") — originally
    attributed to a SoftHSM2 mechanism-parameter limitation. The same underlying code path
    (`base_hsm::Session::encrypt`/`decrypt`'s `RsaOaepSha256` branch) is also exercised directly
    by the shared Rust test suite's `rsa_oaep_encrypt`, which has been passing in CI for SoftHSM2.
    A same-session investigation found and fixed a real bug in that branch (a hardcoded `NULL`
    OAEP empty-label source pointer, where SoftHSM2 requires a non-null pointer —
    `rsa_oaep_requires_source_data_ptr` in the quirks table below), but whether that fix
    resolves the KMIP-level test vector specifically has not yet been empirically re-verified
    end-to-end against a live SoftHSM2 token. Treat this row as unresolved until the manifest
    vector is re-run and either updated or confirmed still-failing.

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
  `aes_cbc_encrypt`. Only SoftHSM2 and AWS CloudHSM currently exercise the full EC/ECDSA/EdDSA/PSS
  matrix in CI; Proteccio, Crypt2Pay, and Utimaco's shared test composition covers AES, RSA
  PKCS#1v1.5/OAEP, and RSA signing only — their EC/PSS/EdDSA rows are marked 📄 (vendor-documented)
  rather than ✅ until that CI coverage is extended.
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
