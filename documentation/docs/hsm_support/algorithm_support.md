# HSM algorithm support by model

This page compares PKCS#11 algorithm and capability coverage across the HSM models natively
integrated by Eviden KMS: **SoftHSM2**, **Kryoptic**, **Proteccio**, **Crypt2Pay**, **Utimaco**,
**AWS CloudHSM**, **GCP Cloud HSM**, **Azure Cloud HSM**, **SmartCard HSM**, and **Thales Luna**.
All models share the same `BaseHsm` implementation (`crate/hsm/base_hsm`); per-model differences
come from (a) real PKCS#11 mechanism availability on the device/library, and (b) a small set of
vendor-specific behavioral quirks captured in each model's `HsmCapabilities`
(`crate/hsm/<model>/src/lib.rs`).

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
- — **Not tested** — not exercised by this model's test suite, and no vendor documentation was
  checked for it.

## Key generation

| Algorithm / curve | SoftHSM2 | Kryoptic | Proteccio | Crypt2Pay | Utimaco | AWS CloudHSM | GCP Cloud HSM | Azure Cloud HSM | SmartCard HSM | Thales Luna |
| --- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| AES-128/192/256 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| RSA-2048 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — | ✅ | ✅ | ✅ |
| EC P-224 | ✅ | ❌ | 📄 | ⚠️ | 📄 | ✅ | — | 📄 | 📄 | ✅ |
| EC P-256 | ✅ | ✅ | 📄 | ⚠️ | 📄 | ✅ | — | 📄 | 📄 | ✅ |
| EC P-384 | ✅ | ✅ | 📄 | ⚠️ | 📄 | ✅ | — | 📄 | 📄 | ✅ |
| EC P-521 | ✅ | ✅ | 📄 | ⚠️ | 📄 | ✅ | — | 📄 | 📄 | ✅ |
| EC secp256k1 (non-fips) | ✅ | 📄 | 📄 | 📄 | 📄 | 📄 | — | 📄 | 📄 | — |
| EC secp192k1 (non-fips) | ✅ | 📄 | 📄 | 📄 | 📄 | 📄 | — | — | 📄 | — |
| EC Brainpool / FRP256v1 | ❌ | ❌ | 📄 | 📄 | ❌ | ❌ | — | — | ❌ | — |
| Ed25519 (non-fips) | ✅ | ✅ | ❌ | 📄 | 📄 | ✅ | — | 📄 | 📄 | ✅ |
| Ed448 (non-fips) | ✅ | ❌ | ❌ | 📄 | 📄 | ✅ | — | — | 📄 | ✅ |

## Encryption mechanisms

| Mechanism | SoftHSM2 | Kryoptic | Proteccio | Crypt2Pay | Utimaco | AWS CloudHSM | GCP Cloud HSM | Azure Cloud HSM | SmartCard HSM | Thales Luna |
| --- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| AES-GCM | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | 📄 | ✅ |
| AES-CBC (+ multi-round) | ✅ | ✅ | 📄 | 📄 | 📄 | ✅ | ✅ (single-round) | ✅ (single-round) | ✅ | ✅ |
| RSA PKCS#1 v1.5 | ✅ | ✅ | ✅ | ✅ | ✅ | 📄 | — | 📄 | ✅ | ✅ |
| RSA-OAEP (SHA-256), direct `Encrypt`/`Decrypt` | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ | — | ✅ | ✅ | ✅ |
| RSA-OAEP key wrap (`C_WrapKey`/`C_UnwrapKey`) | ❌ | 📄 | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ | ❌ | ✅ |

## Signing mechanisms

| Mechanism | SoftHSM2 | Kryoptic | Proteccio | Crypt2Pay | Utimaco | AWS CloudHSM | GCP Cloud HSM | Azure Cloud HSM | SmartCard HSM | Thales Luna |
| --- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| RSA PKCS#1 v1.5 (SHA-1/256/384/512) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — | ✅ (SHA-256) | ✅ | ✅ |
| RSA-PSS (SHA-256/384/512) | ✅ | ✅ | 📄 | 📄 | 📄 | 📄 | — | 📄 | 📄 | ✅ |
| ECDSA (raw `CKM_ECDSA` and/or combined `CKM_ECDSA_SHA*`) | ✅ | ✅ | 📄 | ⚠️ | 📄 | ✅ | — | 📄 (P-256/P-384 only) | 📄 | ✅ |
| ECDSA secp256k1 (non-fips) | ✅ | 📄 | 📄 | 📄 | 📄 | 📄 | — | ❌ | 📄 | — |
| ECDSA secp192k1 (non-fips) | ✅ | 📄 | 📄 | 📄 | 📄 | 📄 | — | ❌ | 📄 | — |
| EdDSA Ed25519 (non-fips) | ✅ | ✅ | ❌ | 📄 | 📄 | ✅ | — | ❌ | 📄 | ✅ |
| EdDSA Ed448 (non-fips) | ✅ | ❌ | ❌ | 📄 | 📄 | ✅ | — | ❌ | 📄 | ✅ |

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
    `ecdsa_sign_all_curves_and_hashes`, and `eddsa_sign_all_curves` test functions
    capability-probe per curve (skip-and-warn on failure) rather than hard-failing the whole
    test, so a per-curve gap on one backend does not block the rest of the suite.

!!! note Thales Luna: `CKA_SENSITIVE`, AES-GCM, and FIPS-mode IV
    Luna rejects an explicit `CKA_SENSITIVE=false` with `CKR_ATTRIBUTE_VALUE_INVALID`, so the KMS
    omits `CKA_SENSITIVE` on Luna and controls exportability with `CKA_EXTRACTABLE` only. The Luna
    Client exports the PKCS#11 3.0 message-based encryption functions, but `C_MessageEncryptInit`
    fails for AES-GCM (`CKR_FUNCTION_NOT_SUPPORTED`); the KMS uses classic `C_EncryptInit`
    AES-GCM instead. In FIPS mode, Luna generates the AES-GCM IV itself and appends it to the
    output; the KMS uses that IV with firmware 7.9.3 or later (96-bit IV) and rejects the 16-byte
    IV of older firmware. This FIPS behavior follows the Thales documentation and has not been
    exercised on a FIPS-mode partition.

!!! note Azure Cloud HSM: limits of the vendor's PKCS#11 library
    The rows above follow the Azure Cloud HSM *PKCS#11 Integration Guide* (a PKCS#11 v2.40
    library, `libazcloudhsm_pkcs11.so`). It lists key generation for NIST P-192/P-224/P-256/P-384/
    P-521 and secp256k1, plus Ed25519/X25519 through `CKM_EC_KEY_PAIR_GEN`, but states that **only
    P-256 and P-384 are supported for sign/verify** and its sign/verify mechanism table has no
    `CKM_EDDSA`; ECDSA with secp256k1/secp192k1 and EdDSA are therefore ❌ for signing even where
    key generation is documented. Sign Recover and Verify Recover are not supported. The guide's
    curve list has no Brainpool/FRP256v1 or secp192k1, although Microsoft's HSM-level
    *Supported cryptographic algorithms* page names them (non-FIPS); those rows stay — because the
    two vendor documents disagree and this repository has not exercised them. The firmware also
    does not store `CKA_START_DATE`/`CKA_END_DATE`, which is why HSM key auto-rotation is
    unavailable (see the quirks table).

## Vendor-specific quirks

These are objective, code-level behavioral differences captured in each model's
`HsmCapabilities` (`crate/hsm/<model>/src/lib.rs`), not algorithm availability — `BaseHsm` already
branches on them so KMS operations behave correctly regardless of HSM model.

| Capability | SoftHSM2 | Kryoptic | Proteccio | Crypt2Pay | Utimaco | AWS CloudHSM | GCP Cloud HSM | Azure Cloud HSM | SmartCard HSM | Thales Luna |
| --- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| PKCS#11 v3.0 message-based AES-GCM | ❌ | ✅ (default) | ✅ | ❌ | ✅ | ✅ | ❌ | ❌ (v2.40 library) | ✅ | ❌ |
| Caller-supplied AES-GCM IV | ✅ | ✅ (default) | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ |
| Caller-supplied AES-GCM IV in FIPS builds (IG C.H) | ✅ (not FIPS-validated) | ✅ (not FIPS-validated) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| RSA-OAEP empty-label source pointer | non-null required | NULL (default) | NULL | NULL | NULL | NULL required | NULL | NULL | NULL | NULL |
| `CKA_START_DATE`/`CKA_END_DATE` (HSM key auto-rotation) | ❌ | ✅ (default) | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ |
| Explicit `CKA_SENSITIVE` on key generation | ✅ | ✅ (default) | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ | ❌ |
| Enforces ECDSA digest ≥ curve strength | ❌ | ❌ (default) | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ (default) | ❌ | ❌ |
| `FindObjects` page size | 32 | 10 (default) | 64 | 64 | 64 | 64 | 64 | 64 | 16 | 256 |
| `CKA_LABEL` length limit | none | none (default) | 128 bytes | none | none | none | none | none | none | none |

Azure Cloud HSM leaves `supports_aes_gcm_message` at its default (`true`), but `BaseHsm` only
uses message-based AES-GCM when the loaded library also exports the v3.0 message functions
(`HsmLib::supports_message_encrypt`); the Azure v2.40 library does not, so classic
`C_EncryptInit` AES-GCM with an HSM-generated IV is used.

In FIPS builds, an HSM without a usable PKCS#11 v3.0 message API gets AES-GCM with an
HSM-generated IV even when it accepts a caller-supplied IV; only the SoftHSM2 and Kryoptic
development tokens keep the caller-supplied IV. `hsm_model = "other"` uses the SoftHSM2 PKCS#11
quirks but is treated as a FIPS-validated module and tries the v3.0 message API first. Use
`key_encryption_key_wrapping_algorithm = "aes-key-wrap-padding"` (see
[HSM operations](hsm_operations.md#choosing-the-wrapping-algorithm)) on an HSM that generates
no GCM IV.

## Methodology

- ✅ rows are grounded in the shared test functions each model's `test_hsm_<model>_all` actually
  calls (`crate/hsm/<model>/src/tests.rs`), e.g. `generate_ec_keypair`,
  `ecdsa_sign_all_curves_and_hashes`, `rsa_pss_sign_all_algorithms`, `eddsa_sign_all_curves`,
  `aes_cbc_encrypt`. These functions capability-probe per curve/operation (skip-and-warn on
  failure) rather than hard-failing the whole test, so a passing test does not by itself prove
  every curve row: per-curve skips show up as warnings in the test log (e.g. Kryoptic's
  P-224/Ed448).
- CI runs SoftHSM2, Kryoptic, and the Utimaco simulator on every build, and Proteccio and
  Crypt2Pay on upstream builds (`.github/workflows/test_all.yml`). The AWS CloudHSM, GCP Cloud
  HSM, and Azure Cloud HSM jobs are disabled. GCP Cloud HSM's suite covers AES only
  (`generate_aes_key`, `aes_gcm_encrypt`, `aes_cbc_encrypt`); its other algorithm rows are — (not
  tested). Azure Cloud HSM's suite (`test_hsm_azure_cloud_hsm_all`) covers AES/RSA/EC key
  generation, RSA-OAEP encrypt and key wrap, AES-GCM, single-round AES-CBC, RSA SHA-256 PKCS#1
  v1.5 signing, and ECDSA; it does not call the multi-round CBC, RSA PKCS#1 v1.5 encryption,
  RSA-PSS, or EdDSA functions.
- Proteccio, Crypt2Pay, Utimaco, and Azure Cloud HSM call the same shared EC/ECDSA functions
  (Proteccio, Crypt2Pay, and Utimaco also RSA-PSS), but their EC, ECDSA, and RSA-PSS rows stay 📄
  (vendor-documented) until a run's log confirms each curve and digest.
- Thales Luna rows come from the Luna suite (`crate/hsm/luna/src/tests.rs`, also run by
  `mise run test:hsm:luna`) against a Luna Network HSM 7 partition (firmware 7.9.1, Luna Client
  10.9.3, not in FIPS mode), with every curve and digest confirmed in the run log. Luna sits on a
  private network and is not part of CI.
- EC secp256k1/secp192k1 share one generic, curve-agnostic code path in `base_hsm` (no
  vendor-specific branching) and are not part of the shared test suite. SoftHSM2's rows are ✅
  from an end-to-end create/sign/verify run against it; the other models' rows are 📄 or —, even
  where the same model's NIST P-curve rows are ✅.
- Quirks table values come directly from each model's `HsmCapabilities` struct fields
  (`rsa_oaep_requires_source_data_ptr`, `supports_aes_gcm_message`, `supports_key_dates`,
  `enforces_ecdsa_digest_strength`, `max_label_len`, `find_max_object_count`, etc.).
- 📄 rows are sourced from vendor PKCS#11 documentation (Proteccio *Developer's Guide*; Crypt2Pay
  *PKCS#11 API User Guide*; Azure Cloud HSM *PKCS#11 Integration Guide*) for mechanisms not yet
  exercised by this repository's tests.
- ChaCha20/ChaCha20-Poly1305, documented by Crypt2Pay as a vendor extension, is not implemented
  anywhere in `crate/hsm/base_hsm` and is therefore out of scope for this table (a KMS-side gap,
  not an HSM limitation).
- If you spot a mismatch, or extend test coverage for a 📄 or — row, please open an issue or PR
  updating this page.

## See also

- [HSM keys & operations](hsm_operations.md) — KMIP-operation-level mechanism documentation
  (message sizes, CLI examples, delegation details).
- [Multi-HSM support](multi_hsm.md) — platform support matrix and multi-instance configuration.
- [SoftHSM2 setup](softhsm2.md) · [Kryoptic setup](kryoptic.md) · [Proteccio setup](proteccio.md) ·
  [Crypt2Pay setup](crypt2pay.md) · [Utimaco setup](utimaco.md) ·
  [AWS CloudHSM setup](aws_cloudhsm.md) · [GCP Cloud HSM setup](gcp_cloud_hsm.md) ·
  [Azure Cloud HSM setup](azure_cloud_hsm.md) ·
  [SmartCard HSM setup](sc_hsm.md) · [Thales Luna setup](luna.md)
