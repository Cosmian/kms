//! PKCS#11 v3.0/v3.1-specific conformance tests.
//!
//! Per explicit project direction, PKCS#11 v2.40-era baseline tests (init, session/slot
//! lifecycle, SSH RSA/EC-P256 signing, key discovery, veracrypt `CKO_DATA` lookup — see
//! `tests.rs`) must never be mixed with PKCS#11 v3.0/v3.1-specific conformance tests in the
//! same file. This module holds only the latter: Interfaces API (`C_GetInterfaceList`/
//! `C_GetInterface`), `CKO_PROFILE` self-declaration, `CKM_AES_GCM` encrypt/decrypt, HSM-KEK
//! multi-curve signing (P-256/secp256k1/Ed25519), and the Ed25519/Ed448 regression tests.

use ckms::{
    config::CKMS_CONF_ENV,
    reexport::cosmian_kms_cli_actions::reexport::{
        cosmian_kmip::{
            kmip_0::kmip_types::HashingAlgorithm,
            kmip_2_1::{
                kmip_attributes::Attributes,
                kmip_operations::SignatureVerify,
                kmip_types::{
                    CryptographicAlgorithm, CryptographicDomainParameters, CryptographicParameters,
                    DigitalSignatureAlgorithm, RecommendedCurve, UniqueIdentifier,
                    ValidityIndicator,
                },
            },
        },
        cosmian_kms_client::KmsClient,
    },
};
use cosmian_logger::log_init;
use cosmian_pkcs11_module::{
    ModuleError,
    pkcs11::{
        C_CloseSession, C_Decrypt, C_DecryptInit, C_Encrypt, C_EncryptInit, C_Finalize,
        C_FindObjects, C_FindObjectsFinal, C_FindObjectsInit, C_GetAttributeValue,
        C_GetMechanismInfo, C_Initialize, C_OpenSession, C_SetAttributeValue, SLOT_ID,
    },
    traits::{
        Backend, DigestType, KeyAlgorithm, SignatureAlgorithm, backend as registered_backend,
    },
};
use pkcs11_sys::{
    CK_ATTRIBUTE, CK_GCM_PARAMS, CK_INTERFACE, CK_INVALID_HANDLE, CK_MECHANISM, CK_MECHANISM_INFO,
    CK_OBJECT_CLASS, CK_PROFILE_ID, CK_ULONG, CK_UTF8CHAR, CK_VERSION, CKA_CLASS, CKA_LABEL,
    CKA_PRIVATE, CKA_PROFILE_ID, CKA_UNIQUE_ID, CKF_DECRYPT, CKF_ENCRYPT, CKF_SERIAL_SESSION,
    CKM_AES_GCM, CKO_PROFILE, CKP_AUTHENTICATION_TOKEN, CKP_BASELINE_PROVIDER,
    CKP_EXTENDED_PROVIDER, CKP_PUBLIC_CERTIFICATES_TOKEN, CKR_ARGUMENTS_BAD,
    CKR_ATTRIBUTE_READ_ONLY, CKR_BUFFER_TOO_SMALL, CKR_OK, CRYPTOKI_VERSION_MAJOR,
    CRYPTOKI_VERSION_MINOR,
};
use serial_test::serial;
use test_kms_server::{
    start_default_test_kms_server, start_default_test_kms_server_with_softhsm2_and_kek,
};

use crate::{
    C_GetInterface, C_GetInterfaceList,
    backend::CliBackend,
    error::{Pkcs11Error, result::Pkcs11Result},
    kms_object::key_algorithm_from_attributes,
    tests::{
        create_ec_ssh_keypair, create_rsa_ssh_keypair, initialize_backend,
        save_pkcs11_client_config, test_init,
    },
};

/// Sentinel byte used by `test_aes_gcm_encrypt_rejects_undersized_output_buffer` to detect
/// out-of-bounds writes past a caller-declared buffer capacity.
const UNDERSIZED_BUFFER_GUARD: u8 = 0xAA;

/// Verify a signature server-side via the KMIP `SignatureVerify` operation
/// and assert it is cryptographically valid.
async fn assert_signature_valid(
    kms_rest_client: &KmsClient,
    pk_id: &str,
    cryptographic_parameters: Option<CryptographicParameters>,
    data: Option<Vec<u8>>,
    digested_data: Option<Vec<u8>>,
    signature: Vec<u8>,
) {
    let request = SignatureVerify {
        unique_identifier: Some(UniqueIdentifier::TextString(pk_id.to_owned())),
        cryptographic_parameters,
        data,
        digested_data,
        signature_data: Some(signature),
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
    };
    let response = kms_rest_client
        .signature_verify(request)
        .await
        .expect("SignatureVerify request failed");
    assert_eq!(
        response.validity_indicator,
        Some(ValidityIndicator::Valid),
        "signature must be cryptographically valid"
    );
}

/// MANDATORY test: a PKCS#11 request for `ECDSA` P-256, addressed to a KMS
/// server that uses an HSM-KEK (SoftHSM2-backed Key-Encryption-Key).
///
/// The private key is created (and transparently wrapped by the HSM-resident
/// KEK), a signature is produced via `CliBackend::remote_sign` on a
/// pre-computed 32-byte SHA-256 digest (matching `CKM_ECDSA` convention), and
/// the signature is verified server-side against the public key.
#[test]
#[serial]
#[ignore = "Requires softhsm2 — set up and invoked by mise run test:hsm-softhsm2"]
fn test_hsm_kek_ecdsa_p256_sign() -> Pkcs11Result<()> {
    log_init(None);
    let rt = tokio::runtime::Runtime::new()?;
    let (owner_client_conf, sk_id, pk_id) = rt.block_on(async {
        let ctx = start_default_test_kms_server_with_softhsm2_and_kek().await;
        let kms_rest_client = ctx.get_owner_client();
        let (sk_id, pk_id) = create_ec_ssh_keypair(&kms_rest_client, RecommendedCurve::P256).await;
        (ctx.owner_client_config.clone(), sk_id, pk_id)
    });

    let kms_rest_client = KmsClient::new_with_config(owner_client_conf)?;
    let backend = CliBackend::instantiate(kms_rest_client.clone());
    // Pre-computed 32-byte SHA-256 digest (CKM_ECDSA convention)
    let prehash = [0x42_u8; 32];
    let signature = backend.remote_sign(&sk_id, &SignatureAlgorithm::Ecdsa, &prehash)?;
    assert!(
        !signature.is_empty(),
        "ECDSA P-256 signature must not be empty"
    );

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(assert_signature_valid(
        &kms_rest_client,
        &pk_id,
        Some(CryptographicParameters {
            digital_signature_algorithm: Some(DigitalSignatureAlgorithm::ECDSAWithSHA256),
            ..Default::default()
        }),
        None,
        Some(prehash.to_vec()),
        signature,
    ));
    Ok(())
}

/// MANDATORY test: a PKCS#11 request for `ECDSA` secp256k1, addressed to a
/// KMS server that uses an HSM-KEK (SoftHSM2-backed Key-Encryption-Key).
///
/// `secp256k1` is not a FIPS-approved curve (`algorithm_policy::validate_curve`
/// only allow-lists it under the `non-fips` feature); this whole test module
/// is already gated behind `#[cfg(feature = "non-fips")]` in `lib.rs`, which
/// is what allows this test to run at all.
#[test]
#[serial]
#[ignore = "Requires softhsm2 — set up and invoked by mise run test:hsm-softhsm2"]
fn test_hsm_kek_ecdsa_secp256k1_sign() -> Pkcs11Result<()> {
    log_init(None);
    let rt = tokio::runtime::Runtime::new()?;
    let (owner_client_conf, sk_id, pk_id) = rt.block_on(async {
        let ctx = start_default_test_kms_server_with_softhsm2_and_kek().await;
        let kms_rest_client = ctx.get_owner_client();
        let (sk_id, pk_id) =
            create_ec_ssh_keypair(&kms_rest_client, RecommendedCurve::SECP256K1).await;
        (ctx.owner_client_config.clone(), sk_id, pk_id)
    });

    let kms_rest_client = KmsClient::new_with_config(owner_client_conf)?;
    let backend = CliBackend::instantiate(kms_rest_client.clone());
    // Pre-computed 32-byte SHA-256 digest (CKM_ECDSA convention)
    let prehash = [0x24_u8; 32];
    let signature = backend.remote_sign(&sk_id, &SignatureAlgorithm::Ecdsa, &prehash)?;
    assert!(
        !signature.is_empty(),
        "ECDSA secp256k1 signature must not be empty"
    );

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(assert_signature_valid(
        &kms_rest_client,
        &pk_id,
        Some(CryptographicParameters {
            digital_signature_algorithm: Some(DigitalSignatureAlgorithm::ECDSAWithSHA256),
            ..Default::default()
        }),
        None,
        Some(prehash.to_vec()),
        signature,
    ));
    Ok(())
}

/// MANDATORY test: a PKCS#11 request for `EdDSA` Ed25519, addressed to a KMS
/// server that uses an HSM-KEK (SoftHSM2-backed Key-Encryption-Key).
///
/// `CKM_EDDSA` passes the raw message (Ed25519 hashes internally) rather than
/// a pre-computed digest, unlike the ECDSA tests above.
#[test]
#[serial]
#[ignore = "Requires softhsm2 — set up and invoked by mise run test:hsm-softhsm2"]
fn test_hsm_kek_eddsa_ed25519_sign() -> Pkcs11Result<()> {
    log_init(None);
    let rt = tokio::runtime::Runtime::new()?;
    let (owner_client_conf, sk_id, pk_id) = rt.block_on(async {
        let ctx = start_default_test_kms_server_with_softhsm2_and_kek().await;
        let kms_rest_client = ctx.get_owner_client();
        let (sk_id, pk_id) =
            create_ec_ssh_keypair(&kms_rest_client, RecommendedCurve::CURVEED25519).await;
        (ctx.owner_client_config.clone(), sk_id, pk_id)
    });

    let kms_rest_client = KmsClient::new_with_config(owner_client_conf)?;
    let backend = CliBackend::instantiate(kms_rest_client.clone());
    let data = b"hello HSM-KEK world, this is a test message for Ed25519 signing".to_vec();
    let signature = backend.remote_sign(&sk_id, &SignatureAlgorithm::EdDsa, &data)?;
    assert_eq!(signature.len(), 64, "Ed25519 signature must be 64 bytes");

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(assert_signature_valid(
        &kms_rest_client,
        &pk_id,
        None,
        Some(data),
        None,
        signature,
    ));
    Ok(())
}

/// Regression test for issue #1183: `key_algorithm_from_attributes` must resolve
/// Ed25519/Ed448 keys directly from the bare `CryptographicAlgorithm` value, as
/// produced by `ckms ec keys create --curve ed25519/ed448`, without requiring
/// `CryptographicDomainParameters`/`RecommendedCurve` to be present.
#[test]
fn test_key_algorithm_from_attributes_eddsa_bare_algorithm() {
    let ed25519_attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::Ed25519),
        ..Default::default()
    };
    assert_eq!(
        key_algorithm_from_attributes(&ed25519_attributes)
            .expect("Ed25519 key algorithm must resolve without cryptographic domain parameters"),
        KeyAlgorithm::Ed25519
    );

    let ed448_attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::Ed448),
        ..Default::default()
    };
    assert_eq!(
        key_algorithm_from_attributes(&ed448_attributes)
            .expect("Ed448 key algorithm must resolve without cryptographic domain parameters"),
        KeyAlgorithm::Ed448
    );

    // Genuinely unsupported algorithms must still be rejected (no regression).
    let unsupported_attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::DES),
        ..Default::default()
    };
    assert!(
        key_algorithm_from_attributes(&unsupported_attributes).is_err(),
        "DES must still be rejected as an unsupported cryptographic algorithm"
    );

    // Unlike Ed25519/Ed448, the generic EC/ECDH algorithms require the recommended curve
    // from the cryptographic domain parameters to disambiguate the concrete `KeyAlgorithm`.
    for (algorithm, curve, expected) in [
        (
            CryptographicAlgorithm::EC,
            RecommendedCurve::P256,
            KeyAlgorithm::EccP256,
        ),
        (
            CryptographicAlgorithm::EC,
            RecommendedCurve::SECP256K1,
            KeyAlgorithm::Secp256k1,
        ),
        (
            CryptographicAlgorithm::ECDH,
            RecommendedCurve::P384,
            KeyAlgorithm::EccP384,
        ),
        (
            CryptographicAlgorithm::ECDH,
            RecommendedCurve::CURVE25519,
            KeyAlgorithm::X25519,
        ),
    ] {
        let attributes = Attributes {
            cryptographic_algorithm: Some(algorithm),
            cryptographic_domain_parameters: Some(CryptographicDomainParameters {
                recommended_curve: Some(curve),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert_eq!(
            key_algorithm_from_attributes(&attributes)
                .expect("EC/ECDH key algorithm must resolve given a recommended curve"),
            expected,
            "{algorithm:?}/{curve:?} must map to {expected:?}"
        );
    }

    // EC/ECDH without domain parameters (unlike Ed25519/Ed448) must be rejected.
    let ec_missing_domain_parameters = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::EC),
        ..Default::default()
    };
    assert!(
        key_algorithm_from_attributes(&ec_missing_domain_parameters).is_err(),
        "EC without cryptographic domain parameters must be rejected"
    );
}

/// Regression test for issue #1183: an Ed25519 keypair created via the standard
/// KMIP/REST path (mirroring `ckms ec keys create --curve ed25519`) must be
/// discoverable through the PKCS#11 backend, exactly like RSA/EC P-256 SSH keys
/// in `test_ssh_key_discovery`. Before the fix, such keys were silently skipped
/// by `key_algorithm_from_attributes` (`Unsupported cryptographic algorithm: Ed25519`),
/// so `find_all_private_keys`/`find_all_public_keys` (and therefore
/// `C_FindObjectsInit`/`C_FindObjects`) never returned them.
#[test]
#[serial]
fn test_ed25519_key_discovery() -> Pkcs11Result<()> {
    log_init(None);
    let rt = tokio::runtime::Runtime::new()?;
    let (owner_client_conf, ed25519_sk_id, ed25519_pk_id) = rt.block_on(async {
        let ctx = start_default_test_kms_server().await;
        let kms_rest_client = ctx.get_owner_client();
        let (sk_id, pk_id) =
            create_ec_ssh_keypair(&kms_rest_client, RecommendedCurve::CURVEED25519).await;
        (ctx.owner_client_config.clone(), sk_id, pk_id)
    });

    let backend = CliBackend::instantiate(KmsClient::new_with_config(owner_client_conf)?);

    let private_keys = backend.find_all_private_keys()?;
    assert!(
        private_keys.iter().any(|k| k.remote_id() == ed25519_sk_id),
        "Ed25519 private key {ed25519_sk_id} not found in find_all_private_keys"
    );

    let public_keys = backend.find_all_public_keys()?;
    assert!(
        public_keys.iter().any(|k| k.remote_id() == ed25519_pk_id),
        "Ed25519 public key {ed25519_pk_id} not found in find_all_public_keys"
    );
    Ok(())
}

/// PKCS#11 v3.0 rollout (issue #1156): full `CKM_AES_GCM` encrypt/decrypt round trip against a
/// live KMS server, exercising the AAD threading and ciphertext||tag concatenation convention
/// implemented in `kms_object::kms_encrypt_async`/`kms_decrypt_async`.
#[test]
#[serial]
#[expect(unsafe_code, clippy::indexing_slicing)]
fn test_aes_gcm_encrypt_decrypt_roundtrip() -> Pkcs11Result<()> {
    let _backend = initialize_backend()?;
    let conf_path = save_pkcs11_client_config();
    // SAFETY: `#[serial]` ensures no other thread concurrently reads or modifies the process
    // environment, satisfying the thread-safety requirement for `set_var` (Rust 2024 edition).
    unsafe {
        std::env::set_var(CKMS_CONF_ENV, &conf_path);
    }

    test_init();
    assert_eq!(C_Initialize(std::ptr::null_mut()), CKR_OK);
    let mut handle = CK_INVALID_HANDLE;
    assert_eq!(
        // SAFETY: `SLOT_ID` is the only valid slot; the two null/None args are optional and
        // intentionally unused; `handle` is a properly-aligned out-parameter on the stack.
        unsafe {
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                std::ptr::null_mut(),
                None,
                &raw mut handle,
            )
        },
        CKR_OK
    );

    // Locate the pre-imported "vol1" AES key, exactly like `test_generate_key_encrypt_decrypt`.
    let mut label_bytes = b"vol1".to_vec();
    let label_len: CK_ULONG = label_bytes.len().try_into()?;
    #[allow(clippy::cast_ptr_alignment)]
    let mut template = [CK_ATTRIBUTE {
        type_: CKA_LABEL,
        pValue: label_bytes.as_mut_ptr().cast::<std::ffi::c_void>(),
        ulValueLen: label_len,
    }];
    let template_len: CK_ULONG = template.len().try_into()?;
    assert_eq!(
        unsafe { C_FindObjectsInit(handle, template.as_mut_ptr(), template_len) },
        CKR_OK
    );
    let mut obj_handles = [CK_INVALID_HANDLE; 4];
    let mut count: CK_ULONG = 0;
    let max_count: CK_ULONG = obj_handles.len().try_into()?;
    assert_eq!(
        unsafe { C_FindObjects(handle, obj_handles.as_mut_ptr(), max_count, &raw mut count) },
        CKR_OK
    );
    assert_eq!(C_FindObjectsFinal(handle), CKR_OK);
    assert!(
        count > 0,
        "C_FindObjects should locate the pre-imported 'vol1' AES key"
    );
    let key_handle = obj_handles[0];

    let mut iv = [0x11_u8; 12];
    let mut aad = b"pkcs11-v3-rollout-aad".to_vec();
    let mut gcm_params = CK_GCM_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len().try_into()?,
        ulIvBits: 0,
        pAAD: aad.as_mut_ptr(),
        ulAADLen: aad.len().try_into()?,
        ulTagBits: 128,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        pParameter: (&raw mut gcm_params).cast::<std::ffi::c_void>(),
        ulParameterLen: size_of::<CK_GCM_PARAMS>().try_into()?,
    };

    let mut plaintext = b"pkcs11-v3-rollout-aes-gcm-test-message".to_vec();
    assert_eq!(
        unsafe { C_EncryptInit(handle, &raw mut mechanism, key_handle) },
        CKR_OK
    );
    // ciphertext || 16-byte tag, per the PKCS#11 CKM_AES_GCM C_Encrypt convention.
    let mut ciphertext = vec![0_u8; plaintext.len() + 16];
    let mut ciphertext_len: CK_ULONG = ciphertext.len().try_into()?;
    assert_eq!(
        unsafe {
            C_Encrypt(
                handle,
                plaintext.as_mut_ptr(),
                plaintext.len().try_into()?,
                ciphertext.as_mut_ptr(),
                &raw mut ciphertext_len,
            )
        },
        CKR_OK
    );
    ciphertext.truncate(usize::try_from(ciphertext_len)?);
    assert_ne!(ciphertext[..ciphertext.len() - 16], plaintext[..]);

    assert_eq!(
        unsafe { C_DecryptInit(handle, &raw mut mechanism, key_handle) },
        CKR_OK
    );
    let mut decrypted = vec![0_u8; ciphertext.len()];
    let mut decrypted_len: CK_ULONG = decrypted.len().try_into()?;
    assert_eq!(
        unsafe {
            C_Decrypt(
                handle,
                ciphertext.as_mut_ptr(),
                ciphertext.len().try_into()?,
                decrypted.as_mut_ptr(),
                &raw mut decrypted_len,
            )
        },
        CKR_OK
    );
    decrypted.truncate(usize::try_from(decrypted_len)?);
    assert_eq!(decrypted, plaintext);

    assert_eq!(C_CloseSession(handle), CKR_OK);
    assert_eq!(C_Finalize(std::ptr::null_mut()), CKR_OK);
    Ok(())
}

/// Regression test for a security-review finding: `Session::encrypt` used to overwrite
/// `*pulEncryptedDataLen` with the ciphertext length *before* checking it against the caller's
/// original buffer capacity, so the too-small-buffer check always compared the freshly
/// overwritten value against itself and never actually caught anything — the caller would
/// then write `plaintext_len + 16` (AES-GCM tag) bytes into a `plaintext_len`-sized buffer,
/// silently corrupting adjacent heap memory instead of returning `CKR_BUFFER_TOO_SMALL`.
#[test]
#[serial]
#[expect(unsafe_code)]
fn test_aes_gcm_encrypt_rejects_undersized_output_buffer() -> Pkcs11Result<()> {
    let _backend = initialize_backend()?;
    let conf_path = save_pkcs11_client_config();
    // SAFETY: `#[serial]` ensures no other thread concurrently reads or modifies the process
    // environment, satisfying the thread-safety requirement for `set_var` (Rust 2024 edition).
    unsafe {
        std::env::set_var(CKMS_CONF_ENV, &conf_path);
    }

    test_init();
    assert_eq!(C_Initialize(std::ptr::null_mut()), CKR_OK);
    let mut handle = CK_INVALID_HANDLE;
    assert_eq!(
        // SAFETY: `SLOT_ID` is the only valid slot; the two null/None args are optional and
        // intentionally unused; `handle` is a properly-aligned out-parameter on the stack.
        unsafe {
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                std::ptr::null_mut(),
                None,
                &raw mut handle,
            )
        },
        CKR_OK
    );

    let mut label_bytes = b"vol1".to_vec();
    let label_len: CK_ULONG = label_bytes.len().try_into()?;
    #[allow(clippy::cast_ptr_alignment)]
    let mut template = [CK_ATTRIBUTE {
        type_: CKA_LABEL,
        pValue: label_bytes.as_mut_ptr().cast::<std::ffi::c_void>(),
        ulValueLen: label_len,
    }];
    let template_len: CK_ULONG = template.len().try_into()?;
    assert_eq!(
        unsafe { C_FindObjectsInit(handle, template.as_mut_ptr(), template_len) },
        CKR_OK
    );
    let mut obj_handles = [CK_INVALID_HANDLE; 4];
    let mut count: CK_ULONG = 0;
    let max_count: CK_ULONG = obj_handles.len().try_into()?;
    assert_eq!(
        unsafe { C_FindObjects(handle, obj_handles.as_mut_ptr(), max_count, &raw mut count) },
        CKR_OK
    );
    assert_eq!(C_FindObjectsFinal(handle), CKR_OK);
    assert!(count > 0);
    let key_handle = obj_handles[0];

    let mut iv = [0x22_u8; 12];
    let mut aad: Vec<u8> = Vec::new();
    let mut gcm_params = CK_GCM_PARAMS {
        pIv: iv.as_mut_ptr(),
        ulIvLen: iv.len().try_into()?,
        ulIvBits: 0,
        pAAD: aad.as_mut_ptr(),
        ulAADLen: 0,
        ulTagBits: 128,
    };
    let mut mechanism = CK_MECHANISM {
        mechanism: CKM_AES_GCM,
        pParameter: (&raw mut gcm_params).cast::<std::ffi::c_void>(),
        ulParameterLen: size_of::<CK_GCM_PARAMS>().try_into()?,
    };

    let mut plaintext = b"undersized-output-buffer-regression".to_vec();
    assert_eq!(
        unsafe { C_EncryptInit(handle, &raw mut mechanism, key_handle) },
        CKR_OK
    );
    // Deliberately too small: exactly `plaintext.len()`, i.e. missing room for the 16-byte
    // AES-GCM tag that `C_Encrypt` appends. Guard bytes surround the buffer so an
    // out-of-bounds write (the pre-fix bug) would corrupt a detectable sentinel instead of
    // undefined process memory.
    let mut guarded_buffer = vec![UNDERSIZED_BUFFER_GUARD; plaintext.len() + 16];
    let undersized_len: CK_ULONG = plaintext.len().try_into()?;
    let mut ciphertext_len: CK_ULONG = undersized_len;
    let rv = unsafe {
        C_Encrypt(
            handle,
            plaintext.as_mut_ptr(),
            plaintext.len().try_into()?,
            guarded_buffer.as_mut_ptr(),
            &raw mut ciphertext_len,
        )
    };
    assert_eq!(
        rv, CKR_BUFFER_TOO_SMALL,
        "an output buffer too small to hold ciphertext+tag must be rejected, not silently \
         overflowed"
    );
    // The required length must still be reported so a retry with a correctly-sized buffer
    // can succeed, per the PKCS#11 spec's two-call convention.
    assert_eq!(usize::try_from(ciphertext_len)?, plaintext.len() + 16);
    // The guard bytes past `undersized_len` must be untouched — proves no out-of-bounds write
    // occurred.
    assert!(
        guarded_buffer
            .get(usize::try_from(undersized_len)?..)
            .expect("undersized_len is within guarded_buffer's bounds by construction")
            .iter()
            .all(|&b| b == UNDERSIZED_BUFFER_GUARD),
        "C_Encrypt must not write past the caller-declared buffer capacity on \
         CKR_BUFFER_TOO_SMALL"
    );

    assert_eq!(C_CloseSession(handle), CKR_OK);
    assert_eq!(C_Finalize(std::ptr::null_mut()), CKR_OK);
    Ok(())
}

/// Regression test for a security-review finding: `C_GetMechanismInfo` used to report
/// `CKM_AES_GCM` with the `CKF_SIGN` flag (the catch-all default for signature mechanisms)
/// instead of `CKF_ENCRYPT | CKF_DECRYPT`, which would cause PKCS#11 clients that check
/// mechanism capability flags before use to incorrectly reject AES-GCM encryption/decryption.
#[test]
#[serial]
#[expect(unsafe_code)]
fn test_get_mechanism_info_aes_gcm_reports_encrypt_decrypt() -> Pkcs11Result<()> {
    let _backend = initialize_backend()?;
    let conf_path = save_pkcs11_client_config();
    // SAFETY: `#[serial]` ensures no other thread concurrently reads or modifies the process
    // environment, satisfying the thread-safety requirement for `set_var` (Rust 2024 edition).
    unsafe {
        std::env::set_var(CKMS_CONF_ENV, &conf_path);
    }
    test_init();
    assert_eq!(C_Initialize(std::ptr::null_mut()), CKR_OK);

    let mut info = CK_MECHANISM_INFO::default();
    assert_eq!(
        // SAFETY: `SLOT_ID` is the only valid slot; `info` is a properly-aligned out-parameter.
        unsafe { C_GetMechanismInfo(SLOT_ID, CKM_AES_GCM, &raw mut info) },
        CKR_OK
    );
    // `CK_MECHANISM_INFO` is a packed struct on Windows; bind the field to a local before
    // referencing it in `assert_eq!`'s format args to avoid E0793 (unaligned packed-field
    // reference).
    let flags = info.flags;
    assert_eq!(
        flags,
        CKF_ENCRYPT | CKF_DECRYPT,
        "CKM_AES_GCM must report CKF_ENCRYPT | CKF_DECRYPT, not the CKF_SIGN default"
    );

    assert_eq!(C_Finalize(std::ptr::null_mut()), CKR_OK);
    Ok(())
}

/// PKCS#11 v3.0 Interfaces API gap-fill (issue #1153 follow-up): `C_GetInterfaceList` must
/// implement the standard two-call convention and return the sole "PKCS 11" v3.0 interface;
/// `C_GetInterface` must resolve that same interface both when `pInterfaceName`/`pVersion` are
/// null (any interface/version accepted) and when they exactly match.
#[test]
#[serial]
#[expect(unsafe_code)]
fn test_get_interface_list_and_get_interface() -> Pkcs11Result<()> {
    let _backend = initialize_backend()?;
    let conf_path = save_pkcs11_client_config();
    // SAFETY: `#[serial]` ensures no other thread concurrently reads or modifies the process
    // environment, satisfying the thread-safety requirement for `set_var` (Rust 2024 edition).
    unsafe {
        std::env::set_var(CKMS_CONF_ENV, &conf_path);
    }
    test_init();
    let backend_before_discovery = registered_backend()?;

    // First call: null buffer, learn the count.
    let mut count: CK_ULONG = 0;
    assert_eq!(
        // SAFETY: `pul_count` is a valid stack out-parameter; `p_interfaces_list` is
        // intentionally null (count-query call, per the two-call convention).
        unsafe { C_GetInterfaceList(std::ptr::null_mut(), &raw mut count) },
        CKR_OK
    );
    assert_eq!(count, 1, "this module exposes exactly one interface");

    // Second call: too-small buffer must report CKR_BUFFER_TOO_SMALL and the required count.
    let mut zero_count: CK_ULONG = 0;
    let mut interfaces = [CK_INTERFACE {
        pInterfaceName: std::ptr::null_mut(),
        pFunctionList: std::ptr::null_mut(),
        flags: 0,
    }; 1];
    assert_eq!(
        // SAFETY: `interfaces` is a valid 1-element buffer; `zero_count` (0) under-reports its
        // capacity on purpose to exercise the too-small path.
        unsafe { C_GetInterfaceList(interfaces.as_mut_ptr(), &raw mut zero_count) },
        CKR_BUFFER_TOO_SMALL
    );
    assert_eq!(zero_count, 1);

    // Third call: correctly sized buffer must succeed and return the "PKCS 11" interface.
    let mut full_count: CK_ULONG = 1;
    assert_eq!(
        // SAFETY: `interfaces` is a valid 1-element buffer, matching `full_count`.
        unsafe { C_GetInterfaceList(interfaces.as_mut_ptr(), &raw mut full_count) },
        CKR_OK
    );
    assert_eq!(full_count, 1);
    assert!(!interfaces[0].pInterfaceName.is_null());
    // SAFETY: `pInterfaceName` was just populated by a successful `C_GetInterfaceList` call
    // above, and is guaranteed NUL-terminated by `PKCS11_INTERFACE_NAME`.
    let name = unsafe { std::ffi::CStr::from_ptr(interfaces[0].pInterfaceName.cast()) };
    assert_eq!(name.to_bytes(), b"PKCS 11");

    // `C_GetInterface` with null name/version must resolve to the same sole interface.
    let mut interface_ptr: *mut CK_INTERFACE = std::ptr::null_mut();
    assert_eq!(
        // SAFETY: `pp_interface` is a valid stack out-parameter; name/version are
        // intentionally null (accept-any-interface call).
        unsafe {
            C_GetInterface(
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &raw mut interface_ptr,
                0,
            )
        },
        CKR_OK
    );
    assert!(!interface_ptr.is_null());

    // `C_GetInterface` with a matching name and major version must also succeed.
    let mut name_bytes = b"PKCS 11\0".to_vec();
    let mut version = CK_VERSION {
        major: CRYPTOKI_VERSION_MAJOR,
        minor: CRYPTOKI_VERSION_MINOR,
    };
    assert_eq!(
        // SAFETY: `name_bytes` is NUL-terminated and well within `MAX_INTERFACE_NAME_LEN`;
        // `version` is a valid, properly-aligned `CK_VERSION` on the stack.
        unsafe {
            C_GetInterface(
                name_bytes.as_mut_ptr().cast::<CK_UTF8CHAR>(),
                &raw mut version,
                &raw mut interface_ptr,
                0,
            )
        },
        CKR_OK
    );
    let backend_after_discovery = registered_backend()?;
    assert!(
        std::sync::Arc::ptr_eq(&backend_before_discovery, &backend_after_discovery),
        "interface discovery must not replace an already authenticated backend"
    );
    Ok(())
}

/// `C_GetInterface` must reject an unknown interface name, an unsupported major version, and any
/// non-zero `flags` request (this module's sole interface makes no special guarantees).
#[test]
#[serial]
#[expect(unsafe_code)]
fn test_get_interface_rejects_mismatches() -> Pkcs11Result<()> {
    let _backend = initialize_backend()?;
    let conf_path = save_pkcs11_client_config();
    // SAFETY: see other tests in this file for the `#[serial]` + `set_var` justification.
    unsafe {
        std::env::set_var(CKMS_CONF_ENV, &conf_path);
    }

    let mut interface_ptr: *mut CK_INTERFACE = std::ptr::null_mut();

    // Unknown interface name.
    let mut bad_name = b"NOT PKCS 11\0".to_vec();
    assert_eq!(
        // SAFETY: `bad_name` is NUL-terminated and within `MAX_INTERFACE_NAME_LEN`;
        // `interface_ptr` is a valid stack out-parameter.
        unsafe {
            C_GetInterface(
                bad_name.as_mut_ptr().cast::<CK_UTF8CHAR>(),
                std::ptr::null_mut(),
                &raw mut interface_ptr,
                0,
            )
        },
        CKR_ARGUMENTS_BAD
    );

    // Unsupported major version.
    let mut wrong_version = CK_VERSION { major: 1, minor: 0 };
    assert_eq!(
        // SAFETY: `wrong_version` is a valid, properly-aligned `CK_VERSION` on the stack;
        // `interface_ptr` is a valid stack out-parameter.
        unsafe {
            C_GetInterface(
                std::ptr::null_mut(),
                &raw mut wrong_version,
                &raw mut interface_ptr,
                0,
            )
        },
        CKR_ARGUMENTS_BAD
    );

    // A minor version *below* the implemented one (e.g. a v3.0 request against this v3.1
    // implementation) is backward-compatible and must be accepted, not rejected — a v3.1
    // interface is a superset of v3.0. Only a minor version *above* the implemented one is
    // truly unsupported.
    let mut compatible_minor = CK_VERSION {
        major: CRYPTOKI_VERSION_MAJOR,
        minor: 0,
    };
    assert_eq!(
        // SAFETY: `compatible_minor` and `interface_ptr` are valid stack values.
        unsafe {
            C_GetInterface(
                std::ptr::null_mut(),
                &raw mut compatible_minor,
                &raw mut interface_ptr,
                0,
            )
        },
        CKR_OK
    );
    assert!(!interface_ptr.is_null());

    let mut unsupported_minor = CK_VERSION {
        major: CRYPTOKI_VERSION_MAJOR,
        minor: CRYPTOKI_VERSION_MINOR.saturating_add(1),
    };
    assert_eq!(
        // SAFETY: `unsupported_minor` and `interface_ptr` are valid stack values.
        unsafe {
            C_GetInterface(
                std::ptr::null_mut(),
                &raw mut unsupported_minor,
                &raw mut interface_ptr,
                0,
            )
        },
        CKR_ARGUMENTS_BAD
    );

    // Non-zero flags: no interface satisfies any special guarantee.
    assert_eq!(
        // SAFETY: `interface_ptr` is a valid stack out-parameter; name/version are null.
        unsafe {
            C_GetInterface(
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                &raw mut interface_ptr,
                1,
            )
        },
        CKR_ARGUMENTS_BAD
    );
    Ok(())
}

/// PKCS#11 Profiles v3.1 gap-fill (issue #1153 follow-up): the module must self-declare its
/// OASIS conformance profiles via `CKO_PROFILE` objects, discoverable through `C_FindObjects`
/// with `CKA_CLASS = CKO_PROFILE` — including on a session that has not called `C_Login`
/// (`CKA_PRIVATE` must be `CK_FALSE`).
#[test]
#[serial]
#[expect(unsafe_code)]
fn test_profile_objects_self_declared() -> Pkcs11Result<()> {
    let _backend = initialize_backend()?;
    let conf_path = save_pkcs11_client_config();
    // SAFETY: see other tests in this file for the `#[serial]` + `set_var` justification.
    unsafe {
        std::env::set_var(CKMS_CONF_ENV, &conf_path);
    }

    test_init();
    assert_eq!(C_Initialize(std::ptr::null_mut()), CKR_OK);
    let mut handle = CK_INVALID_HANDLE;
    assert_eq!(
        // SAFETY: `SLOT_ID` is the only valid slot; the two null/None args are optional and
        // intentionally unused; `handle` is a properly-aligned out-parameter on the stack.
        unsafe {
            C_OpenSession(
                SLOT_ID,
                CKF_SERIAL_SESSION,
                std::ptr::null_mut(),
                None,
                &raw mut handle,
            )
        },
        CKR_OK
    );

    // Search for CKO_PROFILE objects (no login performed on this session).
    let mut class: CK_OBJECT_CLASS = CKO_PROFILE;
    #[allow(clippy::cast_ptr_alignment)]
    let mut template = [CK_ATTRIBUTE {
        type_: CKA_CLASS,
        pValue: (&raw mut class).cast::<std::ffi::c_void>(),
        ulValueLen: std::mem::size_of::<CK_OBJECT_CLASS>().try_into()?,
    }];
    let template_len: CK_ULONG = template.len().try_into()?;
    assert_eq!(
        // SAFETY: `handle` is a valid open session; `template` is a correctly-sized,
        // properly-aligned `CK_ATTRIBUTE` array with `template_len` elements, all alive
        // for the duration of the call.
        unsafe { C_FindObjectsInit(handle, template.as_mut_ptr(), template_len) },
        CKR_OK
    );
    let mut obj_handles = [CK_INVALID_HANDLE; 8];
    let mut count: CK_ULONG = 0;
    let max_count: CK_ULONG = obj_handles.len().try_into()?;
    assert_eq!(
        // SAFETY: `handle` is a valid open session after a successful C_FindObjectsInit;
        // `obj_handles` is a buffer of `max_count` elements; `count` is a valid stack
        // out-parameter.
        unsafe { C_FindObjects(handle, obj_handles.as_mut_ptr(), max_count, &raw mut count) },
        CKR_OK
    );
    assert_eq!(C_FindObjectsFinal(handle), CKR_OK);

    let count_usize = usize::try_from(count)?;
    assert!(
        count_usize >= 3,
        "expected at least Baseline/Authentication Token/Public Certificates Token profiles, \
         got {count_usize}"
    );

    // Verify each returned object really is a public (non-private), CKO_PROFILE object whose
    // CKA_PROFILE_ID is one of the profiles this module declares support for.
    let known_profiles: [CK_PROFILE_ID; 4] = [
        CKP_BASELINE_PROVIDER,
        CKP_EXTENDED_PROVIDER,
        CKP_AUTHENTICATION_TOKEN,
        CKP_PUBLIC_CERTIFICATES_TOKEN,
    ];
    let mut seen_profiles = Vec::new();
    let mut seen_unique_ids = std::collections::HashSet::new();
    for &obj_handle in obj_handles.iter().take(count_usize) {
        let mut sentinel = 0xA5_u8;
        let mut undersized = [CK_ATTRIBUTE {
            type_: CKA_UNIQUE_ID,
            pValue: (&raw mut sentinel).cast::<std::ffi::c_void>(),
            ulValueLen: 1,
        }];
        assert_eq!(
            // SAFETY: the one-byte output is valid; the call must report the required
            // size without writing beyond or modifying this undersized buffer.
            unsafe { C_GetAttributeValue(handle, obj_handle, undersized.as_mut_ptr(), 1) },
            CKR_BUFFER_TOO_SMALL
        );
        assert!(undersized[0].ulValueLen > 1);
        assert_eq!(sentinel, 0xA5);
        assert_eq!(
            // SAFETY: the template contains one valid attribute and `obj_handle` is live.
            unsafe { C_SetAttributeValue(handle, obj_handle, undersized.as_mut_ptr(), 1) },
            CKR_ATTRIBUTE_READ_ONLY
        );

        let mut class_value: CK_OBJECT_CLASS = 0;
        let mut private_value: pkcs11_sys::CK_BBOOL = 0;
        let mut profile_id_value: CK_PROFILE_ID = 0;
        let mut unique_id_value = [0_u8; 64];
        #[allow(clippy::cast_ptr_alignment)]
        let mut attr_template = [
            CK_ATTRIBUTE {
                type_: CKA_CLASS,
                pValue: (&raw mut class_value).cast::<std::ffi::c_void>(),
                ulValueLen: std::mem::size_of::<CK_OBJECT_CLASS>().try_into()?,
            },
            CK_ATTRIBUTE {
                type_: CKA_PRIVATE,
                pValue: (&raw mut private_value).cast::<std::ffi::c_void>(),
                ulValueLen: std::mem::size_of::<pkcs11_sys::CK_BBOOL>().try_into()?,
            },
            CK_ATTRIBUTE {
                type_: CKA_PROFILE_ID,
                pValue: (&raw mut profile_id_value).cast::<std::ffi::c_void>(),
                ulValueLen: std::mem::size_of::<CK_PROFILE_ID>().try_into()?,
            },
            CK_ATTRIBUTE {
                type_: CKA_UNIQUE_ID,
                pValue: unique_id_value.as_mut_ptr().cast::<std::ffi::c_void>(),
                ulValueLen: unique_id_value.len().try_into()?,
            },
        ];
        let attr_template_len: CK_ULONG = attr_template.len().try_into()?;
        assert_eq!(
            // SAFETY: `handle` is a valid open session; `obj_handle` was just returned by
            // `C_FindObjects` above; `attr_template` entries all point to valid, correctly-sized,
            // properly-aligned stack buffers.
            unsafe {
                C_GetAttributeValue(
                    handle,
                    obj_handle,
                    attr_template.as_mut_ptr(),
                    attr_template_len,
                )
            },
            CKR_OK
        );
        assert_eq!(class_value, CKO_PROFILE);
        assert_eq!(
            private_value, 0,
            "profile objects must be public (CKA_PRIVATE = CK_FALSE) to be discoverable \
             pre-login"
        );
        assert!(
            known_profiles.contains(&profile_id_value),
            "unexpected CKA_PROFILE_ID: {profile_id_value}"
        );
        let unique_id_len = usize::try_from(attr_template[3].ulValueLen)?;
        let unique_id_bytes = unique_id_value.get(..unique_id_len).ok_or_else(|| {
            Pkcs11Error::Conversion(format!(
                "CKA_UNIQUE_ID length {unique_id_len} exceeds the test buffer"
            ))
        })?;
        let unique_id = std::str::from_utf8(unique_id_bytes)
            .map_err(|e| Pkcs11Error::Default(e.to_string()))?;
        assert!(unique_id.starts_with("pkcs11-profile:"));
        assert!(seen_unique_ids.insert(unique_id.to_owned()));
        seen_profiles.push(profile_id_value);
    }
    assert!(seen_profiles.contains(&CKP_BASELINE_PROVIDER));
    assert!(seen_profiles.contains(&CKP_AUTHENTICATION_TOKEN));
    assert!(seen_profiles.contains(&CKP_PUBLIC_CERTIFICATES_TOKEN));

    assert_eq!(
        find_profile_count(handle, CKP_BASELINE_PROVIDER)?,
        1,
        "CKA_PROFILE_ID must select exactly one declared profile"
    );
    assert_eq!(
        find_profile_count(handle, CK_PROFILE_ID::MAX)?,
        0,
        "an unknown CKA_PROFILE_ID must select no profiles"
    );

    assert_eq!(C_CloseSession(handle), CKR_OK);
    assert_eq!(C_Finalize(std::ptr::null_mut()), CKR_OK);
    Ok(())
}

#[expect(unsafe_code)]
fn find_profile_count(
    session: pkcs11_sys::CK_SESSION_HANDLE,
    requested_profile: CK_PROFILE_ID,
) -> Pkcs11Result<CK_ULONG> {
    let mut profile = requested_profile;
    let mut template = [CK_ATTRIBUTE {
        type_: CKA_PROFILE_ID,
        pValue: (&raw mut profile).cast::<std::ffi::c_void>(),
        ulValueLen: std::mem::size_of::<CK_PROFILE_ID>().try_into()?,
    }];
    let template_len = template.len().try_into()?;
    // SAFETY: `session` is open and the template references valid stack values.
    assert_eq!(
        unsafe { C_FindObjectsInit(session, template.as_mut_ptr(), template_len) },
        CKR_OK
    );
    let mut handles = [CK_INVALID_HANDLE; 4];
    let mut count = 0;
    let max_count = handles.len().try_into()?;
    // SAFETY: output buffers are valid for the supplied lengths.
    assert_eq!(
        unsafe { C_FindObjects(session, handles.as_mut_ptr(), max_count, &raw mut count) },
        CKR_OK
    );
    assert_eq!(C_FindObjectsFinal(session), CKR_OK);
    Ok(count)
}

/// Closes the `CKM_RSA_PKCS_PSS` coverage gap: RSA-PSS is declared as a supported
/// mechanism (`module/src/core/mechanism.rs`) but had no sign/verify test. Signs a
/// message via `CliBackend::remote_sign` with `SignatureAlgorithm::RsaPss` (SHA-256
/// digest/MGF1, 32-byte salt) and verifies the KMS accepts it as cryptographically
/// valid.
#[test]
#[serial]
#[ignore = "Requires softhsm2 — set up and invoked by mise run test:hsm-softhsm2"]
fn test_hsm_kek_rsa_pss_sign() -> Pkcs11Result<()> {
    log_init(None);
    let rt = tokio::runtime::Runtime::new()?;
    let (owner_client_conf, sk_id, pk_id) = rt.block_on(async {
        let ctx = start_default_test_kms_server_with_softhsm2_and_kek().await;
        let kms_rest_client = ctx.get_owner_client();
        let (sk_id, pk_id) = create_rsa_ssh_keypair(&kms_rest_client, 2048).await;
        (ctx.owner_client_config.clone(), sk_id, pk_id)
    });

    let kms_rest_client = KmsClient::new_with_config(owner_client_conf)?;
    let backend = CliBackend::instantiate(kms_rest_client.clone());
    // CKM_RSA_PKCS_PSS is a "bare" PSS mechanism (PKCS#11 v3.1 §6.4.7): it
    // "operate[s] only on the part of PKCS #1 that involves block formatting
    // and RSA, given a hash value; it does not compute a hash value on the
    // message to be signed." So the caller must supply a pre-computed SHA-256
    // digest, not the raw message (mirrors the `CKM_ECDSA` convention already
    // used by `test_hsm_kek_ecdsa_p256_sign` above).
    let message = b"hello HSM-KEK world, this is a test message for RSA-PSS signing".to_vec();
    let digest = openssl::sha::sha256(&message).to_vec();
    let algorithm = SignatureAlgorithm::RsaPss {
        digest: DigestType::Sha256,
        mask_generation_function: DigestType::Sha256,
        salt_length: 32,
    };
    let signature = backend.remote_sign(&sk_id, &algorithm, &digest)?;
    assert_eq!(
        signature.len(),
        256,
        "RSA-2048-PSS signature must be 256 bytes"
    );

    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(assert_signature_valid(
        &kms_rest_client,
        &pk_id,
        Some(CryptographicParameters {
            digital_signature_algorithm: Some(DigitalSignatureAlgorithm::RSASSAPSS),
            hashing_algorithm: Some(HashingAlgorithm::SHA256),
            mask_generator: None,
            mask_generator_hashing_algorithm: None,
            salt_length: Some(32),
            ..Default::default()
        }),
        None,
        Some(digest),
        signature,
    ));
    Ok(())
}

/// MANDATORY: end-to-end `C_Verify` round trip through the module's real PKCS#11
/// verify path (`Backend::remote_verify`, backing `C_VerifyInit`/`C_Verify`), closing
/// the most significant PKCS#11 conformance gap found in the audit: before this fix,
/// `Pkcs11PublicKey::verify()` unconditionally returned `FunctionNotSupported` and no
/// real PKCS#11 client could verify a signature through this module.
///
/// Also asserts the negative case: a tampered signature must be rejected with
/// `ModuleError::SignatureInvalid` (which `C_Verify`/`C_VerifyFinal` map to
/// `CKR_SIGNATURE_INVALID`), not a generic error — PKCS#11 clients rely on this
/// distinction to tell "verification failed" apart from "operation error".
#[test]
#[serial]
#[ignore = "Requires softhsm2 — set up and invoked by mise run test:hsm-softhsm2"]
fn test_hsm_kek_c_verify_round_trip() -> Pkcs11Result<()> {
    log_init(None);
    let rt = tokio::runtime::Runtime::new()?;
    let (owner_client_conf, sk_id, pk_id) = rt.block_on(async {
        let ctx = start_default_test_kms_server_with_softhsm2_and_kek().await;
        let kms_rest_client = ctx.get_owner_client();
        let (sk_id, pk_id) = create_ec_ssh_keypair(&kms_rest_client, RecommendedCurve::P256).await;
        (ctx.owner_client_config.clone(), sk_id, pk_id)
    });

    let kms_rest_client = KmsClient::new_with_config(owner_client_conf)?;
    let backend = CliBackend::instantiate(kms_rest_client);
    let prehash = [0x77_u8; 32];
    let signature = backend.remote_sign(&sk_id, &SignatureAlgorithm::Ecdsa, &prehash)?;

    // Positive case: a genuine signature must verify successfully through the same
    // `Backend::remote_verify` path used by the real `C_VerifyInit`/`C_Verify` functions.
    backend
        .remote_verify(&pk_id, &SignatureAlgorithm::Ecdsa, &prehash, &signature)
        .expect("a genuine ECDSA P-256 signature must verify successfully via C_Verify");

    // Negative case: a tampered signature must be rejected with CKR_SIGNATURE_INVALID,
    // not a generic backend error.
    let mut tampered_signature = signature;
    if let Some(first_byte) = tampered_signature.first_mut() {
        *first_byte ^= 0xFF;
    }
    let err = backend
        .remote_verify(
            &pk_id,
            &SignatureAlgorithm::Ecdsa,
            &prehash,
            &tampered_signature,
        )
        .expect_err("a tampered signature must be rejected, not silently accepted");
    assert!(
        matches!(err, ModuleError::SignatureInvalid),
        "tampered signature must map to ModuleError::SignatureInvalid (-> CKR_SIGNATURE_INVALID via C_Verify), got: {err:?}"
    );
    Ok(())
}
