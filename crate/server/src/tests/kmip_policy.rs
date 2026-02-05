#![allow(clippy::unwrap_used, clippy::expect_used)]

#[cfg(feature = "non-fips")]
use cosmian_kms_client_utils::export_utils::export_request;
#[cfg(feature = "non-fips")]
use cosmian_kms_client_utils::reexport::cosmian_kmip::kmip_2_1::requests::{
    create_ec_key_pair_request, decrypt_request, encrypt_request,
};
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::{
    CreateKeyPairResponse, DecryptResponse, EncryptResponse,
};
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    kmip_data_structures::KeyWrappingSpecification,
    kmip_types::{EncryptionKeyInformation, WrappingMethod},
};
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{BlockCipherMode, ErrorReason, HashingAlgorithm, PaddingMethod},
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_operations::{Create, Encrypt, Operation},
        kmip_types::{
            CryptographicAlgorithm, CryptographicParameters, DigitalSignatureAlgorithm,
            RecommendedCurve,
        },
    },
    ttlv::to_ttlv,
};
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_2_1::kmip_types::UniqueIdentifier, time_normalize,
};
use strum::IntoEnumIterator;

#[cfg(feature = "non-fips")]
use super::test_utils::https_clap_config_opts;
#[cfg(feature = "non-fips")]
use super::test_utils::{post_2_1, test_app, test_app_with_clap_config};
#[cfg(feature = "non-fips")]
use crate::core::operations::algorithm_policy::{
    enforce_ecies_fixed_suite_for_attributes, enforce_ecies_fixed_suite_for_pkey_id,
};
use crate::{
    config::{ClapConfig, ServerParams},
    core::operations::algorithm_policy::enforce_kmip_algorithm_policy_for_operation,
    error::KmsError,
};

fn params_with_default_policy() -> ServerParams {
    let mut params =
        ServerParams::try_from(ClapConfig::default()).expect("default clap config should build");
    params.kmip_policy.enforce = true;
    params
}

fn params_with_allowlists(conf: ClapConfig) -> ServerParams {
    ServerParams::try_from(conf).expect("config should build")
}

fn deny_reason(res: Result<(), KmsError>) -> ErrorReason {
    match res {
        Ok(()) => panic!("expected KMIP policy failure"),
        Err(KmsError::Kmip21Error(reason, _)) => reason,
        Err(other) => {
            panic!("unexpected error type (wanted Kmip21Error): {other:?}")
        }
    }
}

fn assert_policy_denied(res: Result<(), KmsError>) {
    if res.is_err() {
        // (debug) removed
    }
    let reason = deny_reason(res);
    assert_eq!(
        reason,
        ErrorReason::Constraint_Violation,
        "policy enforcement should return Constraint_Violation for denied parameters"
    );
}

fn enforce(params: &ServerParams, operation_tag: &str, op: &Operation) -> Result<(), KmsError> {
    let ttlv = to_ttlv(op)?;
    // (debug) removed
    enforce_kmip_algorithm_policy_for_operation(params, operation_tag, &ttlv)
}

#[cfg(feature = "non-fips")]
fn ecies_policy_conf(curve: RecommendedCurve, allowed_shake: CryptographicAlgorithm) -> ClapConfig {
    let mut conf = https_clap_config_opts(None);
    conf.kmip.enforce = true;
    conf.kmip.allowlists.curves = Some(vec![curve]);
    conf.kmip.allowlists.algorithms = Some(vec![
        CryptographicAlgorithm::EC,
        CryptographicAlgorithm::ECDH,
        allowed_shake,
    ]);
    conf
}

#[cfg(feature = "non-fips")]
async fn e2e_ecies_roundtrip_with_policy(
    curve: RecommendedCurve,
    allowed_shake: CryptographicAlgorithm,
) -> Result<(), KmsError> {
    let conf = ecies_policy_conf(curve, allowed_shake);
    let app = Box::pin(test_app_with_clap_config(conf, None)).await;

    let create_kp = create_ec_key_pair_request(None, ["e2e-ecies-matrix"], curve, false, None)
        .expect("create_ec_key_pair_request should build");
    let create_resp: CreateKeyPairResponse = post_2_1(&app, &create_kp).await?;
    let pk_uid = create_resp
        .public_key_unique_identifier
        .as_str()
        .expect("public key uid should be a string")
        .to_owned();
    let pk_uid_for_encrypt = if pk_uid.ends_with("_pk") {
        pk_uid
    } else {
        format!("{pk_uid}_pk")
    };
    let sk_uid = create_resp
        .private_key_unique_identifier
        .as_str()
        .expect("private key uid should be a string")
        .to_owned();

    let plaintext = b"ecies-matrix".to_vec();
    let enc_req = encrypt_request(
        &pk_uid_for_encrypt,
        None,
        plaintext.clone(),
        None,
        None,
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::EC),
            ..Default::default()
        }),
    )
    .expect("encrypt_request should build");
    let enc_resp: EncryptResponse = post_2_1(&app, &enc_req).await?;
    let ciphertext = enc_resp.data.expect("ciphertext should be present");

    let dec_req = decrypt_request(
        &sk_uid,
        None,
        ciphertext,
        None,
        None,
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::EC),
            ..Default::default()
        }),
    );
    let dec_resp: DecryptResponse = post_2_1(&app, &dec_req).await?;
    let recovered = dec_resp.data.expect("plaintext should be present");
    assert_eq!(&*recovered, &plaintext);
    Ok(())
}

#[cfg(feature = "non-fips")]
fn assert_constraint_violation(err: KmsError) {
    match err {
        KmsError::Kmip21Error(ErrorReason::Constraint_Violation, _) => {}
        KmsError::ServerError(msg) if msg.contains("Constraint_Violation") => {}
        other => panic!("expected Constraint_Violation, got: {other:?}"),
    }
}

#[cfg(feature = "non-fips")]
#[actix_web::test]
async fn e2e_ecies_matrix_p256_shake128_passes_shake256_fails() {
    Box::pin(e2e_ecies_roundtrip_with_policy(
        RecommendedCurve::P256,
        CryptographicAlgorithm::SHAKE128,
    ))
    .await
    .expect("P-256 should work with SHAKE128 allowlisted");

    let err = Box::pin(e2e_ecies_roundtrip_with_policy(
        RecommendedCurve::P256,
        CryptographicAlgorithm::SHAKE256,
    ))
    .await
    .unwrap_err();
    assert_constraint_violation(err);
}

#[cfg(feature = "non-fips")]
#[actix_web::test]
async fn e2e_ecies_matrix_p384_shake256_passes_shake128_fails() {
    Box::pin(e2e_ecies_roundtrip_with_policy(
        RecommendedCurve::P384,
        CryptographicAlgorithm::SHAKE256,
    ))
    .await
    .expect("P-384 should work with SHAKE256 allowlisted");

    let err = Box::pin(e2e_ecies_roundtrip_with_policy(
        RecommendedCurve::P384,
        CryptographicAlgorithm::SHAKE128,
    ))
    .await
    .unwrap_err();
    assert_constraint_violation(err);
}

#[cfg(feature = "non-fips")]
#[actix_web::test]
async fn e2e_ecies_matrix_p521_shake256_passes_shake128_fails() {
    Box::pin(e2e_ecies_roundtrip_with_policy(
        RecommendedCurve::P521,
        CryptographicAlgorithm::SHAKE256,
    ))
    .await
    .expect("P-521 should work with SHAKE256 allowlisted");

    let err = Box::pin(e2e_ecies_roundtrip_with_policy(
        RecommendedCurve::P521,
        CryptographicAlgorithm::SHAKE128,
    ))
    .await
    .unwrap_err();
    assert_constraint_violation(err);
}

#[cfg(feature = "non-fips")]
#[actix_web::test]
async fn e2e_ecies_is_denied_when_curves_allowlist_is_unset() {
    let mut conf = https_clap_config_opts(None);
    conf.kmip.enforce = true;
    conf.kmip.allowlists.curves = None;
    conf.kmip.allowlists.algorithms = Some(vec![
        CryptographicAlgorithm::EC,
        CryptographicAlgorithm::ECDH,
        CryptographicAlgorithm::SHAKE128,
        CryptographicAlgorithm::SHAKE256,
    ]);

    let app = Box::pin(test_app_with_clap_config(conf, None)).await;

    // Create a keypair (key creation itself isn't gated by curve allowlist).
    let create_kp = create_ec_key_pair_request(
        None,
        ["e2e-ecies-curves-unset"],
        RecommendedCurve::P256,
        false,
        None,
    )
    .expect("create_ec_key_pair_request should build");
    let create_resp: CreateKeyPairResponse = post_2_1(&app, &create_kp).await.unwrap();
    let pk_uid = create_resp
        .public_key_unique_identifier
        .as_str()
        .expect("public key uid should be a string")
        .to_owned();
    let pk_uid_for_encrypt = if pk_uid.ends_with("_pk") {
        pk_uid
    } else {
        format!("{pk_uid}_pk")
    };

    let plaintext = b"ecies-curves-unset".to_vec();
    let enc_req = encrypt_request(
        &pk_uid_for_encrypt,
        None,
        plaintext,
        None,
        None,
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::EC),
            ..Default::default()
        }),
    )
    .expect("encrypt_request should build");

    let err = post_2_1::<_, _, EncryptResponse, _>(&app, &enc_req)
        .await
        .unwrap_err();
    assert_constraint_violation(err);
}

#[cfg(feature = "non-fips")]
#[actix_web::test]
async fn e2e_ecies_is_denied_when_curves_allowlist_is_empty() {
    let mut conf = https_clap_config_opts(None);
    conf.kmip.enforce = true;
    conf.kmip.allowlists.curves = Some(vec![]);
    conf.kmip.allowlists.algorithms = Some(vec![
        CryptographicAlgorithm::EC,
        CryptographicAlgorithm::ECDH,
        CryptographicAlgorithm::SHAKE128,
        CryptographicAlgorithm::SHAKE256,
    ]);

    let app = Box::pin(test_app_with_clap_config(conf, None)).await;

    // With empty curves allowlist, curve usage is unrestricted globally,
    // but ECIES is explicitly disabled.
    let create_kp = create_ec_key_pair_request(
        None,
        ["e2e-ecies-curves-empty"],
        RecommendedCurve::P256,
        false,
        None,
    )
    .expect("create_ec_key_pair_request should build");
    let create_resp: CreateKeyPairResponse = post_2_1(&app, &create_kp).await.unwrap();
    let pk_uid = create_resp
        .public_key_unique_identifier
        .as_str()
        .expect("public key uid should be a string")
        .to_owned();
    let pk_uid_for_encrypt = if pk_uid.ends_with("_pk") {
        pk_uid
    } else {
        format!("{pk_uid}_pk")
    };

    let plaintext = b"ecies-curves-empty".to_vec();
    let enc_req = encrypt_request(
        &pk_uid_for_encrypt,
        None,
        plaintext,
        None,
        None,
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::EC),
            ..Default::default()
        }),
    )
    .expect("encrypt_request should build");

    let err = post_2_1::<_, _, EncryptResponse, _>(&app, &enc_req)
        .await
        .unwrap_err();
    assert_constraint_violation(err);
}

#[cfg(feature = "non-fips")]
fn wrapping_spec(
    wrapping_key_uid: &str,
    cp: CryptographicParameters,
) -> cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_data_structures::KeyWrappingSpecification{
    KeyWrappingSpecification {
        wrapping_method: WrappingMethod::Encrypt,
        encryption_key_information: Some(EncryptionKeyInformation {
            unique_identifier: UniqueIdentifier::TextString(wrapping_key_uid.to_owned()),
            cryptographic_parameters: Some(cp),
        }),
        mac_or_signature_key_information: None,
        attribute_name: None,
        encoding_option: None,
    }
}

#[cfg(feature = "non-fips")]
#[test]
fn kmip_policy_key_wrapping_aes_kw_suite_requires_aes_and_nist_key_wrap() {
    // Suite: AES Key Wrap (RFC3394)
    let mut conf = ClapConfig::default();
    conf.kmip.allowlists.algorithms = Some(vec![CryptographicAlgorithm::AES]);
    conf.kmip.allowlists.block_cipher_modes = Some(vec![BlockCipherMode::NISTKeyWrap]);
    let mut params = params_with_allowlists(conf);
    params.kmip_policy.enforce = true;

    let op = Operation::Export(
        cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::Export {
            unique_identifier: Some(UniqueIdentifier::TextString("target".to_owned())),
            key_format_type: None,
            key_wrap_type: None,
            key_wrapping_specification: Some(wrapping_spec(
                "kek",
                CryptographicParameters {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                    block_cipher_mode: Some(BlockCipherMode::NISTKeyWrap),
                    ..Default::default()
                },
            )),
            ..Default::default()
        },
    );

    enforce(&params, "Export", &op).expect("AES-KW should be allowed with minimal allowlists");
}

#[cfg(feature = "non-fips")]
#[test]
fn kmip_policy_key_wrapping_aes_kwp_suite_requires_aes_and_kwp_mode() {
    // Suite: AES Key Wrap with Padding (RFC5649)
    let mut conf = ClapConfig::default();
    conf.kmip.allowlists.algorithms = Some(vec![CryptographicAlgorithm::AES]);
    conf.kmip.allowlists.block_cipher_modes = Some(vec![BlockCipherMode::AESKeyWrapPadding]);
    let mut params = params_with_allowlists(conf);
    params.kmip_policy.enforce = true;

    let op = Operation::Export(
        cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::Export {
            unique_identifier: Some(UniqueIdentifier::TextString("target".to_owned())),
            key_format_type: None,
            key_wrap_type: None,
            key_wrapping_specification: Some(wrapping_spec(
                "kek",
                CryptographicParameters {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                    block_cipher_mode: Some(BlockCipherMode::AESKeyWrapPadding),
                    ..Default::default()
                },
            )),
            ..Default::default()
        },
    );

    enforce(&params, "Export", &op).expect("AES-KWP should be allowed with minimal allowlists");
}

#[cfg(feature = "non-fips")]
#[test]
fn kmip_policy_key_wrapping_aes_gcm_suite_requires_aes_and_gcm() {
    // Suite: AES-GCM key wrap
    let mut conf = ClapConfig::default();
    conf.kmip.allowlists.algorithms = Some(vec![CryptographicAlgorithm::AES]);
    conf.kmip.allowlists.block_cipher_modes = Some(vec![BlockCipherMode::GCM]);
    let mut params = params_with_allowlists(conf);
    params.kmip_policy.enforce = true;

    let op = Operation::Export(
        cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::Export {
            unique_identifier: Some(UniqueIdentifier::TextString("target".to_owned())),
            key_format_type: None,
            key_wrap_type: None,
            key_wrapping_specification: Some(wrapping_spec(
                "kek",
                CryptographicParameters {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                    block_cipher_mode: Some(BlockCipherMode::GCM),
                    ..Default::default()
                },
            )),
            ..Default::default()
        },
    );

    enforce(&params, "Export", &op)
        .expect("AES-GCM wrap should be allowed with minimal allowlists");
}

#[cfg(feature = "non-fips")]
#[actix_web::test]
async fn e2e_encrypt_decrypt_p384_shake256_only_passes_shake128_only_fails() {
    // Start a full test app (routes + KMS + sqlite).
    let app = test_app(None, None).await;

    // Create a P-384 keypair so the stored key has RecommendedCurve=P384.
    // Use the public request builder (client_utils) so IDs and tags match server expectations.
    let create_kp = create_ec_key_pair_request(
        None,
        ["e2e-ecies-p384"],
        RecommendedCurve::P384,
        false,
        None,
    )
    .expect("create_ec_key_pair_request should build");

    let create_resp: CreateKeyPairResponse = post_2_1(&app, &create_kp).await.unwrap();
    let pk_uid = create_resp
        .public_key_unique_identifier
        .as_str()
        .expect("public key uid should be a string")
        .to_owned();
    let pk_uid_for_encrypt = if pk_uid.ends_with("_pk") {
        pk_uid.clone()
    } else {
        format!("{pk_uid}_pk")
    };
    let sk_uid = create_resp
        .private_key_unique_identifier
        .as_str()
        .expect("private key uid should be a string")
        .to_owned();

    let plaintext = b"p384-ecies-roundtrip".to_vec();

    // Baseline sanity: Encrypt/Decrypt works (policy defaults allow SHAKE256 in non-fips).
    let enc_req = encrypt_request(
        &pk_uid_for_encrypt,
        None,
        plaintext.clone(),
        None,
        None,
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::EC),
            ..Default::default()
        }),
    )
    .expect("encrypt_request should build");
    let enc_resp: EncryptResponse = post_2_1(&app, &enc_req).await.unwrap();
    let ciphertext = enc_resp.data.expect("ciphertext should be present");

    let dec_req = decrypt_request(
        &sk_uid,
        None,
        ciphertext,
        None,
        None,
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::EC),
            ..Default::default()
        }),
    );
    let dec_resp: DecryptResponse = post_2_1(&app, &dec_req).await.unwrap();
    assert_eq!(
        &*dec_resp.data.expect("plaintext should be present"),
        &plaintext
    );

    // Now exercise the policy helpers directly in the same way Encrypt/Decrypt do:
    // - With curve known (P-384), SHAKE256-only must pass.
    // - SHAKE128-only must fail.
    let mut conf = ClapConfig::default();
    conf.kmip.allowlists.curves = Some(vec![RecommendedCurve::P384]);
    conf.kmip.allowlists.algorithms = Some(vec![
        CryptographicAlgorithm::EC,
        CryptographicAlgorithm::SHAKE256,
    ]);
    let mut params = params_with_allowlists(conf);
    params.kmip_policy.enforce = true;

    // Attributes containing the curve as stored in the KMIP object.
    let attrs = Attributes {
        cryptographic_domain_parameters: Some(
            cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::CryptographicDomainParameters {
                recommended_curve: Some(RecommendedCurve::P384),
                ..Default::default()
            },
        ),
        ..Default::default()
    };

    enforce_ecies_fixed_suite_for_attributes(&params, "Encrypt", "e2e-key", &attrs)
        .expect("P-384 ECIES should be allowed with SHAKE256-only when curve is known");

    params.kmip_policy.allowlists.algorithms = Some(vec![
        CryptographicAlgorithm::EC,
        CryptographicAlgorithm::SHAKE128,
    ]);
    assert_policy_denied(enforce_ecies_fixed_suite_for_attributes(
        &params, "Encrypt", "e2e-key", &attrs,
    ));
}

#[cfg(feature = "non-fips")]
async fn create_kek_and_target_for_export<B, S>(app: &S) -> (String, String)
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    fn create_aes_key_request(tag: &str) -> Operation {
        Operation::Create(Create {
            object_type: cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_objects::ObjectType::SymmetricKey,
            attributes: Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                cryptographic_length: Some(256),
                cryptographic_usage_mask: Some(
                    cosmian_kms_server_database::reexport::cosmian_kmip::kmip_0::kmip_types::CryptographicUsageMask::WrapKey
                        | cosmian_kms_server_database::reexport::cosmian_kmip::kmip_0::kmip_types::CryptographicUsageMask::Encrypt,
                ),
                activation_date: Some(
                    time_normalize().expect("time_normalize should work"),
                ),
                // Use Alternative Name as a lightweight label.
                alternative_name: Some(
                    cosmian_kms_server_database::reexport::cosmian_kmip::kmip_0::kmip_types::AlternativeName {
                        alternative_name_type: cosmian_kms_server_database::reexport::cosmian_kmip::kmip_0::kmip_types::AlternativeNameType::UninterpretedTextString,
                        alternative_name_value: tag.to_owned(),
                    },
                ),
                ..Default::default()
            },
            protection_storage_masks: None,
        })
    }

    // Create a symmetric KEK (wrapping key)
    let kek_req = create_aes_key_request("e2e-kek");
    let kek_resp: cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::CreateResponse =
        post_2_1(app, &kek_req).await.unwrap();
    let kek_uid = kek_resp
        .unique_identifier
        .as_str()
        .expect("kek uid should be a string")
        .to_owned();

    // Create a target symmetric key to export
    let target_req = create_aes_key_request("e2e-target");
    let target_resp: cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::CreateResponse =
        post_2_1(app, &target_req).await.unwrap();
    let target_uid = target_resp
        .unique_identifier
        .as_str()
        .expect("target uid should be a string")
        .to_owned();

    (kek_uid, target_uid)
}

#[cfg(feature = "non-fips")]
#[actix_web::test]
async fn e2e_kmip_policy_key_wrapping_aes_kw_suite_requires_aes_and_nist_key_wrap() {
    let mut conf = https_clap_config_opts(None);
    conf.kmip.allowlists.algorithms = Some(vec![CryptographicAlgorithm::AES]);
    conf.kmip.allowlists.block_cipher_modes = Some(vec![BlockCipherMode::NISTKeyWrap]);
    conf.kmip.enforce = true;

    let app = Box::pin(test_app_with_clap_config(conf, None)).await;
    let (kek_uid, target_uid) = create_kek_and_target_for_export(&app).await;

    let export = export_request(
        &target_uid,
        false,
        Some(&kek_uid),
        None,
        false,
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            block_cipher_mode: Some(BlockCipherMode::NISTKeyWrap),
            ..Default::default()
        }),
        None,
    );

    let _resp: cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::ExportResponse =
        post_2_1(&app, &export).await.unwrap();
}

#[cfg(feature = "non-fips")]
#[actix_web::test]
async fn e2e_kmip_policy_key_wrapping_aes_kwp_suite_requires_aes_and_kwp_mode() {
    let mut conf = https_clap_config_opts(None);
    conf.kmip.allowlists.algorithms = Some(vec![CryptographicAlgorithm::AES]);
    conf.kmip.allowlists.block_cipher_modes = Some(vec![BlockCipherMode::AESKeyWrapPadding]);
    conf.kmip.enforce = true;

    let app = Box::pin(test_app_with_clap_config(conf, None)).await;
    let (kek_uid, target_uid) = create_kek_and_target_for_export(&app).await;

    let export = export_request(
        &target_uid,
        false,
        Some(&kek_uid),
        None,
        false,
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            block_cipher_mode: Some(BlockCipherMode::AESKeyWrapPadding),
            ..Default::default()
        }),
        None,
    );

    let _resp: cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::ExportResponse =
        post_2_1(&app, &export).await.unwrap();
}

#[cfg(feature = "non-fips")]
#[actix_web::test]
async fn e2e_kmip_policy_key_wrapping_aes_gcm_suite_requires_aes_and_gcm() {
    let mut conf = https_clap_config_opts(None);
    conf.kmip.allowlists.algorithms = Some(vec![CryptographicAlgorithm::AES]);
    conf.kmip.allowlists.block_cipher_modes = Some(vec![BlockCipherMode::GCM]);
    conf.kmip.enforce = true;

    let app = Box::pin(test_app_with_clap_config(conf, None)).await;
    let (kek_uid, target_uid) = create_kek_and_target_for_export(&app).await;

    let export = export_request(
        &target_uid,
        false,
        Some(&kek_uid),
        None,
        false,
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            block_cipher_mode: Some(BlockCipherMode::GCM),
            ..Default::default()
        }),
        None,
    );

    let _resp: cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::ExportResponse =
        post_2_1(&app, &export).await.unwrap();
}

#[cfg(feature = "non-fips")]
#[actix_web::test]
async fn e2e_kmip_policy_key_wrapping_rsa_pkcs1v15_sha256_suite_requires_rsa_pkcs1v15_and_sha256() {
    let mut conf = https_clap_config_opts(None);
    conf.kmip.allowlists.algorithms = Some(vec![
        CryptographicAlgorithm::AES,
        CryptographicAlgorithm::RSA,
    ]);
    conf.kmip.allowlists.padding_methods = Some(vec![PaddingMethod::PKCS1v15]);
    conf.kmip.allowlists.hashes = Some(vec![HashingAlgorithm::SHA256]);
    conf.kmip.enforce = true;

    let app = Box::pin(test_app_with_clap_config(conf, None)).await;
    let (_kek_uid, target_uid) = create_kek_and_target_for_export(&app).await;

    // NOTE: For RSA wrapping suites, the wrapping key should be an RSA key.
    // Here we only validate that the KMIP policy is exposed and enforced end-to-end
    // at request parsing time: we send an Export request that declares RSA+PKCS1v1.5+SHA256
    // in its wrapping CryptographicParameters.
    //
    // The request will be rejected later by runtime wrapping if the KEK is not RSA.
    // So we use a non-existent placeholder uid and assert policy passes but runtime fails
    // with a non-policy error.

    let export = export_request(
        &target_uid,
        false,
        Some("placeholder-rsa-kek"),
        None,
        false,
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::PKCS1v15),
            hashing_algorithm: Some(HashingAlgorithm::SHA256),
            ..Default::default()
        }),
        None,
    );

    let err = post_2_1::<_, _, cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::ExportResponse, _>(&app, &export)
        .await
        .unwrap_err();
    assert!(
        !matches!(
            err,
            KmsError::Kmip21Error(ErrorReason::Constraint_Violation, _)
        ),
        "should not fail at KMIP policy level"
    );
}

#[cfg(feature = "non-fips")]
#[actix_web::test]
async fn e2e_kmip_policy_key_wrapping_rsa_oaep_sha256_suite_requires_rsa_oaep_and_sha256() {
    let mut conf = https_clap_config_opts(None);
    conf.kmip.allowlists.algorithms = Some(vec![
        CryptographicAlgorithm::AES,
        CryptographicAlgorithm::RSA,
    ]);
    conf.kmip.allowlists.padding_methods = Some(vec![PaddingMethod::OAEP]);
    conf.kmip.allowlists.hashes = Some(vec![HashingAlgorithm::SHA256]);
    conf.kmip.enforce = true;

    let app = Box::pin(test_app_with_clap_config(conf, None)).await;
    let (_kek_uid, target_uid) = create_kek_and_target_for_export(&app).await;

    let export = export_request(
        &target_uid,
        false,
        Some("placeholder-rsa-kek"),
        None,
        false,
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::OAEP),
            hashing_algorithm: Some(HashingAlgorithm::SHA256),
            ..Default::default()
        }),
        None,
    );

    let err = post_2_1::<
        _,
        _,
        cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::ExportResponse,
        _,
    >(&app, &export)
    .await
    .unwrap_err();
    assert!(
        !matches!(
            err,
            KmsError::Kmip21Error(ErrorReason::Constraint_Violation, _)
        ),
        "should not fail at KMIP policy level"
    );
}

#[cfg(feature = "non-fips")]
#[actix_web::test]
async fn e2e_kmip_policy_key_wrapping_rsa_aes_key_wrap_sha256_suite_requires_rsa_and_sha256() {
    let mut conf = https_clap_config_opts(None);
    conf.kmip.allowlists.algorithms = Some(vec![
        CryptographicAlgorithm::AES,
        CryptographicAlgorithm::RSA,
    ]);
    conf.kmip.allowlists.padding_methods = Some(vec![PaddingMethod::None]);
    conf.kmip.allowlists.hashes = Some(vec![HashingAlgorithm::SHA256]);
    conf.kmip.enforce = true;

    let app = Box::pin(test_app_with_clap_config(conf, None)).await;
    let (_kek_uid, target_uid) = create_kek_and_target_for_export(&app).await;

    let export = export_request(
        &target_uid,
        false,
        Some("placeholder-rsa-kek"),
        None,
        false,
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::None),
            hashing_algorithm: Some(HashingAlgorithm::SHA256),
            ..Default::default()
        }),
        None,
    );

    let err = post_2_1::<
        _,
        _,
        cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::ExportResponse,
        _,
    >(&app, &export)
    .await
    .unwrap_err();
    assert!(
        !matches!(
            err,
            KmsError::Kmip21Error(ErrorReason::Constraint_Violation, _)
        ),
        "should not fail at KMIP policy level"
    );
}

#[cfg(feature = "non-fips")]
#[test]
fn ecies_standard_curve_is_denied_when_shake128_is_not_allowed() {
    let mut conf = ClapConfig::default();
    // Ensure ECIES is enabled via curve allowlist, but exclude SHAKE128 from algorithms.
    conf.kmip.allowlists.curves = Some(vec![RecommendedCurve::P256]);
    conf.kmip.allowlists.algorithms = Some(vec![CryptographicAlgorithm::EC]);
    let mut params = params_with_allowlists(conf);
    params.kmip_policy.enforce = true;

    let res = enforce_ecies_fixed_suite_for_pkey_id(
        &params,
        "Encrypt",
        "test-key",
        openssl::pkey::Id::EC,
    );

    assert_policy_denied(res);
}

#[cfg(feature = "non-fips")]
#[test]
fn ecies_standard_curve_is_allowed_when_shake128_is_allowed() {
    let mut conf = ClapConfig::default();
    conf.kmip.allowlists.curves = Some(vec![RecommendedCurve::P256]);
    conf.kmip.allowlists.algorithms = Some(vec![
        CryptographicAlgorithm::EC,
        CryptographicAlgorithm::SHAKE128,
        CryptographicAlgorithm::SHAKE256,
    ]);
    let mut params = params_with_allowlists(conf);
    params.kmip_policy.enforce = true;

    enforce_ecies_fixed_suite_for_pkey_id(&params, "Encrypt", "test-key", openssl::pkey::Id::EC)
        .expect("ECIES on standard curve should be allowed when SHAKE128 is allowlisted");
}

#[cfg(feature = "non-fips")]
#[test]
fn ecies_standard_curve_is_denied_when_shake256_is_not_allowed_in_strict_mode() {
    let mut conf = ClapConfig::default();
    conf.kmip.allowlists.curves = Some(vec![RecommendedCurve::P256]);
    // Strict fallback for standard curves requires both SHAKE128 and SHAKE256.
    conf.kmip.allowlists.algorithms = Some(vec![
        CryptographicAlgorithm::EC,
        CryptographicAlgorithm::SHAKE128,
    ]);
    let mut params = params_with_allowlists(conf);
    params.kmip_policy.enforce = true;

    let res = enforce_ecies_fixed_suite_for_pkey_id(
        &params,
        "Encrypt",
        "test-key",
        openssl::pkey::Id::EC,
    );

    assert_policy_denied(res);
}

#[cfg(feature = "non-fips")]
#[test]
fn ecies_p384_requires_shake256_when_curve_is_known_from_attributes() {
    let mut conf = ClapConfig::default();
    conf.kmip.allowlists.curves = Some(vec![RecommendedCurve::P384]);
    conf.kmip.allowlists.algorithms = Some(vec![
        CryptographicAlgorithm::EC,
        CryptographicAlgorithm::SHAKE128,
        CryptographicAlgorithm::SHAKE256,
    ]);
    let mut params = params_with_allowlists(conf);
    params.kmip_policy.enforce = true;

    // Tighten algorithms to *exclude* SHAKE256 and assert denial.
    params.kmip_policy.allowlists.algorithms = Some(vec![
        CryptographicAlgorithm::EC,
        CryptographicAlgorithm::SHAKE128,
    ]);

    let attrs = Attributes {
        cryptographic_domain_parameters: Some(
            cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::CryptographicDomainParameters {
                recommended_curve: Some(RecommendedCurve::P384),
                ..Default::default()
            },
        ),
        ..Default::default()
    };

    assert_policy_denied(enforce_ecies_fixed_suite_for_attributes(
        &params, "Encrypt", "test-key", &attrs,
    ));

    // Now allow SHAKE256 and ensure it passes.
    params.kmip_policy.allowlists.algorithms = Some(vec![
        CryptographicAlgorithm::EC,
        CryptographicAlgorithm::SHAKE256,
    ]);

    enforce_ecies_fixed_suite_for_attributes(&params, "Encrypt", "test-key", &attrs)
        .expect("P-384 ECIES should require SHAKE256 when curve is known");
}

#[test]
fn default_policy_allows_aes_gcm_encrypt_params() {
    let params = params_with_default_policy();

    let op = Operation::Encrypt(Box::new(Encrypt {
        unique_identifier: None,
        cryptographic_parameters: Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            block_cipher_mode: Some(BlockCipherMode::GCM),
            padding_method: None,
            hashing_algorithm: None,
            digital_signature_algorithm: None,
            ..Default::default()
        }),
        data: None,
        i_v_counter_nonce: None,
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: None,
    }));

    enforce(&params, "Encrypt", &op).expect("AES-GCM should be allowed by default policy");
}

#[test]
fn default_policy_denies_deprecated_algorithm_des() {
    let params = params_with_default_policy();

    let op = Operation::Create(Create {
        object_type: cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_objects::ObjectType::SymmetricKey,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::DES),
            cryptographic_length: Some(56),
            ..Default::default()
        },
        protection_storage_masks: None,
    });

    assert_policy_denied(enforce(&params, "Create", &op));
}

#[test]
fn default_policy_denies_aes_invalid_key_size() {
    let params = params_with_default_policy();

    let op = Operation::Create(Create {
        object_type: cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_objects::ObjectType::SymmetricKey,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(64),
            ..Default::default()
        },
        protection_storage_masks: None,
    });

    assert_policy_denied(enforce(&params, "Create", &op));
}

#[test]
fn aes_key_sizes_allowlist_denies_non_standard_size() {
    let mut conf = ClapConfig::default();
    // Allow only standard AES key sizes.
    conf.kmip.allowlists.aes_key_sizes = Some(vec![
        crate::config::AesKeySize::Aes128,
        crate::config::AesKeySize::Aes192,
        crate::config::AesKeySize::Aes256,
    ]);
    let mut params = params_with_allowlists(conf);
    params.kmip_policy.enforce = true;

    // 320 is non-standard and must be denied when allowlisted.
    let op = Operation::Create(Create {
        object_type: cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_objects::ObjectType::SymmetricKey,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(320),
            ..Default::default()
        },
        protection_storage_masks: None,
    });

    assert_policy_denied(enforce(&params, "Create", &op));
}

#[test]
fn default_policy_denies_rsa_too_small() {
    let params = params_with_default_policy();

    let op = Operation::Create(Create {
        object_type: cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_objects::ObjectType::PublicKey,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            cryptographic_length: Some(1024),
            ..Default::default()
        },
        protection_storage_masks: None,
    });

    assert_policy_denied(enforce(&params, "Create", &op));
}

#[test]
fn rsa_key_sizes_allowlist_denies_non_standard_size() {
    let mut conf = ClapConfig::default();
    // Allow a typical RSA key size set.
    conf.kmip.allowlists.rsa_key_sizes = Some(vec![
        crate::config::RsaKeySize::Rsa2048,
        crate::config::RsaKeySize::Rsa3072,
        crate::config::RsaKeySize::Rsa4096,
    ]);
    let mut params = params_with_allowlists(conf);
    params.kmip_policy.enforce = true;

    // 3073 is non-standard and must be denied when allowlisted.
    let op = Operation::Create(Create {
        object_type: cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_objects::ObjectType::PublicKey,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            cryptographic_length: Some(3073),
            ..Default::default()
        },
        protection_storage_masks: None,
    });

    assert_policy_denied(enforce(&params, "Create", &op));
}

#[test]
fn default_policy_denies_disallowed_block_cipher_mode_ecb() {
    let mut conf = ClapConfig::default();
    // Default policy is unrestricted (no allowlists). To test an allowlist denial,
    // explicitly configure a block cipher mode allowlist that excludes ECB.
    conf.kmip.allowlists.block_cipher_modes = Some(vec![BlockCipherMode::GCM]);
    let mut params = params_with_allowlists(conf);
    params.kmip_policy.enforce = true;

    let op = Operation::Encrypt(Box::new(Encrypt {
        unique_identifier: None,
        cryptographic_parameters: Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            block_cipher_mode: Some(BlockCipherMode::ECB),
            ..Default::default()
        }),
        data: None,
        i_v_counter_nonce: None,
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: None,
    }));

    assert_policy_denied(enforce(&params, "Encrypt", &op));
}

#[test]
fn override_allowlists_can_tighten_policy() {
    let mut conf = ClapConfig::default();

    // Only allow RSA for algorithms, and only allow SHA512 for hashes.
    conf.kmip.allowlists.algorithms = Some(vec![CryptographicAlgorithm::RSA]);
    conf.kmip.allowlists.hashes = Some(vec![HashingAlgorithm::SHA512]);
    conf.kmip.allowlists.signature_algorithms = Some(vec![
        DigitalSignatureAlgorithm::SHA512WithRSAEncryption,
        DigitalSignatureAlgorithm::RSASSAPSS,
    ]);
    conf.kmip.allowlists.curves = Some(vec![RecommendedCurve::P256]);
    conf.kmip.allowlists.block_cipher_modes = Some(vec![BlockCipherMode::GCM]);
    conf.kmip.allowlists.padding_methods = Some(vec![PaddingMethod::OAEP]);
    conf.kmip.allowlists.mgf_hashes = Some(vec![HashingAlgorithm::SHA512]);

    let mut params = params_with_allowlists(conf);
    params.kmip_policy.enforce = true;

    // AES should now be denied.
    let create_aes = Operation::Create(Create {
        object_type: cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_objects::ObjectType::SymmetricKey,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(256),
            ..Default::default()
        },
        protection_storage_masks: None,
    });
    assert_policy_denied(enforce(&params, "Create", &create_aes));

    // Hashing algorithm SHA256 should be denied.
    let op_hash = Operation::Hash(
        cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::Hash {
            cryptographic_parameters: CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA256),
                ..Default::default()
            },
            data: None,
            correlation_value: None,
            init_indicator: None,
            final_indicator: None,
        },
    );
    assert_policy_denied(enforce(&params, "Hash", &op_hash));
}

#[test]
fn default_policy_allows_signature_algorithm_rsa_sha256() {
    let params = params_with_default_policy();

    // Validate via Create attributes.
    let op = Operation::Create(Create {
        object_type: cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_objects::ObjectType::PrivateKey,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            // Default policy denies RSA-2048 (ANSSI guide); use 3072+.
            cryptographic_length: Some(3072),
            digital_signature_algorithm: Some(DigitalSignatureAlgorithm::SHA256WithRSAEncryption),
            ..Default::default()
        },
        protection_storage_masks: None,
    });

    enforce(&params, "Create", &op)
        .expect("RSA+SHA256 signature algorithm should be allowed by default policy");
}

#[test]
fn default_policy_allows_curve_p256() {
    let params = params_with_default_policy();

    let op = Operation::Create(Create {
        object_type: cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_objects::ObjectType::PublicKey,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::EC),
            cryptographic_domain_parameters: Some(
                cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::CryptographicDomainParameters {
                    recommended_curve: Some(RecommendedCurve::P256),
                    ..Default::default()
                },
            ),
            ..Default::default()
        },
        protection_storage_masks: None,
    });

    enforce(&params, "Create", &op).expect("P256 should be allowed by default policy");
}

#[test]
fn default_policy_denies_padding_method_none_allowed_list() {
    // Create a config that only allows PKCS5 padding.
    let mut conf = ClapConfig::default();
    conf.kmip.allowlists.padding_methods = Some(vec![PaddingMethod::PKCS5]);
    let mut params = params_with_allowlists(conf);
    params.kmip_policy.enforce = true;

    // OAEP should now be denied.
    let op = Operation::Encrypt(Box::new(Encrypt {
        unique_identifier: None,
        cryptographic_parameters: Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::OAEP),
            ..Default::default()
        }),
        data: None,
        i_v_counter_nonce: None,
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: None,
    }));

    assert_policy_denied(enforce(&params, "Encrypt", &op));
}

#[test]
fn enforced_policy_with_empty_allowlists_denies_all_operations() {
    let mut conf = ClapConfig::default();

    // Explicitly configure empty allowlists: with enforcement enabled,
    // `allow()` will require membership and thus deny all tokens.
    conf.kmip.allowlists.algorithms = Some(vec![]);
    conf.kmip.allowlists.hashes = Some(vec![]);
    conf.kmip.allowlists.signature_algorithms = Some(vec![]);
    conf.kmip.allowlists.curves = Some(vec![]);
    conf.kmip.allowlists.block_cipher_modes = Some(vec![]);
    conf.kmip.allowlists.padding_methods = Some(vec![]);
    conf.kmip.allowlists.mgf_hashes = Some(vec![]);
    // Note: `rsa_key_sizes`/`aes_key_sizes` are enforced at request-time.
    // The deny-all semantics are exercised via other empty allowlists.

    let mut params = params_with_allowlists(conf);
    params.kmip_policy.enforce = true;

    // Create: denied for every algorithm (algorithms allowlist is empty).
    // Note: not all algorithms support Create as a symmetric key in a real KMIP server,
    // but policy evaluation happens before operation execution, so the policy must deny
    // them uniformly here.
    for alg in CryptographicAlgorithm::iter() {
        let create = Operation::Create(Create {
            object_type: cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_objects::ObjectType::SymmetricKey,
            attributes: Attributes {
                cryptographic_algorithm: Some(alg),
                cryptographic_length: Some(256),
                ..Default::default()
            },
            protection_storage_masks: None,
        });
        assert_policy_denied(enforce(&params, "Create", &create));
    }

    // Encrypt: denied (algorithm + mode allowlists empty).
    let encrypt = Operation::Encrypt(Box::new(Encrypt {
        unique_identifier: None,
        cryptographic_parameters: Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            block_cipher_mode: Some(BlockCipherMode::GCM),
            ..Default::default()
        }),
        data: None,
        i_v_counter_nonce: None,
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: None,
    }));
    assert_policy_denied(enforce(&params, "Encrypt", &encrypt));

    // Hash: denied (hash allowlist empty).
    let hash = Operation::Hash(
        cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::Hash {
            cryptographic_parameters: CryptographicParameters {
                hashing_algorithm: Some(HashingAlgorithm::SHA256),
                ..Default::default()
            },
            data: None,
            correlation_value: None,
            init_indicator: None,
            final_indicator: None,
        },
    );
    assert_policy_denied(enforce(&params, "Hash", &hash));
}
