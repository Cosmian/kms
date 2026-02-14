#[cfg(feature = "non-fips")]
use cosmian_kms_client_utils::configurable_kem_utils::build_create_configurable_kem_keypair_request;
use cosmian_kms_client_utils::export_utils::export_request;
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{
        AlternativeName, AlternativeNameType, BlockCipherMode, CryptographicUsageMask, ErrorReason,
        HashingAlgorithm, PaddingMethod,
    },
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_objects::ObjectType,
        kmip_operations::{
            Create, CreateKeyPairResponse, CreateResponse, DecryptResponse, EncryptResponse,
            ExportResponse,
        },
        kmip_types::{CryptographicAlgorithm, CryptographicParameters},
        requests::{decrypt_request, encrypt_request},
    },
    time_normalize,
};

#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kms_crypto::reexport::cosmian_crypto_core::bytes_ser_de::Serializable;
#[cfg(feature = "non-fips")]
use zeroize::Zeroizing;

use crate::{
    error::KmsError,
    tests::test_utils::{https_clap_config_opts, post_2_1, test_app_with_clap_config},
};

async fn create_kek_and_target_for_export<B, S>(app: &S) -> (String, String)
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
    B: actix_web::body::MessageBody,
{
    fn create_aes_key_request(
        tag: &str,
    ) -> cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::Operation
    {
        cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::Operation::Create(
            Create {
                object_type: ObjectType::SymmetricKey,
                attributes: Attributes {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                    cryptographic_length: Some(256),
                    cryptographic_usage_mask: Some(
                        CryptographicUsageMask::WrapKey | CryptographicUsageMask::Encrypt,
                    ),
                    activation_date: Some(time_normalize().expect("time_normalize should work")),
                    alternative_name: Some(AlternativeName {
                        alternative_name_type: AlternativeNameType::UninterpretedTextString,
                        alternative_name_value: tag.to_owned(),
                    }),
                    ..Default::default()
                },
                protection_storage_masks: None,
            },
        )
    }

    let kek_req = create_aes_key_request("e2e-kek");
    let kek_resp: CreateResponse = post_2_1(app, &kek_req).await.unwrap();
    let kek_uid = kek_resp
        .unique_identifier
        .as_str()
        .expect("kek uid should be a string")
        .to_owned();

    let target_req = create_aes_key_request("e2e-target");
    let target_resp: CreateResponse = post_2_1(app, &target_req).await.unwrap();
    let target_uid = target_resp
        .unique_identifier
        .as_str()
        .expect("target uid should be a string")
        .to_owned();

    (kek_uid, target_uid)
}

#[actix_web::test]
async fn e2e_kmip_policy_key_wrapping_aes_kw_suite_requires_aes_and_nist_key_wrap() {
    let mut conf = https_clap_config_opts(None);
    conf.kmip_policy.allowlists.algorithms = Some(vec![CryptographicAlgorithm::AES]);
    conf.kmip_policy.allowlists.block_cipher_modes = Some(vec![BlockCipherMode::NISTKeyWrap]);
    conf.kmip_policy.policy_id = Some("CUSTOM".to_owned());

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

    let _resp: ExportResponse = post_2_1(&app, &export).await.unwrap();
}

#[actix_web::test]
async fn e2e_kmip_policy_key_wrapping_aes_kwp_suite_requires_aes_and_kwp_mode() {
    let mut conf = https_clap_config_opts(None);
    conf.kmip_policy.allowlists.algorithms = Some(vec![CryptographicAlgorithm::AES]);
    conf.kmip_policy.allowlists.block_cipher_modes = Some(vec![BlockCipherMode::AESKeyWrapPadding]);
    conf.kmip_policy.policy_id = Some("CUSTOM".to_owned());

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

    let _resp: ExportResponse = post_2_1(&app, &export).await.unwrap();
}

#[actix_web::test]
async fn e2e_kmip_policy_key_wrapping_aes_gcm_suite_requires_aes_and_gcm() {
    let mut conf = https_clap_config_opts(None);
    conf.kmip_policy.allowlists.algorithms = Some(vec![CryptographicAlgorithm::AES]);
    conf.kmip_policy.allowlists.block_cipher_modes = Some(vec![BlockCipherMode::GCM]);
    conf.kmip_policy.policy_id = Some("CUSTOM".to_owned());

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

    let _resp: ExportResponse = post_2_1(&app, &export).await.unwrap();
}

#[actix_web::test]
async fn e2e_kmip_policy_key_wrapping_rsa_oaep_sha256_suite_requires_rsa_oaep_and_sha256() {
    let mut conf = https_clap_config_opts(None);
    conf.kmip_policy.allowlists.algorithms = Some(vec![
        CryptographicAlgorithm::AES,
        CryptographicAlgorithm::RSA,
    ]);
    conf.kmip_policy.allowlists.padding_methods = Some(vec![PaddingMethod::OAEP]);
    conf.kmip_policy.allowlists.hashes = Some(vec![HashingAlgorithm::SHA256]);
    conf.kmip_policy.policy_id = Some("CUSTOM".to_owned());

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

    let err = post_2_1::<_, _, ExportResponse, _>(&app, &export)
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

#[actix_web::test]
async fn e2e_kmip_policy_key_wrapping_rsa_aes_key_wrap_sha256_suite_requires_rsa_and_sha256() {
    let mut conf = https_clap_config_opts(None);
    conf.kmip_policy.allowlists.algorithms = Some(vec![
        CryptographicAlgorithm::AES,
        CryptographicAlgorithm::RSA,
    ]);
    conf.kmip_policy.allowlists.padding_methods = Some(vec![PaddingMethod::None]);
    conf.kmip_policy.allowlists.hashes = Some(vec![HashingAlgorithm::SHA256]);
    conf.kmip_policy.policy_id = Some("CUSTOM".to_owned());

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

    let err = post_2_1::<_, _, ExportResponse, _>(&app, &export)
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
async fn e2e_default_policy_allows_configurable_kem_roundtrip() {
    let mut conf = https_clap_config_opts(None);
    conf.kmip_policy.policy_id = Some("DEFAULT".to_owned());

    let app = Box::pin(test_app_with_clap_config(conf, None)).await;

    // Use a pre-quantum KEM tag (P-256) so the request does not include a nested
    // post-quantum `CryptographicAlgorithm` in `CryptographicParameters`.
    let create_kp = build_create_configurable_kem_keypair_request(
        None,
        ["e2e-configurable-kem"],
        10,
        false,
        None,
    )
    .expect("build_create_configurable_kem_keypair_request should build");
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
    let sk_uid = create_resp
        .private_key_unique_identifier
        .as_str()
        .expect("private key uid should be a string")
        .to_owned();

    let enc_req = encrypt_request(
        &pk_uid_for_encrypt,
        None,
        Vec::new(),
        None,
        None,
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::ConfigurableKEM),
            ..Default::default()
        }),
    )
    .expect("encrypt_request should build");
    let enc_resp: EncryptResponse = post_2_1(&app, &enc_req).await.unwrap();
    let enc_data = enc_resp.data.expect("encrypt response should include data");

    let (expected_key, encapsulation) =
        <(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>)>::deserialize(&enc_data)
            .expect("configurable-kem encrypt response should deserialize");

    let dec_req = decrypt_request(
        &sk_uid,
        None,
        encapsulation.to_vec(),
        None,
        None,
        Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::ConfigurableKEM),
            ..Default::default()
        }),
    );
    let dec_resp: DecryptResponse = post_2_1(&app, &dec_req).await.unwrap();
    let recovered_key = dec_resp.data.expect("decrypt response should include data");

    assert_eq!(recovered_key.to_vec(), expected_key.to_vec());
}
