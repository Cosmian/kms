use cosmian_kms_client_utils::export_utils::export_request;
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{
        AlternativeName, AlternativeNameType, BlockCipherMode, CryptographicUsageMask, ErrorReason,
        HashingAlgorithm, PaddingMethod,
    },
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_objects::ObjectType,
        kmip_operations::{Create, CreateResponse, ExportResponse},
        kmip_types::{CryptographicAlgorithm, CryptographicParameters},
    },
    time_normalize,
};

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
