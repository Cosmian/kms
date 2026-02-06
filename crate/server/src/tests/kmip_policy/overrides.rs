#![allow(clippy::unwrap_used, clippy::expect_used)]

#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::CreateResponse;
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{BlockCipherMode, HashingAlgorithm, PaddingMethod},
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_objects::ObjectType,
        kmip_operations::{Create, Hash, Operation},
        kmip_types::{
            CryptographicAlgorithm, CryptographicDomainParameters, CryptographicParameters,
            DigitalSignatureAlgorithm, RecommendedCurve,
        },
    },
};

#[cfg(feature = "non-fips")]
use super::helpers::{assert_constraint_violation, https_clap_config_opts};
use super::helpers::{assert_policy_denied, enforce, params_with_allowlists};
#[cfg(feature = "non-fips")]
use crate::tests::test_utils::{post_2_1, test_app_with_clap_config};

#[test]
fn override_allowlists_can_tighten_policy() {
    let mut conf = crate::config::ClapConfig::default();

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

    let create_aes = Operation::Create(Create {
        object_type: ObjectType::SymmetricKey,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(256),
            ..Default::default()
        },
        protection_storage_masks: None,
    });
    assert_policy_denied(enforce(&params, "Create", &create_aes));

    let op_hash = Operation::Hash(Hash {
        cryptographic_parameters: CryptographicParameters {
            hashing_algorithm: Some(HashingAlgorithm::SHA256),
            ..Default::default()
        },
        data: None,
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
    });
    assert_policy_denied(enforce(&params, "Hash", &op_hash));

    // Sanity: curve also restricted.
    let create_ec = Operation::Create(Create {
        object_type: ObjectType::PublicKey,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::EC),
            cryptographic_domain_parameters: Some(CryptographicDomainParameters {
                recommended_curve: Some(RecommendedCurve::P384),
                ..Default::default()
            }),
            ..Default::default()
        },
        protection_storage_masks: None,
    });
    assert_policy_denied(enforce(&params, "Create", &create_ec));
}

#[cfg(feature = "non-fips")]
#[actix_web::test]
async fn e2e_override_allowlists_can_tighten_policy() {
    let mut conf = https_clap_config_opts(None);

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
    conf.kmip.enforce = true;

    let app = Box::pin(test_app_with_clap_config(conf, None)).await;

    let create_aes = Operation::Create(Create {
        object_type: ObjectType::SymmetricKey,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(256),
            ..Default::default()
        },
        protection_storage_masks: None,
    });
    let err = post_2_1::<_, _, CreateResponse, _>(&app, &create_aes)
        .await
        .unwrap_err();
    assert_constraint_violation(err);

    let op_hash = Operation::Hash(Hash {
        cryptographic_parameters: CryptographicParameters {
            hashing_algorithm: Some(HashingAlgorithm::SHA256),
            ..Default::default()
        },
        data: Some(Vec::from(&b"hello"[..])),
        ..Default::default()
    });
    let err = post_2_1::<_, _, cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::HashResponse, _>(
        &app,
        &op_hash,
    )
    .await
    .unwrap_err();
    assert_constraint_violation(err);
}
