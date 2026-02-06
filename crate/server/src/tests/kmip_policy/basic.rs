#![allow(clippy::unwrap_used, clippy::expect_used)]

#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_0::kmip_types::AlternativeName;
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_0::kmip_types::{
    AlternativeNameType, CryptographicUsageMask,
};
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::{
    CreateKeyPairResponse, CreateResponse, EncryptResponse,
};
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::UniqueIdentifier;
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::requests::create_ec_key_pair_request;
#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kmip::time_normalize;
use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{BlockCipherMode, HashingAlgorithm, PaddingMethod},
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_objects::ObjectType,
        kmip_operations::{Create, Encrypt, Hash, Operation},
        kmip_types::{
            CryptographicAlgorithm, CryptographicDomainParameters, CryptographicParameters,
            DigitalSignatureAlgorithm, RecommendedCurve,
        },
    },
};
use strum::IntoEnumIterator;
use zeroize::Zeroizing;

#[cfg(feature = "non-fips")]
use super::helpers::{
    assert_constraint_violation, create_aes_key_with_size, https_clap_config_opts,
};
use super::helpers::{
    assert_policy_denied, enforce, params_with_allowlists, params_with_default_policy,
};
#[cfg(feature = "non-fips")]
use crate::tests::test_utils::{post_2_1, test_app_with_clap_config};

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

#[cfg(feature = "non-fips")]
#[actix_web::test]
async fn e2e_default_policy_allows_aes_gcm_encrypt_params() {
    let mut conf = https_clap_config_opts(None);
    conf.kmip.enforce = true;
    let app = Box::pin(test_app_with_clap_config(conf, None)).await;

    let key_uid = create_aes_key_with_size(&app, "e2e-aes-gcm", 256)
        .await
        .expect("create AES key should succeed");

    let req = Operation::Encrypt(Box::new(Encrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(key_uid)),
        cryptographic_parameters: Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            block_cipher_mode: Some(BlockCipherMode::GCM),
            ..Default::default()
        }),
        data: Some(Zeroizing::new(b"hello".to_vec())),
        ..Default::default()
    }));

    let _resp: EncryptResponse = post_2_1(&app, &req)
        .await
        .expect("AES-GCM encrypt should be allowed by default policy");
}

#[test]
fn default_policy_denies_deprecated_algorithm_des() {
    let params = params_with_default_policy();

    let op = Operation::Create(Create {
        object_type: ObjectType::SymmetricKey,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::DES),
            cryptographic_length: Some(56),
            ..Default::default()
        },
        protection_storage_masks: None,
    });

    assert_policy_denied(enforce(&params, "Create", &op));
}

#[cfg(feature = "non-fips")]
#[actix_web::test]
async fn e2e_default_policy_denies_deprecated_algorithm_des() {
    let mut conf = https_clap_config_opts(None);
    conf.kmip.enforce = true;
    let app = Box::pin(test_app_with_clap_config(conf, None)).await;

    let req = Operation::Create(Create {
        object_type: ObjectType::SymmetricKey,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::DES),
            cryptographic_length: Some(56),
            ..Default::default()
        },
        protection_storage_masks: None,
    });

    let _err = post_2_1::<_, _, CreateResponse, _>(&app, &req)
        .await
        .unwrap_err();
}

#[test]
fn default_policy_denies_aes_invalid_key_size() {
    let params = params_with_default_policy();

    let op = Operation::Create(Create {
        object_type: ObjectType::SymmetricKey,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(64),
            ..Default::default()
        },
        protection_storage_masks: None,
    });

    assert_policy_denied(enforce(&params, "Create", &op));
}

#[cfg(feature = "non-fips")]
#[actix_web::test]
async fn e2e_default_policy_denies_aes_invalid_key_size() {
    let mut conf = https_clap_config_opts(None);
    conf.kmip.enforce = true;
    let app = Box::pin(test_app_with_clap_config(conf, None)).await;

    let req = Operation::Create(Create {
        object_type: ObjectType::SymmetricKey,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(64),
            ..Default::default()
        },
        protection_storage_masks: None,
    });

    let err = post_2_1::<_, _, CreateResponse, _>(&app, &req)
        .await
        .unwrap_err();
    assert_constraint_violation(err);
}

#[test]
fn aes_key_sizes_allowlist_denies_non_standard_size() {
    let mut conf = crate::config::ClapConfig::default();
    conf.kmip.allowlists.aes_key_sizes = Some(vec![
        crate::config::AesKeySize::Aes128,
        crate::config::AesKeySize::Aes192,
        crate::config::AesKeySize::Aes256,
    ]);
    let mut params = params_with_allowlists(conf);
    params.kmip_policy.enforce = true;

    let op = Operation::Create(Create {
        object_type: ObjectType::SymmetricKey,
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
        object_type: ObjectType::PublicKey,
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
    let mut conf = crate::config::ClapConfig::default();
    conf.kmip.allowlists.rsa_key_sizes = Some(vec![
        crate::config::RsaKeySize::Rsa2048,
        crate::config::RsaKeySize::Rsa3072,
        crate::config::RsaKeySize::Rsa4096,
    ]);
    let mut params = params_with_allowlists(conf);
    params.kmip_policy.enforce = true;

    let op = Operation::Create(Create {
        object_type: ObjectType::PublicKey,
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
    let mut conf = crate::config::ClapConfig::default();
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

#[cfg(feature = "non-fips")]
#[actix_web::test]
async fn e2e_default_policy_denies_disallowed_block_cipher_mode_ecb() {
    let mut conf = https_clap_config_opts(None);
    conf.kmip.enforce = true;
    conf.kmip.allowlists.block_cipher_modes = Some(vec![BlockCipherMode::GCM]);
    let app = Box::pin(test_app_with_clap_config(conf, None)).await;

    let key_uid = create_aes_key_with_size(&app, "e2e-aes-ecb", 256)
        .await
        .expect("create AES key should succeed");

    let req = Operation::Encrypt(Box::new(Encrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(key_uid)),
        cryptographic_parameters: Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            block_cipher_mode: Some(BlockCipherMode::ECB),
            ..Default::default()
        }),
        data: Some(Zeroizing::new(b"hello".to_vec())),
        ..Default::default()
    }));

    let err = post_2_1::<_, _, EncryptResponse, _>(&app, &req)
        .await
        .unwrap_err();
    assert_constraint_violation(err);
}

#[test]
fn default_policy_allows_signature_algorithm_rsa_sha256() {
    let params = params_with_default_policy();

    let op = Operation::Create(Create {
        object_type: ObjectType::PrivateKey,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            cryptographic_length: Some(3072),
            digital_signature_algorithm: Some(DigitalSignatureAlgorithm::SHA256WithRSAEncryption),
            ..Default::default()
        },
        protection_storage_masks: None,
    });

    enforce(&params, "Create", &op)
        .expect("RSA+SHA256 signature algorithm should be allowed by default policy");
}

#[cfg(feature = "non-fips")]
#[actix_web::test]
async fn e2e_default_policy_allows_signature_algorithm_rsa_sha256() {
    default_policy_allows_signature_algorithm_rsa_sha256();
}

#[test]
fn default_policy_allows_curve_p256() {
    let params = params_with_default_policy();

    let op = Operation::Create(Create {
        object_type: ObjectType::PublicKey,
        attributes: Attributes {
            cryptographic_algorithm: Some(CryptographicAlgorithm::EC),
            cryptographic_domain_parameters: Some(CryptographicDomainParameters {
                recommended_curve: Some(RecommendedCurve::P256),
                ..Default::default()
            }),
            ..Default::default()
        },
        protection_storage_masks: None,
    });

    enforce(&params, "Create", &op).expect("P256 should be allowed by default policy");
}

#[cfg(feature = "non-fips")]
#[actix_web::test]
async fn e2e_default_policy_allows_curve_p256() {
    let mut conf = https_clap_config_opts(None);
    conf.kmip.enforce = true;
    conf.kmip.allowlists.curves = Some(vec![RecommendedCurve::P256]);
    conf.kmip.allowlists.algorithms = Some(vec![
        CryptographicAlgorithm::EC,
        CryptographicAlgorithm::ECDH,
    ]);
    let app = Box::pin(test_app_with_clap_config(conf, None)).await;

    let create_kp = create_ec_key_pair_request(
        None,
        ["e2e-curve-p256"],
        RecommendedCurve::P256,
        false,
        None,
    )
    .expect("create_ec_key_pair_request should build");
    let _resp: CreateKeyPairResponse = post_2_1(&app, &create_kp)
        .await
        .expect("P256 keypair creation should be allowed by curve allowlist");
}

#[test]
fn default_policy_denies_padding_method_none_allowed_list() {
    let mut conf = crate::config::ClapConfig::default();
    conf.kmip.allowlists.padding_methods = Some(vec![PaddingMethod::PKCS5]);
    let mut params = params_with_allowlists(conf);
    params.kmip_policy.enforce = true;

    let op = Operation::Encrypt(Box::new(Encrypt {
        unique_identifier: None,
        cryptographic_parameters: Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::OAEP),
            ..Default::default()
        }),
        data: Some(Zeroizing::new(b"hello".to_vec())),
        i_v_counter_nonce: None,
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
        authenticated_encryption_additional_data: None,
    }));

    assert_policy_denied(enforce(&params, "Encrypt", &op));
}

#[cfg(feature = "non-fips")]
#[actix_web::test]
async fn e2e_default_policy_denies_padding_method_none_allowed_list() {
    let mut conf = https_clap_config_opts(None);
    conf.kmip.enforce = true;
    conf.kmip.allowlists.padding_methods = Some(vec![PaddingMethod::PKCS5]);
    let app = Box::pin(test_app_with_clap_config(conf, None)).await;

    let key_uid = create_aes_key_with_size(&app, "e2e-padding-deny", 256)
        .await
        .expect("create AES key should succeed");

    let req = Operation::Encrypt(Box::new(Encrypt {
        unique_identifier: Some(UniqueIdentifier::TextString(key_uid)),
        cryptographic_parameters: Some(CryptographicParameters {
            cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
            padding_method: Some(PaddingMethod::OAEP),
            ..Default::default()
        }),
        data: Some(Zeroizing::new(b"hello".to_vec())),
        ..Default::default()
    }));

    let err = post_2_1::<_, _, EncryptResponse, _>(&app, &req)
        .await
        .unwrap_err();
    assert_constraint_violation(err);
}

#[test]
fn enforced_policy_with_empty_allowlists_denies_all_operations() {
    let mut conf = crate::config::ClapConfig::default();

    conf.kmip.allowlists.algorithms = Some(vec![]);
    conf.kmip.allowlists.hashes = Some(vec![]);
    conf.kmip.allowlists.signature_algorithms = Some(vec![]);
    conf.kmip.allowlists.curves = Some(vec![]);
    conf.kmip.allowlists.block_cipher_modes = Some(vec![]);
    conf.kmip.allowlists.padding_methods = Some(vec![]);
    conf.kmip.allowlists.mgf_hashes = Some(vec![]);

    let mut params = params_with_allowlists(conf);
    params.kmip_policy.enforce = true;

    for alg in CryptographicAlgorithm::iter() {
        let create = Operation::Create(Create {
            object_type: ObjectType::SymmetricKey,
            attributes: Attributes {
                cryptographic_algorithm: Some(alg),
                cryptographic_length: Some(256),
                ..Default::default()
            },
            protection_storage_masks: None,
        });
        assert_policy_denied(enforce(&params, "Create", &create));
    }

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

    let hash = Operation::Hash(Hash {
        cryptographic_parameters: CryptographicParameters {
            hashing_algorithm: Some(HashingAlgorithm::SHA256),
            ..Default::default()
        },
        data: None,
        correlation_value: None,
        init_indicator: None,
        final_indicator: None,
    });
    assert_policy_denied(enforce(&params, "Hash", &hash));
}

// Helpers used by e2e_export_wrapping
#[cfg(feature = "non-fips")]
fn _create_aes_key_request_for_export(tag: &str) -> Operation {
    Operation::Create(Create {
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
    })
}
