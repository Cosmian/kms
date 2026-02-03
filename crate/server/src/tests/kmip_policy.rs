#![allow(clippy::unwrap_used, clippy::expect_used)]

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
use strum::IntoEnumIterator;

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
