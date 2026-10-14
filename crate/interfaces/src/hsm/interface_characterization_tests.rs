//! Characterization tests pinning every outcome of `HsmObjectFilter::try_from(&Attributes)`.

use cosmian_kmip::kmip_2_1::{
    kmip_attributes::Attributes, kmip_objects::ObjectType, kmip_types::CryptographicAlgorithm,
};

use super::HsmObjectFilter;

fn filter(
    algorithm: Option<CryptographicAlgorithm>,
    object_type: Option<ObjectType>,
) -> Result<HsmObjectFilter, String> {
    let attributes = Attributes {
        cryptographic_algorithm: algorithm,
        object_type,
        ..Attributes::default()
    };
    HsmObjectFilter::try_from(&attributes).map_err(|e| e.to_string())
}

fn assert_filter(
    algorithm: Option<CryptographicAlgorithm>,
    object_type: Option<ObjectType>,
    expected: &HsmObjectFilter,
) {
    let actual = filter(algorithm, object_type).unwrap();
    assert!(actual == *expected);
}

#[test]
fn characterization_hsm_object_filter_try_from_algorithm_only() {
    assert_filter(None, None, &HsmObjectFilter::Any);
    assert_filter(
        Some(CryptographicAlgorithm::AES),
        None,
        &HsmObjectFilter::AesKey,
    );
    assert_filter(
        Some(CryptographicAlgorithm::RSA),
        None,
        &HsmObjectFilter::RsaKey,
    );
    assert_filter(
        Some(CryptographicAlgorithm::EC),
        None,
        &HsmObjectFilter::EcKey,
    );
    assert_filter(
        Some(CryptographicAlgorithm::ECDSA),
        None,
        &HsmObjectFilter::EcKey,
    );
    assert_filter(
        Some(CryptographicAlgorithm::ECDH),
        None,
        &HsmObjectFilter::EcKey,
    );
}

#[cfg(feature = "non-fips")]
#[test]
fn characterization_hsm_object_filter_try_from_edwards_algorithms() {
    assert_filter(
        Some(CryptographicAlgorithm::Ed25519),
        None,
        &HsmObjectFilter::EcKey,
    );
    assert_filter(
        Some(CryptographicAlgorithm::Ed448),
        None,
        &HsmObjectFilter::EcKey,
    );
}

#[test]
fn characterization_hsm_object_filter_try_from_object_type_only() {
    assert_filter(
        None,
        Some(ObjectType::SymmetricKey),
        &HsmObjectFilter::AesKey,
    );
    assert_filter(
        None,
        Some(ObjectType::PublicKey),
        &HsmObjectFilter::RsaPublicKey,
    );
    assert_filter(
        None,
        Some(ObjectType::PrivateKey),
        &HsmObjectFilter::RsaPrivateKey,
    );
}

#[test]
fn characterization_hsm_object_filter_try_from_symmetric_key_combinations() {
    assert_filter(
        Some(CryptographicAlgorithm::AES),
        Some(ObjectType::SymmetricKey),
        &HsmObjectFilter::AesKey,
    );
    assert_eq!(
        filter(
            Some(CryptographicAlgorithm::RSA),
            Some(ObjectType::SymmetricKey)
        )
        .err()
        .unwrap(),
        "Incompatible object type: SymmetricKey with RSA/EC"
    );
    assert_eq!(
        filter(
            Some(CryptographicAlgorithm::EC),
            Some(ObjectType::SymmetricKey)
        )
        .err()
        .unwrap(),
        "Incompatible object type: SymmetricKey with RSA/EC"
    );
    assert_eq!(
        filter(
            Some(CryptographicAlgorithm::ECDSA),
            Some(ObjectType::SymmetricKey)
        )
        .err()
        .unwrap(),
        "Incompatible object type: SymmetricKey with RSA/EC"
    );
}

#[test]
fn characterization_hsm_object_filter_try_from_public_key_combinations() {
    assert_filter(
        Some(CryptographicAlgorithm::RSA),
        Some(ObjectType::PublicKey),
        &HsmObjectFilter::RsaPublicKey,
    );
    assert_filter(
        Some(CryptographicAlgorithm::EC),
        Some(ObjectType::PublicKey),
        &HsmObjectFilter::EcPublicKey,
    );
    assert_filter(
        Some(CryptographicAlgorithm::ECDH),
        Some(ObjectType::PublicKey),
        &HsmObjectFilter::EcPublicKey,
    );
    assert_eq!(
        filter(
            Some(CryptographicAlgorithm::AES),
            Some(ObjectType::PublicKey)
        )
        .err()
        .unwrap(),
        "Incompatible object type: PublicKey with AES"
    );
}

#[test]
fn characterization_hsm_object_filter_try_from_private_key_combinations() {
    assert_filter(
        Some(CryptographicAlgorithm::RSA),
        Some(ObjectType::PrivateKey),
        &HsmObjectFilter::RsaPrivateKey,
    );
    assert_filter(
        Some(CryptographicAlgorithm::EC),
        Some(ObjectType::PrivateKey),
        &HsmObjectFilter::EcPrivateKey,
    );
    assert_filter(
        Some(CryptographicAlgorithm::ECDSA),
        Some(ObjectType::PrivateKey),
        &HsmObjectFilter::EcPrivateKey,
    );
    assert_eq!(
        filter(
            Some(CryptographicAlgorithm::AES),
            Some(ObjectType::PrivateKey)
        )
        .err()
        .unwrap(),
        "Incompatible object type: PrivateKey with AES"
    );
}

#[test]
fn characterization_hsm_object_filter_try_from_unsupported_algorithm() {
    assert_eq!(
        filter(Some(CryptographicAlgorithm::HMACSHA256), None)
            .err()
            .unwrap(),
        "Unsupported cryptographic algorithm for HSMs: HMACSHA256"
    );
    assert_eq!(
        filter(
            Some(CryptographicAlgorithm::HMACSHA256),
            Some(ObjectType::PublicKey)
        )
        .err()
        .unwrap(),
        "Unsupported cryptographic algorithm for HSMs: HMACSHA256"
    );
}

#[test]
fn characterization_hsm_object_filter_try_from_unsupported_object_type() {
    assert_eq!(
        filter(None, Some(ObjectType::Certificate)).err().unwrap(),
        "Unsupported object type for HSMs: Certificate"
    );
    assert_eq!(
        filter(
            Some(CryptographicAlgorithm::AES),
            Some(ObjectType::SecretData)
        )
        .err()
        .unwrap(),
        "Unsupported object type for HSMs: SecretData"
    );
}
