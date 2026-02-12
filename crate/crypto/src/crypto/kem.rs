//! This module implements a generic KEM which concrete variant is chosen at
//! runtime among a set of authorized variants chosen at initialization time.
//!
//! Implementations of the concrete variants are chosen at compile-time.

use cosmian_cover_crypt::{
    AccessPolicy, ConfigurableKEM, ConfigurableKemDk, ConfigurableKemEk, ConfigurableKemEnc,
    KemTag, PostQuantumKemTag, PreQuantumKemTag,
};
use cosmian_crypto_core::bytes_ser_de::Serializable;
use cosmian_kmip::{
    DataToEncrypt,
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType, PrivateKey, PublicKey},
        kmip_types::{
            CryptographicAlgorithm, KeyFormatType, Link, LinkType, LinkedObjectIdentifier,
            RecommendedCurve,
        },
    },
};
use cosmian_logger::debug;
use zeroize::Zeroizing;

use crate::{
    CryptoError,
    crypto::{KeyPair, cover_crypt::attributes::access_structure_from_attributes},
};

fn cryptographic_algorithm_to_post_quantum_kem_tag(
    alg: CryptographicAlgorithm,
) -> Result<PostQuantumKemTag, CryptoError> {
    match alg {
        CryptographicAlgorithm::MLKEM_512 => Ok(PostQuantumKemTag::MlKem512),
        CryptographicAlgorithm::MLKEM_768 => Ok(PostQuantumKemTag::MlKem768),
        alg => Err(CryptoError::Kmip(format!(
            "{alg:?} not supported as post-quantum KEM"
        ))),
    }
}

fn recommended_curve_to_pre_quantum_kem_tag(
    curve: RecommendedCurve,
) -> Result<PreQuantumKemTag, CryptoError> {
    match curve {
        RecommendedCurve::P256 => Ok(PreQuantumKemTag::P256),
        RecommendedCurve::CURVE25519 => Ok(PreQuantumKemTag::R25519),
        curve => Err(CryptoError::Kmip(format!(
            "curve {curve:?} not supported as basis for a pre-quantum KEM"
        ))),
    }
}

#[allow(clippy::too_many_arguments)]
pub fn kem_keygen(
    dk_uid: String,
    dk_attributes: Option<Attributes>,
    ek_uid: String,
    ek_attributes: Option<Attributes>,
    common_attributes: Attributes,
) -> Result<KeyPair, CryptoError> {
    let tag = match (
        common_attributes
            .cryptographic_domain_parameters
            .and_then(|params| params.recommended_curve),
        common_attributes
            .cryptographic_parameters
            .as_ref()
            .and_then(|params| params.cryptographic_algorithm),
    ) {
        (None, None) => {
            return Err(CryptoError::Kmip(
                "no KEM configuration defined".to_string(),
            ));
        }
        (None, Some(alg)) => {
            if CryptographicAlgorithm::CoverCrypt == alg {
                KemTag::Abe
            } else {
                KemTag::PostQuantum(cryptographic_algorithm_to_post_quantum_kem_tag(alg)?)
            }
        }
        (Some(curve), None) => KemTag::PreQuantum(recommended_curve_to_pre_quantum_kem_tag(curve)?),
        (Some(curve), Some(alg)) => KemTag::Hybridized(
            recommended_curve_to_pre_quantum_kem_tag(curve)?,
            cryptographic_algorithm_to_post_quantum_kem_tag(alg)?,
        ),
    };

    let access_structure = access_structure_from_attributes(&common_attributes).ok();
    let (dk, ek) = ConfigurableKEM::keygen(tag, access_structure)?;

    Ok(KeyPair::new(
        create_dk_object(
            dk.serialize()?,
            dk_attributes.unwrap_or_else(|| common_attributes.clone()),
            ek_uid,
        )?,
        create_ek_object(
            ek.serialize()?,
            ek_attributes.unwrap_or(common_attributes),
            dk_uid,
        )?,
    ))
}

pub fn kem_encaps(
    ek: &[u8],
    data: Option<&Zeroizing<Vec<u8>>>,
) -> Result<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>), CryptoError> {
    let ek = ConfigurableKemEk::deserialize(ek).map_err(|e| {
        CryptoError::ConversionError(format!(
            "failed deserializing the configurable-KEM encapsulation: {e}"
        ))
    })?;

    let ap = if ek.get_tag()? == KemTag::Abe {
        let data = data.ok_or_else(|| {
            CryptoError::ObjectNotFound(
                "a data field containing an access policy must be given \
                 in order to create a CoverCrypt encapsulation"
                    .to_owned(),
            )
        })?;
        let data = DataToEncrypt::try_from_bytes(data).map_err(|e| {
            CryptoError::ConversionError(format!(
                "failed deserializing data to encrypt the configurable-KEM \
                 encapsulation: {e}"
            ))
        })?;
        let ap = data.encryption_policy.ok_or_else(|| {
            CryptoError::ObjectNotFound(
                "access-policy field must be given in the data to create \
                 a CoverCrypt encapsulation"
                    .to_owned(),
            )
        })?;
        Some(AccessPolicy::parse(&ap).map_err(|e| {
            CryptoError::ConversionError(format!(
                "failed parsing the access policy for the configurable-KEM \
                 encapsulation: {e}"
            ))
        })?)
    } else {
        None
    };

    let (key, enc) = ConfigurableKEM::enc(&ek, ap.as_ref()).map_err(|e| {
        CryptoError::Default(format!("configurable-KEM encapsulation failure: {e}"))
    })?;

    Ok((
        key,
        enc.serialize().map_err(|e| {
            CryptoError::ConversionError(format!(
                "failed serializing the configurable-KEM encapsulation: {e}"
            ))
        })?,
    ))
}

pub fn kem_decaps(dk: &[u8], enc: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let dk = ConfigurableKemDk::deserialize(dk)?;
    let enc = ConfigurableKemEnc::deserialize(enc)?;
    let key = ConfigurableKEM::dec(&dk, &enc)?;
    Ok(key)
}

fn create_dk_object(
    dk_bytes: Zeroizing<Vec<u8>>,
    mut attributes: Attributes,
    ek_uid: String,
) -> Result<Object, CryptoError> {
    debug!(
        "create_dk_object: key len: {}, attributes: {attributes}",
        dk_bytes.len()
    );

    attributes.object_type = Some(ObjectType::PrivateKey);
    attributes.key_format_type = Some(KeyFormatType::ConfigurableKEMSecretKey);
    attributes.set_cryptographic_usage_mask_bits(CryptographicUsageMask::Unrestricted);
    attributes.link = Some(vec![Link {
        link_type: LinkType::PublicKeyLink,
        linked_object_identifier: LinkedObjectIdentifier::TextString(ek_uid),
    }]);
    attributes.sensitive = attributes.sensitive.or(Some(true));

    let mut tags = attributes.get_tags();
    tags.insert("_sk".to_owned());
    attributes.set_tags(tags)?;

    let cryptographic_length = Some(i32::try_from(dk_bytes.len())? * 8);
    Ok(Object::PrivateKey(PrivateKey {
        key_block: KeyBlock {
            cryptographic_algorithm: Some(CryptographicAlgorithm::ConfigurableKEM),
            key_format_type: KeyFormatType::ConfigurableKEMSecretKey,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(dk_bytes),
                attributes: Some(attributes),
            }),
            cryptographic_length,
            key_wrapping_data: None,
        },
    }))
}

fn create_ek_object(
    ek_bytes: Zeroizing<Vec<u8>>,
    mut attributes: Attributes,
    dk_uid: String,
) -> Result<Object, CryptoError> {
    attributes.sensitive = None;
    attributes.object_type = Some(ObjectType::PublicKey);
    attributes.key_format_type = Some(KeyFormatType::ConfigurableKEMPublicKey);
    attributes.set_cryptographic_usage_mask_bits(CryptographicUsageMask::Encrypt);
    attributes.link = Some(vec![Link {
        link_type: LinkType::PrivateKeyLink,
        linked_object_identifier: LinkedObjectIdentifier::TextString(dk_uid),
    }]);

    // Add the "_pk" system tag to the attributes
    let mut tags = attributes.get_tags();
    tags.insert("_pk".to_owned());
    attributes.set_tags(tags)?;

    let cryptographic_length = Some(i32::try_from(ek_bytes.len())? * 8);

    Ok(Object::PublicKey(PublicKey {
        key_block: KeyBlock {
            cryptographic_algorithm: Some(CryptographicAlgorithm::ConfigurableKEM),
            key_format_type: KeyFormatType::ConfigurableKEMPublicKey,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(ek_bytes),
                attributes: Some(attributes),
            }),
            cryptographic_length,
            key_wrapping_data: None,
        },
    }))
}
