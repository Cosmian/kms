//! This module implements a generic KEM which concrete variant is chosen at
//! runtime among a set of authorized variants chosen at initialization time.
//!
//! Implementations of the concrete variants are chosen at compile-time.

use cosmian_cover_crypt::{
    ConfigurableKEM, ConfigurableKemDk, ConfigurableKemEk, ConfigurableKemEnc, KemTag,
    PostQuantumKemTag, PreQuantumKemTag,
};
use cosmian_crypto_core::bytes_ser_de::{Deserializer, Serializable};
use cosmian_kmip::{
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        extra::tagging::{SYSTEM_TAG_PRIVATE_KEY, SYSTEM_TAG_PUBLIC_KEY},
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

pub fn kem_keygen(
    vendor_id: &str,
    dk_uid: String,
    dk_attributes: Option<Attributes>,
    ek_uid: String,
    ek_attributes: Option<Attributes>,
    common_attributes: &Attributes,
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
            return Err(CryptoError::Kmip("no KEM configuration defined".to_owned()));
        }
        (None, Some(alg)) => {
            if CryptographicAlgorithm::CoverCrypt == alg {
                return Err(CryptoError::NotSupported(
                    "CoverCrypt is not supported by the configurable-KEM yet".to_owned(),
                ));
            }
            KemTag::PostQuantum(cryptographic_algorithm_to_post_quantum_kem_tag(alg)?)
        }
        (Some(curve), None) => KemTag::PreQuantum(recommended_curve_to_pre_quantum_kem_tag(curve)?),
        (Some(curve), Some(alg)) => KemTag::Hybridized(
            recommended_curve_to_pre_quantum_kem_tag(curve)?,
            cryptographic_algorithm_to_post_quantum_kem_tag(alg)?,
        ),
    };

    let access_structure = access_structure_from_attributes(vendor_id, common_attributes).ok();
    let (dk, ek) = ConfigurableKEM::keygen(tag, access_structure)?;

    // Per-key attributes inherit the common ones, as for every other key pair type.
    let with_common = |attributes: Option<Attributes>| {
        let mut attributes = attributes.unwrap_or_default();
        attributes.merge(common_attributes, false);
        attributes
    };
    Ok(KeyPair::new(
        create_dk_object(
            vendor_id,
            dk.serialize()?,
            with_common(dk_attributes),
            ek_uid,
        )?,
        create_ek_object(
            vendor_id,
            ek.serialize()?,
            with_common(ek_attributes),
            dk_uid,
        )?,
    ))
}

/// A KEM result: `(shared secret, encapsulation)`.
pub type KemEncapsulation = (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>);

pub fn kem_encaps(ek: &[u8]) -> Result<KemEncapsulation, CryptoError> {
    let ek = ConfigurableKemEk::deserialize(ek).map_err(|e| {
        CryptoError::ConversionError(format!(
            "failed deserializing the configurable-KEM encapsulation: {e}"
        ))
    })?;

    let ap = if ek.get_tag() == KemTag::Abe {
        return Err(CryptoError::NotSupported(
            "CoverCrypt is not supported by the configurable-KEM yet".to_owned(),
        ));
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

/// Pack a KEM result as the `Data` of a KMIP `Encrypt` response: the serialized
/// `(shared secret, encapsulation)` tuple. The encapsulation is a KEM ciphertext, not an
/// IV/counter/nonce, so `IVCounterNonce` stays empty for every KEM.
pub fn pack_kem_encapsulation(
    shared_secret: Zeroizing<Vec<u8>>,
    encapsulation: Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    (shared_secret, encapsulation).serialize().map_err(|e| {
        CryptoError::ConversionError(format!("failed serializing the KEM encapsulation: {e}"))
    })
}

/// Inverse of [`pack_kem_encapsulation`]: returns `(shared secret, encapsulation)`.
pub fn unpack_kem_encapsulation(data: &[u8]) -> Result<KemEncapsulation, CryptoError> {
    KemEncapsulation::deserialize(data).map_err(|e| {
        CryptoError::ConversionError(format!(
            "the KEM response data is not a (shared secret, encapsulation) tuple: {e}"
        ))
    })
}

/// Return the pre-quantum curve and the post-quantum algorithm of a serialized
/// `ConfigurableKEM` key (public or private), as encoded in the key itself, whatever its
/// KMIP attributes claim. Policy checks must rely on this, since attributes can be relabelled.
pub fn kem_key_components(
    key: &[u8],
) -> Result<(Option<RecommendedCurve>, Option<CryptographicAlgorithm>), CryptoError> {
    // Both key types serialize their `KemTag` first: read only that.
    let tag: KemTag = Deserializer::new(key).read().map_err(|e| {
        CryptoError::ConversionError(format!("failed reading the configurable-KEM key tag: {e}"))
    })?;
    let curve = |c| match c {
        PreQuantumKemTag::P256 => RecommendedCurve::P256,
        PreQuantumKemTag::R25519 => RecommendedCurve::CURVE25519,
    };
    let algorithm = |a| match a {
        PostQuantumKemTag::MlKem512 => CryptographicAlgorithm::MLKEM_512,
        PostQuantumKemTag::MlKem768 => CryptographicAlgorithm::MLKEM_768,
    };
    Ok(match tag {
        KemTag::PreQuantum(c) => (Some(curve(c)), None),
        KemTag::PostQuantum(a) => (None, Some(algorithm(a))),
        KemTag::Hybridized(c, a) => (Some(curve(c)), Some(algorithm(a))),
        KemTag::Abe => (None, Some(CryptographicAlgorithm::CoverCrypt)),
    })
}

pub fn kem_decaps(dk: &[u8], enc: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let dk = ConfigurableKemDk::deserialize(dk)?;

    if dk.get_tag() == KemTag::Abe {
        return Err(CryptoError::NotSupported(
            "CoverCrypt is not supported by the configurable-KEM yet".to_owned(),
        ));
    }

    let enc = ConfigurableKemEnc::deserialize(enc)?;
    let key = ConfigurableKEM::dec(&dk, &enc)?;
    Ok(key)
}

fn create_dk_object(
    vendor_id: &str,
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
    // A requested mask is kept as is; decapsulation is a KMIP Decrypt.
    attributes.cryptographic_usage_mask = attributes
        .cryptographic_usage_mask
        .or(Some(CryptographicUsageMask::Decrypt));
    attributes.link = Some(vec![Link {
        link_type: LinkType::PublicKeyLink,
        linked_object_identifier: LinkedObjectIdentifier::TextString(ek_uid),
    }]);
    attributes.sensitive = attributes.sensitive.or(Some(true));

    let mut tags = attributes.get_tags(vendor_id);
    tags.insert(SYSTEM_TAG_PRIVATE_KEY.to_owned());
    attributes.set_tags(vendor_id, tags)?;

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
    vendor_id: &str,
    ek_bytes: Zeroizing<Vec<u8>>,
    mut attributes: Attributes,
    dk_uid: String,
) -> Result<Object, CryptoError> {
    attributes.sensitive = None;
    attributes.object_type = Some(ObjectType::PublicKey);
    attributes.key_format_type = Some(KeyFormatType::ConfigurableKEMPublicKey);
    // A requested mask is kept as is; encapsulation is a KMIP Encrypt.
    attributes.cryptographic_usage_mask = attributes
        .cryptographic_usage_mask
        .or(Some(CryptographicUsageMask::Encrypt));
    attributes.link = Some(vec![Link {
        link_type: LinkType::PrivateKeyLink,
        linked_object_identifier: LinkedObjectIdentifier::TextString(dk_uid),
    }]);

    // Add the SYSTEM_TAG_PUBLIC_KEY system tag to the attributes
    let mut tags = attributes.get_tags(vendor_id);
    tags.insert(SYSTEM_TAG_PUBLIC_KEY.to_owned());
    attributes.set_tags(vendor_id, tags)?;

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

#[expect(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::{pack_kem_encapsulation, unpack_kem_encapsulation};

    #[test]
    fn kem_encapsulation_pack_round_trip() {
        // a ciphertext longer than 127 bytes has a multi-byte length prefix
        let secret = Zeroizing::new(vec![7_u8; 32]);
        let encapsulation = Zeroizing::new(vec![9_u8; 1088]);
        let packed = pack_kem_encapsulation(secret.clone(), encapsulation.clone()).unwrap();
        let (s, e) = unpack_kem_encapsulation(&packed).unwrap();
        assert_eq!((s, e), (secret, encapsulation));
        // golden layout, shared with the Web UI parser and the vector runner:
        // LEB128 length + secret, LEB128 length (1088 = 0xC0 0x08) + encapsulation
        assert_eq!(packed.len(), 1 + 32 + 2 + 1088);
        assert_eq!(packed.get(..1).unwrap(), &[32]);
        assert_eq!(packed.get(33..35).unwrap(), &[0xC0, 0x08]);
        // truncated and trailing data are refused, not silently shortened or ignored
        let (_, truncated) = packed.split_last().unwrap();
        unpack_kem_encapsulation(truncated).unwrap_err();
        unpack_kem_encapsulation(&[]).unwrap_err();
        let mut trailing = packed.to_vec();
        trailing.push(0);
        unpack_kem_encapsulation(&trailing).unwrap_err();
    }
}
