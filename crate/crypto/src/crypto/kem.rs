//! This module implements a generic KEM which concrete variant is chosen at
//! runtime among a set of authorized variants chosen at initialization time.
//!
//! Implementations of the concrete variants are chosen at compile-time.

#![allow(dead_code, unused_variables)]

use crate::{CryptoError, crypto::KeyPair};
#[cfg(feature = "non-fips")]
use cosmian_cover_crypt::{AccessPolicy, AccessStructure};
use cosmian_crypto_core::{
    Aes256Gcm, SymmetricKey,
    bytes_ser_de::Serializable,
    reexport::rand_core::CryptoRngCore,
    traits::{AE_InPlace, KEM, cyclic_group_to_kem::GenericKem},
};
use cosmian_kmip::{
    kmip_0::kmip_types::CryptographicUsageMask,
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType, PrivateKey, PublicKey},
        kmip_types::{
            CryptographicAlgorithm, KeyFormatType, Link, LinkType, LinkedObjectIdentifier,
        },
    },
};
use cosmian_logger::debug;
use cosmian_openssl_provider::{hash::Sha256, kem::MonadicKEM, p256::P256};
use cosmian_rust_curve25519_provider::R25519;
use std::collections::HashSet;
use zeroize::Zeroizing;

// In order to avoid defining one enumeration type per KEM object with one
// variant per concrete KEM option, this module uses dynamic typing on the
// concrete key and encapsulation types by to consuming and returning byte
// strings. Serialization can be used once the concrete KEM is chosen to
// retrieve the typed objects.
//
// The following functions implement this logic: they are parametric on a KEM
// type -- and thus need to be called once the concrete KEM implementation is
// known, and perform both the KEM operation and serialization/deserialization
// of the key and encapsulation objects.

#[allow(clippy::type_complexity)]
fn generic_keygen<const KEY_LENGTH: usize, Kem: KEM<KEY_LENGTH>>(
    rng: &mut impl CryptoRngCore,
) -> Result<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>), CryptoError>
where
    Kem::DecapsulationKey: Serializable,
{
    let (dk, ek) = Kem::keygen(rng).map_err(|e| CryptoError::Default(e.to_string()))?;
    Ok((
        dk.serialize()
            .map_err(|e| CryptoError::Default(format!("DK serialization error in KEM: {e}")))?,
        ek.serialize()
            .map_err(|e| CryptoError::Default(format!("EK serialization error in KEM: {e}")))?,
    ))
}

fn generic_enc<const KEY_LENGTH: usize, Kem: KEM<KEY_LENGTH>>(
    pk: &[u8],
    rng: &mut impl CryptoRngCore,
) -> Result<(SymmetricKey<KEY_LENGTH>, Zeroizing<Vec<u8>>), CryptoError> {
    let ek = <Kem as KEM<KEY_LENGTH>>::EncapsulationKey::deserialize(pk)
        .map_err(|e| CryptoError::Default(format!("EK deserialization error in KEM: {e}")))?;
    let (key, enc) = Kem::enc(&ek, rng).map_err(|e| CryptoError::Default(e.to_string()))?;
    Ok((
        key,
        enc.serialize().map_err(|e| {
            CryptoError::Default(format!("encapsulation serialization error in KEM: {e}"))
        })?,
    ))
}

fn generic_dec<const KEY_LENGTH: usize, Kem: KEM<KEY_LENGTH>>(
    dk: &[u8],
    enc: &[u8],
) -> Result<SymmetricKey<KEY_LENGTH>, CryptoError>
where
    Kem::DecapsulationKey: Serializable,
{
    let dk = <Kem as KEM<KEY_LENGTH>>::DecapsulationKey::deserialize(dk)
        .map_err(|e| CryptoError::Default(format!("DK deserialization error in KEM: {e}")))?;
    let enc = <Kem as KEM<KEY_LENGTH>>::Encapsulation::deserialize(enc).map_err(|e| {
        CryptoError::Default(format!("encapsulation deserialization error in KEM: {e}"))
    })?;
    Kem::dec(&dk, &enc).map_err(|e| CryptoError::Default(e.to_string()))
}

// However, in order to enforce type safety, KEM objects must be tagged by the
// concrete KEM used.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KemTag {
    PreQuantum(PreQuantumKemTag),
    PostQuantum(PostQuantumKemTag),
    Hybridized(PreQuantumKemTag, PostQuantumKemTag),
    #[cfg(feature = "non-fips")]
    Abe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PreQuantumKemTag {
    P256,
    R25519,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PostQuantumKemTag {
    MlKem,
}

impl Serializable for KemTag {
    // NOTE: the correctness of this serialization relies on the unicity of
    // algorithm IDs.

    type Error = CryptoError;

    fn length(&self) -> usize {
        match self {
            Self::PreQuantum(_) | Self::PostQuantum(_) => 2,
            Self::Hybridized(_, _) => 3,
            #[cfg(feature = "non-fips")]
            Self::Abe => 2,
        }
    }

    fn write(
        &self,
        ser: &mut cosmian_crypto_core::bytes_ser_de::Serializer,
    ) -> Result<usize, Self::Error> {
        match self {
            Self::PreQuantum(tag) => (0_u64, KemAlgorithm::from(tag)).write(ser),
            Self::PostQuantum(tag) => (1_u64, KemAlgorithm::from(tag)).write(ser),
            Self::Hybridized(tag1, tag2) => {
                (2_u64, (KemAlgorithm::from(tag1), KemAlgorithm::from(tag2))).write(ser)
            }
            #[cfg(feature = "non-fips")]
            Self::Abe => 3u64.write(ser),
        }
        .map_err(|e| {
            Self::Error::ConversionError(format!("error upon writing KEM tag {self:?}: {e}"))
        })
    }

    fn read(de: &mut cosmian_crypto_core::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
        let value = de.read::<usize>()?;
        match value {
            0 => de
                .read::<KemAlgorithm>()
                .and_then(PreQuantumKemTag::try_from)
                .map(Self::PreQuantum),
            1 => de
                .read::<KemAlgorithm>()
                .and_then(PostQuantumKemTag::try_from)
                .map(Self::PostQuantum),
            2 => de
                .read::<(KemAlgorithm, KemAlgorithm)>()
                .map_err(|e| {
                    Self::Error::ConversionError(format!(
                        "error upon reading pair of KEM algorithms: {e}"
                    ))
                })
                .and_then(|(algo1, algo2)| {
                    Ok(Self::Hybridized(
                        PreQuantumKemTag::try_from(algo1)?,
                        PostQuantumKemTag::try_from(algo2)?,
                    ))
                }),
            #[cfg(feature = "non-fips")]
            3 => Ok(KemTag::Abe),
            _ => Err(Self::Error::ConversionError(format!(
                "value {value} is not a valid KEM tag"
            ))),
        }
    }
}

// Those tags can be used to dynamically check that the intended KEM
// implementation is authorized on the running instance by testing for its
// membership in a set of authorized KEM algorithms. This allows to parameterize
// a KMS instance at initialization time by reading this set of authorized KEM
// algorithm from a configuration file.

/// Available KEM algorithms.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum KemAlgorithm {
    P256,
    R25519,
    MlKem,
    #[cfg(feature = "non-fips")]
    Covercrypt,
}

type P256Kem = MonadicKEM<32, P256, Sha256>;
type R25519Kem = GenericKem<32, R25519, Sha256>;

// Even though lengths of the keys encapsulated by the two combined KEM schemes
// can vary, it is much simpler to enforce their equality, which is performed
// here by binding the three key lengths required by the KEM combiner to the
// same one.
type KemCombiner<const LENGTH: usize, Kem1, Kem2> =
    cosmian_crypto_core::traits::kem_combiner::KemCombiner<
        LENGTH,
        LENGTH,
        LENGTH,
        Kem1,
        Kem2,
        Sha256,
    >;

//
// TODO: use a proper ML-KEM provider.
//
type MlKem = GenericKem<32, P256, Sha256>;

impl KemAlgorithm {
    /// Asserts the given KEM tag corresponds to an authorized KEM algorithm.
    ///
    /// A hybridized KEM is authorized as long as both underlying KEM algorithms
    /// are authorized.
    fn check_tag(tag: KemTag, authorized_algorithms: &HashSet<Self>) -> Result<(), CryptoError> {
        match tag {
            KemTag::PreQuantum(tag) => Self::from(&tag).check_algorithm(authorized_algorithms),
            KemTag::PostQuantum(tag) => Self::from(&tag).check_algorithm(authorized_algorithms),
            KemTag::Hybridized(tag1, tag2) => Self::from(&tag1)
                .check_algorithm(authorized_algorithms)
                .and_then(|()| Self::from(&tag2).check_algorithm(authorized_algorithms)),
            #[cfg(feature = "non-fips")]
            KemTag::Abe => Self::Covercrypt.check_algorithm(authorized_algorithms),
        }
    }

    fn check_algorithm(self, authorized_algorithms: &HashSet<Self>) -> Result<(), CryptoError> {
        if authorized_algorithms.contains(&self) {
            Ok(())
        } else {
            Err(CryptoError::NotSupported(format!(
                "unauthorized KEM algorithm: {self:?}"
            )))
        }
    }
}

impl From<&PreQuantumKemTag> for KemAlgorithm {
    fn from(tag: &PreQuantumKemTag) -> Self {
        match tag {
            PreQuantumKemTag::P256 => Self::P256,
            PreQuantumKemTag::R25519 => Self::R25519,
        }
    }
}

impl TryFrom<KemAlgorithm> for PreQuantumKemTag {
    type Error = CryptoError;

    fn try_from(algorithm: KemAlgorithm) -> Result<Self, Self::Error> {
        #[allow(clippy::match_wildcard_for_single_variants)]
        match algorithm {
            KemAlgorithm::P256 => Ok(Self::P256),
            KemAlgorithm::R25519 => Ok(Self::R25519),
            _ => Err(Self::Error::ConversionError(format!(
                "algorithm {algorithm:?} is no a valid pre-quantum KEM"
            ))),
        }
    }
}

impl From<&PostQuantumKemTag> for KemAlgorithm {
    fn from(tag: &PostQuantumKemTag) -> Self {
        match tag {
            PostQuantumKemTag::MlKem => Self::MlKem,
        }
    }
}

impl TryFrom<KemAlgorithm> for PostQuantumKemTag {
    type Error = CryptoError;

    fn try_from(algorithm: KemAlgorithm) -> Result<Self, Self::Error> {
        match algorithm {
            KemAlgorithm::MlKem => Ok(Self::MlKem),
            _ => Err(Self::Error::ConversionError(format!(
                "algorithm {algorithm:?} is no a valid post-quantum KEM"
            ))),
        }
    }
}

impl Serializable for KemAlgorithm {
    type Error = CryptoError;

    fn length(&self) -> usize {
        1
    }

    fn write(
        &self,
        ser: &mut cosmian_crypto_core::bytes_ser_de::Serializer,
    ) -> Result<usize, Self::Error> {
        match self {
            Self::P256 => ser.write(&1_usize),
            Self::R25519 => ser.write(&2_usize),
            Self::MlKem => ser.write(&3_usize),
            #[cfg(feature = "non-fips")]
            Self::Covercrypt => ser.write(&4usize),
        }
        .map_err(|e| {
            CryptoError::ConversionError(format!("error upon writing KEM algorithm {self:?}: {e}"))
        })
    }

    fn read(de: &mut cosmian_crypto_core::bytes_ser_de::Deserializer) -> Result<Self, Self::Error> {
        let value = de.read::<usize>().map_err(|e| {
            CryptoError::ConversionError(format!("error upon reading KEM algorithm: {e}"))
        })?;
        match value {
            1 => Ok(Self::P256),
            2 => Ok(Self::R25519),
            3 => Ok(Self::MlKem),
            #[cfg(feature = "non-fips")]
            4 => Ok(Self::Covercrypt),
            _ => Err(CryptoError::ConversionError(format!(
                "value {value} is not a valid KEM algorithm"
            ))),
        }
    }
}

// Finally, we can implement a KEM-like interface for our configurable KEM which
// deserializes KEM objects as couple (tag, bytes), checks tag legality and
// compatibility across objects before the KEM operation with corresponding
// implementation, and finally serializes returned objects as (tag, bytes)
// couples.

pub struct ConfigurableKEM;

impl ConfigurableKEM {
    /// Length of the key encapsulated by this configurable KEM.
    // NOTE: the type-system ensures that all concrete KEM implementations used
    // indeed return 32-byte keys.
    const KEY_LENGTH: usize = 32;

    #[allow(clippy::too_many_arguments)]
    fn keygen(
        tag: KemTag,
        authorized_algorithms: &HashSet<KemAlgorithm>,
        dk_uid: String,
        dk_attributes: Option<Attributes>,
        ek_uid: String,
        ek_attributes: Option<Attributes>,
        common_attributes: Attributes,
        #[cfg(feature = "non-fips")] access_structure: Option<AccessStructure>,
        sensitive: bool,
        rng: &mut impl CryptoRngCore,
    ) -> Result<KeyPair, CryptoError> {
        KemAlgorithm::check_tag(tag, authorized_algorithms)?;

        let (dk_bytes, ek_bytes) = match tag {
            KemTag::PreQuantum(PreQuantumKemTag::P256) => {
                generic_keygen::<{ Self::KEY_LENGTH }, P256Kem>(rng)
            }
            KemTag::PreQuantum(PreQuantumKemTag::R25519) => {
                generic_keygen::<{ Self::KEY_LENGTH }, R25519Kem>(rng)
            }
            KemTag::PostQuantum(PostQuantumKemTag::MlKem) => {
                generic_keygen::<{ Self::KEY_LENGTH }, MlKem>(rng)
            }
            KemTag::Hybridized(PreQuantumKemTag::P256, PostQuantumKemTag::MlKem) => {
                generic_keygen::<
                    { Self::KEY_LENGTH },
                    KemCombiner<{ Self::KEY_LENGTH }, P256Kem, MlKem>,
                >(rng)
            }
            KemTag::Hybridized(PreQuantumKemTag::R25519, PostQuantumKemTag::MlKem) => {
                generic_keygen::<
                    { Self::KEY_LENGTH },
                    KemCombiner<{ Self::KEY_LENGTH }, R25519Kem, MlKem>,
                >(rng)
            }
            #[cfg(feature = "non-fips")]
            KemTag::Abe => {
                let access_structure = access_structure.ok_or_else(|| {
                    CryptoError::Default(
                        "cannot execute a Covercrypt key generation without an access structure"
                            .to_string(),
                    )
                })?;
                todo!()
            }
        }?;

        Ok(KeyPair::new(
            Self::create_dk_object(
                (tag, dk_bytes).serialize()?,
                dk_attributes.unwrap_or_else(|| common_attributes.clone()),
                ek_uid,
                sensitive,
            )?,
            Self::create_ek_object(
                (tag, ek_bytes).serialize()?,
                ek_attributes.unwrap_or(common_attributes),
                dk_uid,
            )?,
        ))
    }

    fn enc(
        ek: &[u8],
        rng: &mut impl CryptoRngCore,
        #[cfg(feature = "non-fips")] access_policy: &Option<AccessPolicy>,
    ) -> Result<(SymmetricKey<{ Self::KEY_LENGTH }>, Zeroizing<Vec<u8>>), CryptoError> {
        let (tag, pk_bytes) = <(KemTag, Vec<u8>)>::deserialize(ek).map_err(|e| {
            CryptoError::Default(format!(
                "failed deserializing the tag and encapsulation key in configurable KEM: {e}"
            ))
        })?;

        match tag {
            KemTag::PreQuantum(PreQuantumKemTag::P256) => {
                generic_enc::<{ Self::KEY_LENGTH }, P256Kem>(&pk_bytes, rng)
            }
            KemTag::PreQuantum(PreQuantumKemTag::R25519) => {
                generic_enc::<{ Self::KEY_LENGTH }, R25519Kem>(&pk_bytes, rng)
            }
            KemTag::PostQuantum(PostQuantumKemTag::MlKem) => {
                generic_enc::<{ Self::KEY_LENGTH }, MlKem>(&pk_bytes, rng)
            }
            KemTag::Hybridized(PreQuantumKemTag::P256, PostQuantumKemTag::MlKem) => {
                generic_enc::<{ Self::KEY_LENGTH }, KemCombiner<{ Self::KEY_LENGTH }, P256Kem, MlKem>>(
                    ek, rng,
                )
            }
            KemTag::Hybridized(PreQuantumKemTag::R25519, PostQuantumKemTag::MlKem) => {
                generic_enc::<
                    { Self::KEY_LENGTH },
                    KemCombiner<{ Self::KEY_LENGTH }, R25519Kem, MlKem>,
                >(ek, rng)
            }
            #[cfg(feature = "non-fips")]
            KemTag::Abe => todo!(),
        }
    }

    fn dec(dk: &[u8], enc: &[u8]) -> Result<SymmetricKey<{ Self::KEY_LENGTH }>, CryptoError> {
        let (tag, dk_bytes) = <(KemTag, Zeroizing<Vec<u8>>)>::deserialize(dk).map_err(|e| {
            CryptoError::Default(format!(
                "failed deserializing the tag and decapsulation key in configurable KEM: {e}"
            ))
        })?;

        let (tag_, enc_bytes) = <(KemTag, Vec<u8>)>::deserialize(enc).map_err(|e| {
            CryptoError::Default(format!(
                "failed deserializing the tag and encapsulation in configurable KEM: {e}"
            ))
        })?;

        if tag != tag_ {
            return Err(CryptoError::Default(format!(
                "heterogeneous decapsulation-key and encapsulation tags: {tag:?} != {tag_:?}"
            )));
        }

        match tag {
            KemTag::PreQuantum(PreQuantumKemTag::P256) => {
                generic_dec::<{ Self::KEY_LENGTH }, P256Kem>(&dk_bytes, &enc_bytes)
            }
            KemTag::PreQuantum(PreQuantumKemTag::R25519) => {
                generic_dec::<{ Self::KEY_LENGTH }, R25519Kem>(&dk_bytes, &enc_bytes)
            }
            KemTag::PostQuantum(PostQuantumKemTag::MlKem) => {
                generic_dec::<{ Self::KEY_LENGTH }, MlKem>(&dk_bytes, &enc_bytes)
            }
            KemTag::Hybridized(PreQuantumKemTag::P256, PostQuantumKemTag::MlKem) => {
                generic_dec::<{ Self::KEY_LENGTH }, KemCombiner<{ Self::KEY_LENGTH }, P256Kem, MlKem>>(
                    &dk_bytes, &enc_bytes,
                )
            }
            KemTag::Hybridized(PreQuantumKemTag::R25519, PostQuantumKemTag::MlKem) => {
                generic_dec::<
                    { Self::KEY_LENGTH },
                    KemCombiner<{ Self::KEY_LENGTH }, R25519Kem, MlKem>,
                >(&dk_bytes, &enc_bytes)
            }
            #[cfg(feature = "non-fips")]
            KemTag::Abe => todo!(),
        }
    }

    fn encrypt(
        pk: &[u8],
        ptx: &[u8],
        #[cfg(feature = "non-fips")] access_policy: &Option<AccessPolicy>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let (key, enc) = Self::enc(
            pk,
            rng,
            #[cfg(feature = "non-fips")]
            access_policy,
        )?;

        let mut nonce = [0; 12];
        rng.fill_bytes(&mut nonce);

        let mut ctx = vec![0; ptx.len()];
        ctx.copy_from_slice(ptx);

        let tag = Aes256Gcm::encrypt_in_place(
            &key,
            &mut ctx[enc.len() + nonce.len()..enc.len() + nonce.len() + ptx.len()],
            &nonce,
        )
        .map_err(|e| CryptoError::Default(format!("AE encryption error in PKE: {e}")))?;

        (enc, nonce, ctx, tag).serialize().map_err(|e| {
            CryptoError::Default(format!("serialization encryption error in PKE: {e}"))
        })
    }

    fn decrypt(dk: &[u8], ctx: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let (enc, nonce, mut ptx, tag) =
            <(Vec<u8>, [u8; 12], Zeroizing<Vec<u8>>, [u8; 16])>::deserialize(ctx).map_err(|e| {
                CryptoError::Default(format!("serialization encryption error in PKE: {e}"))
            })?;
        let key = Self::dec(dk, &enc)?;
        Aes256Gcm::decrypt_in_place(&key, &mut ptx, &nonce, &tag)
            .map_err(|e| CryptoError::Default(format!("AE decryption error in PKE: {e}")))?;

        Ok(ptx)
    }

    fn create_dk_object(
        dk_bytes: Zeroizing<Vec<u8>>,
        mut attributes: Attributes,
        ek_uid: String,
        sensitive: bool,
    ) -> Result<Object, CryptoError> {
        debug!(
            "create_dk_object: key len: {}, attributes: {attributes}",
            dk_bytes.len()
        );

        attributes.object_type = Some(ObjectType::PrivateKey);

        //
        // TODO: use the proper key-format type.
        //
        attributes.key_format_type = Some(KeyFormatType::CoverCryptSecretKey);

        attributes.set_cryptographic_usage_mask_bits(CryptographicUsageMask::Unrestricted);
        attributes.link = Some(vec![Link {
            link_type: LinkType::PublicKeyLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString(ek_uid),
        }]);
        attributes.sensitive = sensitive.then_some(true);

        let mut tags = attributes.get_tags();
        tags.insert("_sk".to_owned());
        attributes.set_tags(tags)?;

        let cryptographic_length = Some(i32::try_from(dk_bytes.len())? * 8);
        Ok(Object::PrivateKey(PrivateKey {
            key_block: KeyBlock {
                //
                // TODO: add a new KEM cryptographic algorithm.
                //
                cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
                key_format_type: KeyFormatType::CoverCryptSecretKey,
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

        //
        // TODO: use the proper key-format type.
        //
        attributes.key_format_type = Some(KeyFormatType::CoverCryptPublicKey);
        // Covercrypt keys are set to have unrestricted usage.
        attributes.set_cryptographic_usage_mask_bits(CryptographicUsageMask::Unrestricted);

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
                //
                // TODO: add a new KEM cryptographic algorithm.
                //
                cryptographic_algorithm: Some(CryptographicAlgorithm::CoverCrypt),
                key_format_type: KeyFormatType::CoverCryptPublicKey,
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmian_crypto_core::bytes_ser_de::test_serialization;

    #[test]
    fn test_tag_serialization() {
        // Exhaustively test serializations.
        test_serialization(&KemTag::PreQuantum(PreQuantumKemTag::P256)).unwrap();
        test_serialization(&KemTag::PreQuantum(PreQuantumKemTag::R25519)).unwrap();
        test_serialization(&KemTag::PostQuantum(PostQuantumKemTag::MlKem)).unwrap();
        test_serialization(&KemTag::Hybridized(
            PreQuantumKemTag::P256,
            PostQuantumKemTag::MlKem,
        ))
        .unwrap();
        test_serialization(&KemTag::Hybridized(
            PreQuantumKemTag::R25519,
            PostQuantumKemTag::MlKem,
        ))
        .unwrap();
        #[cfg(feature = "non-fips")]
        test_serialization(&KemTag::Abe).unwrap();
    }
}
