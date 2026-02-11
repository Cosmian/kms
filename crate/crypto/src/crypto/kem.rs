//! This module implements a generic KEM which concrete variant is chosen at
//! runtime among a set of authorized variants chosen at initialization time.
//!
//! Implementations of the concrete variants are chosen at compile-time.

use crate::{
    CryptoError,
    crypto::{KeyPair, cover_crypt::attributes::access_structure_from_attributes},
};
use cosmian_cover_crypt::{
    AccessPolicy, Covercrypt, MasterPublicKey, UserSecretKey, XEnc,
    kem::mlkem::{MlKem512, MlKem768},
    traits::KemAc,
};
use cosmian_crypto_core::{
    CsRng, SymmetricKey,
    bytes_ser_de::{Deserializer, Serializable, Serializer},
    reexport::rand_core::{CryptoRngCore, SeedableRng},
    traits::{KEM, cyclic_group_to_kem::GenericKem},
};
use cosmian_kmip::{
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
use cosmian_openssl_provider::{hash::Sha256, kem::MonadicKEM, p256::P256};
use cosmian_rust_curve25519_provider::R25519;
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
    ek: &[u8],
    rng: &mut impl CryptoRngCore,
) -> Result<(SymmetricKey<KEY_LENGTH>, Zeroizing<Vec<u8>>), CryptoError> {
    let ek = <Kem as KEM<KEY_LENGTH>>::EncapsulationKey::deserialize(ek)
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
    Abe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PreQuantumKemTag {
    P256,
    R25519,
}

impl TryFrom<RecommendedCurve> for PreQuantumKemTag {
    type Error = CryptoError;

    fn try_from(curve: RecommendedCurve) -> Result<Self, Self::Error> {
        match curve {
            RecommendedCurve::P256 => Ok(Self::P256),
            RecommendedCurve::CURVE25519 => Ok(Self::R25519),
            curve => {
                return Err(CryptoError::Kmip(format!(
                    "curve {curve:?} not supported as basis for a pre-quantum KEM"
                )));
            }
        }
    }
}

impl Serializable for PreQuantumKemTag {
    type Error = CryptoError;

    fn length(&self) -> usize {
        1
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        match self {
            Self::P256 => ser.write(&1_u64),
            Self::R25519 => ser.write(&2_u64),
        }
        .map_err(CryptoError::from)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        match de.read::<u64>()? {
            1 => Ok(Self::P256),
            2 => Ok(Self::R25519),
            n => Err(CryptoError::ConversionError(format!(
                "{n} is not a valid pre-quantum-KEM tag"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PostQuantumKemTag {
    MlKem512,
    MlKem768,
}

impl TryFrom<CryptographicAlgorithm> for PostQuantumKemTag {
    type Error = CryptoError;

    fn try_from(alg: CryptographicAlgorithm) -> Result<Self, Self::Error> {
        match alg {
            CryptographicAlgorithm::MLKEM_512 => Ok(Self::MlKem512),
            CryptographicAlgorithm::MLKEM_768 => Ok(Self::MlKem768),
            alg => {
                return Err(CryptoError::Kmip(format!(
                    "{alg:?} not supported as post-quantum KEM"
                )));
            }
        }
    }
}

impl Serializable for PostQuantumKemTag {
    type Error = CryptoError;

    fn length(&self) -> usize {
        1
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        match self {
            Self::MlKem512 => ser.write(&1_u64),
            Self::MlKem768 => ser.write(&2_u64),
        }
        .map_err(CryptoError::from)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        match de.read::<u64>()? {
            1 => Ok(Self::MlKem512),
            2 => Ok(Self::MlKem768),
            n => Err(CryptoError::ConversionError(format!(
                "{n} is not a valid post-quantum-KEM tag"
            ))),
        }
    }
}

impl Serializable for KemTag {
    type Error = CryptoError;

    fn length(&self) -> usize {
        match self {
            Self::PreQuantum(_) | Self::PostQuantum(_) => 2,
            Self::Hybridized(_, _) => 3,
            Self::Abe => 1,
        }
    }

    fn write(
        &self,
        ser: &mut cosmian_crypto_core::bytes_ser_de::Serializer,
    ) -> Result<usize, Self::Error> {
        match self {
            Self::PreQuantum(tag) => Ok(ser.write(&1_u64)? + ser.write(tag)?),
            Self::PostQuantum(tag) => Ok(ser.write(&2_u64)? + ser.write(tag)?),
            Self::Hybridized(tag1, tag2) => {
                Ok(ser.write(&3_u64)? + ser.write(tag1)? + ser.write(tag2)?)
            }
            Self::Abe => Ok(ser.write(&4_u64)?),
        }
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        match de.read::<usize>()? {
            1 => de.read::<PreQuantumKemTag>().map(Self::PreQuantum),
            2 => de.read::<PostQuantumKemTag>().map(Self::PostQuantum),
            3 => de
                .read::<(PreQuantumKemTag, PostQuantumKemTag)>()
                .map(|(tag1, tag2)| Self::Hybridized(tag1, tag2))
                .map_err(Self::Error::from),
            4 => Ok(Self::Abe),
            n => Err(Self::Error::ConversionError(format!(
                "{n} is not a valid KEM tag"
            ))),
        }
    }
}

// Finally, we can implement a KEM-like interface for our configurable KEM which
// deserializes KEM objects as couple (tag, bytes), checks tag legality and
// compatibility across objects before the KEM operation with corresponding
// implementation, and finally serializes returned objects as (tag, bytes)
// couples.

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
        Sha256, // SHA256 from the OpenSSL provider.
    >;

pub struct ConfigurableKEM;

impl ConfigurableKEM {
    #[allow(clippy::too_many_arguments)]
    pub fn keygen(
        dk_uid: String,
        dk_attributes: Option<Attributes>,
        ek_uid: String,
        ek_attributes: Option<Attributes>,
        common_attributes: Attributes,
    ) -> Result<KeyPair, CryptoError> {
        let rng = &mut CsRng::from_entropy();

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
                    KemTag::PostQuantum(alg.try_into()?)
                }
            }
            (Some(curve), None) => KemTag::PreQuantum(curve.try_into()?),
            (Some(curve), Some(alg)) => KemTag::Hybridized(curve.try_into()?, alg.try_into()?),
        };

        let (dk_bytes, ek_bytes) = match tag {
            KemTag::PreQuantum(PreQuantumKemTag::P256) => {
                generic_keygen::<{ P256Kem::KEY_LENGTH }, P256Kem>(rng)
            }
            KemTag::PreQuantum(PreQuantumKemTag::R25519) => {
                generic_keygen::<{ R25519Kem::KEY_LENGTH }, R25519Kem>(rng)
            }
            KemTag::PostQuantum(PostQuantumKemTag::MlKem512) => {
                generic_keygen::<{ MlKem512::KEY_LENGTH }, MlKem512>(rng)
            }
            KemTag::PostQuantum(PostQuantumKemTag::MlKem768) => {
                generic_keygen::<{ MlKem768::KEY_LENGTH }, MlKem768>(rng)
            }
            KemTag::Hybridized(PreQuantumKemTag::P256, PostQuantumKemTag::MlKem512) => {
                generic_keygen::<
                    { P256Kem::KEY_LENGTH },
                    KemCombiner<{ P256Kem::KEY_LENGTH }, P256Kem, MlKem512>,
                >(rng)
            }
            KemTag::Hybridized(PreQuantumKemTag::P256, PostQuantumKemTag::MlKem768) => {
                generic_keygen::<
                    { P256Kem::KEY_LENGTH },
                    KemCombiner<{ P256Kem::KEY_LENGTH }, P256Kem, MlKem768>,
                >(rng)
            }
            KemTag::Hybridized(PreQuantumKemTag::R25519, PostQuantumKemTag::MlKem512) => {
                generic_keygen::<
                    { R25519Kem::KEY_LENGTH },
                    KemCombiner<{ R25519Kem::KEY_LENGTH }, R25519Kem, MlKem512>,
                >(rng)
            }
            KemTag::Hybridized(PreQuantumKemTag::R25519, PostQuantumKemTag::MlKem768) => {
                generic_keygen::<
                    { R25519Kem::KEY_LENGTH },
                    KemCombiner<{ R25519Kem::KEY_LENGTH }, R25519Kem, MlKem768>,
                >(rng)
            }
            KemTag::Abe => {
                let access_structure = access_structure_from_attributes(&common_attributes)
                    .map_err(|_| {
                        CryptoError::Default(
                        "cannot execute a Covercrypt key generation without an access structure"
                            .to_owned(),
                    )
                    })?;
                let cc = Covercrypt::default();
                let (mut msk, _) = cc.setup()?;
                msk.access_structure = access_structure;
                let mpk = cc.update_msk(&mut msk)?;
                Ok((msk.serialize()?, mpk.serialize()?))
            }
        }?;

        Ok(KeyPair::new(
            Self::create_dk_object(
                (tag, dk_bytes).serialize()?,
                dk_attributes.unwrap_or_else(|| common_attributes.clone()),
                ek_uid,
            )?,
            Self::create_ek_object(
                (tag, ek_bytes).serialize()?,
                ek_attributes.unwrap_or(common_attributes),
                dk_uid,
            )?,
        ))
    }

    pub fn enc(
        ek_bytes: &[u8],
        access_policy: Option<&Zeroizing<Vec<u8>>>,
    ) -> Result<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>), CryptoError> {
        let (tag, ek_bytes) = <(KemTag, Vec<u8>)>::deserialize(ek_bytes).map_err(|e| {
            CryptoError::Default(format!(
                "failed deserializing the tag and encapsulation key in configurable KEM: {e}"
            ))
        })?;

        let rng = &mut CsRng::from_entropy();

        let (key, enc) = match tag {
            KemTag::PreQuantum(PreQuantumKemTag::P256) => {
                generic_enc::<{ P256Kem::KEY_LENGTH }, P256Kem>(&ek_bytes, rng)
            }
            KemTag::PreQuantum(PreQuantumKemTag::R25519) => {
                generic_enc::<{ R25519Kem::KEY_LENGTH }, R25519Kem>(&ek_bytes, rng)
            }
            KemTag::PostQuantum(PostQuantumKemTag::MlKem512) => {
                generic_enc::<{ MlKem512::KEY_LENGTH }, MlKem512>(&ek_bytes, rng)
            }
            KemTag::PostQuantum(PostQuantumKemTag::MlKem768) => {
                generic_enc::<{ MlKem768::KEY_LENGTH }, MlKem768>(&ek_bytes, rng)
            }
            KemTag::Hybridized(PreQuantumKemTag::P256, PostQuantumKemTag::MlKem512) => {
                generic_enc::<
                    { P256Kem::KEY_LENGTH },
                    KemCombiner<{ P256Kem::KEY_LENGTH }, P256Kem, MlKem512>,
                >(&ek_bytes, rng)
            }
            KemTag::Hybridized(PreQuantumKemTag::P256, PostQuantumKemTag::MlKem768) => {
                generic_enc::<
                    { P256Kem::KEY_LENGTH },
                    KemCombiner<{ P256Kem::KEY_LENGTH }, P256Kem, MlKem768>,
                >(&ek_bytes, rng)
            }
            KemTag::Hybridized(PreQuantumKemTag::R25519, PostQuantumKemTag::MlKem512) => {
                generic_enc::<
                    { R25519Kem::KEY_LENGTH },
                    KemCombiner<{ R25519Kem::KEY_LENGTH }, R25519Kem, MlKem512>,
                >(&ek_bytes, rng)
            }
            KemTag::Hybridized(PreQuantumKemTag::R25519, PostQuantumKemTag::MlKem768) => {
                generic_enc::<
                    { R25519Kem::KEY_LENGTH },
                    KemCombiner<{ R25519Kem::KEY_LENGTH }, R25519Kem, MlKem768>,
                >(&ek_bytes, rng)
            }
            KemTag::Abe => {
                let ap = access_policy
                    .ok_or_else(|| {
                        CryptoError::Default(
                            "cannot create a Covercrypt encapsulation without an access policy"
                                .to_owned(),
                        )
                    })
                    .and_then(|ap| {
                        AccessPolicy::parse(&String::from_utf8_lossy(&*ap).to_owned())
                            .map_err(CryptoError::from)
                    })?;
                let mpk = MasterPublicKey::deserialize(&ek_bytes)?;
                let (key, ctx) = Covercrypt::default().encaps(&mpk, &ap)?;
                Ok((SymmetricKey::from(key), ctx.serialize()?))
            }
        }?;

        let mut key_bytes = Zeroizing::new(vec![0; key.len()]);
        key_bytes.copy_from_slice(&*key);
        Ok((key_bytes, enc))
    }

    pub fn dec(dk: &[u8], enc: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let (dk_tag, dk_bytes) = <(KemTag, Zeroizing<Vec<u8>>)>::deserialize(dk).map_err(|e| {
            CryptoError::Default(format!(
                "failed deserializing the tag and decapsulation key in configurable KEM: {e}"
            ))
        })?;

        let (enc_tag, enc_bytes) = <(KemTag, Vec<u8>)>::deserialize(enc).map_err(|e| {
            CryptoError::Default(format!(
                "failed deserializing the tag and encapsulation in configurable KEM: {e}"
            ))
        })?;

        if dk_tag != enc_tag {
            return Err(CryptoError::Default(format!(
                "heterogeneous decapsulation-key and encapsulation tags: {dk_tag:?} != {enc_tag:?}"
            )));
        }

        let key = match dk_tag {
            KemTag::PreQuantum(PreQuantumKemTag::P256) => {
                generic_dec::<{ P256Kem::KEY_LENGTH }, P256Kem>(&dk_bytes, &enc_bytes)
            }
            KemTag::PreQuantum(PreQuantumKemTag::R25519) => {
                generic_dec::<{ R25519Kem::KEY_LENGTH }, R25519Kem>(&dk_bytes, &enc_bytes)
            }
            KemTag::PostQuantum(PostQuantumKemTag::MlKem512) => {
                generic_dec::<{ MlKem512::KEY_LENGTH }, MlKem512>(&dk_bytes, &enc_bytes)
            }
            KemTag::PostQuantum(PostQuantumKemTag::MlKem768) => {
                generic_dec::<{ MlKem768::KEY_LENGTH }, MlKem768>(&dk_bytes, &enc_bytes)
            }
            KemTag::Hybridized(PreQuantumKemTag::P256, PostQuantumKemTag::MlKem512) => {
                generic_dec::<
                    { P256Kem::KEY_LENGTH },
                    KemCombiner<{ P256Kem::KEY_LENGTH }, P256Kem, MlKem512>,
                >(&dk_bytes, &enc_bytes)
            }
            KemTag::Hybridized(PreQuantumKemTag::P256, PostQuantumKemTag::MlKem768) => {
                generic_dec::<
                    { P256Kem::KEY_LENGTH },
                    KemCombiner<{ P256Kem::KEY_LENGTH }, P256Kem, MlKem768>,
                >(&dk_bytes, &enc_bytes)
            }
            KemTag::Hybridized(PreQuantumKemTag::R25519, PostQuantumKemTag::MlKem512) => {
                generic_dec::<
                    { R25519Kem::KEY_LENGTH },
                    KemCombiner<{ R25519Kem::KEY_LENGTH }, R25519Kem, MlKem512>,
                >(&dk_bytes, &enc_bytes)
            }
            KemTag::Hybridized(PreQuantumKemTag::R25519, PostQuantumKemTag::MlKem768) => {
                generic_dec::<
                    { R25519Kem::KEY_LENGTH },
                    KemCombiner<{ R25519Kem::KEY_LENGTH }, R25519Kem, MlKem768>,
                >(&dk_bytes, &enc_bytes)
            }
            KemTag::Abe => {
                let usk = UserSecretKey::deserialize(&dk_bytes)?;
                let enc = XEnc::deserialize(&enc_bytes)?;
                let key = Covercrypt::default().decaps(&usk, &enc)?.ok_or_else(|| {
                    CryptoError::Default(
                        "cannot open Covercrypt encapsulation: incompatible access rights"
                            .to_owned(),
                    )
                })?;
                Ok(SymmetricKey::from(key))
            }
        }?;

        let mut key_bytes = Zeroizing::new(vec![0; key.len()]);
        key_bytes.copy_from_slice(&*key);
        Ok(key_bytes)
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
        attributes.key_format_type = Some(KeyFormatType::ConfigurableKEM);
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
        attributes.key_format_type = Some(KeyFormatType::ConfigurableKEM);
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
        test_serialization(&KemTag::PostQuantum(PostQuantumKemTag::MlKem512)).unwrap();
        test_serialization(&KemTag::Hybridized(
            PreQuantumKemTag::P256,
            PostQuantumKemTag::MlKem512,
        ))
        .unwrap();
        test_serialization(&KemTag::Hybridized(
            PreQuantumKemTag::R25519,
            PostQuantumKemTag::MlKem512,
        ))
        .unwrap();
        test_serialization(&KemTag::Abe).unwrap();
    }
}
