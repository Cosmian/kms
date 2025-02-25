//! The HSM Store is a store that allows to create, retrieve, update and delete objects on an HSM.
//! It is the link between the database and the HSM.

#![allow(unused_variables)]
use std::{collections::HashSet, path::PathBuf, sync::Arc};

use KmipKeyMaterial::TransparentRSAPublicKey;
use async_trait::async_trait;
use cosmian_kmip::{
    SafeBigUint,
    kmip_2_1::{
        kmip_data_structures::{KeyBlock, KeyMaterial as KmipKeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType, PrivateKey, PublicKey, SymmetricKey},
        kmip_types::{
            Attributes, CryptographicAlgorithm, CryptographicUsageMask, KeyFormatType,
            StateEnumeration,
        },
    },
};
use num_bigint_dig::BigUint;
use tracing::debug;

use crate::{
    AtomicOperation, HSM, HsmKeyAlgorithm, HsmKeypairAlgorithm, HsmObject, InterfaceError,
    InterfaceResult, KeyMaterial, ObjectWithMetadata, ObjectsStore, SessionParams,
};

pub struct HsmStore {
    hsm: Arc<dyn HSM + Send + Sync>,
    hsm_admin: String,
}

impl HsmStore {
    pub fn new(hsm: Arc<dyn HSM + Send + Sync>, hsm_admin: &str) -> Self {
        Self {
            hsm,
            hsm_admin: hsm_admin.to_owned(),
        }
    }
}

#[async_trait(?Send)]
impl ObjectsStore for HsmStore {
    fn filename(&self, _group_id: u128) -> Option<PathBuf> {
        None
    }

    // Only single keys are created using this call,
    // keypair creation goes through the atomic operations
    /// Create a key on the HSM
    /// `tags` are not available on HSMs
    async fn create(
        &self,
        uid: Option<String>,
        owner: &str,
        object: &Object,
        attributes: &Attributes,
        _tags: &HashSet<String>,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<String> {
        if owner != self.hsm_admin {
            return Err(InterfaceError::InvalidRequest(
                "Only the HSM Admin can create HSM objects".to_owned(),
            ));
        }
        // try converting the rest of the uid into a slot_id
        let uid = uid.as_ref().ok_or_else(|| {
            InterfaceError::InvalidRequest(
                "An HSM create request must have a uid in the form of 'hsm::<slot_id>::<key_id>'"
                    .to_string(),
            )
        })?;
        let (slot_id, key_id) = parse_uid(uid)?;
        if object.object_type() != ObjectType::SymmetricKey {
            return Err(InterfaceError::InvalidRequest(
                "Only symmetric keys can be created on the HSM in this server".to_owned(),
            ));
        }
        let algorithm = attributes.cryptographic_algorithm.as_ref().ok_or_else(|| {
            InterfaceError::InvalidRequest(
                "Create: HSM keys must have a cryptographic algorithm specified".to_owned(),
            )
        })?;
        if *algorithm != CryptographicAlgorithm::AES {
            return Err(InterfaceError::InvalidRequest(
                "Only AES symmetric keys can be created on the HSM in this server".to_owned(),
            ));
        }
        let key_length = attributes.cryptographic_length.as_ref().ok_or_else(|| {
            InterfaceError::InvalidRequest(
                "Symmetric key must have a cryptographic length specified".to_owned(),
            )
        })?;
        self.hsm
            .create_key(
                slot_id,
                key_id.as_bytes(),
                HsmKeyAlgorithm::AES,
                usize::try_from(*key_length).map_err(|e| {
                    InterfaceError::InvalidRequest(format!("Invalid key length: {e}"))
                })?,
                attributes.sensitive,
            )
            .await?;
        debug!("Created HSM AES Key of length {key_length} with id {uid}",);
        Ok(uid.to_owned())
    }

    async fn retrieve(
        &self,
        uid: &str,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<Option<ObjectWithMetadata>> {
        // try converting the rest of the uid into a slot_id and key id
        let (slot_id, key_id) = parse_uid(uid)?;
        Ok(
            if let Some(hsm_object) = self.hsm.export(slot_id, key_id.as_bytes()).await? {
                // Convert the HSM object into an ObjectWithMetadata
                let owm = to_object_with_metadata(&hsm_object, uid, self.hsm_admin.as_str())?;
                Some(owm)
            } else {
                None
            },
        )
    }

    async fn retrieve_tags(
        &self,
        uid: &str,
        params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<HashSet<String>> {
        // Not supported for HSMs
        Ok(HashSet::new())
    }

    async fn update_object(
        &self,
        uid: &str,
        object: &Object,
        attributes: &Attributes,
        tags: Option<&HashSet<String>>,
        params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<()> {
        // not supported for HSMs
        Err(InterfaceError::InvalidRequest(
            "Update object is not supported for HSMs".to_owned(),
        ))
    }

    async fn update_state(
        &self,
        uid: &str,
        state: StateEnumeration,
        params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<()> {
        // not supported for HSMs
        Err(InterfaceError::InvalidRequest(
            "Update state is not supported for HSMs".to_owned(),
        ))
    }

    async fn delete(
        &self,
        uid: &str,
        params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<()> {
        let (slot_id, key_id) = parse_uid(uid)?;
        self.hsm.delete(slot_id, key_id.as_bytes()).await?;
        Ok(())
    }

    async fn atomic(
        &self,
        user: &str,
        operations: &[AtomicOperation],
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<Vec<String>> {
        if let Some((uid, object, attributes, _tags)) = is_rsa_keypair_creation(operations) {
            debug!("Creating RSA keypair with uid: {uid}");
            if user != self.hsm_admin {
                return Err(InterfaceError::InvalidRequest(
                    "Only the HSM Admin can create HSM keypairs".to_owned(),
                ));
            }
            let (slot_id, sk_id) = parse_uid(&uid)?;
            let pk_id = sk_id.clone() + "_pk";
            self.hsm
                .create_keypair(
                    slot_id,
                    sk_id.as_bytes(),
                    pk_id.as_bytes(),
                    HsmKeypairAlgorithm::RSA,
                    usize::try_from(attributes.cryptographic_length.unwrap_or(2048)).map_err(
                        |e| InterfaceError::InvalidRequest(format!("Invalid key length: {e}")),
                    )?,
                    attributes.sensitive,
                )
                .await?;
            return Ok(vec![
                format!("hsm::{slot_id}::{sk_id}"),
                format!("hsm::{slot_id}::{pk_id}"),
            ]);
        }

        Err(InterfaceError::InvalidRequest(
            "HSM atomic operations only support RSA keypair creations for now".to_owned(),
        ))
    }

    async fn is_object_owned_by(
        &self,
        _uid: &str,
        owner: &str,
        _params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<bool> {
        debug!(
            "Is {owner} is the owner of {_uid}? {}",
            owner == self.hsm_admin
        );
        Ok(owner == self.hsm_admin)
    }

    async fn list_uids_for_tags(
        &self,
        tags: &HashSet<String>,
        params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<HashSet<String>> {
        todo!()
    }

    async fn find(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<StateEnumeration>,
        user: &str,
        user_must_be_owner: bool,
        params: Option<Arc<dyn SessionParams>>,
    ) -> InterfaceResult<Vec<(String, StateEnumeration, Attributes)>> {
        todo!()
    }
}

/// The creation of RSA key pairs is done via 2 atomic operations,
/// one to create the private key and one to generate the public key.
/// All the information we need is contained in the atomic operation
/// to create the private key, so we recover it here
///
/// # Returns
///  - the uid of the private key
/// - the object of the private key
/// - the attributes of the private key
fn is_rsa_keypair_creation(
    operations: &[AtomicOperation],
) -> Option<(String, Object, Attributes, HashSet<String>)> {
    operations
        .iter()
        .filter_map(|op| match op {
            AtomicOperation::Create((uid, object, attributes, tags)) => {
                if object.object_type() != ObjectType::PrivateKey {
                    return None;
                }
                if !attributes
                    .cryptographic_algorithm
                    .as_ref()
                    .is_some_and(|algorithm| *algorithm == CryptographicAlgorithm::RSA)
                {
                    return None;
                }
                Some((
                    uid.clone(),
                    object.clone(),
                    attributes.clone(),
                    tags.clone(),
                ))
            }
            _ => None,
        })
        .collect::<Vec<_>>()
        .first()
        .cloned()
}

/// Parse the `uid` into a `slot_id` and `key_id`
fn parse_uid(uid: &str) -> Result<(usize, String), InterfaceError> {
    let (slot_id, key_id) = uid
        .trim_start_matches("hsm::")
        .split_once("::")
        .ok_or_else(|| {
            InterfaceError::InvalidRequest(
                "An HSM request must have a uid in the form of 'hsm::<slot_id>::<key_id>'"
                    .to_owned(),
            )
        })?;
    let slot_id = slot_id.parse::<usize>().map_err(|e| {
        InterfaceError::InvalidRequest(format!("The slot_id must be a valid unsigned integer: {e}"))
    })?;
    Ok((slot_id, key_id.to_owned()))
}

fn to_object_with_metadata(
    hsm_object: &HsmObject,
    uid: &str,
    user: &str,
) -> InterfaceResult<ObjectWithMetadata> {
    match hsm_object.key_material() {
        KeyMaterial::AesKey(bytes) => {
            let length: i32 = 8 * i32::try_from(bytes.len())
                .map_err(|e| InterfaceError::InvalidRequest(format!("Invalid key length: {e}")))?;
            let mut attributes = Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                cryptographic_length: Some(length),
                object_type: Some(ObjectType::SymmetricKey),
                // TODO: query these flags from the HSM
                cryptographic_usage_mask: Some(
                    CryptographicUsageMask::Encrypt
                        | CryptographicUsageMask::Decrypt
                        | CryptographicUsageMask::WrapKey
                        | CryptographicUsageMask::UnwrapKey
                        | CryptographicUsageMask::KeyAgreement,
                ),
                ..Attributes::default()
            };
            let mut tags: HashSet<String> =
                serde_json::from_str(hsm_object.id()).unwrap_or_else(|_| HashSet::new());
            tags.insert("_kk".to_owned());
            attributes
                .set_tags(tags)
                .map_err(|e| InterfaceError::InvalidRequest(format!("Invalid tags: {e}")))?;
            let kmip_key_material = KmipKeyMaterial::TransparentSymmetricKey { key: bytes.clone() };
            let object = Object::SymmetricKey(SymmetricKey {
                key_block: KeyBlock {
                    key_format_type: KeyFormatType::TransparentSymmetricKey,
                    key_compression_type: None,
                    key_value: KeyValue {
                        key_material: kmip_key_material,
                        attributes: Some(attributes.clone()),
                    },
                    cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                    cryptographic_length: Some(
                        8 * i32::try_from(bytes.len()).map_err(|e| {
                            InterfaceError::InvalidRequest(format!("Invalid key length: {e}"))
                        })?,
                    ),
                    key_wrapping_data: None,
                },
            });
            Ok(ObjectWithMetadata::new(
                uid.to_owned(),
                object,
                user.to_owned(),
                StateEnumeration::Active,
                attributes,
            ))
        }
        KeyMaterial::RsaPrivateKey(km) => {
            let mut attributes = Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                cryptographic_length: Some(
                    8 * i32::try_from(km.modulus.len()).map_err(|e| {
                        InterfaceError::InvalidRequest(format!("Invalid key length: {e}"))
                    })?,
                ),
                object_type: Some(ObjectType::PrivateKey),
                // TODO: query these flags from the HSM
                cryptographic_usage_mask: Some(
                    CryptographicUsageMask::Decrypt
                        | CryptographicUsageMask::UnwrapKey
                        | CryptographicUsageMask::Sign,
                ),
                ..Attributes::default()
            };
            let mut tags: HashSet<String> =
                serde_json::from_str(hsm_object.id()).unwrap_or_else(|_| HashSet::new());
            tags.insert("_sk".to_owned());
            attributes
                .set_tags(tags)
                .map_err(|e| InterfaceError::InvalidRequest(format!("Invalid tags: {e}")))?;
            let kmip_key_material = KmipKeyMaterial::TransparentRSAPrivateKey {
                modulus: Box::new(BigUint::from_bytes_be(km.modulus.as_slice())),
                private_exponent: Some(Box::new(SafeBigUint::from_bytes_be(
                    km.private_exponent.as_slice(),
                ))),
                public_exponent: Some(Box::new(BigUint::from_bytes_be(
                    km.public_exponent.as_slice(),
                ))),
                p: Some(Box::new(SafeBigUint::from_bytes_be(km.prime_1.as_slice()))),
                q: Some(Box::new(SafeBigUint::from_bytes_be(km.prime_2.as_slice()))),
                prime_exponent_p: Some(Box::new(SafeBigUint::from_bytes_be(
                    km.exponent_1.as_slice(),
                ))),
                prime_exponent_q: Some(Box::new(SafeBigUint::from_bytes_be(
                    km.exponent_2.as_slice(),
                ))),
                crt_coefficient: Some(Box::new(SafeBigUint::from_bytes_be(
                    km.coefficient.as_slice(),
                ))),
            };
            let object = Object::PrivateKey(PrivateKey {
                key_block: KeyBlock {
                    key_format_type: KeyFormatType::TransparentRSAPrivateKey,
                    key_compression_type: None,
                    key_value: KeyValue {
                        key_material: kmip_key_material,
                        attributes: Some(attributes.clone()),
                    },
                    cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                    cryptographic_length: Some(
                        8 * i32::try_from(km.modulus.len()).map_err(|e| {
                            InterfaceError::InvalidRequest(format!("Invalid key length: {e}"))
                        })?,
                    ),
                    key_wrapping_data: None,
                },
            });
            Ok(ObjectWithMetadata::new(
                uid.to_owned(),
                object,
                user.to_owned(),
                StateEnumeration::Active,
                attributes,
            ))
        }
        KeyMaterial::RsaPublicKey(km) => {
            let mut attributes = Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                cryptographic_length: Some(
                    i32::try_from(km.modulus.len()).map_err(|e| {
                        InterfaceError::InvalidRequest(format!("Invalid key length: {e}"))
                    })? * 8,
                ),
                object_type: Some(ObjectType::PrivateKey),
                // TODO: query these flags from the HSM
                cryptographic_usage_mask: Some(
                    CryptographicUsageMask::Encrypt
                        | CryptographicUsageMask::WrapKey
                        | CryptographicUsageMask::Verify,
                ),
                ..Attributes::default()
            };
            let mut tags: HashSet<String> =
                serde_json::from_str(hsm_object.id()).unwrap_or_else(|_| HashSet::new());
            tags.insert("_sk".to_owned());
            attributes
                .set_tags(tags)
                .map_err(|e| InterfaceError::InvalidRequest(format!("Invalid tags: {e}")))?;
            let kmip_key_material = TransparentRSAPublicKey {
                modulus: Box::new(BigUint::from_bytes_be(km.modulus.as_slice())),
                public_exponent: Box::new(BigUint::from_bytes_be(km.public_exponent.as_slice())),
            };
            let object = Object::PublicKey(PublicKey {
                key_block: KeyBlock {
                    key_format_type: KeyFormatType::TransparentRSAPublicKey,
                    key_compression_type: None,
                    key_value: KeyValue {
                        key_material: kmip_key_material,
                        attributes: Some(attributes.clone()),
                    },
                    cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                    cryptographic_length: Some(
                        i32::try_from(km.modulus.len()).map_err(|e| {
                            InterfaceError::InvalidRequest(format!("Invalid key length: {e}"))
                        })? * 8,
                    ),
                    key_wrapping_data: None,
                },
            });
            Ok(ObjectWithMetadata::new(
                uid.to_owned(),
                object,
                user.to_owned(),
                StateEnumeration::Active,
                attributes,
            ))
        }
    }
}
