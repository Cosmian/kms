//! The HSM Store is a store that allows the creation, retrieval, update, and deletion of objects on an HSM.
//! It is the link between the database and the HSM.

use std::{collections::HashSet, sync::Arc};

use KmipKeyMaterial::TransparentRSAPublicKey;
use async_trait::async_trait;
use cosmian_kmip::{
    SafeBigInt,
    kmip_0::kmip_types::{CryptographicUsageMask, State},
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_data_structures::{KeyBlock, KeyMaterial as KmipKeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType, PrivateKey, PublicKey, SymmetricKey},
        kmip_types::{CryptographicAlgorithm, KeyFormatType},
    },
};
use cosmian_logger::{debug, error, trace, warn};
use num_bigint_dig::{BigInt, Sign};

use crate::{
    AtomicOperation, HSM, HsmKeyAlgorithm, HsmKeypairAlgorithm, HsmObject, HsmObjectFilter,
    InterfaceError, InterfaceResult, KeyMaterial, ObjectWithMetadata, ObjectsStore, as_hsm_uid,
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
    ) -> InterfaceResult<String> {
        if owner != self.hsm_admin {
            return Err(InterfaceError::InvalidRequest(
                "Only the HSM Admin can create HSM objects".to_owned(),
            ));
        }
        // try converting the rest of the uid into a slot_id
        let uid = uid.as_ref().ok_or_else(|| {
            InterfaceError::InvalidRequest(
                format!("An HSM create request must have a uid in the form of 'hsm::<slot_id>::<key_id>'. Got {uid:?}"
            ))
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
                attributes.sensitive.unwrap_or_default(),
            )
            .await?;
        debug!("Created HSM AES Key of length {key_length} with id {uid}",);
        Ok(uid.to_owned())
    }

    async fn retrieve(&self, uid: &str) -> InterfaceResult<Option<ObjectWithMetadata>> {
        // try converting the rest of the UID into a slot_id and key id
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

    async fn retrieve_tags(&self, _uid: &str) -> InterfaceResult<HashSet<String>> {
        // Not supported for HSMs
        Ok(HashSet::new())
    }

    async fn update_object(
        &self,
        _uid: &str,
        _object: &Object,
        _attributes: &Attributes,
        _tags: Option<&HashSet<String>>,
    ) -> InterfaceResult<()> {
        // not supported for HSMs
        Err(InterfaceError::InvalidRequest(
            "Update object is not supported for HSMs".to_owned(),
        ))
    }

    async fn update_state(&self, _uid: &str, _state: State) -> InterfaceResult<()> {
        // not supported for HSMs
        Err(InterfaceError::InvalidRequest(
            "Update state is not supported for HSMs".to_owned(),
        ))
    }

    async fn delete(&self, uid: &str) -> InterfaceResult<()> {
        let (slot_id, key_id) = parse_uid(uid)?;
        self.hsm.delete(slot_id, key_id.as_bytes()).await?;
        Ok(())
    }

    async fn atomic(
        &self,
        user: &str,
        operations: &[AtomicOperation],
    ) -> InterfaceResult<Vec<String>> {
        if let Some((uid, _object, attributes, _tags)) = is_rsa_keypair_creation(operations) {
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
                    attributes.sensitive.unwrap_or_default(),
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

    async fn is_object_owned_by(&self, _uid: &str, owner: &str) -> InterfaceResult<bool> {
        debug!(
            "Is {owner}, the owner of {_uid}? {}",
            owner == self.hsm_admin
        );
        Ok(owner == self.hsm_admin)
    }

    async fn list_uids_for_tags(
        &self,
        _tags: &HashSet<String>,
    ) -> InterfaceResult<HashSet<String>> {
        // Not Tags on the HSM
        Ok(HashSet::new())
    }

    async fn find(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<State>,
        user: &str,
        user_must_be_owner: bool,
    ) -> InterfaceResult<Vec<(String, State, Attributes)>> {
        let slot_ids = self.hsm.get_available_slot_list().await?;
        let mut uids = Vec::new();
        if user_must_be_owner && user != self.hsm_admin {
            warn!(
                "User '{}' is not the HSM admin '{}' but 'user_must_be_owner'",
                user, self.hsm_admin
            );
            return Ok(uids);
        }
        let mut search_attributes = researched_attributes.cloned().unwrap_or_else(|| {
            debug!("No researched_attributes provided. Defaulting to empty filter attributes");
            Attributes::default()
        });
        match check_basic_compatibility(&search_attributes, state) {
            Ok(()) => {}
            Err(e) => {
                debug!("{e}");
                return Ok(uids);
            }
        }
        let object_filter = match HsmObjectFilter::try_from(&search_attributes) {
            Ok(object_filter) => object_filter,
            Err(e) => {
                warn!("{e}");
                return Ok(uids);
            }
        };
        let key_size_filter = search_attributes.get_cryptographic_length();
        let key_id_filter = match search_attributes.unique_identifier {
            Some(unique_identifier) => {
                let Some(str) = unique_identifier.as_str() else {
                    return Ok(uids);
                };
                Some(str.to_owned())
            }
            None => None,
        };

        for slot_id in slot_ids {
            let found = self
                .hsm
                .find(slot_id, object_filter.clone())
                .await
                .unwrap_or(vec![]);
            for object_id in found {
                trace!("Getting metadata for: {:02X?}", object_id);
                let object_meta = self
                    .hsm
                    .get_key_metadata(slot_id, &object_id)
                    .await
                    .unwrap_or_default();
                if let Some(expected_key_size) = key_size_filter {
                    if let Some(meta) = object_meta {
                        if meta.key_length_in_bits != expected_key_size {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }
                let object_string = match str::from_utf8(&object_id) {
                    Ok(object_string) => object_string,
                    Err(err) => {
                        error!("Failed to decode object_id {}", err);
                        continue;
                    }
                };
                let uid = as_hsm_uid!(slot_id, object_string);
                trace!("Found: {uid}");
                if let Some(ref wanted_id) = key_id_filter {
                    if !uid.eq(wanted_id) {
                        continue;
                    }
                }
                uids.push((uid, State::Active, Attributes::default()));
            }
        }

        Ok(uids)
    }
}

fn check_basic_compatibility(
    researched_attributes: &Attributes,
    state: Option<State>,
) -> InterfaceResult<()> {
    // HSM keys are always active.
    if let Some(s) = state {
        if s != State::Active {
            return Err(InterfaceError::Default(format!(
                "Unsupported state for HSMs: expected Active, got {s:?}"
            )));
        }
    }

    if researched_attributes.link.is_some() {
        return Err(InterfaceError::Default(
            "Unsupported attribute for HSMs: link".to_owned(),
        ));
    }

    if !researched_attributes.get_tags().is_empty() {
        return Err(InterfaceError::Default(
            "Unsupported attribute for HSMs: tags".to_owned(),
        ));
    }

    if researched_attributes.object_group.is_some() {
        return Err(InterfaceError::Default(
            "Unsupported attribute for HSMs: object_group".to_owned(),
        ));
    }

    if researched_attributes.object_group_member.is_some() {
        return Err(InterfaceError::Default(
            "Unsupported attribute for HSMs: object_group_member".to_owned(),
        ));
    }

    if researched_attributes.comment.is_some() {
        return Err(InterfaceError::Default(
            "Unsupported attribute for HSMs: comment".to_owned(),
        ));
    }

    if researched_attributes.contact_information.is_some() {
        return Err(InterfaceError::Default(
            "Unsupported attribute for HSMs: contact_information".to_owned(),
        ));
    }

    if let Some(critical) = researched_attributes.critical {
        if critical {
            return Err(InterfaceError::Default(
                "Unsupported attribute for HSMs: critical = true".to_owned(),
            ));
        }
    }

    if researched_attributes.description.is_some() {
        return Err(InterfaceError::Default(
            "Unsupported attribute for HSMs: description".to_owned(),
        ));
    }

    if researched_attributes.digest.is_some() {
        return Err(InterfaceError::Default(
            "Unsupported attribute for HSMs: digest".to_owned(),
        ));
    }

    if researched_attributes.short_unique_identifier.is_some() {
        return Err(InterfaceError::Default(
            "Unsupported attribute for HSMs: short_unique_identifier".to_owned(),
        ));
    }

    if researched_attributes.cryptographic_usage_mask.is_some() {
        return Err(InterfaceError::Default(
            "Unsupported attribute for HSMs: cryptographic_usage_mask".to_owned(),
        ));
    }

    if researched_attributes.x_509_certificate_identifier.is_some() {
        return Err(InterfaceError::Default(
            "Unsupported attribute for HSMs: x_509_certificate_identifier".to_owned(),
        ));
    }

    if researched_attributes.x_509_certificate_issuer.is_some() {
        return Err(InterfaceError::Default(
            "Unsupported attribute for HSMs: x_509_certificate_issuer".to_owned(),
        ));
    }

    if researched_attributes.x_509_certificate_subject.is_some() {
        return Err(InterfaceError::Default(
            "Unsupported attribute for HSMs: x_509_certificate_subject".to_owned(),
        ));
    }

    Ok(())
}

/// The creation of RSA key pairs is done via 2 atomic operations,
/// one to create the private key and one to generate the public key.
/// All the information we need is contained in the atomic operation
/// to create the private key, so we recover it here
///
/// # Returns
/// - the UID of the private key
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
                    key_value: Some(KeyValue::Structure {
                        key_material: kmip_key_material,
                        attributes: Some(attributes.clone()),
                    }),
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
                State::Active,
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
                modulus: Box::new(BigInt::from_bytes_be(Sign::Plus, km.modulus.as_slice())),
                private_exponent: Some(Box::new(SafeBigInt::from_bytes_be(
                    km.private_exponent.as_slice(),
                ))),
                public_exponent: Some(Box::new(BigInt::from_bytes_be(
                    Sign::Plus,
                    km.public_exponent.as_slice(),
                ))),
                p: Some(Box::new(SafeBigInt::from_bytes_be(km.prime_1.as_slice()))),
                q: Some(Box::new(SafeBigInt::from_bytes_be(km.prime_2.as_slice()))),
                prime_exponent_p: Some(Box::new(SafeBigInt::from_bytes_be(
                    km.exponent_1.as_slice(),
                ))),
                prime_exponent_q: Some(Box::new(SafeBigInt::from_bytes_be(
                    km.exponent_2.as_slice(),
                ))),
                c_r_t_coefficient: Some(Box::new(SafeBigInt::from_bytes_be(
                    km.coefficient.as_slice(),
                ))),
            };
            let object = Object::PrivateKey(PrivateKey {
                key_block: KeyBlock {
                    key_format_type: KeyFormatType::TransparentRSAPrivateKey,
                    key_compression_type: None,
                    key_value: Some(KeyValue::Structure {
                        key_material: kmip_key_material,
                        attributes: Some(attributes.clone()),
                    }),
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
                State::Active,
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
                modulus: Box::new(BigInt::from_bytes_be(Sign::Plus, km.modulus.as_slice())),
                public_exponent: Box::new(BigInt::from_bytes_be(
                    Sign::Plus,
                    km.public_exponent.as_slice(),
                )),
            };
            let object = Object::PublicKey(PublicKey {
                key_block: KeyBlock {
                    key_format_type: KeyFormatType::TransparentRSAPublicKey,
                    key_compression_type: None,
                    key_value: Some(KeyValue::Structure {
                        key_material: kmip_key_material,
                        attributes: Some(attributes.clone()),
                    }),
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
                State::Active,
                attributes,
            ))
        }
    }
}
