use std::collections::HashSet;

#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::kmip_2_1::{
        kmip_objects::{PrivateKey, PublicKey},
        kmip_types::RecommendedCurve,
    },
    cosmian_kms_crypto::{
        CryptoError,
        crypto::elliptic_curves::operation::x25519_key_agreement,
        openssl::{kmip_private_key_to_openssl, kmip_public_key_to_openssl},
    },
    cosmian_kms_interfaces::AtomicOperation,
};
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{CryptographicUsageMask, HashingAlgorithm, SecretDataType},
        kmip_2_1::{
            KmipOperation,
            kmip_attributes::Attributes,
            kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
            kmip_objects::{Object, ObjectType, SecretData, SymmetricKey},
            kmip_operations::{DeriveKey, DeriveKeyResponse},
            kmip_types::{DerivationMethod, KeyFormatType, LinkType, UniqueIdentifier},
        },
    },
    cosmian_kms_interfaces::ObjectWithMetadata,
};
use cosmian_logger::debug;
use openssl::{
    hash::MessageDigest,
    md::{Md, MdRef},
    pkcs5::pbkdf2_hmac,
    pkey::Id,
    pkey_ctx::PkeyCtx,
};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    core::{
        KMS, operations::key_ops::crypto_op::ObjectLifecycleExt,
        retrieve_object_utils::user_has_permission, uid_utils::ObjectHandle,
    },
    error::KmsError,
    kms_bail,
    middlewares::UserId,
    result::{KResult, KResultHelper},
};

// Default constants for key derivation
const DEFAULT_PBKDF2_ITERATIONS: i32 = 600_000; // OWASP recommendation for PBKDF2 with SHA-256

pub(crate) async fn derive_key(
    kms: &KMS,
    request: DeriveKey,
    user: &UserId,
) -> KResult<DeriveKeyResponse> {
    debug!("DeriveKey operation starting");
    match request.derivation_method {
        DerivationMethod::PBKDF2 | DerivationMethod::HKDF => {
            Box::pin(derive_key_symmetric(kms, request, user)).await
        }
        DerivationMethod::Asymmetric_Key => {
            Box::pin(derive_key_asymmetric(kms, request, user)).await
        }
        _ => kms_bail!(KmsError::InvalidRequest(format!(
            "DeriveKey: Unsupported derivation method: {:?}",
            request.derivation_method
        ))),
    }
}

async fn derive_key_symmetric(
    kms: &KMS,
    request: DeriveKey,
    user: &UserId,
) -> KResult<DeriveKeyResponse> {
    match request.derivation_method {
        DerivationMethod::PBKDF2 => {
            if request.derivation_parameters.salt.is_none() {
                kms_bail!(KmsError::InvalidRequest(
                    "DeriveKey: Salt is mandatory when derivation method is PBKDF2".to_owned()
                ));
            }
            if request.derivation_parameters.iteration_count.is_none() {
                debug!("DeriveKey: No iteration count provided for PBKDF2, using default");
            }
        }
        DerivationMethod::HKDF => {
            if request.derivation_parameters.derivation_data.is_none() {
                debug!("DeriveKey: No derivation data (info) provided for HKDF");
            }
        }
        DerivationMethod::Asymmetric_Key => {
            kms_bail!(KmsError::InvalidRequest(
                "DeriveKey: invalid symmetric derivation method".to_owned()
            ));
        }
        _ => {}
    }

    if request.derivation_parameters.derivation_data.is_none() {
        debug!(
            "DeriveKey: No derivation data provided - this may be acceptable if a Secret Data \
             object identifier is provided"
        );
    }

    let base_identifier = request
        .object_unique_identifier
        .first()
        .cloned()
        .ok_or_else(|| {
            KmsError::InvalidRequest(
                "DeriveKey: exactly one base object identifier is required for PBKDF2/HKDF"
                    .to_owned(),
            )
        })?;
    if request.object_unique_identifier.len() != 1 {
        kms_bail!(KmsError::InvalidRequest(
            "DeriveKey: exactly one base object identifier is required for PBKDF2/HKDF".to_owned()
        ));
    }

    let base_key_handle = ObjectHandle::try_from(&base_identifier)?;
    let Some(mut base_key_owm) = kms
        .database
        .retrieve_object(base_key_handle.as_str())
        .await?
    else {
        kms_bail!(KmsError::InvalidRequest(format!(
            "DeriveKey: failed to retrieve base object {base_key_handle}"
        )))
    };

    let has_permission =
        user_has_permission(user, Some(&base_key_owm), &KmipOperation::DeriveKey, kms).await?;
    if !has_permission {
        kms_bail!(KmsError::Unauthorized(format!(
            "User {user} does not have DeriveKey permission on object {base_key_handle}"
        )));
    }

    base_key_owm.set_object(
        Box::pin(kms.get_unwrapped(base_key_owm.id(), base_key_owm.object(), user))
            .await
            .with_context(|| {
                format!(
                    "DeriveKey: the base key: {}, cannot be unwrapped.",
                    base_key_owm.id()
                )
            })?,
    );

    if !base_key_owm
        .attributes()
        .is_usage_authorized_for(CryptographicUsageMask::DeriveKey)?
    {
        kms_bail!(KmsError::InvalidRequest(
            "DeriveKey: base object does not have DeriveKey usage mask".to_owned()
        ));
    }

    let base_key_bytes = match base_key_owm.object() {
        Object::SymmetricKey(SymmetricKey { key_block })
        | Object::SecretData(SecretData { key_block, .. }) => key_block.key_bytes()?,
        _ => kms_bail!("DeriveKey: base object must be a SymmetricKey or SecretData"),
    };

    let cryptographic_length_bits = request.attributes.cryptographic_length.ok_or_else(|| {
        KmsError::InvalidRequest("DeriveKey: Cryptographic Length must be specified".to_owned())
    })?;
    let cryptographic_length = usize::try_from(cryptographic_length_bits).map_err(|_e| {
        KmsError::InvalidRequest("DeriveKey: Invalid cryptographic length".to_owned())
    })? / 8;

    if request.object_type == ObjectType::SymmetricKey
        && request.attributes.cryptographic_algorithm.is_none()
    {
        kms_bail!(KmsError::InvalidRequest(
            "DeriveKey: Cryptographic Algorithm must be specified for symmetric keys".to_owned()
        ));
    }

    let hashing_algorithm = request
        .derivation_parameters
        .cryptographic_parameters
        .as_ref()
        .and_then(|cp| cp.hashing_algorithm)
        .unwrap_or(HashingAlgorithm::SHA256);

    let derived_key_bytes = match request.derivation_method {
        DerivationMethod::PBKDF2 => {
            let salt = request
                .derivation_parameters
                .salt
                .as_deref()
                .ok_or_else(|| {
                    KmsError::InvalidRequest("Salt is required for PBKDF2".to_owned())
                })?;
            let iterations = request
                .derivation_parameters
                .iteration_count
                .unwrap_or(DEFAULT_PBKDF2_ITERATIONS);
            let iterations_u32 = u32::try_from(iterations).map_err(|_e| {
                KmsError::InvalidRequest("Invalid iteration count value".to_owned())
            })?;

            derive_pbkdf2(
                &base_key_bytes,
                salt,
                iterations_u32,
                cryptographic_length,
                hashing_algorithm,
            )?
        }
        DerivationMethod::HKDF => {
            let salt = request.derivation_parameters.salt.as_deref().unwrap_or(&[]);
            let info = request
                .derivation_parameters
                .derivation_data
                .as_deref()
                .map_or(&[][..], std::vec::Vec::as_slice);
            derive_hkdf(
                &base_key_bytes,
                salt,
                info,
                cryptographic_length,
                hashing_algorithm,
            )?
        }
        _ => kms_bail!(KmsError::InvalidRequest(format!(
            "DeriveKey: unsupported derivation method: {:?}",
            request.derivation_method
        ))),
    };

    if derived_key_bytes.len() < cryptographic_length {
        kms_bail!(KmsError::InvalidRequest(
            "DeriveKey: specified length exceeds the output of the derivation method".to_owned()
        ));
    }

    let uid = requested_derived_object_id(&request.attributes);
    let mut attributes = request.attributes.clone();
    let derived_object = match request.object_type {
        ObjectType::SymmetricKey => {
            let key_block = KeyBlock {
                key_format_type: KeyFormatType::TransparentSymmetricKey,
                key_compression_type: None,
                key_value: Some(KeyValue::Structure {
                    key_material: KeyMaterial::TransparentSymmetricKey {
                        key: (*derived_key_bytes).clone().into(),
                    },
                    attributes: Some(attributes.clone()),
                }),
                cryptographic_algorithm: attributes.cryptographic_algorithm,
                cryptographic_length: attributes.cryptographic_length,
                key_wrapping_data: None,
            };
            Object::SymmetricKey(SymmetricKey { key_block })
        }
        ObjectType::SecretData => {
            let key_block = KeyBlock {
                key_format_type: KeyFormatType::Opaque,
                key_compression_type: None,
                key_value: Some(KeyValue::Structure {
                    key_material: KeyMaterial::ByteString((*derived_key_bytes).clone().into()),
                    attributes: Some(attributes.clone()),
                }),
                cryptographic_algorithm: None,
                cryptographic_length: Some(cryptographic_length_bits),
                key_wrapping_data: None,
            };
            Object::SecretData(SecretData {
                secret_data_type: SecretDataType::Password,
                key_block,
            })
        }
        _ => kms_bail!(KmsError::InvalidRequest(
            "DeriveKey: object type must be SymmetricKey or SecretData".to_owned()
        )),
    };

    Box::pin(persist_single_base_derived_object(
        kms,
        user,
        &base_key_handle,
        &base_identifier,
        &uid,
        derived_object,
        &mut attributes,
    ))
    .await
}

#[cfg(feature = "non-fips")]
async fn derive_key_asymmetric(
    kms: &KMS,
    request: DeriveKey,
    user: &UserId,
) -> KResult<DeriveKeyResponse> {
    if request.object_unique_identifier.len() != 2 {
        kms_bail!(KmsError::InvalidRequest(
            "DeriveKey: asymmetric derivation requires exactly two identifiers".to_owned()
        ));
    }
    if request.object_type == ObjectType::SymmetricKey {
        kms_bail!(KmsError::InvalidRequest(
            "DeriveKey: asymmetric derivation must create a SecretData object".to_owned()
        ));
    }
    if request.attributes.object_type == Some(ObjectType::SymmetricKey) {
        kms_bail!(KmsError::InvalidRequest(
            "DeriveKey: asymmetric derivation must create a SecretData object".to_owned()
        ));
    }
    if let Some(cryptographic_length) = request.attributes.cryptographic_length
        && cryptographic_length != 256
    {
        kms_bail!(KmsError::InvalidRequest(
            "DeriveKey: asymmetric derivation requires a 256-bit output".to_owned()
        ));
    }

    let [private_identifier, peer_identifier]: [UniqueIdentifier; 2] = request
        .object_unique_identifier
        .clone()
        .try_into()
        .map_err(|_error| {
            KmsError::InvalidRequest(
                "DeriveKey: asymmetric derivation requires exactly two identifiers".to_owned(),
            )
        })?;
    let private_handle = ObjectHandle::try_from(&private_identifier)?;
    let peer_handle = ObjectHandle::try_from(&peer_identifier)?;

    let private_owm = kms
        .database
        .retrieve_object(private_handle.as_str())
        .await?;
    let peer_owm = kms.database.retrieve_object(peer_handle.as_str()).await?;
    let private_allowed =
        user_has_permission(user, private_owm.as_ref(), &KmipOperation::DeriveKey, kms).await?;
    let peer_allowed =
        user_has_permission(user, peer_owm.as_ref(), &KmipOperation::DeriveKey, kms).await?;
    if private_owm.is_none() || peer_owm.is_none() || !private_allowed || !peer_allowed {
        kms_bail!(KmsError::InvalidRequest(
            "DeriveKey: asymmetric derivation requires access to both referenced objects"
                .to_owned()
        ));
    }

    let mut private_owm = private_owm.ok_or_else(|| {
        KmsError::InvalidRequest(
            "DeriveKey: asymmetric derivation requires access to both referenced objects"
                .to_owned(),
        )
    })?;
    let peer_owm = peer_owm.ok_or_else(|| {
        KmsError::InvalidRequest(
            "DeriveKey: asymmetric derivation requires access to both referenced objects"
                .to_owned(),
        )
    })?;

    private_owm.set_object(
        Box::pin(kms.get_unwrapped(private_owm.id(), private_owm.object(), user))
            .await
            .with_context(|| {
                format!(
                    "DeriveKey: the base key: {}, cannot be unwrapped.",
                    private_owm.id()
                )
            })?,
    );

    let private_key_bytes = validate_x25519_private_object(&private_owm)?;
    let peer_public_key_bytes = validate_x25519_public_object(&peer_owm)?;
    let shared_secret = x25519_key_agreement(&private_key_bytes, &peer_public_key_bytes)
        .map_err(map_x25519_crypto_error)?;

    let uid = requested_derived_object_id(&request.attributes);
    let mut attributes = build_x25519_shared_secret_attributes(&uid, &request.attributes);
    let mut derived_object = build_x25519_shared_secret_object(&shared_secret, &attributes);
    let derived_attributes =
        derived_object.setup_with_lifecycle(ObjectType::SecretData, attributes.activation_date)?;
    attributes = derived_attributes;
    attributes.apply_extractable(false);
    attributes.initialize_always_sensitive();
    if let Ok(object_attributes) = derived_object.attributes_mut() {
        *object_attributes = attributes.clone();
    }

    let mut private_link_owm = kms
        .database
        .retrieve_object(private_handle.as_str())
        .await?
        .ok_or_else(|| {
            KmsError::InvalidRequest(
                "DeriveKey: asymmetric derivation requires access to both referenced objects"
                    .to_owned(),
            )
        })?;
    let mut peer_link_owm = kms
        .database
        .retrieve_object(peer_handle.as_str())
        .await?
        .ok_or_else(|| {
            KmsError::InvalidRequest(
                "DeriveKey: asymmetric derivation requires access to both referenced objects"
                    .to_owned(),
            )
        })?;

    add_link_to_attributes(
        &mut private_link_owm,
        LinkType::DerivedKeyLink,
        UniqueIdentifier::TextString(uid.clone()).into(),
    );
    add_link_to_attributes(
        &mut peer_link_owm,
        LinkType::DerivedKeyLink,
        UniqueIdentifier::TextString(uid.clone()).into(),
    );
    add_link_to_object_and_attributes(
        &mut derived_object,
        &mut attributes,
        LinkType::DerivationBaseObjectLink,
        private_identifier.clone().into(),
    );
    add_link_to_object_and_attributes(
        &mut derived_object,
        &mut attributes,
        LinkType::DerivationBaseObjectLink,
        peer_identifier.clone().into(),
    );

    let operations = vec![
        AtomicOperation::Create((
            uid.clone(),
            user.to_owned(),
            derived_object,
            attributes,
            HashSet::new(),
        )),
        AtomicOperation::UpdateObject((
            private_link_owm.id().to_owned(),
            private_link_owm.object().clone(),
            private_link_owm.attributes().clone(),
            None,
        )),
        AtomicOperation::UpdateObject((
            peer_link_owm.id().to_owned(),
            peer_link_owm.object().clone(),
            peer_link_owm.attributes().clone(),
            None,
        )),
    ];

    kms.database.atomic(user, &operations).await.map_err(|e| {
        KmsError::InvalidRequest(format!(
            "DeriveKey: failed to persist asymmetric derived object and links: {e}"
        ))
    })?;
    debug!("DeriveKey asymmetric operation completed successfully");

    Ok(DeriveKeyResponse {
        unique_identifier: UniqueIdentifier::TextString(uid),
    })
}

#[cfg(not(feature = "non-fips"))]
#[allow(clippy::unused_async)] // kept async to match the non-fips `derive_key_asymmetric` signature so the call site in `derive_key` doesn't need feature-specific branching
async fn derive_key_asymmetric(
    _kms: &KMS,
    _request: DeriveKey,
    _user: &UserId,
) -> KResult<DeriveKeyResponse> {
    Err(KmsError::NotSupported(
        "DeriveKey: asymmetric derivation is not supported in FIPS mode".to_owned(),
    ))
}

fn requested_derived_object_id(attributes: &Attributes) -> String {
    attributes
        .unique_identifier
        .as_ref()
        .map(ToString::to_string)
        .filter(|uid| !uid.is_empty())
        .unwrap_or_else(|| format!("derived-{}", Uuid::new_v4()))
}

async fn persist_single_base_derived_object(
    kms: &KMS,
    user: &UserId,
    base_key_handle: &ObjectHandle<'_>,
    base_identifier: &UniqueIdentifier,
    uid: &str,
    mut derived_object: Object,
    attributes: &mut Attributes,
) -> KResult<DeriveKeyResponse> {
    let derived_attributes = derived_object.setup_with_lifecycle(
        object_type_for_derived_object(&derived_object),
        attributes.activation_date,
    )?;
    *attributes = derived_attributes;
    if let Ok(object_attributes) = derived_object.attributes_mut() {
        *object_attributes = attributes.clone();
    }

    let tags = HashSet::new();
    let uid = kms
        .database
        .create(
            Some(uid.to_owned()),
            user,
            &derived_object,
            attributes,
            &tags,
        )
        .await
        .map_err(|e| {
            KmsError::InvalidRequest(format!("DeriveKey: failed to store derived object: {e}"))
        })?;

    let mut base_object_owm = kms
        .database
        .retrieve_object(base_key_handle.as_str())
        .await?
        .ok_or_else(|| KmsError::InvalidRequest("Failed to retrieve base object".to_owned()))?;
    add_link_to_attributes(
        &mut base_object_owm,
        LinkType::DerivedKeyLink,
        UniqueIdentifier::TextString(uid.clone()).into(),
    );

    kms.database
        .update_object(
            base_key_handle.as_str(),
            base_object_owm.object(),
            base_object_owm.attributes(),
            None,
        )
        .await
        .map_err(|e| {
            KmsError::InvalidRequest(format!(
                "DeriveKey: failed to update base object with derived key link: {e}"
            ))
        })?;

    let mut derived_object_owm =
        kms.database.retrieve_object(&uid).await?.ok_or_else(|| {
            KmsError::InvalidRequest("Failed to retrieve derived object".to_owned())
        })?;
    add_link_to_attributes(
        &mut derived_object_owm,
        LinkType::DerivationBaseObjectLink,
        base_identifier.clone().into(),
    );

    kms.database
        .update_object(
            &uid,
            derived_object_owm.object(),
            derived_object_owm.attributes(),
            None,
        )
        .await
        .map_err(|e| {
            KmsError::InvalidRequest(format!(
                "DeriveKey: failed to update derived object with base object link: {e}"
            ))
        })?;

    debug!("DeriveKey operation completed successfully");
    Ok(DeriveKeyResponse {
        unique_identifier: UniqueIdentifier::TextString(uid),
    })
}

const fn object_type_for_derived_object(object: &Object) -> ObjectType {
    match object {
        Object::SymmetricKey(_) => ObjectType::SymmetricKey,
        _ => ObjectType::SecretData,
    }
}

fn add_link_to_attributes(
    object_with_metadata: &mut ObjectWithMetadata,
    link_type: LinkType,
    linked_object_identifier: cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::LinkedObjectIdentifier,
) {
    object_with_metadata
        .attributes_mut()
        .add_link(link_type, linked_object_identifier.clone());
    if let Ok(object_attributes) = object_with_metadata.object_mut().attributes_mut() {
        object_attributes.add_link(link_type, linked_object_identifier);
    }
}

#[cfg(feature = "non-fips")]
fn add_link_to_object_and_attributes(
    object: &mut Object,
    attributes: &mut Attributes,
    link_type: LinkType,
    linked_object_identifier: cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::LinkedObjectIdentifier,
) {
    attributes.add_link(link_type, linked_object_identifier.clone());
    if let Ok(object_attributes) = object.attributes_mut() {
        object_attributes.add_link(link_type, linked_object_identifier);
    }
}

#[cfg(feature = "non-fips")]
fn validate_x25519_private_object(private_owm: &ObjectWithMetadata) -> KResult<Zeroizing<Vec<u8>>> {
    match private_owm.object() {
        Object::PrivateKey(PrivateKey { .. }) => {
            let Some(recommended_curve) = private_owm
                .attributes()
                .cryptographic_domain_parameters
                .as_ref()
                .and_then(|params| params.recommended_curve)
            else {
                kms_bail!(KmsError::InvalidRequest(
                    "DeriveKey: private key must declare the X25519 curve attribute".to_owned()
                ));
            };
            if recommended_curve != RecommendedCurve::CURVE25519 {
                kms_bail!(KmsError::InvalidRequest(
                    "DeriveKey: private key must use the X25519 curve".to_owned()
                ));
            }

            if !private_owm
                .attributes()
                .is_usage_authorized_for(CryptographicUsageMask::DeriveKey)?
                || !private_owm
                    .attributes()
                    .is_usage_authorized_for(CryptographicUsageMask::KeyAgreement)?
            {
                kms_bail!(KmsError::InvalidRequest(
                    "DeriveKey: private key must allow DeriveKey and KeyAgreement".to_owned()
                ));
            }
            let openssl_private_key = kmip_private_key_to_openssl(private_owm.object())
                .map_err(map_x25519_crypto_error)?;
            // Authoritative curve check: the top-level `Attributes` curve (checked above)
            // can diverge from the curve actually embedded in the object's `KeyMaterial`,
            // which is what determines the OpenSSL `Id` used to build this key (see
            // crate/crypto/src/openssl/private_key.rs). Ed25519/X25519 raw scalars are
            // both 32 bytes, so only checking the byte length would not catch a signing
            // key (Ed25519) being reused as a Diffie-Hellman key (X25519). Re-validate
            // against the actually-constructed key's own `Id` to close that gap.
            if openssl_private_key.id() != Id::X25519 {
                kms_bail!(KmsError::InvalidRequest(
                    "DeriveKey: private key material is not an X25519 key".to_owned()
                ));
            }
            let raw_bytes = Zeroizing::new(
                openssl_private_key
                    .raw_private_key()
                    .map_err(|error| map_x25519_crypto_error(error.into()))?,
            );
            if raw_bytes.len() != 32 {
                kms_bail!(KmsError::InvalidRequest(
                    "DeriveKey: private key must contain exactly 32 raw X25519 bytes".to_owned()
                ));
            }
            Ok(raw_bytes)
        }
        _ => kms_bail!(KmsError::InvalidRequest(
            "DeriveKey: first identifier must reference a private key".to_owned()
        )),
    }
}

#[cfg(feature = "non-fips")]
fn validate_x25519_public_object(peer_owm: &ObjectWithMetadata) -> KResult<Zeroizing<Vec<u8>>> {
    match peer_owm.object() {
        Object::PublicKey(PublicKey { .. }) => {
            let Some(recommended_curve) = peer_owm
                .attributes()
                .cryptographic_domain_parameters
                .as_ref()
                .and_then(|params| params.recommended_curve)
            else {
                kms_bail!(KmsError::InvalidRequest(
                    "DeriveKey: peer public key must declare the X25519 curve attribute".to_owned()
                ));
            };
            if recommended_curve != RecommendedCurve::CURVE25519 {
                kms_bail!(KmsError::InvalidRequest(
                    "DeriveKey: peer public key must use the X25519 curve".to_owned()
                ));
            }

            if !peer_owm
                .attributes()
                .is_usage_authorized_for(CryptographicUsageMask::KeyAgreement)?
            {
                kms_bail!(KmsError::InvalidRequest(
                    "DeriveKey: peer public key must allow KeyAgreement".to_owned()
                ));
            }
            let openssl_public_key =
                kmip_public_key_to_openssl(peer_owm.object()).map_err(map_x25519_crypto_error)?;
            // See the matching comment in `validate_x25519_private_object`: the
            // top-level `Attributes` curve can diverge from the curve actually
            // embedded in `KeyMaterial`, which drives which OpenSSL `Id` this key
            // was built with. Re-check the authoritative, actually-constructed `Id`.
            if openssl_public_key.id() != Id::X25519 {
                kms_bail!(KmsError::InvalidRequest(
                    "DeriveKey: peer public key material is not an X25519 key".to_owned()
                ));
            }
            let raw_bytes = Zeroizing::new(
                openssl_public_key
                    .raw_public_key()
                    .map_err(|error| map_x25519_crypto_error(error.into()))?,
            );
            if raw_bytes.len() != 32 {
                kms_bail!(KmsError::InvalidRequest(
                    "DeriveKey: peer public key must contain exactly 32 raw X25519 bytes"
                        .to_owned()
                ));
            }
            Ok(raw_bytes)
        }
        _ => kms_bail!(KmsError::InvalidRequest(
            "DeriveKey: second identifier must reference a public key".to_owned()
        )),
    }
}

#[cfg(feature = "non-fips")]
fn build_x25519_shared_secret_attributes(uid: &str, request_attributes: &Attributes) -> Attributes {
    let mut attributes = request_attributes.clone();
    attributes.object_type = Some(ObjectType::SecretData);
    attributes.unique_identifier = Some(UniqueIdentifier::TextString(uid.to_owned()));
    attributes.cryptographic_length = Some(256);
    attributes.cryptographic_algorithm = None;
    attributes.cryptographic_usage_mask = Some(CryptographicUsageMask::DeriveKey);
    attributes.key_format_type = Some(KeyFormatType::Opaque);
    attributes.sensitive = Some(true);
    attributes.apply_extractable(false);
    attributes
}

#[cfg(feature = "non-fips")]
fn build_x25519_shared_secret_object(shared_secret: &[u8], attributes: &Attributes) -> Object {
    Object::SecretData(SecretData {
        secret_data_type: SecretDataType::Seed,
        key_block: KeyBlock {
            key_format_type: KeyFormatType::Opaque,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(shared_secret.to_vec().into()),
                attributes: Some(attributes.clone()),
            }),
            cryptographic_algorithm: None,
            cryptographic_length: Some(256),
            key_wrapping_data: None,
        },
    })
}

#[cfg(feature = "non-fips")]
fn map_x25519_crypto_error(error: CryptoError) -> KmsError {
    match error {
        CryptoError::Derivation(_) => {
            KmsError::InvalidRequest("DeriveKey: invalid X25519 peer public key".to_owned())
        }
        other => {
            KmsError::CryptographicError(format!("DeriveKey: X25519 key agreement failed: {other}"))
        }
    }
}

/// Map `HashingAlgorithm` to OpenSSL `MdRef` for HKDF
fn get_md(algorithm: HashingAlgorithm) -> KResult<&'static MdRef> {
    match algorithm {
        HashingAlgorithm::SHA1 => Ok(Md::sha1()),
        HashingAlgorithm::SHA224 => Ok(Md::sha224()),
        HashingAlgorithm::SHA256 => Ok(Md::sha256()),
        HashingAlgorithm::SHA384 => Ok(Md::sha384()),
        HashingAlgorithm::SHA512 => Ok(Md::sha512()),
        _ => Err(KmsError::InvalidRequest(format!(
            "Unsupported hashing algorithm: {algorithm:?}"
        ))),
    }
}

/// Map `HashingAlgorithm` to OpenSSL `MessageDigest` for PBKDF2
fn get_message_digest(algorithm: HashingAlgorithm) -> KResult<MessageDigest> {
    match algorithm {
        HashingAlgorithm::SHA1 => Ok(MessageDigest::sha1()),
        HashingAlgorithm::SHA224 => Ok(MessageDigest::sha224()),
        HashingAlgorithm::SHA256 => Ok(MessageDigest::sha256()),
        HashingAlgorithm::SHA384 => Ok(MessageDigest::sha384()),
        HashingAlgorithm::SHA512 => Ok(MessageDigest::sha512()),
        _ => Err(KmsError::InvalidRequest(format!(
            "Unsupported hashing algorithm: {algorithm:?}"
        ))),
    }
}

/// PBKDF2 key derivation using OpenSSL's `pbkdf2_hmac`
///
/// Returns the derived key wrapped in [`Zeroizing`] so the bytes are scrubbed
/// from memory when the value is dropped (EXT1-1).
fn derive_pbkdf2(
    key: &[u8],
    salt: &[u8],
    iterations: u32,
    length: usize,
    hashing_algorithm: HashingAlgorithm,
) -> KResult<Zeroizing<Vec<u8>>> {
    let digest = get_message_digest(hashing_algorithm)?;
    let mut output = Zeroizing::new(vec![0_u8; length]);

    pbkdf2_hmac(
        key,
        salt,
        usize::try_from(iterations)
            .map_err(|e| KmsError::InvalidRequest(format!("Invalid iteration count: {e}")))?,
        digest,
        &mut output,
    )
    .map_err(|e| KmsError::CryptographicError(format!("PBKDF2 derivation failed: {e}")))?;

    Ok(output)
}

/// HKDF key derivation using OpenSSL's native HKDF implementation
///
/// Returns the derived key wrapped in [`Zeroizing`] so the bytes are scrubbed
/// from memory when the value is dropped (EXT1-1).
fn derive_hkdf(
    key: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
    hashing_algorithm: HashingAlgorithm,
) -> KResult<Zeroizing<Vec<u8>>> {
    // Get the message digest for the hashing algorithm
    let md = get_md(hashing_algorithm)?;

    // Create HKDF context
    let mut ctx = PkeyCtx::new_id(Id::HKDF)
        .map_err(|e| KmsError::CryptographicError(format!("Failed to create HKDF context: {e}")))?;

    // Initialize the context for key derivation
    ctx.derive_init().map_err(|e| {
        KmsError::CryptographicError(format!("Failed to initialize HKDF derivation: {e}"))
    })?;

    // Set the hash function
    ctx.set_hkdf_md(md).map_err(|e| {
        KmsError::CryptographicError(format!("Failed to set HKDF hash function: {e}"))
    })?;

    // Set the input key material (IKM)
    ctx.set_hkdf_key(key)
        .map_err(|e| KmsError::CryptographicError(format!("Failed to set HKDF key: {e}")))?;

    // Set salt if provided, otherwise OpenSSL will use a zero salt
    if !salt.is_empty() {
        ctx.set_hkdf_salt(salt)
            .map_err(|e| KmsError::CryptographicError(format!("Failed to set HKDF salt: {e}")))?;
    }

    // Set info if provided
    if !info.is_empty() {
        ctx.add_hkdf_info(info)
            .map_err(|e| KmsError::CryptographicError(format!("Failed to set HKDF info: {e}")))?;
    }

    // Derive the key material
    let mut output = Zeroizing::new(vec![0_u8; length]);
    ctx.derive(Some(&mut output))
        .map_err(|e| KmsError::CryptographicError(format!("HKDF derivation failed: {e}")))?;

    Ok(output)
}
