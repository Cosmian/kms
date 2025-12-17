use std::collections::HashSet;

use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::{CryptographicUsageMask, HashingAlgorithm, SecretDataType, State},
    kmip_2_1::{
        KmipOperation,
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_objects::{Object, ObjectType, SecretData, SymmetricKey},
        kmip_operations::{DeriveKey, DeriveKeyResponse},
        kmip_types::{DerivationMethod, KeyFormatType, LinkType, UniqueIdentifier},
    },
    time_normalize,
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

use crate::{
    core::{KMS, retrieve_object_utils::user_has_permission},
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

// Default constants for key derivation
const DEFAULT_PBKDF2_ITERATIONS: u32 = 600_000; // OWASP recommendation for PBKDF2 with SHA-256

pub(crate) async fn derive_key(
    kms: &KMS,
    request: DeriveKey,
    user: &str,
) -> KResult<DeriveKeyResponse> {
    debug!("DeriveKey operation starting");

    // Validate derivation parameters according to KMIP specification
    match request.derivation_method {
        DerivationMethod::PBKDF2 => {
            // For PBKDF2, salt is mandatory
            if request.derivation_parameters.salt.is_none() {
                kms_bail!(KmsError::InvalidRequest(
                    "DeriveKey: Salt is mandatory when derivation method is PBKDF2".to_owned()
                ));
            }
            // iteration_count is also mandatory for PBKDF2 (though we have a default)
            if request.derivation_parameters.iteration_count.is_none() {
                debug!("DeriveKey: No iteration count provided for PBKDF2, using default");
            }
        }
        DerivationMethod::HKDF => {
            // For HKDF, derivation_data (info) is commonly used but not strictly mandatory
            // Salt is optional for HKDF (can be empty)
            if request.derivation_parameters.derivation_data.is_none() {
                debug!("DeriveKey: No derivation data (info) provided for HKDF");
            }
        }
        _ => {
            kms_bail!(KmsError::InvalidRequest(format!(
                "DeriveKey: Unsupported derivation method: {:?}",
                request.derivation_method
            )));
        }
    }

    // Validate that derivation_data is provided unless a Secret Data object is referenced
    // According to KMIP spec: "Mandatory unless the Unique Identifier of a Secret Data object is provided"
    if request.derivation_parameters.derivation_data.is_none() {
        // Check if we have a secret data object identifier - this would be an alternative way to provide derivation data
        // For now, we'll issue a warning as the exact mechanism for Secret Data object references isn't clear in the current implementation
        debug!(
            "DeriveKey: No derivation data provided - this may be acceptable if a Secret Data \
             object identifier is provided"
        );
    }

    // Get the base key identifier from the correct field
    let base_key_id = request.object_unique_identifier.to_string();

    // Retrieve the base key from the database
    let Some(mut base_key_owm) = kms.database.retrieve_object(&base_key_id).await? else {
        kms_bail!(KmsError::InvalidRequest(format!(
            "DeriveKey: failed to retrieve base object {base_key_id}"
        )))
    };

    // Check that the user has permission to derive from the base key
    let has_permission =
        user_has_permission(user, Some(&base_key_owm), &KmipOperation::DeriveKey, kms).await?;

    if !has_permission {
        kms_bail!(KmsError::Unauthorized(format!(
            "User {user} does not have DeriveKey permission on object {base_key_id}"
        )));
    }

    // Unwrap the base key if it's wrapped
    base_key_owm.set_object(
        kms.get_unwrapped(base_key_owm.id(), base_key_owm.object(), user)
            .await
            .with_context(|| {
                format!(
                    "DeriveKey: the base key: {}, cannot be unwrapped.",
                    base_key_owm.id()
                )
            })?,
    );

    let base_key_object = base_key_owm.object();
    let base_key_attributes = base_key_owm.attributes();

    // Check that the base object has the Derive Key bit set in its Cryptographic Usage Mask
    if !base_key_attributes.is_usage_authorized_for(CryptographicUsageMask::DeriveKey)? {
        kms_bail!(KmsError::InvalidRequest(
            "DeriveKey: base object does not have DeriveKey usage mask".to_owned()
        ));
    }

    // Extract the key material from the base object (supports both SymmetricKey and SecretData)
    let base_key_bytes = match base_key_object {
        Object::SymmetricKey(SymmetricKey { key_block })
        | Object::SecretData(SecretData { key_block, .. }) => key_block.key_bytes()?,
        _ => kms_bail!("DeriveKey: base object must be a SymmetricKey or SecretData"),
    };

    // Validate that required attributes are provided for the derived object
    let cryptographic_length = request.attributes.cryptographic_length.ok_or_else(|| {
        KmsError::InvalidRequest("DeriveKey: Cryptographic Length must be specified".to_owned())
    })?;
    let cryptographic_length = usize::try_from(cryptographic_length).map_err(|_e| {
        KmsError::InvalidRequest("DeriveKey: Invalid cryptographic length".to_owned())
    })? / 8; // Convert from bits to bytes

    // For symmetric keys, cryptographic algorithm must also be specified
    if request.object_type == ObjectType::SymmetricKey
        && request.attributes.cryptographic_algorithm.is_none()
    {
        kms_bail!(KmsError::InvalidRequest(
            "DeriveKey: Cryptographic Algorithm must be specified for symmetric keys".to_owned()
        ));
    }

    // Get the hashing algorithm from cryptographic parameters, default to SHA-256
    let hashing_algorithm = request
        .derivation_parameters
        .cryptographic_parameters
        .as_ref()
        .and_then(|cp| cp.hashing_algorithm)
        .unwrap_or(HashingAlgorithm::SHA256);

    // Derive the new key based on the method
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
                .unwrap_or_else(|| i32::try_from(DEFAULT_PBKDF2_ITERATIONS).unwrap_or(600_000)); // Fallback if somehow DEFAULT doesn't fit in i32
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
            let salt = request.derivation_parameters.salt.as_deref().unwrap_or(&[]); // Empty salt is acceptable for HKDF
            let info = request
                .derivation_parameters
                .derivation_data
                .as_deref()
                .map_or(&[][..], std::vec::Vec::as_slice); // Empty info is acceptable for HKDF

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

    // Validate that the derived key length doesn't exceed the derivation method output
    if derived_key_bytes.len() < cryptographic_length {
        kms_bail!(KmsError::InvalidRequest(
            "DeriveKey: specified length exceeds the output of the derivation method".to_owned()
        ));
    }

    // Determine lifecycle state per KMIP 2.1 spec (same as Create/Register/Import):
    // - If ActivationDate is absent or in the future → PreActive state
    // - If ActivationDate is present and <= now → Active state
    let now = time_normalize()?;
    let activation_allows_active = request.attributes.activation_date.is_some_and(|d| d <= now);
    let desired_state = if activation_allows_active {
        debug!(
            "DeriveKey: activation_date={:?} <= now, setting state to Active",
            request.attributes.activation_date
        );
        State::Active
    } else {
        debug!("DeriveKey: no activation_date or future date, setting state to PreActive");
        State::PreActive
    };

    // Set the state in request attributes before creating the object
    let mut attributes = request.attributes.clone();
    attributes.state = Some(desired_state);
    // Set lifecycle timestamps
    // Zero milliseconds for KMIP serialization compatibility
    let now_stored = time_normalize()?;
    attributes.initial_date = Some(now_stored);
    attributes.original_creation_date = Some(now_stored);
    attributes.last_change_date = Some(now_stored);
    if desired_state == State::Active {
        attributes.activation_date = Some(now_stored);
    }

    // Create the derived object based on the requested type
    let derived_object = match request.object_type {
        ObjectType::SymmetricKey => {
            let key_block = KeyBlock {
                key_format_type: KeyFormatType::TransparentSymmetricKey,
                key_compression_type: None,
                key_value: Some(KeyValue::Structure {
                    key_material: KeyMaterial::TransparentSymmetricKey {
                        key: derived_key_bytes.clone().into(),
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
            debug!("Creating SecretData object");
            let key_block = KeyBlock {
                key_format_type: KeyFormatType::Opaque,
                key_compression_type: None,
                key_value: Some(KeyValue::ByteString(derived_key_bytes.into())),
                cryptographic_algorithm: None,
                cryptographic_length: Some(i32::try_from(cryptographic_length * 8).map_err(
                    |_e| KmsError::InvalidRequest("Invalid cryptographic length".to_owned()),
                )?),
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

    // Generate a unique ID for the derived object
    let derived_object_id = format!("derived-{}", Uuid::new_v4());

    // Create empty tags for now
    let tags = HashSet::new();

    // Store the derived object
    let uid = kms
        .database
        .create(
            Some(derived_object_id.clone()),
            user,
            &derived_object,
            &attributes,
            &tags,
        )
        .await
        .map_err(|e| {
            KmsError::InvalidRequest(format!("DeriveKey: failed to store derived object: {e}"))
        })?;

    // Create link attributes as required by the KMIP specification

    // For the base object: create Link attribute of Link Type Derived Key pointing to the derived object
    // Add the link to the base object's attributes (need to retrieve and update)
    let mut base_object_owm = kms
        .database
        .retrieve_object(&base_key_id)
        .await?
        .ok_or_else(|| KmsError::InvalidRequest("Failed to retrieve base object".to_owned()))?;

    base_object_owm.attributes_mut().set_link(
        LinkType::DerivedKeyLink,
        UniqueIdentifier::TextString(uid.clone()).into(),
    );

    kms.database
        .update_object(
            &base_key_id,
            base_object_owm.object(),
            base_object_owm.attributes(),
            None, // tags
        )
        .await
        .map_err(|e| {
            KmsError::InvalidRequest(format!(
                "DeriveKey: failed to update base object with derived key link: {e}"
            ))
        })?;

    // For the derived object: create Link attribute of Link Type Derivation Base Object pointing to the base object
    let mut derived_object_owm =
        kms.database.retrieve_object(&uid).await?.ok_or_else(|| {
            KmsError::InvalidRequest("Failed to retrieve derived object".to_owned())
        })?;

    derived_object_owm.attributes_mut().set_link(
        LinkType::DerivationBaseObjectLink,
        request.object_unique_identifier.clone().into(),
    );

    kms.database
        .update_object(
            &uid,
            derived_object_owm.object(),
            derived_object_owm.attributes(),
            None, // tags
        )
        .await
        .map_err(|e| {
            KmsError::InvalidRequest(format!(
                "DeriveKey: failed to update derived object with base object link: {e}"
            ))
        })?;

    debug!("DeriveKey operation completed successfully");

    // Return the response with only the unique identifier as per KMIP specification
    Ok(DeriveKeyResponse {
        unique_identifier: UniqueIdentifier::TextString(uid),
    })
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
fn derive_pbkdf2(
    key: &[u8],
    salt: &[u8],
    iterations: u32,
    length: usize,
    hashing_algorithm: HashingAlgorithm,
) -> KResult<Vec<u8>> {
    let digest = get_message_digest(hashing_algorithm)?;
    let mut output = vec![0_u8; length];

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
fn derive_hkdf(
    key: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
    hashing_algorithm: HashingAlgorithm,
) -> KResult<Vec<u8>> {
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
    let mut output = vec![0_u8; length];
    ctx.derive(Some(&mut output))
        .map_err(|e| KmsError::CryptographicError(format!("HKDF derivation failed: {e}")))?;

    Ok(output)
}
