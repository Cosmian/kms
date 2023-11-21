use cosmian_kmip::kmip::{
    kmip_data_structures::{
        KeyBlock, KeyMaterial, KeyValue, KeyWrappingData, KeyWrappingSpecification,
    },
    kmip_objects::ObjectType,
    kmip_types::{EncodingOption, LinkType, WrappingMethod},
};
use cosmian_kms_utils::{
    access::{ExtraDatabaseParams, ObjectOperationType},
    crypto::wrap::encrypt_bytes,
};

use crate::{
    core::KMS,
    database::retrieve_object_for_operation,
    kms_bail,
    result::{KResult, KResultHelper},
};

/// Wrap a key with a wrapping key
/// The wrapping key is fetched from the database
/// The key is wrapped using the wrapping key
///
/// # Arguments
/// * `object_key_block` - the key block of the object to wrap
/// * `key_wrapping_specification` - the key wrapping specification
/// * `kms` - the kms
/// * `user` - the user performing the call
/// * `params` - the extra database parameters
/// # Returns
/// * `KResult<()>` - the result of the operation
pub async fn wrap_key(
    object_key_block: &mut KeyBlock,
    key_wrapping_specification: &KeyWrappingSpecification,
    kms: &KMS,
    user: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<()> {
    if object_key_block.key_wrapping_data.is_some() {
        kms_bail!("unable to wrap the key: it is already wrapped")
    }
    // check that the wrapping method is supported
    match &key_wrapping_specification.wrapping_method {
        WrappingMethod::Encrypt => {
            // ok
        }
        x => {
            kms_bail!("Unable to wrap the key: wrapping method is not supported: {x:?}")
        }
    }

    // determine the encoding of the wrapping
    let encoding = key_wrapping_specification
        .encoding_option
        .unwrap_or(EncodingOption::TTLVEncoding);

    let wrapping_key_uid = match &key_wrapping_specification.encryption_key_information {
        Some(eki) => &eki.unique_identifier,
        None => kms_bail!("unable to unwrap key: unwrapping key uid is missing"),
    };

    // fetch the wrapping key
    let wrapping_key = retrieve_object_for_operation(
        wrapping_key_uid,
        ObjectOperationType::Encrypt,
        kms,
        owner,
        params,
    )
    .await?;

    // in the case the key is a Private Key, we need to fetch the corresponding private key or certificate
    let object_type = wrapping_key.object.object_type();
    let wrapping_key = match object_type {
        ObjectType::PublicKey | ObjectType::Certificate => wrapping_key,
        ObjectType::PrivateKey => {
            let attributes = wrapping_key.object.attributes()?;
            let public_key_uid = attributes
                .get_link(LinkType::PublicKeyLink)
                .or_else(|| attributes.get_link(LinkType::CertificateLink))
                .context("unable to find a certificate or public key for the private key")?;
            // fetch the private key
            retrieve_object_for_operation(
                &public_key_uid,
                ObjectOperationType::Decrypt,
                kms,
                owner,
                params,
            )
            .await?
        }
        _ => kms_bail!("unwrap_key: unsupported object type: {}", object_type),
    };

    // wrap the key based on the encoding
    let mut rng = kms.rng.lock().expect("could not acquire a lock on the rng");
    match encoding {
        EncodingOption::TTLVEncoding => {
            let plaintext = serde_json::to_vec(&object_key_block.key_value)?;
            let ciphertext = encrypt_bytes(&mut *rng, &wrapping_key.object, &plaintext)?;
            object_key_block.key_value = KeyValue {
                key_material: KeyMaterial::ByteString(ciphertext),
                // not clear whether this should be filled or not
                attributes: object_key_block.key_value.attributes.clone(),
            };
        }
        EncodingOption::NoEncoding => {
            let plaintext = object_key_block.key_bytes()?;
            let ciphertext = encrypt_bytes(&mut *rng, &wrapping_key.object, &plaintext)?;
            object_key_block.key_value.key_material = KeyMaterial::ByteString(ciphertext);
        }
    };
    let key_wrapping_data = KeyWrappingData {
        wrapping_method: key_wrapping_specification.wrapping_method,
        encryption_key_information: key_wrapping_specification
            .encryption_key_information
            .clone(),
        mac_or_signature_key_information: key_wrapping_specification
            .mac_or_signature_key_information
            .clone(),
        encoding_option: key_wrapping_specification.encoding_option,
        ..KeyWrappingData::default()
    };
    object_key_block.key_wrapping_data = Some(key_wrapping_data);

    Ok(())
}
