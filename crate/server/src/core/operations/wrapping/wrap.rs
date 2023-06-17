use cosmian_kmip::kmip::{
    kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue, KeyWrappingData},
    kmip_types::{EncodingOption, WrappingMethod},
};
use cosmian_kms_utils::{access::ExtraDatabaseParams, crypto::wrap::encrypt_bytes};

use super::get_key;
use crate::{core::KMS, kms_bail, result::KResult};

/// Wrap a key with a wrapping key
/// The wrapping key is fetched from the database
/// The key is wrapped using the wrapping key
///
/// # Arguments
/// * `object_uid` - the uid of the object to wrap
/// * `object_key_block` - the key block of the object to wrap
/// * `key_wrapping_data` - the key wrapping data
/// * `kms` - the kms
/// * `owner` - the owner of the object
/// * `params` - the extra database parameters
/// # Returns
/// * `KResult<()>` - the result of the operation
pub async fn wrap_key(
    object_uid: &str,
    object_key_block: &mut KeyBlock,
    key_wrapping_data: &KeyWrappingData,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<()> {
    if object_key_block.key_wrapping_data.is_some() {
        kms_bail!("unable to wrap the key {object_uid}: it is already wrapped")
    }
    // check that the wrapping method is supported
    match &key_wrapping_data.wrapping_method {
        WrappingMethod::Encrypt => {
            // ok
        }
        x => {
            kms_bail!(
                "Unable to wrap the key {object_uid}: wrapping method is not supported: {x:?}"
            )
        }
    }

    // determine the encoding of the wrapping
    let encoding = key_wrapping_data
        .encoding_option
        .unwrap_or(EncodingOption::NoEncoding);

    let wrapping_key_uid = match &key_wrapping_data.encryption_key_information {
        Some(eki) => &eki.unique_identifier,
        None => kms_bail!("unable to unwrap key: unwrapping key uid is missing"),
    };

    // fetch the wrapping key
    let wrapping_key = get_key(wrapping_key_uid, kms, owner, params).await?;

    // wrap the key based on the encoding
    let mut rng = kms.rng.lock().expect("could not acquire a lock on the rng");
    match encoding {
        EncodingOption::TTLVEncoding => {
            let plaintext = serde_json::to_vec(&object_key_block.key_value)?;
            let ciphertext = encrypt_bytes(&mut *rng, &wrapping_key, &plaintext)?;
            object_key_block.key_value = KeyValue {
                key_material: KeyMaterial::ByteString(ciphertext),
                // not clear whether this should be filled or not
                attributes: object_key_block.key_value.attributes.clone(),
            };
        }
        EncodingOption::NoEncoding => {
            let plaintext = object_key_block.key_bytes()?;
            let ciphertext = encrypt_bytes(&mut *rng, &wrapping_key, &plaintext)?;
            object_key_block.key_value.key_material = KeyMaterial::ByteString(ciphertext);
        }
    };
    object_key_block.key_wrapping_data = Some(key_wrapping_data.clone());

    Ok(())
}
