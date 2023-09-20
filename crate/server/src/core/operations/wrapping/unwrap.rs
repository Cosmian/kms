use cosmian_kmip::kmip::{
    kmip_data_structures::KeyBlock, kmip_objects::ObjectType, kmip_types::LinkType,
};
use cosmian_kms_utils::{access::ExtraDatabaseParams, crypto::wrap::unwrap_key_block};

use super::get_key;
use crate::{
    core::KMS,
    kms_bail,
    result::{KResult, KResultHelper},
};

/// Unwrap a key
/// This function is used to unwrap a key before storing it in the database
///
/// # Arguments
/// * `object_type` - the type of the object to unwrap
/// * `object_key_block` - the key block of the object to unwrap
/// * `kms` - the KMS
/// * `owner` - the owner of the object to unwrap
/// * `params` - the extra database parameters
/// # Returns
/// * `KResult<()>` - the result of the operation
pub async fn unwrap_key(
    object_type: ObjectType,
    object_key_block: &mut KeyBlock,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<()> {
    let wrapping_key_uid = match &object_key_block.key_wrapping_data {
        Some(kwd) => match &kwd.encryption_key_information {
            Some(eki) => &eki.unique_identifier,
            None => kms_bail!("unable to unwrap key: unwrapping key uid is missing"),
        },
        None => kms_bail!("unwrap_key: unable to unwrap key: key wrapping data is missing"),
    };

    // fetch the unwrapping key
    let wrap_key = get_key(wrapping_key_uid, kms, owner, params).await?;

    // in the case the key is a PublicKey, we need to fetch the corresponding private key
    let unwrapping_key = match wrap_key.object_type() {
        ObjectType::PublicKey => {
            let private_key_uid = wrap_key
                .attributes()?
                .get_link(LinkType::PrivateKeyLink)
                .context("unable to unwrap key: public key does not have a private key link")?;
            // fetch the private key
            get_key(&private_key_uid, kms, owner, params).await?
        }
        _ => wrap_key,
    };

    unwrap_key_block(object_type, object_key_block, &unwrapping_key)?;
    Ok(())
}
