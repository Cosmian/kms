use cosmian_kmip::kmip::{kmip_objects::Object, kmip_types::StateEnumeration};
use cosmian_kms_utils::access::{ExtraDatabaseParams, ObjectOperationType};
pub use unwrap::unwrap_key;
pub use wrap::wrap_key;

use crate::{core::KMS, error::KmsError, kms_bail, result::KResult};

mod unwrap;
mod wrap;

async fn get_key(
    key_uid: &str,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<Object> {
    // check if unwrapping key exists and retrieve it
    let owm = kms
        .db
        .retrieve(key_uid, owner, ObjectOperationType::Get, params)
        .await?
        .pop()
        .ok_or_else(|| {
            KmsError::ItemNotFound(format!(
                "unable to fetch the key with uid: {key_uid} not found"
            ))
        })?;
    // check if unwrapping key is active
    match owm.state {
        StateEnumeration::Active => {
            //OK
        }
        x => {
            kms_bail!("unable to fetch the key with uid: {key_uid}. The key is not active: {x:?}")
        }
    }
    Ok(owm.object)
}
