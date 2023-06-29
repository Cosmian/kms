use cosmian_kms_utils::access::ExtraDatabaseParams;

use super::locate_user_decryption_keys;
use crate::{
    core::{operations::recursively_destroy_key, KMS},
    result::KResult,
};

/// Revoke all the user decryption keys associated with the master private key
pub(crate) async fn destroy_user_decryption_keys(
    master_private_key_id: &str,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<()> {
    if let Some(ids) =
        locate_user_decryption_keys(kms, master_private_key_id, None, None, owner, params).await?
    {
        for id in ids {
            recursively_destroy_key(&id, kms, owner, params).await?;
        }
    }
    Ok(())
}
