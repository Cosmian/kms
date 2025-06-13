use std::{collections::HashSet, sync::Arc};

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::kmip_2_1::kmip_types::UniqueIdentifier, cosmian_kms_interfaces::SessionParams,
};

use super::locate_usk;
use crate::{
    core::{KMS, operations::recursively_destroy_object},
    result::KResult,
};

/// Revoke all the user decryption keys associated with the master secret key
pub(crate) async fn destroy_user_decryption_keys(
    msk_uid: &str,
    remove: bool,
    kms: &KMS,
    owner: &str,
    params: Option<Arc<dyn SessionParams>>,
    // keys that should be skipped
    ids_to_skip: HashSet<String>,
) -> KResult<()> {
    if let Some(ids) = locate_usk(kms, msk_uid, None, None, owner, params.clone()).await? {
        for id in ids.into_iter().filter(|id| !ids_to_skip.contains(id)) {
            recursively_destroy_object(
                &UniqueIdentifier::TextString(id),
                remove,
                kms,
                owner,
                params.clone(),
                ids_to_skip.clone(),
            )
            .await?;
        }
    }
    Ok(())
}
