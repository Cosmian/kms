use std::{collections::HashSet, sync::Arc};

use cosmian_kmip::kmip_2_1::kmip_types::{RevocationReason, StateEnumeration, UniqueIdentifier};
use cosmian_kms_interfaces::SessionParams;

use super::locate_usk;
use crate::{
    core::{operations::recursively_revoke_key, KMS},
    result::KResult,
};

/// Revoke all the user decryption keys associated with the master secret key
pub(crate) async fn revoke_user_decryption_keys(
    master_secret_key_id: &str,
    revocation_reason: RevocationReason,
    compromise_occurrence_date: Option<i64>,
    kms: &KMS,
    owner: &str,
    params: Option<Arc<dyn SessionParams>>, // keys that should be skipped
    ids_to_skip: HashSet<String>,
) -> KResult<()> {
    if let Some(ids) = locate_usk(
        kms,
        master_secret_key_id,
        None,
        Some(StateEnumeration::Active),
        owner,
        params.clone(),
    )
    .await?
    {
        for id in ids.iter().filter(|&id| !ids_to_skip.contains(id)) {
            recursively_revoke_key(
                &UniqueIdentifier::TextString(id.to_owned()),
                revocation_reason.clone(),
                compromise_occurrence_date,
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
