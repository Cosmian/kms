use std::{collections::HashSet, sync::Arc};

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{RevocationReason, State},
        kmip_2_1::kmip_types::UniqueIdentifier,
    },
    cosmian_kms_interfaces::SessionParams,
};
use time::OffsetDateTime;

use super::locate_usk;
use crate::{
    core::{KMS, operations::recursively_revoke_key},
    result::KResult,
};

/// Revoke all the user decryption keys associated with the master secret key
pub(crate) async fn revoke_user_decryption_keys(
    master_secret_key_id: &str,
    revocation_reason: RevocationReason,
    compromise_occurrence_date: Option<OffsetDateTime>,
    kms: &KMS,
    owner: &str,
    params: Option<Arc<dyn SessionParams>>, // keys that should be skipped
    ids_to_skip: HashSet<String>,
) -> KResult<()> {
    if let Some(ids) = locate_usk(
        kms,
        master_secret_key_id,
        None,
        Some(State::Active),
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
