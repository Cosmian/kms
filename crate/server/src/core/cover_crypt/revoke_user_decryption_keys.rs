use cosmian_kmip::kmip::kmip_types::{RevocationReason, StateEnumeration};
use cosmian_kms_utils::types::ExtraDatabaseParams;

use super::locate_user_decryption_keys;
use crate::{
    core::{operations::revoke_key, KMS},
    result::KResult,
};

/// Revoke all the user decryption keys associated with the master private key
pub(crate) async fn revoke_user_decryption_keys(
    master_private_key_id: &str,
    revocation_reason: RevocationReason,
    compromise_occurrence_date: Option<u64>,
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<()> {
    if let Some(ids) = locate_user_decryption_keys(
        kms,
        master_private_key_id,
        None,
        Some(StateEnumeration::Active),
        owner,
        params,
    )
    .await?
    {
        for id in ids {
            let _ = revoke_key(
                &id,
                revocation_reason.clone(),
                compromise_occurrence_date,
                kms,
                owner,
                params,
            )
            .await;
        }
    }
    Ok(())
}
