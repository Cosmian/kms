//! KMIP `ReKey` for symmetric keys — dispatcher.
//!
//! Routes the request to either the SQL-backed pipeline ([`sql::SqlSymmetricRekeyer`]) or
//! the HSM PKCS#11 rotation path ([`hsm`] module) based on the UID prefix.

mod hsm;
mod sql;

use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
    kmip_operations::{ReKey, ReKeyResponse},
    kmip_types::UniqueIdentifier,
};
use cosmian_logger::trace;

use self::sql::SqlSymmetricRekeyer;
use crate::{
    core::{
        KMS,
        uid_utils::{has_prefix, resolve_uid_or_keyset},
    },
    error::KmsError,
    result::{KResult, KResultHelper},
};

/// KMIP `ReKey` operation for symmetric keys (KMIP 2.1 §6.1.46).
///
/// - For regular (SQL) keys: generates fresh key material, handles wrapping, links generations.
/// - For HSM-resident keys (UID starts with `hsm::`): calls `C_GenerateKey` on the same HSM
///   slot, assigns a generation-suffix UID (`original::N+1`), and updates `CKA_LABEL` /
///   `CKA_START_DATE` / `CKA_END_DATE` on both the old and new keys.
pub(crate) async fn rekey(kms: &KMS, request: ReKey, owner: &str) -> KResult<ReKeyResponse> {
    trace!("ReKey: {}", serde_json::to_string(&request)?);
    let uid = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?
        .as_str()
        .context("ReKey: the unique identifier must be a string")?
        .to_owned();

    // Resolve keyset references (`name@latest`, `name@first`, `name@N`, bare name) to a
    // concrete UID before routing. This allows `re-key --key-id my-keyset@latest` to work
    // transparently for both SQL and HSM-backed keysets.
    let uid = if let Some(resolved) = resolve_uid_or_keyset(&uid, "ReKey", kms, owner).await? {
        trace!("ReKey: resolved keyset ref '{}' → '{}'", uid, resolved);
        resolved
    } else {
        uid
    };

    // Route HSM-resident keys through the dedicated PKCS#11 rotation path.
    // The general RekeyOperation pipeline is designed for SQL-backed keys and
    // is not applicable to non-extractable HSM key material.
    if has_prefix(&uid).is_some() {
        return Box::pin(kms.rekey_hsm_symmetric(&uid, owner)).await;
    }

    let request = ReKey {
        unique_identifier: Some(UniqueIdentifier::TextString(uid)),
        ..request
    };
    SqlSymmetricRekeyer {
        offset: request.offset,
    }
    .execute(kms, &request, owner)
    .await
}
