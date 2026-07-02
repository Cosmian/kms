//! KMIP `ReKeyKeyPair` for asymmetric key pairs — dispatcher.
//!
//! Routes the request to either:
//! - The Covercrypt in-place attribute rekey (non-FIPS only, [`covercrypt`] module).
//! - The SQL-backed key pair rotation pipeline ([`sql::SqlKeypairRekeyer`]).

#[cfg(feature = "non-fips")]
mod covercrypt;
mod sql;

use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::ErrorReason,
    kmip_2_1::{
        kmip_operations::{ReKeyKeyPair, ReKeyKeyPairResponse},
        kmip_types::UniqueIdentifier,
    },
};
use cosmian_logger::trace;

use self::sql::SqlKeypairRekeyer;
use super::common::execute_rekey;
use crate::{
    core::{KMS, uid_utils::resolve_uid_or_keyset},
    error::KmsError,
    result::KResult,
};

/// KMIP `ReKeyKeyPair` operation for asymmetric key pairs.
///
/// Per KMIP 1.4 §4.5:
/// - Creates a replacement key pair with new Unique Identifiers.
/// - Sets `ReplacementObjectLink` on both old private and public keys.
/// - Sets `ReplacedObjectLink` on both new private and public keys.
/// - The replacement keys take over the Name attributes of the existing keys.
/// - The existing keys' State is NOT changed.
/// - If `offset` is provided, date computation per Table 176 is applied.
/// - Rotation metadata is set on both old and new keys.
///
/// For Covercrypt keys (non-FIPS only), delegates to the existing in-place
/// attribute-level rekey which mutates the key material without creating new UIDs.
pub(crate) async fn rekey_keypair(
    kms: &KMS,
    request: ReKeyKeyPair,
    user: &str,
) -> KResult<ReKeyKeyPairResponse> {
    trace!("ReKeyKeyPair: {}", serde_json::to_string(&request)?);

    // Covercrypt early-return: uses a completely different code path (in-place attribute rekey)
    // that doesn't fit the rotation trait pattern.
    #[cfg(feature = "non-fips")]
    if let Some(response) = covercrypt::try_covercrypt_rekey(kms, &request, user).await? {
        return Ok(response);
    }

    // Resolve keyset references (`name@latest`, `name@first`, `name@N`, bare name) to a concrete
    // private-key UID before routing, so that `re-key --key-id my-kp@latest` works transparently.
    let request = if let Some(uid_str) = request
        .private_key_unique_identifier
        .as_ref()
        .and_then(|u| u.as_str())
    {
        if let Some(resolved) = resolve_uid_or_keyset(uid_str, "ReKeyKeyPair", kms, user).await? {
            trace!(
                "ReKeyKeyPair: resolved keyset ref '{}' → '{}'",
                uid_str, resolved
            );
            ReKeyKeyPair {
                private_key_unique_identifier: Some(UniqueIdentifier::TextString(resolved)),
                ..request
            }
        } else {
            request
        }
    } else {
        request
    };

    Box::pin(execute_rekey(
        &SqlKeypairRekeyer {
            offset: request.offset,
        },
        kms,
        &request,
        user,
    ))
    .await
}

impl KMS {
    /// Retrieve the linked public key from the database.
    pub(super) async fn retrieve_linked_public_key(
        &self,
        pk_uid: &str,
    ) -> KResult<cosmian_kms_server_database::reexport::cosmian_kms_interfaces::ObjectWithMetadata>
    {
        self.database
            .retrieve_objects(pk_uid)
            .await?
            .into_values()
            .next()
            .ok_or_else(|| {
                KmsError::Kmip21Error(
                    ErrorReason::Item_Not_Found,
                    format!("ReKeyKeyPair: linked public key '{pk_uid}' not found in database"),
                )
            })
    }
}
