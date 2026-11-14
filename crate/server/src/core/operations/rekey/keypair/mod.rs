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
        KmipOperation,
        kmip_attributes::Attributes,
        kmip_operations::{ReKeyKeyPair, ReKeyKeyPairResponse},
        kmip_types::UniqueIdentifier,
    },
};
use cosmian_logger::trace;

use self::sql::SqlKeypairRekeyer;
use super::common::execute_rekey;
use crate::{
    core::{
        KMS,
        uid_utils::{ObjectHandle, resolve_uid_or_keyset},
    },
    error::KmsError,
    middlewares::UserId,
    result::KResult,
};

/// KMIP `ReKeyKeyPair` operation for asymmetric key pairs.
///
/// Per KMIP 1.4 §4.5:
/// - Creates a replacement key pair with new Unique Identifiers.
/// - Sets `ReplacementObjectLink` on both old private and public keys.
/// - Sets `ReplacedObjectLink` on both new private and public keys.
/// - The replacement keys take over the Name attributes of the existing keys.
/// - An Active existing key is retired: its Deactivation Date is set to now, which
///   moves it to Deactivated (KMIP 2.1 §4.18, §4.57 transition 6). Keys in any other
///   state keep their state.
/// - If `offset` is provided, date computation per Table 176 is applied.
/// - Rotation metadata is set on both old and new keys.
///
/// For Covercrypt keys (non-FIPS only), delegates to the existing in-place
/// attribute-level rekey which mutates the key material without creating new UIDs.
pub(crate) async fn rekey_keypair(
    kms: &KMS,
    request: ReKeyKeyPair,
    user: &UserId,
) -> KResult<ReKeyKeyPairResponse> {
    trace!("ReKeyKeyPair request");

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
        if let Some(resolved) =
            resolve_uid_or_keyset(ObjectHandle::from(uid_str), "ReKeyKeyPair", kms, user).await?
        {
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

    // Desired attributes of each replacement key: the common ones, overridden by the
    // key-specific ones (KMIP 2.1 Table 310).
    let requested = |specific: Option<&Attributes>| {
        let mut attributes = request.common_attributes.clone()?;
        if let Some(specific) = specific {
            attributes.merge(specific, true);
        }
        Some(attributes)
    };
    let rekeyer = SqlKeypairRekeyer {
        offset: request.offset,
        private_key_attributes: requested(request.private_key_attributes.as_ref())
            .or_else(|| request.private_key_attributes.clone()),
        public_key_attributes: requested(request.public_key_attributes.as_ref())
            .or_else(|| request.public_key_attributes.clone()),
    };
    Box::pin(execute_rekey(&rekeyer, kms, &request, user)).await
}

impl KMS {
    /// Retrieve the public key linked from a private key being re-keyed.
    ///
    /// The link is client-editable, so the caller must hold `Rekey` on the public key
    /// too; otherwise it is reported as not found (no existence oracle).
    pub(super) async fn retrieve_linked_public_key(
        &self,
        pk_uid: &str,
        user: &UserId,
    ) -> KResult<cosmian_kms_server_database::reexport::cosmian_kms_interfaces::ObjectWithMetadata>
    {
        let not_found = || {
            KmsError::Kmip21Error(
                ErrorReason::Object_Not_Found,
                format!("ReKeyKeyPair: linked public key '{pk_uid}' not found"),
            )
        };
        let owm = self
            .database
            .retrieve_object(pk_uid)
            .await?
            .ok_or_else(not_found)?;
        if !self
            .user_can_perform_operation(&owm, user, &KmipOperation::Rekey)
            .await?
        {
            return Err(not_found());
        }
        Ok(owm)
    }
}
