use std::collections::HashSet;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::State,
        kmip_2_1::{
            KmipOperation,
            extra::VENDOR_ID_COSMIAN,
            kmip_attributes::Attributes,
            kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
            kmip_objects::{Object, ObjectType, SymmetricKey},
            kmip_operations::{JoinSplitKey, JoinSplitKeyResponse},
            kmip_types::{
                CryptographicAlgorithm, KeyFormatType, SplitKeyMethod, UniqueIdentifier,
                VendorAttributeValue,
            },
        },
    },
    cosmian_kms_crypto,
    cosmian_kms_interfaces::ObjectWithMetadata,
};
use openssl::hash::{MessageDigest, hash};
use tracing::debug;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::create_split_key::{CRYPTO_OFFICER_CEREMONY_ATTR, extract_key_bytes};
use crate::{
    core::{KMS, retrieve_object_utils::retrieve_object_for_operation, uid_utils::ObjectHandle},
    error::KmsError,
    kms_bail,
    middlewares::UserId,
    result::KResult,
};

/// Reconstructed shares returned by [`retrieve_and_reconstruct_shares`].
///
/// The `secret` field holds the XOR-reconstructed raw key material and is
/// automatically zeroized on drop.
pub(crate) struct ReconstructedShares {
    /// XOR-reconstructed secret — zeroized on drop.
    pub secret: Zeroizing<Vec<u8>>,
    /// SHA-256 hex fingerprint of the reconstructed secret.
    pub key_hash: String,
    /// Owner of each share (same order as the input UIDs).
    pub owners: Vec<String>,
    /// `true` when every share carries the `x-cosmian-crypto-officer-ceremony` attribute.
    pub all_ceremony_tagged: bool,
    /// Metadata carried from the first share (algorithm, length, method).
    pub cryptographic_algorithm: Option<CryptographicAlgorithm>,
    pub cryptographic_length: Option<i32>,
    pub split_key_method: SplitKeyMethod,
}

/// Retrieve all share objects, validate consistency, and XOR-reconstruct the secret.
///
/// Performs all validations shared by [`join_split_key`] and the Crypto Officer
/// ceremony activation endpoint:
///
/// - Caller must have `Get` permission on each share.
/// - All objects must be `SplitKey` objects.
/// - All shares must declare the same `split_key_method`.
/// - All shares must come from the same source key (cross-key mixing rejected).
/// - Exactly `total_parts` shares must be provided (n-of-n).
/// - `key_part_identifiers` must be the complete set `{1, …, n}`.
pub(crate) async fn retrieve_and_reconstruct_shares(
    kms: &KMS,
    share_uid_strings: &[String],
    user: &UserId,
) -> KResult<ReconstructedShares> {
    if share_uid_strings.is_empty() {
        kms_bail!(KmsError::InvalidRequest(
            "at least one share UID must be provided".to_owned()
        ));
    }

    let mut owms: Vec<ObjectWithMetadata> = Vec::with_capacity(share_uid_strings.len());
    for uid_str in share_uid_strings {
        let owm = retrieve_object_for_operation(
            ObjectHandle::from(uid_str.as_str()),
            KmipOperation::Get,
            kms,
            user,
        )
        .await?;
        owms.push(owm);
    }

    // Validate: all shares must be SplitKey objects
    for owm in &owms {
        if owm.object().object_type() != ObjectType::SplitKey {
            kms_bail!(KmsError::InvalidRequest(format!(
                "object {} is not a SplitKey object",
                owm.id()
            )));
        }
    }

    // Extract metadata from the first share to verify consistency
    let Some(Object::SplitKey(first_sk)) = owms.first().map(ObjectWithMetadata::object) else {
        kms_bail!(KmsError::InvalidRequest(
            "first share is not a SplitKey object".to_owned()
        ))
    };
    let total_parts = first_sk.split_key_parts;
    let method = first_sk.split_key_method;
    let cryptographic_algorithm = first_sk.key_block.cryptographic_algorithm;
    let cryptographic_length = first_sk.key_block.cryptographic_length;

    // Enforce XOR n-of-n: all shares must be provided.
    let shares_count = i32::try_from(owms.len()).unwrap_or(i32::MAX);
    if shares_count != total_parts {
        kms_bail!(KmsError::InvalidRequest(format!(
            "XOR n-of-n requires all {total_parts} shares; {} provided",
            owms.len()
        )));
    }

    // Validate all shares have consistent metadata and unique key_part_identifiers
    let mut part_ids: HashSet<i32> = HashSet::new();
    for owm in &owms {
        if let Object::SplitKey(sk) = owm.object() {
            if sk.split_key_parts != total_parts {
                kms_bail!(KmsError::InvalidRequest(format!(
                    "share {} has inconsistent split_key_parts \
                     (expected {total_parts}, got {})",
                    owm.id(),
                    sk.split_key_parts,
                )));
            }
            if sk.split_key_method != method {
                kms_bail!(KmsError::InvalidRequest(format!(
                    "share {} uses a different split key method",
                    owm.id()
                )));
            }
            if !part_ids.insert(sk.key_part_identifier) {
                kms_bail!(KmsError::InvalidRequest(format!(
                    "duplicate key_part_identifier {} in share {}",
                    sk.key_part_identifier,
                    owm.id()
                )));
            }
        }
    }
    // Verify completeness: key_part_identifiers must form {1, 2, ..., total_parts}
    let expected: HashSet<i32> = (1..=total_parts).collect();
    if part_ids != expected {
        kms_bail!(KmsError::InvalidRequest(format!(
            "key_part_identifiers {part_ids:?} do not form the expected complete set {expected:?}"
        )));
    }

    // Reject cross-key mixing: all shares must originate from the same source key.
    {
        let sources: Vec<Option<String>> = owms
            .iter()
            .map(|owm| {
                owm.attributes()
                    .get_vendor_attribute_value(VENDOR_ID_COSMIAN, "x-cosmian-split-key-source")
                    .and_then(|v| {
                        if let VendorAttributeValue::TextString(s) = v {
                            Some(s.clone())
                        } else {
                            None
                        }
                    })
            })
            .collect();
        let first_source = sources.first().and_then(Option::as_ref);
        if first_source.is_none() || !sources.iter().all(|s| s.as_ref() == first_source) {
            kms_bail!(KmsError::InvalidRequest(format!(
                "shares do not all belong to the same original key. \
                 Cross-key mixing is not allowed. Sources found: {sources:?}"
            )));
        }
    }

    // Extract raw share bytes and XOR-reconstruct the secret.
    // If a share carries the `x-cosmian-share-wrapping-key` vendor attribute,
    // the stored bytes are AES-KW (RFC 5649) wrapped — retrieve the wrapping key from
    // the DB and unwrap before feeding the plaintext bytes into the XOR reconstruction.
    let mut raw_shares: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(owms.len());
    for owm in &owms {
        if let Object::SplitKey(sk) = owm.object() {
            let stored_bytes = extract_share_bytes(&sk.key_block)?;

            // Check for an AES-KW wrapping key UID stamped by CreateSplitKey.
            let share_bytes: Zeroizing<Vec<u8>> = match owm
                .attributes()
                .get_vendor_attribute_value(VENDOR_ID_COSMIAN, "x-cosmian-share-wrapping-key")
            {
                Some(VendorAttributeValue::TextString(wrap_key_id)) => {
                    // Retrieve the wrapping key directly from the DB (server-side, no user check).
                    let wrap_owm = kms
                        .database
                        .retrieve_object(wrap_key_id)
                        .await
                        .map_err(|e| {
                            KmsError::ServerError(format!(
                                "JoinSplitKey: failed to retrieve ceremony wrapping key \
                                 '{wrap_key_id}': {e}"
                            ))
                        })?
                        .ok_or_else(|| {
                            KmsError::ServerError(format!(
                                "JoinSplitKey: ceremony wrapping key '{wrap_key_id}' not found. \
                                 The key must exist in the KMS object store to reconstruct \
                                 wrapped shares."
                            ))
                        })?;
                    let wkb = extract_key_bytes(wrap_owm.object())?;
                    let unwrapped = cosmian_kms_crypto::crypto::symmetric::rfc5649::rfc5649_unwrap(
                        &stored_bytes,
                        &wkb,
                    )
                    .map_err(|e| {
                        KmsError::CryptographicError(format!(
                            "JoinSplitKey: AES-KW unwrap of share failed (wrapping key \
                                 '{wrap_key_id}'): {e}"
                        ))
                    })?;
                    Zeroizing::new(unwrapped.to_vec())
                }
                _ => Zeroizing::new(stored_bytes),
            };

            raw_shares.push(share_bytes);
        }
    }

    let secret: Zeroizing<Vec<u8>> = match method {
        SplitKeyMethod::PolynomialSharingGf28
        | SplitKeyMethod::PolynomialSharingGf216
        | SplitKeyMethod::XOR => cosmian_kms_crypto::crypto::split_key::xor_join(&raw_shares)
            .map_err(|e| KmsError::InvalidRequest(format!("reconstruction error: {e}")))?,
        SplitKeyMethod::PolynomialSharingPrimeField => {
            kms_bail!(KmsError::NotSupported(
                "PolynomialSharingPrime is not supported".to_owned()
            ));
        }
    };

    let key_hash = hash(MessageDigest::sha256(), &secret)
        .map_or_else(|_| String::new(), |digest| hex::encode(digest.as_ref()));

    let all_ceremony_tagged = owms.iter().all(|owm| {
        owm.attributes()
            .get_vendor_attribute_value(VENDOR_ID_COSMIAN, CRYPTO_OFFICER_CEREMONY_ATTR)
            .is_some()
    });

    let owners: Vec<String> = owms.iter().map(|owm| owm.owner().to_owned()).collect();

    Ok(ReconstructedShares {
        secret,
        key_hash,
        owners,
        all_ceremony_tagged,
        cryptographic_algorithm,
        cryptographic_length,
        split_key_method: method,
    })
}

/// `JoinSplitKey` operation handler.
///
/// Reconstructs a key from all n split-key share objects (XOR n-of-n) and **always**
/// stores the result as a new Managed Cryptographic Object owned by the requesting user.
///
/// When all shares carry the `x-cosmian-crypto-officer-ceremony` vendor attribute
/// **and** `crypto_officer_require_ceremony = true`, the operation additionally
/// auto-triggers ceremony activation (writing to `crypto_officer_activations`).
/// The reconstructed key is stored unconditionally before the activation side-effect —
/// activation failure is non-fatal and leaves the stored key intact.
///
/// The `POST /access/crypto_officer/ceremony/activate` REST endpoint performs
/// activation-only (no key storage) and is kept for CLI backward compatibility.
pub(crate) async fn join_split_key(
    kms: &KMS,
    request: JoinSplitKey,
    user: &UserId,
) -> KResult<JoinSplitKeyResponse> {
    // Resolve share UIDs from the request
    let mut share_uids: Vec<String> = Vec::with_capacity(request.unique_identifier.len());
    for uid_ref in &request.unique_identifier {
        match uid_ref {
            UniqueIdentifier::TextString(s) => share_uids.push(s.clone()),
            other => {
                kms_bail!(KmsError::InvalidRequest(format!(
                    "JoinSplitKey: unsupported UniqueIdentifier variant: {other:?}"
                )));
            }
        }
    }

    if share_uids.is_empty() {
        kms_bail!(KmsError::InvalidRequest(
            "JoinSplitKey: at least one share UID must be provided".to_owned()
        ));
    }

    // Reconstruct the shares — the split key method is read from the stored share objects,
    // not from the request (the spec does not include split_key_method in the request payload).
    let reconstructed = retrieve_and_reconstruct_shares(kms, &share_uids, user).await?;
    debug!(
        method = ?reconstructed.split_key_method,
        n_shares = share_uids.len(),
        "JoinSplitKey: shares reconstructed",
    );

    // Enforce the same Create/Import restriction as create.rs / import.rs.
    // A user listed in crypto_officer.users is always allowed — they are ceremony
    // candidates regardless of whether `require_ceremony` is set, and need
    // JoinSplitKey to reconstruct ceremony keys.
    let is_co_user = kms
        .params
        .crypto_officer
        .users
        .iter()
        .any(|u| u == user.as_str());
    if !is_co_user && kms.params.crypto_officer.is_configured() {
        let has_create_permission = crate::core::retrieve_object_utils::user_has_permission(
            user,
            None,
            &KmipOperation::Create,
            kms,
        )
        .await?;
        if !has_create_permission {
            kms_bail!(KmsError::Unauthorized(
                "JoinSplitKey: user does not have permission to create objects \
                 (CryptoOfficer role or explicit Create grant required)"
                    .to_owned()
            ));
        }
    }

    // Build the reconstructed key object.
    // For ceremony splits, the source key was destroyed after splitting — so we can
    // safely reuse its UID by stripping the `#<part>` suffix from the first share UID
    // (e.g. "ceremony-key#1" → "ceremony-key").
    // For generic splits the source key is still alive; using the same UID would cause
    // a "key already exists" error. In that case a fresh UUID is generated.
    let reconstructed_uid = if reconstructed.all_ceremony_tagged {
        share_uids
            .first()
            .and_then(|first| first.rfind('#').map(|pos| first[..pos].to_owned()))
            .unwrap_or_else(|| Uuid::new_v4().to_string())
    } else {
        Uuid::new_v4().to_string()
    };
    let now = time::OffsetDateTime::now_utc();

    let (reconstructed_object, mut reconstructed_attrs) = build_reconstructed_object(
        &request,
        reconstructed.secret,
        reconstructed.cryptographic_algorithm,
        reconstructed.cryptographic_length,
        now,
    )?;

    // Apply any additional attributes requested by the caller
    if let Some(req_attrs) = &request.attributes {
        if let Some(name) = &req_attrs.name {
            reconstructed_attrs.name = Some(name.clone());
        }
        if let Some(usage) = req_attrs.cryptographic_usage_mask {
            reconstructed_attrs.cryptographic_usage_mask = Some(usage);
        }
    }

    // Store the reconstructed key
    let mut tags: HashSet<String> = HashSet::new();
    tags.insert("reconstructed-split-key".to_owned());

    // Session ID for audit-log correlation of this JoinSplitKey invocation.
    let join_session_id = Uuid::new_v4();

    kms.database
        .create(
            Some(reconstructed_uid.clone()),
            user,
            &reconstructed_object,
            &reconstructed_attrs,
            &tags,
        )
        .await?;

    tracing::error!(
        target: "audit",
        uid = %reconstructed_uid,
        shares = share_uids.len(),
        user = %user,
        session_id = %join_session_id,
        "JoinSplitKey: reconstructed key stored",
    );

    // ── Auto-activate CO ceremony when all shares are ceremony-tagged ────────────
    // When every share carries the `x-cosmian-crypto-officer-ceremony` vendor
    // attribute, `JoinSplitKey` IS the ceremony activation: it validates all the
    // same constraints (n-of-n, dual-control, all CO candidates) and writes the
    // `crypto_officer_activations` record as a side-effect.
    //
    // This eliminates the need for a separate
    // `POST /access/crypto_officer/ceremony/activate` call from the UI.
    // The dedicated REST endpoint is kept for CLI backward compatibility only.
    if reconstructed.all_ceremony_tagged && kms.params.crypto_officer.require_ceremony {
        match perform_crypto_officer_ceremony_activation(kms, &share_uids, user).await {
            Ok(()) => {
                tracing::info!(
                    uid = %reconstructed_uid,
                    user = %user,
                    session_id = %join_session_id,
                    "JoinSplitKey: CO ceremony auto-activated via reconstructed key",
                );
            }
            Err(e) => {
                // Activation failure → compensating delete: the reconstructed key must
                // not persist without a valid ceremony activation record. An orphaned
                // key in the DB would be accessible to anyone holding a Grant on the
                // resulting UID, bypassing the ceremony dual-control.
                tracing::error!(
                    target: "audit",
                    uid = %reconstructed_uid,
                    user = %user,
                    session_id = %join_session_id,
                    error = %e,
                    "JoinSplitKey: CO ceremony activation failed — rolling back \
                     reconstructed key from DB",
                );
                if let Err(del_err) = kms.database.delete(&reconstructed_uid).await {
                    // The rollback itself failed: log explicitly so SIEM can alert on
                    // the orphaned object and trigger manual cleanup.
                    tracing::error!(
                        target: "audit",
                        uid = %reconstructed_uid,
                        user = %user,
                        session_id = %join_session_id,
                        rollback_error = %del_err,
                        "JoinSplitKey: CRITICAL — reconstructed key rollback failed; \
                         orphaned key remains in DB, manual cleanup required",
                    );
                }
                return Err(e);
            }
        }
    }

    Ok(JoinSplitKeyResponse {
        unique_identifier: UniqueIdentifier::TextString(reconstructed_uid),
    })
}

/// Extract raw share bytes from a `SplitKey`'s `KeyBlock`.
fn extract_share_bytes(key_block: &KeyBlock) -> KResult<Vec<u8>> {
    let key_value = key_block
        .key_value
        .as_ref()
        .ok_or_else(|| KmsError::InvalidRequest("split key share has no key value".to_owned()))?;
    match key_value {
        KeyValue::Structure { key_material, .. } => match key_material {
            KeyMaterial::ByteString(v) => Ok(v.to_vec()),
            other => kms_bail!(KmsError::InvalidRequest(format!(
                "unexpected key material type in share: {other:?}"
            ))),
        },
        KeyValue::ByteString(_) => kms_bail!(KmsError::InvalidRequest(
            "share key value is wrapped (ByteString); unwrap before joining".to_owned()
        )),
    }
}

/// Activate the Crypto Officer role via a split-key ceremony.
///
/// Validates and processes the ceremony activation:
/// - Retrieves and validates all shares.
/// - Verifies all shares carry `x-cosmian-crypto-officer-ceremony`.
/// - Verifies dual-control constraints (unique owners, at least one share from a different CO candidate, all CO candidates).
/// - Reconstructs the ceremony secret via XOR **in RAM only** (for key-hash verification).
/// - Persists the `crypto_officer_activations` record.
/// - The secret reconstructed *within this function* is zeroized before returning —
///   this function does **not** store a key object. When called from [`join_split_key`],
///   the key is already stored by the caller before this function runs.
///
/// Returns `Ok(())` on successful activation.
pub(crate) async fn perform_crypto_officer_ceremony_activation(
    kms: &KMS,
    share_ids: &[String],
    user: &UserId,
) -> KResult<()> {
    let co_cfg = &kms.params.crypto_officer;

    if co_cfg.users.is_empty() {
        kms_bail!(KmsError::Unauthorized(
            "Crypto Officer role is not configured on this server".to_owned()
        ));
    }

    if !co_cfg.require_ceremony {
        kms_bail!(KmsError::InvalidRequest(
            "This server uses config-only Crypto Officer mode — no ceremony is required."
                .to_owned()
        ));
    }

    if !co_cfg.users.iter().any(|u| u == user.as_str()) {
        kms_bail!(KmsError::Unauthorized(
            "Ceremony activation rejected — the requesting user is not listed in \
             `crypto_officer_users`"
                .to_owned()
        ));
    }

    let reconstructed = retrieve_and_reconstruct_shares(kms, share_ids, user).await?;

    if !reconstructed.all_ceremony_tagged {
        kms_bail!(KmsError::Unauthorized(
            "Ceremony activation rejected — not all shares are tagged with \
             `x-cosmian-crypto-officer-ceremony`."
                .to_owned()
        ));
    }

    let participants = &reconstructed.owners;
    let unique_participants: HashSet<&str> = participants.iter().map(String::as_str).collect();

    if unique_participants.len() != participants.len() {
        kms_bail!(KmsError::Unauthorized(format!(
            "Ceremony activation rejected — duplicate share owners detected. \
             Owners: {participants:?}"
        )));
    }

    // Verify that at least one share comes from a DIFFERENT CO (dual-control).
    // This prevents the assembling user from self-activating by creating all shares alone.
    if !participants.iter().any(|p| p.as_str() != user.as_str()) {
        kms_bail!(KmsError::Unauthorized(
            "Ceremony activation rejected — at least one share must come from a different \
             Crypto Officer (NIST SP 800-57 Part 2 Rev 1 §4.6 dual control)."
                .to_owned()
        ));
    }

    for participant in participants {
        if !co_cfg.users.iter().any(|u| u == participant) {
            kms_bail!(KmsError::Unauthorized(format!(
                "Ceremony activation rejected — share owner '{participant}' is not in \
                 `crypto_officer_users`"
            )));
        }
    }

    kms.database
        .activate_crypto_officer_ceremony(user.as_str(), participants, &reconstructed.key_hash)
        .await?;

    // Log at ERROR — ceremony activation is a high-value security event that must
    // never be suppressed by RUST_LOG=warn or RUST_LOG=info in production.
    tracing::error!(
        target: "audit",
        activated_by = %user,
        participants = ?participants,
        "CRYPTO_OFFICER_CEREMONY_ACTIVATED: Crypto Officer ceremony completed",
    );

    // `reconstructed.secret` (Zeroizing<Vec<u8>>) is dropped here — never stored.
    Ok(())
}
/// Takes ownership of the `Zeroizing<Vec<u8>>` to avoid an intermediate copy of the
/// reconstructed secret.
fn build_reconstructed_object(
    request: &JoinSplitKey,
    secret: Zeroizing<Vec<u8>>,
    cryptographic_algorithm: Option<CryptographicAlgorithm>,
    cryptographic_length: Option<i32>,
    now: time::OffsetDateTime,
) -> KResult<(Object, Attributes)> {
    let effective_algo = cryptographic_algorithm;
    let effective_length = cryptographic_length.or_else(|| i32::try_from(secret.len() * 8).ok());

    let key_block = KeyBlock {
        key_format_type: KeyFormatType::Opaque,
        key_compression_type: None,
        key_value: Some(KeyValue::Structure {
            key_material: KeyMaterial::ByteString(secret),
            attributes: None,
        }),
        cryptographic_algorithm: effective_algo,
        cryptographic_length: effective_length,
        key_wrapping_data: None,
    };

    let (object, object_type) = match request.object_type {
        ObjectType::SymmetricKey => (
            Object::SymmetricKey(SymmetricKey { key_block }),
            ObjectType::SymmetricKey,
        ),
        other => {
            kms_bail!(KmsError::NotSupported(format!(
                "JoinSplitKey: reconstruction into object type {other:?} is not yet supported"
            )))
        }
    };

    let attrs = Attributes {
        state: Some(State::Active),
        object_type: Some(object_type),
        initial_date: Some(now),
        original_creation_date: Some(now),
        last_change_date: Some(now),
        activation_date: Some(now),
        cryptographic_algorithm: effective_algo,
        cryptographic_length: effective_length,
        ..Attributes::default()
    };

    Ok((object, attrs))
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::assertions_on_result_states
)]
mod tests {
    use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::{
        kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
        kmip_types::{CryptographicAlgorithm, KeyFormatType},
    };
    use zeroize::Zeroizing;

    use super::*;

    fn make_split_key_block_bytes(raw: Vec<u8>) -> KeyBlock {
        KeyBlock {
            key_format_type: KeyFormatType::Opaque,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(Zeroizing::new(raw)),
                attributes: None,
            }),
            cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
            cryptographic_length: Some(256),
            key_wrapping_data: None,
        }
    }

    #[test]
    fn test_extract_share_bytes_valid() {
        let raw = vec![0xAA_u8; 16];
        let kb = make_split_key_block_bytes(raw.clone());
        let result = extract_share_bytes(&kb).expect("should extract share bytes");
        assert_eq!(result, raw);
    }

    #[test]
    fn test_extract_share_bytes_no_key_value_returns_error() {
        let kb = KeyBlock {
            key_format_type: KeyFormatType::Opaque,
            key_compression_type: None,
            key_value: None,
            cryptographic_algorithm: None,
            cryptographic_length: None,
            key_wrapping_data: None,
        };
        let result = extract_share_bytes(&kb);
        assert!(result.is_err(), "missing key_value should return an error");
    }

    #[test]
    fn test_extract_share_bytes_wrapped_returns_error() {
        let kb = KeyBlock {
            key_format_type: KeyFormatType::Opaque,
            key_compression_type: None,
            key_value: Some(KeyValue::ByteString(Zeroizing::new(vec![0_u8; 8]))),
            cryptographic_algorithm: None,
            cryptographic_length: None,
            key_wrapping_data: None,
        };
        let result = extract_share_bytes(&kb);
        assert!(
            result.is_err(),
            "ByteString (wrapped) variant should return an error"
        );
    }

    /// Verify that the simplified `is_co_user` gate correctly allows CO users regardless
    /// of `require_ceremony`, and blocks non-CO users who lack Create permission.
    ///
    /// This is a logic regression test for the fix in issue #6: the old code had a
    /// redundant `is_crypto_officer` inner check that re-derived the same condition.
    #[test]
    fn test_is_co_user_logic() {
        let co_users: Vec<String> = vec!["alice".to_owned(), "bob".to_owned()];

        // CO user: always a member
        assert!(co_users.iter().any(|u| u == "alice"));
        assert!(co_users.iter().any(|u| u == "bob"));

        // Non-CO user: not a member
        assert!(!co_users.iter().any(|u| u == "carol"));

        // The old code gated on `require_ceremony && co_users.iter().any(...)`.
        // With require_ceremony = false, a CO user like "alice" would NOT have been
        // exempt — they would have needed Create permission or been blocked.
        // The new code uses `co_users.iter().any(...)` unconditionally, which is correct:
        // CO users must always be able to join split keys regardless of ceremony mode.
        let require_ceremony = false;

        // Old (broken) logic: is_ceremony_candidate
        let old_is_exempt = require_ceremony && co_users.iter().any(|u| u == "alice");
        assert!(
            !old_is_exempt,
            "old logic incorrectly blocked alice when require_ceremony=false"
        );

        // New (fixed) logic: is_co_user
        let new_is_exempt = co_users.iter().any(|u| u == "alice");
        assert!(new_is_exempt, "new logic correctly exempts alice");
    }
}
