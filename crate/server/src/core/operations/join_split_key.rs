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
use tracing::info;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::create_split_key::CRYPTO_OFFICER_CEREMONY_ATTR;
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
/// - The declared split method must match the request.
/// - Exactly `total_parts` shares must be provided (n-of-n).
/// - `key_part_identifiers` must be the complete set `{1, …, n}`.
pub(crate) async fn retrieve_and_reconstruct_shares(
    kms: &KMS,
    share_uid_strings: &[String],
    user: &str,
) -> KResult<ReconstructedShares> {
    if share_uid_strings.is_empty() {
        kms_bail!(KmsError::InvalidRequest(
            "at least one share UID must be provided".to_owned()
        ));
    }

    let user_id = UserId::from(user);
    let mut owms: Vec<ObjectWithMetadata> = Vec::with_capacity(share_uid_strings.len());
    for uid_str in share_uid_strings {
        let owm = retrieve_object_for_operation(
            ObjectHandle::from(uid_str.as_str()),
            KmipOperation::Get,
            kms,
            &user_id,
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

    // Extract raw share bytes and XOR-reconstruct the secret
    let mut raw_shares: Vec<Zeroizing<Vec<u8>>> = Vec::with_capacity(owms.len());
    for owm in &owms {
        if let Object::SplitKey(sk) = owm.object() {
            let share_bytes = extract_share_bytes(&sk.key_block)?;
            raw_shares.push(Zeroizing::new(share_bytes));
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
/// Reconstructs a key from all n split-key share objects (XOR n-of-n) and stores the
/// result as a new Managed Cryptographic Object owned by the requesting user.
///
/// This operation is purely for key reconstruction. To activate the Crypto Officer
/// role via a split-key ceremony, use `POST /access/crypto_officer/ceremony/activate`.
pub(crate) async fn join_split_key(
    kms: &KMS,
    request: JoinSplitKey,
    user: &str,
) -> KResult<JoinSplitKeyResponse> {
    // Resolve share UIDs from the request
    let mut share_uids: Vec<String> =
        Vec::with_capacity(request.split_key_unique_identifiers.len());
    for uid_ref in &request.split_key_unique_identifiers {
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

    // Validate that the declared split method in the request matches the shares.
    // (retrieve_and_reconstruct_shares enforces consistency across all shares;
    //  here we just need the method from the request to compare after retrieval.)
    let reconstructed = retrieve_and_reconstruct_shares(kms, &share_uids, user).await?;

    if request.split_key_method != reconstructed.split_key_method {
        kms_bail!(KmsError::InvalidRequest(format!(
            "JoinSplitKey: request declares split key method {:?} \
             but shares use {:?}",
            request.split_key_method, reconstructed.split_key_method
        )));
    }

    // Enforce the same Create/Import restriction as create.rs / import.rs.
    // Crypto Officer ceremony candidates (users in crypto_officer.users) are exempt because
    // they need JoinSplitKey to be usable regardless of their CO role status.
    let user_id = UserId::from(user);
    let is_ceremony_candidate = kms.params.crypto_officer.require_ceremony
        && kms.params.crypto_officer.users.iter().any(|u| u == user);
    if !is_ceremony_candidate && kms.params.crypto_officer.is_configured() {
        let has_create_permission = crate::core::retrieve_object_utils::user_has_permission(
            &user_id,
            None,
            &KmipOperation::Create,
            kms,
        )
        .await?;
        let is_crypto_officer = !kms.params.crypto_officer.users.is_empty()
            && kms.params.crypto_officer.users.iter().any(|u| u == user);
        if !has_create_permission && !is_crypto_officer {
            kms_bail!(KmsError::Unauthorized(
                "JoinSplitKey: user does not have permission to create objects \
                 (CryptoOfficer role or explicit Create grant required)"
                    .to_owned()
            ));
        }
    }

    // Build the reconstructed key object
    let reconstructed_uid = Uuid::new_v4().to_string();
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

    kms.database
        .create(
            Some(reconstructed_uid.clone()),
            &user_id,
            &reconstructed_object,
            &reconstructed_attrs,
            &tags,
        )
        .await?;

    info!(
        uid = %reconstructed_uid,
        shares = share_uids.len(),
        user = %user,
        "JoinSplitKey: reconstructed key stored",
    );

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
/// - Verifies dual-control constraints (unique owners, assembler ≠ share owner, all CO candidates).
/// - Reconstructs the ceremony secret via XOR **in RAM only**.
/// - Persists the `crypto_officer_activations` record.
/// - The secret is zeroized when the function returns (ADP-20 — never stored).
///
/// Returns `Ok(())` on successful activation.
pub(crate) async fn perform_crypto_officer_ceremony_activation(
    kms: &KMS,
    share_ids: &[String],
    user: &str,
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

    if !co_cfg.users.iter().any(|u| u == user) {
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
    if !participants.iter().any(|p| p.as_str() != user) {
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
        .activate_crypto_officer_ceremony(user, participants, &reconstructed.key_hash)
        .await?;

    info!(
        activated_by = %user,
        participants = ?participants,
        "CRYPTO_OFFICER_CEREMONY_ACTIVATED: Crypto Officer ceremony completed"
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
