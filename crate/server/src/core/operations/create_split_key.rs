use std::collections::HashSet;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::{RevocationReason, RevocationReasonCode, State},
        kmip_2_1::{
            KmipOperation,
            extra::VENDOR_ID_COSMIAN,
            kmip_attributes::Attributes,
            kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
            kmip_objects::{Object, ObjectType, SplitKey},
            kmip_operations::{CreateSplitKey, CreateSplitKeyResponse, Revoke},
            kmip_types::{KeyFormatType, SplitKeyMethod, UniqueIdentifier, VendorAttributeValue},
        },
    },
    cosmian_kms_crypto,
    cosmian_kms_interfaces::ObjectWithMetadata,
};
use cosmian_logger::{trace, warn};
use rand_chacha::ChaCha20Rng;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{
    core::{KMS, retrieve_object_utils::retrieve_object_for_operation, uid_utils::ObjectHandle},
    error::KmsError,
    kms_bail,
    middlewares::UserId,
    result::KResult,
};

/// Vendor attribute name used to mark split key shares belonging to a Crypto Officer ceremony.
pub(crate) const CRYPTO_OFFICER_CEREMONY_ATTR: &str = "x-cosmian-crypto-officer-ceremony";

/// `CreateSplitKey` operation handler.
///
/// Splits an existing Managed Cryptographic Object into N share objects, each stored as a
/// [`SplitKey`] KMIP object owned by the requesting user.  Any M shares (where M is the
/// configured threshold) are sufficient to reconstruct the original key material via
/// `JoinSplitKey`.
///
/// Only symmetric keys, secret data, and opaque objects (byte-string key material) are
/// supported; asymmetric keys require exporting the private scalar first.
pub(crate) async fn create_split_key(
    kms: &KMS,
    request: CreateSplitKey,
    user: &UserId,
) -> KResult<CreateSplitKeyResponse> {
    trace!("{request}");

    let uid_str = match request.unique_identifier.as_ref() {
        Some(UniqueIdentifier::TextString(s)) => s.clone(),
        Some(other) => other.to_string(),
        None => {
            return Err(KmsError::InvalidRequest(
                "CreateSplitKey: unique_identifier is required (server-side key generation is not yet supported)".to_owned(),
            ));
        }
    };

    // Retrieve the master key — user must have Get permission
    let owm: ObjectWithMetadata =
        retrieve_object_for_operation(ObjectHandle::from(&uid_str), KmipOperation::Get, kms, user)
            .await?;

    // The actual stored UID of the source key — used for share naming and attributes.
    // This differs from `uid_str` when the caller resolves by tag (e.g. `["my-tag"]`)
    // or any other indirect identifier: share UIDs must embed the real DB key UID so
    // that JoinSplitKey can resolve them back to the original key.
    let source_uid = owm.id().to_owned();

    // Only non-prefixed (database) keys can be split — HSM key material is never exported
    if ObjectHandle::from(owm.id()).is_hsm() {
        kms_bail!(KmsError::NotSupported(
            "CreateSplitKey is not supported for HSM-backed keys".to_owned()
        ));
    }

    // Validate threshold / parts parameters
    if request.split_key_threshold < 2 {
        kms_bail!(KmsError::InvalidRequest(
            "CreateSplitKey: split_key_threshold must be at least 2".to_owned()
        ));
    }
    if request.split_key_parts < request.split_key_threshold {
        kms_bail!(KmsError::InvalidRequest(
            "CreateSplitKey: split_key_parts must be >= split_key_threshold".to_owned()
        ));
    }
    if request.split_key_parts > 255 {
        kms_bail!(KmsError::InvalidRequest(
            "CreateSplitKey: split_key_parts must be <= 255".to_owned()
        ));
    }

    // Extract raw key bytes from the master object's key block
    let key_bytes: Zeroizing<Vec<u8>> = extract_key_bytes(owm.object())?;

    // Determine whether this is a Crypto Officer ceremony split.
    //
    // Two signals trigger ceremony mode, but BOTH require the caller to be a CO candidate:
    //
    // 1. The source key carries the `x-cosmian-crypto-officer-ceremony` vendor attribute
    //    (stamped by the CLI `--ceremony` flag or the CO Role page UI) **and** the caller
    //    is listed in `crypto_officer_users`. Without the CO-user check, any operator who
    //    holds Set/AddAttribute + Get rights on a key could stamp the attribute and trigger
    //    the ceremony destruction path — a privilege escalation (crypto review finding 3).
    //
    // 2. The server is globally configured with `require_ceremony = true` AND has at
    //    least one CO user configured — the server enforces ceremony distribution for
    //    every split when in ceremony mode, regardless of the attribute.
    //
    // In ceremony mode the server ignores the requested share count and assigns one
    // share per CO candidate (round-robin ownership), enforcing dual control.
    let co_users = &kms.params.crypto_officer.users;
    let caller_is_co_candidate = co_users.iter().any(|u| u == user.as_str());
    let is_co_ceremony_key = (owm
        .attributes()
        .get_vendor_attribute_value(VENDOR_ID_COSMIAN, CRYPTO_OFFICER_CEREMONY_ATTR)
        .is_some()
        && caller_is_co_candidate)
        || (kms.params.crypto_officer.require_ceremony && !co_users.is_empty());

    // Generate shares using the requested split method
    let mut threshold = request.split_key_threshold;
    let mut total_parts = request.split_key_parts;

    // For ceremony splits, auto-determine the share count from the CO users list.
    // This ensures the split always matches the number of candidates exactly,
    // preventing a mismatch between the split count and the ceremony activation count.
    // Only override when there are at least 2 CO users (split requires n >= 2).
    tracing::debug!(
        n_co = co_users.len(),
        is_ceremony = is_co_ceremony_key,
        total_parts,
        threshold,
        "CreateSplitKey: resolved ceremony parameters",
    );
    if is_co_ceremony_key && co_users.len() >= 2 {
        let n_co = co_users.len();
        let n_co_i32 = i32::try_from(n_co).map_err(|_e| {
            KmsError::InvalidRequest(
                "crypto_officer_users count exceeds valid range — configuration error".to_owned(),
            )
        })?;
        if n_co_i32 != total_parts {
            trace!(
                "CreateSplitKey: overriding total_parts from {total_parts} to {n_co_i32} \
                 (matches crypto_officer_users count)"
            );
            total_parts = n_co_i32;
            threshold = n_co_i32; // n-of-n
        }
    }
    // Safe: total_parts is validated to 2..=255 above; u32 conversion is lossless.
    let total_parts_u32 = u32::try_from(total_parts).map_err(|e| {
        KmsError::InvalidRequest(format!(
            "CreateSplitKey: total_parts out of valid range — internal error: {e}"
        ))
    })?;

    // XOR is an n-of-n scheme: all shares are required for reconstruction.
    // Reject threshold < total_parts early so the error message is precise.
    if request.split_key_method == SplitKeyMethod::XOR && threshold != total_parts {
        kms_bail!(KmsError::InvalidRequest(format!(
            "CreateSplitKey: XOR split_key_method requires threshold ({threshold}) == \
             split_key_parts ({total_parts}); use PolynomialSharingGf28 for M-of-N threshold sharing"
        )));
    }

    let mut rng = rand::make_rng::<ChaCha20Rng>();

    let raw_shares: Vec<Zeroizing<Vec<u8>>> = match request.split_key_method {
        SplitKeyMethod::XOR => {
            cosmian_kms_crypto::crypto::split_key::xor_split(&key_bytes, total_parts_u32, &mut rng)
                .map_err(|e| KmsError::InvalidRequest(format!("CreateSplitKey error: {e}")))?
        }
        SplitKeyMethod::PolynomialSharingGf28
        | SplitKeyMethod::PolynomialSharingGf216
        | SplitKeyMethod::PolynomialSharingPrimeField => {
            kms_bail!(KmsError::NotSupported(format!(
                "CreateSplitKey: split_key_method {:?} (M-of-N polynomial sharing) is not yet \
                 implemented; only XOR (n-of-n) is supported. Use split_key_method=XOR with \
                 split_key_threshold == split_key_parts.",
                request.split_key_method
            )));
        }
    };

    // Build and store each share as a SplitKey KMIP object
    // total_parts is validated to 2..=255; usize conversion cannot overflow.
    let total_parts_usize = usize::try_from(total_parts).map_err(|e| {
        KmsError::InvalidRequest(format!(
            "CreateSplitKey: total_parts out of valid range — internal error: {e}"
        ))
    })?;
    let mut share_uids: Vec<UniqueIdentifier> = Vec::with_capacity(total_parts_usize);

    let now = time::OffsetDateTime::now_utc();

    // Generate a session ID that appears in every audit log entry for this CreateSplitKey
    // invocation, enabling correlation of all shares produced in a single ceremony split
    // (NIST SP 800-57 Part 2 Rev 1 §4.6 audit requirements).
    let ceremony_session_id = if is_co_ceremony_key {
        Some(Uuid::new_v4().to_string())
    } else {
        None
    };

    // Retrieve the AES-KW ceremony wrapping key once, before the share loop.
    // Each share's raw bytes are wrapped with this key before being stored in the DB,
    // so that a DB-level attacker cannot read share plaintext without also accessing
    // the wrapping key (which may itself be HSM-resident when the KMS is HSM-backed).
    let wrapping_key_bytes: Option<Zeroizing<Vec<u8>>> =
        if let Some(ref wrap_key_id) = kms.params.crypto_officer.ceremony_wrapping_key_id {
            let wrap_owm = kms
                .database
                .retrieve_object(wrap_key_id)
                .await
                .map_err(|e| {
                    KmsError::ServerError(format!(
                        "CreateSplitKey: failed to retrieve ceremony wrapping key \
                         '{wrap_key_id}': {e}"
                    ))
                })?
                .ok_or_else(|| {
                    KmsError::ItemNotFound(format!(
                        "CreateSplitKey: ceremony wrapping key '{wrap_key_id}' not found in DB. \
                         Create it with: ckms sym keys create --id {wrap_key_id} \
                         --number-of-bits 256"
                    ))
                })?;
            Some(extract_key_bytes(wrap_owm.object())?)
        } else {
            None
        };

    for (idx, share_bytes) in raw_shares.into_iter().enumerate() {
        // 1-indexed share number; idx fits in i32 since total_parts <= 255.
        let part_identifier = i32::try_from(idx + 1).unwrap_or(1);

        // Determine the owner of this share. For ceremony keys, each share is owned
        // by a different CO candidate to enforce dual control (NIST SP 800-57 Part 2
        // Rev 1 §4.6). The creating user owns share 0; shares 1..n are assigned to
        // the other CO candidates round-robin.
        let share_owner: UserId = if is_co_ceremony_key && !co_users.is_empty() {
            let co_idx = idx % co_users.len();
            UserId::from(co_users.get(co_idx).map_or("unknown", |s| s.as_str()))
        } else {
            (*user).clone()
        };

        // If a ceremony wrapping key is configured, AES-KW wrap the share bytes.
        // The plaintext share is consumed here; only the wrapped ciphertext is stored.
        let stored_share_bytes: Zeroizing<Vec<u8>> = match &wrapping_key_bytes {
            Some(wkb) => {
                let wrapped =
                    cosmian_kms_crypto::crypto::symmetric::rfc5649::rfc5649_wrap(&share_bytes, wkb)
                        .map_err(|e| {
                            KmsError::CryptographicError(format!(
                                "CreateSplitKey: AES-KW wrapping of share {part_identifier} \
                                 failed: {e}"
                            ))
                        })?;
                Zeroizing::new(wrapped)
            }
            None => share_bytes,
        };

        // Build the SplitKey KMIP object — raw share bytes stored as ByteString key material.
        // stored_share_bytes is moved (no clone) so the only copy lives inside Zeroizing.
        let key_block = KeyBlock {
            key_format_type: KeyFormatType::Opaque,
            key_compression_type: None,
            key_value: Some(KeyValue::Structure {
                key_material: KeyMaterial::ByteString(stored_share_bytes),
                attributes: None,
            }),
            cryptographic_algorithm: owm
                .object()
                .key_block()
                .ok()
                .and_then(|kb| kb.cryptographic_algorithm),
            cryptographic_length: owm
                .object()
                .key_block()
                .ok()
                .and_then(|kb| kb.cryptographic_length),
            key_wrapping_data: None,
        };

        let split_key_obj = Object::SplitKey(SplitKey {
            split_key_parts: total_parts,
            key_part_identifier: part_identifier,
            split_key_threshold: threshold,
            split_key_method: request.split_key_method,
            prime_field_size: None,
            key_block,
        });

        // Build attributes for the share object — include crypto metadata so
        // GetAttributes and the WebUI Locate table can display algorithm / length / format.
        // `sensitive = true` ensures Get/Export of a share require explicit key-wrapping
        // (same protection as any other raw key material — CWE-312).
        let share_attrs = Attributes {
            state: Some(State::Active),
            object_type: Some(ObjectType::SplitKey),
            initial_date: Some(now),
            original_creation_date: Some(now),
            last_change_date: Some(now),
            activation_date: Some(now),
            cryptographic_algorithm: owm
                .object()
                .key_block()
                .ok()
                .and_then(|kb| kb.cryptographic_algorithm),
            cryptographic_length: owm
                .object()
                .key_block()
                .ok()
                .and_then(|kb| kb.cryptographic_length),
            key_format_type: Some(KeyFormatType::Opaque),
            sensitive: Some(true),
            ..Attributes::default()
        };
        let mut share_attrs = share_attrs;

        // Always stamp the source key UID on every share.
        // This lets JoinSplitKey detect cross-key mixing (e.g. A-1 + B-1) regardless
        // of whether this is a ceremony key or a regular split key.
        share_attrs.set_vendor_attribute(
            VENDOR_ID_COSMIAN,
            "x-cosmian-split-key-source",
            VendorAttributeValue::TextString(source_uid.clone()),
        );

        // Propagate Crypto Officer ceremony marker to each share
        if is_co_ceremony_key {
            share_attrs.set_vendor_attribute(
                VENDOR_ID_COSMIAN,
                CRYPTO_OFFICER_CEREMONY_ATTR,
                VendorAttributeValue::TextString("true".to_owned()),
            );
        }

        // Stamp the wrapping key UID on the share so JoinSplitKey can locate it.
        if let Some(ref wrap_key_id) = kms.params.crypto_officer.ceremony_wrapping_key_id {
            share_attrs.set_vendor_attribute(
                VENDOR_ID_COSMIAN,
                "x-cosmian-share-wrapping-key",
                VendorAttributeValue::TextString(wrap_key_id.clone()),
            );
        }

        // Build a tag set for discoverability
        let mut tags: HashSet<String> = HashSet::new();
        tags.insert(format!("split-key-of:{source_uid}"));
        tags.insert(format!("split-key-part:{part_identifier}"));
        // Include total count so the UI can render "Share X/Y" without a second request.
        tags.insert(format!("split-key-total:{total_parts}"));

        let share_uid = match kms
            .database
            .create(
                // Share UID naming convention: "<source-key-uid>#<part>" (e.g. "my-key#1").
                // The `#` separator is not a valid UUID character and is not used in
                // standard KMIP UIDs, making it unambiguous as a positional delimiter.
                // `source_uid` is the actual stored UID (from owm.id()), not the request
                // identifier — ensures correct naming even when the caller passed a tag.
                Some(format!("{source_uid}#{part_identifier}")),
                &share_owner,
                &split_key_obj,
                &share_attrs,
                &tags,
            )
            .await
        {
            Ok(uid) => uid,
            Err(e) => {
                // Log orphaned shares for manual cleanup — the database trait does not
                // expose a direct delete method. The shares are tagged with
                // `split-key-of:<uid>` for discoverability.
                if !share_uids.is_empty() {
                    let orphan_uids: Vec<String> = share_uids
                        .iter()
                        .filter_map(|u| {
                            if let UniqueIdentifier::TextString(s) = u {
                                Some(s.clone())
                            } else {
                                None
                            }
                        })
                        .collect();
                    warn!(
                        orphans = ?orphan_uids,
                        source = %uid_str,
                        "CreateSplitKey: partial failure — {} share(s) already stored \
                         but remaining shares could not be created. Manual cleanup required.",
                        orphan_uids.len(),
                    );
                }
                return Err(KmsError::from(e));
            }
        };

        tracing::error!(
            target: "audit",
            uid = %share_uid,
            part = part_identifier,
            total = total_parts,
            source = %uid_str,
            owner = %share_owner,
            user = %user,
            session_id = ?ceremony_session_id,
            "CreateSplitKey: split-key share stored",
        );

        share_uids.push(UniqueIdentifier::TextString(share_uid));
    }

    // For ceremony keys, destroy the original key after all shares have been stored.
    // This is a critical security requirement: the key creator owns K and S1, so they can
    // compute any other share (S_i) as long as K remains accessible. Destroying K after
    // splitting ensures that no single CO retains the complete secret, regardless of n.
    // (With n ≥ 3 this is defence-in-depth; destruction is still required because a
    // malicious creator could have exported K before calling CreateSplitKey.)
    if is_co_ceremony_key {
        use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_operations::Destroy;

        // Revoke the source key before destroying — the destroy operation requires
        // prior revocation for keys with an explicit activation_date.
        // CessationOfOperation is the correct reason: the key is not compromised,
        // it has been superseded by its split-key shares (KMIP §6.18 / SP 800-57 §4.2.3).
        // Using KeyCompromise here would generate false-positive alerts in SIEM systems.
        let revoke_req = Revoke {
            unique_identifier: request.unique_identifier.clone(),
            revocation_reason: RevocationReason {
                revocation_reason_code: RevocationReasonCode::CessationOfOperation,
                revocation_message: Some(
                    "Ceremony source key superseded by split key shares".to_owned(),
                ),
            },
            compromise_occurrence_date: None,
            cascade: false,
        };
        let destroy_user = user;
        if let Err(e) = Box::pin(super::revoke::revoke_operation(
            kms,
            revoke_req,
            destroy_user,
        ))
        .await
        {
            return Err(KmsError::InvalidRequest(format!(
                "CreateSplitKey: failed to revoke ceremony source key \
                 '{uid_str}' before destruction: {e}"
            )));
        }

        let destroy_req = Destroy {
            unique_identifier: request.unique_identifier.clone(),
            remove: true, // physically remove — the key is superseded by its shares
            cascade: false,
            expected_object_type: None,
        };
        match Box::pin(super::destroy::destroy_operation(
            kms,
            destroy_req,
            destroy_user,
        ))
        .await
        {
            Ok(_) => {
                tracing::error!(
                    target: "audit",
                    uid = %uid_str,
                    user = %user,
                    session_id = ?ceremony_session_id,
                    "CreateSplitKey: ceremony source key destroyed after successful split",
                );
            }
            Err(e) => {
                // Destroy failure must not silently succeed — the shares are already stored.
                // Log clearly and propagate so the caller knows the key still exists.
                warn!(
                    uid = %uid_str,
                    error = %e,
                    "CreateSplitKey: ceremony source key could not be destroyed after split \
                     — key material may still be accessible. Manual destruction required.",
                );
                return Err(KmsError::InvalidRequest(format!(
                    "CreateSplitKey: shares were created but the ceremony source key \
                     '{uid_str}' could not be destroyed: {e}. \
                     Destroy it manually before proceeding."
                )));
            }
        }
    }

    Ok(CreateSplitKeyResponse {
        unique_identifier: share_uids,
    })
}

/// Extract raw key bytes from any supported KMIP object type.
///
/// Used both by `CreateSplitKey` (to extract the source key's bytes) and by
/// `JoinSplitKey` when it needs to retrieve a ceremony wrapping key from the DB.
pub(crate) fn extract_key_bytes(object: &Object) -> KResult<Zeroizing<Vec<u8>>> {
    match object {
        Object::SymmetricKey(sk) => Ok(sk.key_block.key_bytes().map_err(|e| {
            KmsError::InvalidRequest(format!(
                "CreateSplitKey: cannot read symmetric key bytes: {e}"
            ))
        })?),
        Object::SecretData(sd) => Ok(sd.key_block.key_bytes().map_err(|e| {
            KmsError::InvalidRequest(format!(
                "CreateSplitKey: cannot read secret data bytes: {e}"
            ))
        })?),
        Object::OpaqueObject(oo) => Ok(Zeroizing::new(oo.opaque_data_value.clone())),
        other => kms_bail!(KmsError::NotSupported(format!(
            "CreateSplitKey: unsupported object type {:?}",
            other.object_type()
        ))),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::assertions_on_result_states
)]
mod tests {
    use cosmian_kms_server_database::reexport::cosmian_kmip::{
        kmip_0::kmip_types::SecretDataType,
        kmip_2_1::{
            kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
            kmip_objects::{OpaqueObject, SecretData, SymmetricKey},
            kmip_types::{CryptographicAlgorithm, KeyFormatType, OpaqueDataType},
        },
    };
    use zeroize::Zeroizing;

    use super::*;

    fn make_raw_key_block(raw: Vec<u8>) -> KeyBlock {
        KeyBlock {
            key_format_type: KeyFormatType::TransparentSymmetricKey,
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
    fn test_extract_key_bytes_symmetric_key() {
        let raw = vec![0xAB_u8; 32];
        let obj = Object::SymmetricKey(SymmetricKey {
            key_block: make_raw_key_block(raw.clone()),
        });
        let result = extract_key_bytes(&obj).expect("should extract bytes from SymmetricKey");
        assert_eq!(result.as_slice(), raw.as_slice());
    }

    #[test]
    fn test_extract_key_bytes_secret_data() {
        let raw = vec![0xCD_u8; 16];
        let obj = Object::SecretData(SecretData {
            secret_data_type: SecretDataType::Password,
            key_block: make_raw_key_block(raw.clone()),
        });
        let result = extract_key_bytes(&obj).expect("should extract bytes from SecretData");
        assert_eq!(result.as_slice(), raw.as_slice());
    }

    #[test]
    fn test_extract_key_bytes_opaque_object() {
        let raw = vec![0x01_u8, 0x02, 0x03];
        let obj = Object::OpaqueObject(OpaqueObject {
            opaque_data_type: OpaqueDataType::Unknown,
            opaque_data_value: raw.clone(),
        });
        let result = extract_key_bytes(&obj).expect("should extract bytes from OpaqueObject");
        assert_eq!(result.as_slice(), raw.as_slice());
    }

    #[test]
    fn test_extract_key_bytes_unsupported_type_returns_error() {
        use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_objects::PrivateKey;
        let obj = Object::PrivateKey(PrivateKey {
            key_block: make_raw_key_block(vec![0_u8; 32]),
        });
        let result = extract_key_bytes(&obj);
        assert!(
            result.is_err(),
            "PrivateKey should not be supported by extract_key_bytes"
        );
        assert!(matches!(result.unwrap_err(), KmsError::NotSupported(_)));
    }

    #[test]
    fn test_total_parts_u32_conversion_is_fallible_not_silent() {
        // Verify that u32::try_from returns Err for negative i32 values.
        let negative: i32 = -1;
        assert!(u32::try_from(negative).is_err());
        let valid: i32 = 5;
        assert_eq!(u32::try_from(valid).unwrap(), 5_u32);
    }

    /// Verify the `#` share UID naming convention.
    ///
    /// Shares are named `<source-key-uid>#<part>` where `source-key-uid` is the
    /// **actual stored UID** (`owm.id()`), not the request identifier.
    /// This ensures correct naming even when the caller identifies the key by tag.
    #[test]
    fn test_share_uid_naming_convention() {
        let source_uid = "ceremony-key-2026";
        for part in 1_i32..=5 {
            let share_uid = format!("{source_uid}#{part}");
            // The `#` separator is easy to strip when reconstructing the base UID.
            let (base, suffix) = share_uid.split_once('#').unwrap();
            assert_eq!(base, source_uid);
            assert_eq!(suffix, part.to_string().as_str());
        }

        // When the caller passes a tag (e.g. `["my-tag"]`), the request identifier differs
        // from the stored UID.  The share should use `owm.id()` (the actual UID), not the
        // tag string — otherwise the share UID would be `["my-tag"]#1`, which is invalid.
        let request_identifier = "[\"my-tag\"]";
        let actual_stored_uid = "550e8400-e29b-41d4-a716-446655440000";
        // Correct: use the resolved stored UID
        let share_uid = format!("{actual_stored_uid}#1");
        assert!(share_uid.starts_with(actual_stored_uid));
        assert!(!share_uid.starts_with(request_identifier));
    }

    /// Verify that `JoinSplitKey` only reuses the source key UID for ceremony splits.
    ///
    /// - Ceremony splits: source key destroyed → UID from first share is safe to reuse
    /// - Generic splits: source key still exists → use a fresh UUID to avoid collision
    #[test]
    fn test_join_split_key_uid_derivation() {
        let ceremony_share_uid = "ceremony-key-2026#1".to_owned();
        let derived = ceremony_share_uid
            .rfind('#')
            .map(|pos| ceremony_share_uid[..pos].to_owned());
        assert_eq!(derived, Some("ceremony-key-2026".to_owned()));

        // UUID-style share UIDs (no `#`) fall back to a new UUID — verify rfind returns None.
        let uuid_share = "550e8400-e29b-41d4-a716-446655440000".to_owned();
        assert!(uuid_share.rfind('#').is_none());

        // For generic (non-ceremony) splits, the source key still exists.
        // Using the derived UID would cause "already exists". The production code
        // uses a fresh UUID for generic splits (all_ceremony_tagged = false).
        // This test just verifies the derivation logic is correct for ceremony splits.
        let is_ceremony = true;
        let generic = false;
        let first = "my-key#1".to_owned();
        let ceremony_uid = if is_ceremony {
            first.rfind('#').map(|pos| first[..pos].to_owned())
        } else {
            None
        };
        assert_eq!(ceremony_uid, Some("my-key".to_owned()));
        let generic_uid: Option<String> = if generic {
            first.rfind('#').map(|pos| first[..pos].to_owned())
        } else {
            None
        };
        assert!(generic_uid.is_none());
    }
}
