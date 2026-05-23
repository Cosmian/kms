use std::collections::HashSet;

#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm;
use cosmian_kms_server_database::{
    Database,
    reexport::{
        cosmian_kmip::{
            kmip_0::kmip_types::{ErrorReason, State},
            kmip_2_1::{
                KmipOperation,
                kmip_attributes::Attributes,
                kmip_objects::{Object, ObjectType},
                kmip_types::{CryptographicParameters, UniqueIdentifier},
            },
            time_normalize,
        },
        cosmian_kms_interfaces::ObjectWithMetadata,
    },
};
use time::OffsetDateTime;

use super::digest::digest;
use crate::{
    core::{KMS, uid_utils::has_prefix},
    error::KmsError,
    result::KResult,
};

/// Initialize lifecycle attributes on a newly created or imported object.
///
/// Sets state (`PreActive` or `Active` based on `requested_activation_date`), digest,
/// `initial_date`, `original_creation_date`, `last_change_date`, `activation_date` (if `Active`),
/// and `object_type` on the object's attributes. Returns a clone of the final attributes.
pub(crate) fn setup_object_lifecycle(
    object: &mut Object,
    object_type: ObjectType,
    requested_activation_date: Option<OffsetDateTime>,
) -> KResult<Attributes> {
    let now = time_normalize()?;
    let digest = digest(object)?;
    let attributes = object.attributes_mut()?;

    let activation_allows_active = requested_activation_date.is_some_and(|d| d <= now);
    let state = if activation_allows_active {
        State::Active
    } else {
        State::PreActive
    };

    attributes.state = Some(state);
    attributes.digest = digest;
    attributes.object_type = Some(object_type);
    attributes.initial_date = Some(now);
    attributes.original_creation_date = Some(now);
    attributes.last_change_date = Some(now);
    if state == State::Active {
        attributes.activation_date = Some(now);
    }

    Ok(attributes.clone())
}

/// Fill missing (None) fields in `target` from `source`.
///
/// Every `Option` field of `CryptographicParameters` that is `None` in `target`
/// gets overwritten with the value from `source`.
pub(crate) fn fill_missing_cp_fields(
    target: &mut CryptographicParameters,
    source: &CryptographicParameters,
) {
    macro_rules! fill {
        ($($field:ident),* $(,)?) => {
            $(if target.$field.is_none() { target.$field = source.$field.clone(); })*
        };
    }
    fill!(
        block_cipher_mode,
        padding_method,
        hashing_algorithm,
        key_role_type,
        digital_signature_algorithm,
        cryptographic_algorithm,
        random_iv,
        iv_length,
        tag_length,
        fixed_field_length,
        invocation_field_length,
        counter_length,
        initial_counter_value,
        salt_length,
        mask_generator,
        mask_generator_hashing_algorithm,
        p_source,
        trailer_field,
    );
}

/// Merge request-supplied cryptographic parameters with stored key attributes.
///
/// If the request supplies no parameters, the stored ones are returned as-is.
/// If the request partially specifies parameters, the stored values fill in any
/// `None` fields. This mirrors how other operations respect registered parameters.
pub(crate) fn merge_crypto_params(
    request_params: Option<CryptographicParameters>,
    object: &Object,
) -> CryptographicParameters {
    let stored_cp = object
        .attributes()
        .ok()
        .and_then(|a| a.cryptographic_parameters.clone())
        .unwrap_or_default();
    match request_params {
        None => stored_cp,
        Some(mut req_cp) => {
            fill_missing_cp_fields(&mut req_cp, &stored_cp);
            req_cp
        }
    }
}

/// Resolve the effective cryptographic algorithm for a managed object.
///
/// Checks the key block's algorithm first, then falls back to the object's
/// external attributes.  Returns `None` when neither source provides a value.
#[cfg(feature = "non-fips")]
pub(crate) fn resolve_key_algorithm(owm: &ObjectWithMetadata) -> Option<CryptographicAlgorithm> {
    owm.object()
        .key_block()
        .ok()
        .and_then(|kb| kb.cryptographic_algorithm().copied())
        .or_else(|| owm.attributes().cryptographic_algorithm)
}

/// Returns `true` when `algo` is a PQC signature algorithm (ML-DSA or SLH-DSA).
///
/// These algorithms are dispatched to dedicated PQC signing / verification
/// routines instead of the classic OpenSSL code-path.
#[cfg(feature = "non-fips")]
pub(crate) const fn is_pqc_signature_algorithm(algo: Option<CryptographicAlgorithm>) -> bool {
    use CryptographicAlgorithm::{
        MLDSA_44, MLDSA_65, MLDSA_87, SLHDSA_SHA2_128f, SLHDSA_SHA2_128s, SLHDSA_SHA2_192f,
        SLHDSA_SHA2_192s, SLHDSA_SHA2_256f, SLHDSA_SHA2_256s, SLHDSA_SHAKE_128f, SLHDSA_SHAKE_128s,
        SLHDSA_SHAKE_192f, SLHDSA_SHAKE_192s, SLHDSA_SHAKE_256f, SLHDSA_SHAKE_256s,
    };
    matches!(
        algo,
        Some(
            MLDSA_44
                | MLDSA_65
                | MLDSA_87
                | SLHDSA_SHA2_128s
                | SLHDSA_SHA2_128f
                | SLHDSA_SHA2_192s
                | SLHDSA_SHA2_192f
                | SLHDSA_SHA2_256s
                | SLHDSA_SHA2_256f
                | SLHDSA_SHAKE_128s
                | SLHDSA_SHAKE_128f
                | SLHDSA_SHAKE_192s
                | SLHDSA_SHAKE_192f
                | SLHDSA_SHAKE_256s
                | SLHDSA_SHAKE_256f
        )
    )
}

/// Enforce the KMIP process-window constraints on a managed object.
///
/// An Active key whose current time is before `ProcessStartDate` or after
/// `ProtectStopDate` must be rejected with `Wrong_Key_Lifecycle_State`.
/// This implements the guard required by mandatory profile vectors such as
/// CS-BC-M-14-21 (Encrypt/Decrypt) and CS-AC-M-8-21 (Sign).
pub(crate) fn check_process_window(owm: &ObjectWithMetadata) -> KResult<()> {
    if get_effective_state(owm)? == State::Active {
        if let Ok(attrs) = owm.object().attributes() {
            let now = time_normalize()?;
            let too_early = attrs.process_start_date.is_some_and(|d| now < d);
            let too_late = attrs.protect_stop_date.is_some_and(|d| now > d);
            if too_early || too_late {
                return Err(KmsError::Kmip21Error(
                    ErrorReason::Wrong_Key_Lifecycle_State,
                    "DENIED".to_owned(),
                ));
            }
        }
    }
    Ok(())
}

/// Check whether `user` is allowed to perform `operation` on the given object.
///
/// Returns `true` if the user is the owner **or** has been explicitly granted
/// the requested operation. This is the common authorisation guard used by
/// Destroy and Revoke when iterating over linked objects — callers typically
/// `continue` when the function returns `false`.
pub(crate) async fn user_can_perform_operation(
    owm: &ObjectWithMetadata,
    user: &str,
    operation: &KmipOperation,
    kms: &KMS,
) -> KResult<bool> {
    if user == owm.owner() {
        return Ok(true);
    }
    let permissions = kms
        .database
        .list_user_operations_on_object(owm.id(), user, false)
        .await?;
    Ok(permissions.contains(operation))
}

/// Determine the effective state of an object based on its stored state and `activation_date`.
///
/// According to KMIP 2.1 specification, an object in `PreActive` state with an `activation_date`
/// that has passed should be treated as Active for operational purposes.
///
/// # Arguments
/// * `owm` - The object with metadata to check
///
/// # Returns
/// The effective state that should be used for operations:
/// - If stored state is `PreActive` AND `activation_date` is present and <= now: returns Active
/// - Otherwise: returns the stored state
///
/// # KMIP 2.1 Compliance
/// Per KMIP 2.1 Section 3.1.7 "Key States and Transitions":
/// - A Managed Object transitions from Pre-Active to Active when the Activation Date is reached
/// - This can happen either through explicit Activate operation or automatically when the date arrives
pub(crate) fn get_effective_state(owm: &ObjectWithMetadata) -> KResult<State> {
    let stored_state = owm.state();

    // Only PreActive objects can auto-transition to Active
    if stored_state != State::PreActive {
        return Ok(stored_state);
    }

    // Check if there's an activation_date set
    let activation_date = owm.attributes().activation_date.or_else(|| {
        // Fallback to object's attributes if not in metadata
        owm.object()
            .attributes()
            .ok()
            .and_then(|attrs| attrs.activation_date)
    });

    if let Some(activation_date) = activation_date {
        let now = time_normalize()?;
        if activation_date <= now {
            // The activation date has passed, treat as Active
            return Ok(State::Active);
        }
    }

    // No activation_date or it's in the future, remain PreActive
    Ok(State::PreActive)
}

/// Check whether a user is authorized to perform `operation` on the object identified by `uid`.
///
/// The user is authorized if they own the object, or have been granted the specific
/// `operation` **or** `Get` (which implies read-level access to the key).
///
/// For HSM keys (prefix-based UIDs), the `Get` wildcard is **not** applied — each
/// operation must be explicitly granted.
pub(crate) async fn is_user_authorized_for_operation(
    database: &Database,
    uid: &str,
    user: &str,
    operation: KmipOperation,
) -> KResult<bool> {
    if database.is_object_owned_by(uid, user).await? {
        return Ok(true);
    }
    let ops = database
        .list_user_operations_on_object(uid, user, false)
        .await?;

    // HSM keys: each operation must be explicitly granted — no Get wildcard
    if has_prefix(uid).is_some() {
        return Ok(ops.iter().any(|p| *p == operation));
    }

    Ok(ops
        .iter()
        .any(|p| *p == operation || *p == KmipOperation::Get))
}

/// Collect the single eligible crypto-oracle UID for a cryptographic operation.
///
/// Iterates over `candidate_uids`, retains those that carry a recognized prefix (oracle
/// keys), and filters out any for which the current `user` lacks authorization.
///
/// Returns:
/// * `Ok(None)` — no oracle UID is eligible; the caller should fall through to the standard
///   database path.
/// * `Ok(Some((uid, prefix)))` — exactly one oracle UID is eligible; use it.
/// * `Err(KmsError::InvalidRequest)` — more than one oracle UID is eligible (ambiguous).
pub(crate) async fn select_eligible_oracle_uid(
    operation: KmipOperation,
    op_name: &str,
    candidate_uids: &HashSet<String>,
    unique_identifier: &UniqueIdentifier,
    kms: &KMS,
    user: &str,
) -> KResult<Option<(String, String)>> {
    let mut eligible: Vec<(String, String)> = Vec::new();
    for uid in candidate_uids {
        if let Some(prefix) = has_prefix(uid) {
            if !is_user_authorized_for_operation(&kms.database, uid, user, operation).await? {
                continue;
            }
            eligible.push((uid.clone(), prefix.to_owned()));
        }
    }
    match eligible.len() {
        0 => Ok(None),
        1 => Ok(eligible.into_iter().next()),
        n => {
            let ids: Vec<&str> = eligible.iter().map(|(uid, _)| uid.as_str()).collect();
            Err(KmsError::InvalidRequest(format!(
                "{op_name}: identifier {unique_identifier} resolves to {n} valid oracle keys \
                 {ids:?}; use a unique identifier",
            )))
        }
    }
}

/// Select exactly one key from a set of candidate UIDs for a cryptographic operation.
///
/// `candidate_uids` is a `HashSet` as returned by `uid_utils::uids_from_unique_identifier`.
/// The function:
///
/// 1. Skips prefix-based (oracle) UIDs — those are handled by the caller before this call.
/// 2. Fetches each object from the database and checks it is `Active` via `get_effective_state`.
/// 3. Verifies the user is authorized via `is_user_authorized_for_operation`.
/// 4. Applies `is_eligible` — a caller-supplied predicate that checks object type / usage mask.
/// 5. Enforces uniqueness: the operation **fails** when more than one eligible key is found.
///    This prevents an attacker from silently substituting a key by tagging a second one.
///
/// # Errors
/// * `KmsError::Unauthorized`   — candidates found but the user has no permission on any of them
/// * `KmsError::ItemNotFound`   — no candidate qualifies after all filters
/// * `KmsError::InvalidRequest` — more than one eligible key matched
pub(crate) async fn select_unique_key_for_operation<F>(
    op_name: &str,
    candidate_uids: &HashSet<String>,
    unique_identifier: &UniqueIdentifier,
    operation: KmipOperation,
    kms: &KMS,
    user: &str,
    is_eligible: F,
) -> KResult<ObjectWithMetadata>
where
    F: Fn(&ObjectWithMetadata) -> KResult<bool>,
{
    let uid_display = unique_identifier.to_string();
    let mut eligible: Vec<ObjectWithMetadata> = Vec::new();
    let mut found_but_no_permission = false;

    for uid in candidate_uids {
        // Oracle (prefix) UIDs are handled by the caller — skip them here.
        if has_prefix(uid).is_some() {
            continue;
        }

        let Some(owm) = kms.database.retrieve_object(uid).await? else {
            continue;
        };

        // Must be Active (respects auto-activation via activation_date).
        if get_effective_state(&owm)? != State::Active {
            continue;
        }

        // Permission check via the shared authorization function.
        if !is_user_authorized_for_operation(&kms.database, uid, user, operation).await? {
            found_but_no_permission = true;
            continue;
        }

        // Object-type and usage-mask check supplied by the caller.
        if !is_eligible(&owm)? {
            continue;
        }

        eligible.push(owm);
    }

    match eligible.len() {
        1 => eligible
            .into_iter()
            .next()
            .ok_or_else(|| KmsError::ItemNotFound("unreachable: len == 1".to_owned())),
        0 => Err(if found_but_no_permission {
            KmsError::Unauthorized(format!(
                "{op_name}: user {user} does not have permission to use key: {uid_display}"
            ))
        } else {
            KmsError::ItemNotFound(format!(
                "{op_name}: no valid key found for identifier: {uid_display}"
            ))
        }),
        n => {
            let ids: Vec<&str> = eligible.iter().map(ObjectWithMetadata::id).collect();
            Err(KmsError::InvalidRequest(format!(
                "{op_name}: identifier {uid_display} resolves to {n} valid keys {ids:?}; \
                 use a unique identifier"
            )))
        }
    }
}

/// Record metrics for a cascading (linked-object) operation.
///
/// Used by `destroy` and `revoke` when they cascade to related keys.
pub(crate) fn record_cascading_metrics(
    op_name: &str,
    op_start: std::time::Instant,
    kms: &KMS,
    user: &str,
) {
    if let Some(metrics) = &kms.metrics {
        metrics.record_kmip_operation(op_name, user);
        metrics.record_kmip_operation_duration(op_name, op_start.elapsed().as_secs_f64());
    }
}

#[cfg(test)]
#[allow(clippy::panic_in_result_fn)]
mod tests {
    use cosmian_kms_server_database::reexport::cosmian_kmip::{
        kmip_0::kmip_types::State,
        kmip_2_1::{
            kmip_attributes::Attributes,
            kmip_data_structures::{KeyBlock, KeyValue},
            kmip_objects::{Object, SymmetricKey},
            kmip_types::{CryptographicAlgorithm, KeyFormatType},
        },
    };
    use time::Duration;
    use zeroize::Zeroizing;

    use super::*;

    fn test_object() -> Object {
        Object::SymmetricKey(SymmetricKey {
            key_block: KeyBlock {
                key_format_type: KeyFormatType::Raw,
                key_value: Some(KeyValue::ByteString(Zeroizing::new(vec![1, 2, 3, 4]))),
                key_compression_type: None,
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                cryptographic_length: Some(256),
                key_wrapping_data: None,
            },
        })
    }

    #[test]
    fn test_effective_state_preactive_with_past_activation_date() -> KResult<()> {
        let attrs = Attributes {
            state: Some(State::PreActive),
            activation_date: Some(time_normalize()? - Duration::hours(1)),
            ..Default::default()
        };

        let owm = ObjectWithMetadata::new(
            "test-id".to_owned(),
            test_object(),
            "owner".to_owned(),
            State::PreActive,
            attrs,
        );

        assert_eq!(get_effective_state(&owm)?, State::Active);
        Ok(())
    }

    #[test]
    fn test_effective_state_preactive_with_future_activation_date() -> KResult<()> {
        let attrs = Attributes {
            state: Some(State::PreActive),
            activation_date: Some(time_normalize()? + Duration::hours(1)),
            ..Default::default()
        };

        let owm = ObjectWithMetadata::new(
            "test-id".to_owned(),
            test_object(),
            "owner".to_owned(),
            State::PreActive,
            attrs,
        );

        assert_eq!(get_effective_state(&owm)?, State::PreActive);
        Ok(())
    }

    #[test]
    fn test_effective_state_preactive_without_activation_date() -> KResult<()> {
        let attrs = Attributes {
            state: Some(State::PreActive),
            ..Default::default()
        };

        let owm = ObjectWithMetadata::new(
            "test-id".to_owned(),
            test_object(),
            "owner".to_owned(),
            State::PreActive,
            attrs,
        );

        assert_eq!(get_effective_state(&owm)?, State::PreActive);
        Ok(())
    }

    #[test]
    fn test_effective_state_active_remains_active() -> KResult<()> {
        let attrs = Attributes {
            state: Some(State::Active),
            ..Default::default()
        };

        let owm = ObjectWithMetadata::new(
            "test-id".to_owned(),
            test_object(),
            "owner".to_owned(),
            State::Active,
            attrs,
        );

        assert_eq!(get_effective_state(&owm)?, State::Active);
        Ok(())
    }
}
