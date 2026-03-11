use std::collections::HashSet;

use cosmian_kms_server_database::{
    Database,
    reexport::{
        cosmian_kmip::{
            kmip_0::kmip_types::State,
            kmip_2_1::{KmipOperation, kmip_types::UniqueIdentifier},
            time_normalize,
        },
        cosmian_kms_interfaces::ObjectWithMetadata,
    },
};

use crate::{
    core::{KMS, uid_utils::has_prefix},
    error::KmsError,
    result::KResult,
};

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
    Ok(ops
        .iter()
        .any(|p| *p == operation || *p == KmipOperation::Get))
}

/// Select exactly one key from a set of candidate UIDs for a cryptographic operation.
///
/// `candidate_uids` is a `HashSet` as returned by `uid_utils::uids_from_unique_identifier`.
/// The function:
///
/// 1. Skips prefix-based (oracle) UIDs — those are handled by the caller before this call.
/// 2. Fetches each object from the database and checks it is `Active` via `get_effective_state`.
/// 3. Verifies the user holds at least one of `required_permissions`.
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
    required_permissions: &[KmipOperation],
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

        // Permission check: owners always pass; others need an explicit grant.
        if owm.owner() != user {
            let ops = kms
                .database
                .list_user_operations_on_object(uid, user, false)
                .await?;
            if !ops.iter().any(|p| required_permissions.contains(p)) {
                found_but_no_permission = true;
                continue;
            }
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
