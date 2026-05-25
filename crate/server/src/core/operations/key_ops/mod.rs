mod crypto_op;

use cosmian_kms_server_database::{
    Database,
    reexport::{
        cosmian_kmip::{
            kmip_0::kmip_types::{ErrorReason, State},
            kmip_2_1::{
                KmipOperation,
                kmip_attributes::Attributes,
                kmip_objects::{Object, ObjectType},
            },
            time_normalize,
        },
        cosmian_kms_interfaces::ObjectWithMetadata,
    },
};
pub(crate) use crypto_op::{CryptoOpSpec, has_usage_mask, perform_crypto_operation};
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

// ─── Extension trait: ObjectWithMetadata ─────────────────────────────────────

/// Server-side operations on [`ObjectWithMetadata`] that depend on KMS error types.
pub(crate) trait ObjectWithMetadataOps {
    /// Determine the effective state based on stored state and `activation_date`.
    ///
    /// A `PreActive` object whose `activation_date` has passed is treated as `Active`.
    fn get_effective_state(&self) -> KResult<State>;

    /// Enforce the KMIP process-window constraints.
    ///
    /// An Active key whose current time is before `ProcessStartDate` or after
    /// `ProtectStopDate` is rejected with `Wrong_Key_Lifecycle_State`.
    fn check_process_window(&self) -> KResult<()>;

    /// Check whether `user` is allowed to perform `operation` on this object.
    ///
    /// Returns `true` if the user is the owner or has been explicitly granted
    /// the requested operation.
    async fn user_can_perform_operation(
        &self,
        user: &str,
        operation: &KmipOperation,
        kms: &KMS,
    ) -> KResult<bool>;
}

impl ObjectWithMetadataOps for ObjectWithMetadata {
    fn get_effective_state(&self) -> KResult<State> {
        let stored_state = self.state();

        // Only PreActive objects can auto-transition to Active
        if stored_state != State::PreActive {
            return Ok(stored_state);
        }

        // Check if there's an activation_date set
        let activation_date = self.attributes().activation_date.or_else(|| {
            // Fallback to object's attributes if not in metadata
            self.object()
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

    fn check_process_window(&self) -> KResult<()> {
        if self.get_effective_state()? == State::Active {
            if let Ok(attrs) = self.object().attributes() {
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

    async fn user_can_perform_operation(
        &self,
        user: &str,
        operation: &KmipOperation,
        kms: &KMS,
    ) -> KResult<bool> {
        if user == self.owner() {
            return Ok(true);
        }
        let permissions = kms
            .database
            .list_user_operations_on_object(self.id(), user, false)
            .await?;
        Ok(permissions.contains(operation))
    }
}

// ─── Extension trait: Database ───────────────────────────────────────────────

/// Server-side authorization check on [`Database`].
pub(crate) trait DatabaseOps {
    /// Check whether a user is authorized to perform `operation` on the object
    /// identified by `uid`.
    ///
    /// The user is authorized if they own the object, or have been granted the
    /// specific `operation` **or** `Get` (which implies read-level access).
    /// For HSM keys (prefix-based UIDs), the `Get` wildcard is **not** applied.
    async fn is_user_authorized_for_operation(
        &self,
        uid: &str,
        user: &str,
        operation: KmipOperation,
    ) -> KResult<bool>;
}

impl DatabaseOps for Database {
    async fn is_user_authorized_for_operation(
        &self,
        uid: &str,
        user: &str,
        operation: KmipOperation,
    ) -> KResult<bool> {
        if self.is_object_owned_by(uid, user).await? {
            return Ok(true);
        }
        let ops = self
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

        assert_eq!(owm.get_effective_state()?, State::Active);
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

        assert_eq!(owm.get_effective_state()?, State::PreActive);
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

        assert_eq!(owm.get_effective_state()?, State::PreActive);
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

        assert_eq!(owm.get_effective_state()?, State::Active);
        Ok(())
    }
}
