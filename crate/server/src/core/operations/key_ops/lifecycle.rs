//! Key lifecycle management: authorization helpers, digest-aware lifecycle
//! initialization, and cascading-operation metrics.

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::kmip_2_1::{
        KmipOperation,
        kmip_attributes::Attributes,
        kmip_objects::{Object, ObjectType},
    },
    cosmian_kms_interfaces::ObjectWithMetadata,
};
use time::OffsetDateTime;

use crate::{
    core::{KMS, operations::digest::digest},
    result::KResult,
};

// ─── Lifecycle helpers ───────────────────────────────────────────────────────

/// Check whether `user` is allowed to perform `operation` on this object.
///
/// Returns `true` if the user is the owner or has been explicitly granted
/// the requested operation.
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

// ─── Object lifecycle initialization ─────────────────────────────────────────

/// Initialize lifecycle attributes on a newly created or imported object.
///
/// Computes the KMIP digest (SHA-256 via OpenSSL), then delegates to
/// [`Object::setup_lifecycle`] for the state-machine logic.
pub(crate) fn setup_object_lifecycle(
    object: &mut Object,
    object_type: ObjectType,
    requested_activation_date: Option<OffsetDateTime>,
) -> KResult<Attributes> {
    let computed_digest = digest(object)?;
    Ok(object.setup_lifecycle(object_type, requested_activation_date, computed_digest)?)
}

// ─── Metrics ─────────────────────────────────────────────────────────────────

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

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::panic_in_result_fn)]
mod tests {
    use cosmian_kms_server_database::reexport::cosmian_kmip::{
        kmip_0::kmip_types::State,
        kmip_2_1::{
            kmip_attributes::Attributes,
            kmip_data_structures::{KeyBlock, KeyMaterial, KeyValue},
            kmip_objects::{Object, ObjectType, SymmetricKey},
            kmip_types::{CryptographicAlgorithm, KeyFormatType},
        },
        time_normalize,
    };
    use time::Duration;
    use zeroize::Zeroizing;

    use super::*;

    fn test_object() -> Object {
        Object::SymmetricKey(SymmetricKey {
            key_block: KeyBlock {
                key_format_type: KeyFormatType::Raw,
                key_value: Some(KeyValue::Structure {
                    key_material: KeyMaterial::ByteString(Zeroizing::new(vec![1, 2, 3, 4])),
                    attributes: Some(Attributes::default()),
                }),
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

        assert_eq!(owm.effective_state(), State::Active);
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

        assert_eq!(owm.effective_state(), State::PreActive);
        Ok(())
    }

    #[test]
    fn test_effective_state_preactive_without_activation_date() {
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

        assert_eq!(owm.effective_state(), State::PreActive);
    }

    #[test]
    fn test_setup_object_lifecycle_past_date_gives_active() -> KResult<()> {
        let mut obj = test_object();
        let past = time_normalize()? - Duration::hours(1);
        let attrs = setup_object_lifecycle(&mut obj, ObjectType::SymmetricKey, Some(past))?;
        assert_eq!(attrs.state, Some(State::Active));
        Ok(())
    }

    #[test]
    fn test_setup_object_lifecycle_no_date_gives_preactive() -> KResult<()> {
        let mut obj = test_object();
        let attrs = setup_object_lifecycle(&mut obj, ObjectType::SymmetricKey, None)?;
        assert_eq!(attrs.state, Some(State::PreActive));
        Ok(())
    }

    #[test]
    fn test_setup_object_lifecycle_future_date_gives_preactive() -> KResult<()> {
        let mut obj = test_object();
        let future = time_normalize()? + Duration::hours(1);
        let attrs = setup_object_lifecycle(&mut obj, ObjectType::SymmetricKey, Some(future))?;
        assert_eq!(attrs.state, Some(State::PreActive));
        assert_eq!(attrs.activation_date, Some(future));
        Ok(())
    }

    #[test]
    fn test_effective_state_active_remains_active() {
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

        assert_eq!(owm.effective_state(), State::Active);
    }

    #[test]
    fn test_effective_state_active_with_past_deactivation_date() -> KResult<()> {
        let attrs = Attributes {
            state: Some(State::Active),
            deactivation_date: Some(time_normalize()? - Duration::hours(1)),
            ..Default::default()
        };

        let owm = ObjectWithMetadata::new(
            "test-id".to_owned(),
            test_object(),
            "owner".to_owned(),
            State::Active,
            attrs,
        );

        assert_eq!(owm.effective_state(), State::Deactivated);
        Ok(())
    }

    #[test]
    fn test_effective_state_active_with_future_deactivation_date() -> KResult<()> {
        let attrs = Attributes {
            state: Some(State::Active),
            deactivation_date: Some(time_normalize()? + Duration::hours(1)),
            ..Default::default()
        };

        let owm = ObjectWithMetadata::new(
            "test-id".to_owned(),
            test_object(),
            "owner".to_owned(),
            State::Active,
            attrs,
        );

        assert_eq!(owm.effective_state(), State::Active);
        Ok(())
    }
}
