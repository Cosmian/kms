use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{kmip_0::kmip_types::State, time_normalize},
    cosmian_kms_interfaces::ObjectWithMetadata,
};

use crate::result::KResult;

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
