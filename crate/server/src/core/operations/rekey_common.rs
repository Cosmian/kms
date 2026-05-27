//! Shared logic for KMIP `ReKey` (§4.4) and `ReKeyKeyPair` (§4.5) operations.
//!
//! Both operations follow the same pattern:
//! - The replacement key inherits the Name attribute from the existing key.
//! - Bidirectional links are established (`ReplacementObjectLink` / `ReplacedObjectLink`).
//! - Date arithmetic is applied when an `offset` is provided.
//! - Initial Date and Last Change Date are set to the current time.

use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_types::{LinkType, LinkedObjectIdentifier},
    },
    time_normalize,
};
use time::OffsetDateTime;

use crate::result::KResult;

/// Dates computed for a replacement key based on the existing key's dates and an optional offset.
///
/// Per KMIP 1.4 Tables 172/176:
/// - `activation = initialization + offset` (if offset provided)
/// - `deactivation = old_deactivation + (new_activation - old_activation)` (if both exist)
#[allow(clippy::struct_field_names)]
pub(crate) struct ReplacementDates {
    pub initialization_date: OffsetDateTime,
    pub activation_date: Option<OffsetDateTime>,
    pub deactivation_date: Option<OffsetDateTime>,
}

/// Compute the replacement key's dates from the existing key's attributes and an optional offset.
///
/// KMIP 1.4 §4.4 Table 172 / §4.5 Table 176:
/// - Initialization Date (IT₂) = now (always > IT₁)
/// - Activation Date (AT₂) = IT₂ + Offset (if offset provided), else IT₂ (immediate activation)
/// - Deactivation Date = DT₁ + (AT₂ - AT₁) (if both DT₁ and AT₁ exist)
pub(crate) fn compute_replacement_dates(
    old_attrs: &Attributes,
    offset: Option<i32>,
) -> KResult<ReplacementDates> {
    let now = time_normalize()?;

    let activation_date =
        Some(offset.map_or(now, |secs| now + time::Duration::seconds(i64::from(secs))));

    let deactivation_date = match (old_attrs.deactivation_date, old_attrs.activation_date) {
        (Some(old_deactivation), Some(old_activation)) => {
            // DT₂ = DT₁ + (AT₂ - AT₁)
            activation_date.map(|new_activation| {
                let shift = new_activation - old_activation;
                old_deactivation + shift
            })
        }
        _ => None,
    };

    Ok(ReplacementDates {
        initialization_date: now,
        activation_date,
        deactivation_date,
    })
}

/// Prepare attributes for a replacement key, following KMIP 1.4 §4.4 Table 173 / §4.5 Table 177.
///
/// This function:
/// - Copies attributes from the existing key
/// - Removes stale unique identifier and links
/// - Sets `ReplacedObjectLink` → old key
/// - Transfers the Name from old key (already in the cloned attributes)
/// - Sets Initial Date, Last Change Date to now
/// - Applies offset-based date arithmetic
/// - Clears fields that must not be carried over (`destroy_date`, compromise dates, revocation)
pub(crate) fn prepare_replacement_attributes(
    old_attrs: &Attributes,
    old_uid: &str,
    offset: Option<i32>,
) -> KResult<Attributes> {
    let dates = compute_replacement_dates(old_attrs, offset)?;

    let mut new_attrs = old_attrs.clone();

    // Clear fields that must not be set on the replacement key
    new_attrs.unique_identifier = None;
    new_attrs.destroy_date = None;
    new_attrs.compromise_date = None;
    new_attrs.compromise_occurrence_date = None;
    // Revocation reason is stored in state, not attributes directly

    // Remove any existing replacement/replaced links (from a previous rekey)
    new_attrs.remove_link(LinkType::ReplacementObjectLink);
    new_attrs.remove_link(LinkType::ReplacedObjectLink);

    // Set the ReplacedObjectLink on the new key pointing to the old key
    new_attrs.set_link(
        LinkType::ReplacedObjectLink,
        LinkedObjectIdentifier::TextString(old_uid.to_owned()),
    );

    // Set dates per spec
    new_attrs.initial_date = Some(dates.initialization_date);
    new_attrs.last_change_date = Some(dates.initialization_date);
    new_attrs.activation_date = dates.activation_date;
    if dates.deactivation_date.is_some() {
        new_attrs.deactivation_date = dates.deactivation_date;
    }

    Ok(new_attrs)
}

/// Update the old key's attributes after a rekey operation.
///
/// Per KMIP 1.4 §4.4 Table 173 / §4.5 Table 177:
/// - Sets `ReplacementObjectLink` → new key
/// - Removes the Name attribute (transferred to the replacement)
/// - Updates Last Change Date to now
pub(crate) fn update_old_key_after_rekey(old_attrs: &mut Attributes, new_uid: &str) -> KResult<()> {
    let now = time_normalize()?;

    // Set the ReplacementObjectLink on the old key pointing to the new key
    old_attrs.set_link(
        LinkType::ReplacementObjectLink,
        LinkedObjectIdentifier::TextString(new_uid.to_owned()),
    );

    // Remove the Name from the old key (it's taken over by the new key)
    old_attrs.name = None;

    // Update Last Change Date
    old_attrs.last_change_date = Some(now);

    Ok(())
}
