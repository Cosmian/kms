use cosmian_kms_server_database::reexport::cosmian_kmip::{
    kmip_0::kmip_types::State,
    kmip_2_1::{
        kmip_operations::{Locate, LocateResponse},
        kmip_types::UniqueIdentifier,
    },
};
use cosmian_logger::trace;

use crate::{core::KMS, result::KResult};

/// Server-side cap on Locate result sets (A04-3 / EXT2-4).
///
/// Prevents unbounded database queries and oversized response payloads when a client
/// omits `MaximumItems` or requests more objects than this threshold.
const MAX_LOCATE_ITEMS: u32 = 1000;

pub(crate) async fn locate(
    kms: &KMS,
    request: Locate,
    state: Option<State>,
    user: &str,
) -> KResult<LocateResponse> {
    trace!("{}", request);
    // Determine the effective state filter: prefer explicit parameter, else Attributes.state
    let effective_state = state.or(request.attributes.state);
    // Find all the objects that match the attributes
    let uids_attrs = kms
        .database
        .find(
            Some(&request.attributes),
            effective_state,
            user,
            false,
            kms.vendor_id(),
        )
        .await?;
    for (uid, _, attributes) in &uids_attrs {
        trace!("Found uid: {}, attributes: {}", uid, attributes);
    }

    #[cfg(not(feature = "non-fips"))]
    let mut uids = {
        let mut uids = Vec::new();
        for (uid, state_found, attributes) in uids_attrs {
            trace!(
                "UID: {:?}, State: {:?}, Attributes: {}",
                uid, state_found, attributes
            );
            // If an explicit state filter is provided, enforce it strictly.
            if let Some(s) = effective_state {
                if state_found != s {
                    continue;
                }
            } else {
                // Otherwise, exclude destroyed objects
                if matches!(state_found, State::Destroyed | State::Destroyed_Compromised) {
                    continue;
                }
            }
            // If there is no access structure, accept; otherwise would compare
            // the access policies
            uids.push(UniqueIdentifier::TextString(uid));
        }
        uids
    };

    #[cfg(feature = "non-fips")]
    let mut uids = {
        // Filter the uids that match the access structure.
        //
        // If no explicit state is requested, exclude Destroyed objects by
        // default per KMIP.
        use cosmian_kms_server_database::reexport::cosmian_kms_crypto::crypto::access_policy_from_attributes;

        let mut uids = Vec::new();
        if access_policy_from_attributes(kms.vendor_id(), &request.attributes).is_err() {
            for (uid, state_found, attributes) in uids_attrs {
                trace!(
                    "UID: {:?}, State: {:?}, Attributes: {}",
                    uid, state_found, attributes
                );
                // If an explicit state filter is provided, enforce it strictly.
                if let Some(s) = effective_state {
                    if state_found != s {
                        continue;
                    }
                } else {
                    // Otherwise, exclude destroyed objects
                    if matches!(state_found, State::Destroyed | State::Destroyed_Compromised) {
                        continue;
                    }
                }
                // If there is no access structure, accept; otherwise would
                // compare the access policies
                uids.push(UniqueIdentifier::TextString(uid));
            }
        }
        uids
    };

    // Apply a server-side cap on result set size (A04-3 / EXT2-4).
    // The effective limit is the smaller of: client-supplied MaximumItems (if any)
    // and the server-side MAX_LOCATE_ITEMS constant.  When MaximumItems is absent
    // the server cap is applied automatically to prevent unbounded DB result sets.
    let server_cap = usize::try_from(MAX_LOCATE_ITEMS)?;
    let effective_max = request.maximum_items.map_or(server_cap, |mi| {
        usize::try_from(mi.max(0))
            .unwrap_or(server_cap)
            .min(server_cap)
    });
    if uids.len() > effective_max {
        uids.truncate(effective_max);
    }
    trace!("UIDs count (post-truncate): {}", uids.len());
    let response = LocateResponse {
        located_items: Some(i32::try_from(uids.len())?),
        unique_identifier: if uids.is_empty() { None } else { Some(uids) },
    };

    Ok(response)
}
