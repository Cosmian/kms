use std::sync::Arc;

use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::State,
        kmip_2_1::{
            kmip_operations::{Locate, LocateResponse},
            kmip_types::UniqueIdentifier,
        },
    },
    cosmian_kms_crypto::crypto::access_policy_from_attributes,
    cosmian_kms_interfaces::SessionParams,
};
use cosmian_logger::trace;

use crate::{core::KMS, result::KResult};

pub(crate) async fn locate(
    kms: &KMS,
    request: Locate,
    state: Option<State>,
    user: &str,
    params: Option<Arc<dyn SessionParams>>,
) -> KResult<LocateResponse> {
    trace!("{}", request);
    // Find all the objects that match the attributes
    let uids_attrs = kms
        .database
        .find(Some(&request.attributes), state, user, false, params)
        .await?;
    for (uid, _, attributes) in &uids_attrs {
        trace!("Found uid: {}, attributes: {}", uid, attributes);
    }
    // Filter the uids that match the access access structure and exclude Destroyed objects by default.
    // Per KMIP, destroyed objects should only be returned if explicitly requested via Storage Status Mask.
    let mut uids = Vec::new();
    if access_policy_from_attributes(&request.attributes).is_err() {
        for (uid, state, attributes) in uids_attrs {
            trace!(
                "UID: {:?}, State: {:?}, Attributes: {}",
                uid, state, attributes
            );
            // Exclude destroyed objects unless caller explicitly constrained state (not currently exposed)
            if matches!(state, State::Destroyed | State::Destroyed_Compromised) {
                continue;
            }
            // If there is no access structure, accept; otherwise would compare the access policies
            uids.push(UniqueIdentifier::TextString(uid));
        }
    }

    // Respect MaximumItems only when explicitly provided. If absent, return all matches.
    if let Some(mi) = request.maximum_items {
        let max_items = usize::try_from(mi.max(0))?;
        if uids.len() > max_items {
            uids.truncate(max_items);
        }
    }
    trace!("UIDs count (post-truncate): {}", uids.len());
    let response = LocateResponse {
        located_items: Some(i32::try_from(uids.len())?),
        unique_identifier: if uids.is_empty() { None } else { Some(uids) },
    };

    Ok(response)
}
