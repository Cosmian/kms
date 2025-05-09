use std::sync::Arc;

use cosmian_kmip::{
    kmip_0::kmip_types::State,
    kmip_2_1::{
        kmip_operations::{Locate, LocateResponse},
        kmip_types::UniqueIdentifier,
    },
};
use cosmian_kms_crypto::crypto::cover_crypt::attributes::access_policy_from_attributes;
use cosmian_kms_interfaces::SessionParams;
use tracing::trace;

use crate::{core::KMS, result::KResult};

pub(crate) async fn locate(
    kms: &KMS,
    request: Locate,
    state: Option<State>,
    user: &str,
    params: Option<Arc<dyn SessionParams>>,
) -> KResult<LocateResponse> {
    trace!("Locate request: {}", request);
    // Find all the objects that match the attributes
    let uids_attrs = kms
        .database
        .find(Some(&request.attributes), state, user, false, params)
        .await?;
    trace!("Found {} objects: {:?}", uids_attrs.len(), uids_attrs);
    // Filter the uids that match the access access structure
    let mut uids = Vec::new();
    if !uids_attrs.is_empty() {
        for (uid, _, attributes) in uids_attrs {
            trace!("UID: {:?}, Attributes: {:?}", uid, attributes);
            // If there is no access access structure, do not match and add, otherwise compare the access policies
            if access_policy_from_attributes(&request.attributes).is_err() {
                uids.push(UniqueIdentifier::TextString(uid));
            }
        }
    }

    trace!("UIDs: {:?}", uids);
    let response = LocateResponse {
        located_items: Some(i32::try_from(uids.len())?),
        unique_identifiers: if uids.is_empty() { None } else { Some(uids) },
    };

    Ok(response)
}
