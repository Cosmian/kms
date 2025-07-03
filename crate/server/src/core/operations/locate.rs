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
    if access_policy_from_attributes(&request.attributes).is_err() {
        for (uid, _, attributes) in uids_attrs {
            trace!("UID: {:?}, Attributes: {:?}", uid, attributes);
            // If there is no access access structure, do not match and add, otherwise compare the access policies
            uids.push(UniqueIdentifier::TextString(uid));
        }
    }

    trace!("UIDs: {:?}", uids);
    let response = LocateResponse {
        located_items: Some(i32::try_from(uids.len())?),
        unique_identifier: if uids.is_empty() { None } else { Some(uids) },
    };

    Ok(response)
}
