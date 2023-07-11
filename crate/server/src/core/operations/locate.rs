use cosmian_kmip::kmip::{
    kmip_operations::{Locate, LocateResponse},
    kmip_types::StateEnumeration,
};
use cosmian_kms_utils::{
    access::ExtraDatabaseParams,
    crypto::cover_crypt::{
        attributes::access_policy_from_attributes, locate::compare_cover_crypt_attributes,
    },
};

use crate::{core::KMS, result::KResult};

pub async fn locate(
    kms: &KMS,
    request: Locate,
    state: Option<StateEnumeration>,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<LocateResponse> {
    // Find all the objects that match the attributes
    let uids_attrs = kms
        .db
        .find(Some(&request.attributes), state, owner, params)
        .await?;
    // Filter the uids that match the access policy
    let mut uids = Vec::new();
    if !uids_attrs.is_empty() {
        for (uid, _, attributes, _) in uids_attrs {
            // If there is no access policy, do not match and add, otherwise compare the access policies
            if access_policy_from_attributes(&request.attributes).is_err()
                || compare_cover_crypt_attributes(&attributes, &request.attributes)?
            {
                uids.push(uid);
            }
        }
    }

    let response = LocateResponse {
        located_items: Some(uids.len() as i32),
        unique_identifiers: if uids.is_empty() { None } else { Some(uids) },
    };

    Ok(response)
}
