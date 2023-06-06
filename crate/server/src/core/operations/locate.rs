use cosmian_kmip::kmip::{
    kmip_operations::{Locate, LocateResponse},
    kmip_types::{CryptographicAlgorithm, StateEnumeration},
};
use cosmian_kms_utils::{
    crypto::cover_crypt::{
        attributes::access_policy_from_attributes, locate::compare_cover_crypt_attributes,
    },
    types::ExtraDatabaseParams,
};

use crate::{core::KMS, error::KmsError, kms_bail, result::KResult};

pub async fn locate(
    kms: &KMS,
    request: Locate,
    state: Option<StateEnumeration>,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<LocateResponse> {
    let uids = match &request.attributes.cryptographic_algorithm {
        Some(CryptographicAlgorithm::CoverCrypt) => {
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
            uids
        }
        Some(other) => kms_bail!(KmsError::NotSupported(format!(
            "The locate of an object for algorithm: {other:?} is not yet supported"
        ))),
        None => kms_bail!(KmsError::InvalidRequest(
            "The cryptographic algorithm must be specified for object location".to_string()
        )),
    };

    let response = LocateResponse {
        located_items: Some(uids.len() as i32),
        unique_identifiers: if uids.is_empty() { None } else { Some(uids) },
    };

    Ok(response)
}
