use cosmian_kmip::kmip::kmip_types::Attributes;

use crate::{
    crypto::abe::attributes::{access_policy_from_attributes, attributes_from_attributes},
    result::LibResult,
};

/// 2 types of KMIP attributes comparison: (it depends if
/// `researched_attributes` contains "`abe_attributes`" vendor attributes) first:
///   compare only access policies of the 2 `Attributes` input parameters
/// second:
///   return `true` if both `Attributes` contains the same master private key
/// unique identifier and if one of the ABE attributes (found in
/// `researched_attributes` through vendor attributes) is found in `attributes`
pub fn compare_abe_attributes(
    attributes: &Attributes,
    researched_attributes: &Attributes,
) -> LibResult<bool> {
    match access_policy_from_attributes(attributes) {
        Ok(access_policy) => {
            match access_policy_from_attributes(researched_attributes) {
                Ok(researched_access_policy) => {
                    if researched_access_policy == access_policy {
                        return Ok(true)
                    }
                }
                Err(_) => {
                    let abe_attributes =
                        attributes_from_attributes(researched_attributes).unwrap_or_default();
                    let master_private_key_unique_identifier = match attributes.get_parent_id() {
                        Some(id) => id,
                        None => return Ok(false),
                    };
                    let researched_master_private_key_unique_identifier =
                        match researched_attributes.get_parent_id() {
                            Some(id) => id,
                            None => return Ok(false),
                        };
                    if master_private_key_unique_identifier
                        == researched_master_private_key_unique_identifier
                    {
                        let does_match = access_policy
                            .attributes()
                            .iter()
                            .any(|attr| abe_attributes.contains(attr));
                        if does_match {
                            return Ok(true)
                        }
                    }
                }
            }
            Ok(false)
        }
        Err(_) => Ok(false),
    }
}
